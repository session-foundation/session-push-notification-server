#include "hivemind.hpp"

#include <fmt/chrono.h>
#include <fmt/std.h>
#include <oxenc/base32z.h>
#include <oxenc/bt_producer.h>
#include <oxenc/bt_serialize.h>
#include <oxenmq/batch.h>
#include <oxenmq/message.h>
#include <sodium/crypto_sign_ed25519.h>
#include <spdlog/common.h>
#include <systemd/sd-daemon.h>

#include <chrono>
#include <concepts>
#include <nlohmann/json.hpp>
#include <oxen/log.hpp>
#include <oxen/quic/btstream.hpp>
#include <oxen/quic/format.hpp>
#include <oxen/quic/gnutls_crypto.hpp>
#include <oxen/quic/opt.hpp>
#include <oxenmq/zmq.hpp>
#include <set>
#include <stdexcept>
#include <tuple>
#include <utility>

#include "blake2b.hpp"
#include "hive/signature.hpp"
#include "hive/subscription.hpp"

namespace spns {

namespace log = oxen::log;
static auto cat = log::Cat("hivemind");
static auto stats = log::Cat("stats");

std::atomic<int> next_hivemind_id{1};

HiveMind::HiveMind(Config conf_in) :
        config{std::move(conf_in)},
        pool_{config.pg_connect},
        omq_{std::string{config.omq_pubkey.sv()},
             std::string{config.omq_privkey.sv()},
             false,
             nullptr},
        object_id_{next_hivemind_id++} {

    // fiddle_rlimit_nofile();

    sd_notify(0, "STATUS=Initializing OxenMQ");

    // OMQ is only used for local traffic from the web worker (new/renewed subscriptions) and the
    // individual notifiers, so we don't need a huge number of threads.
    omq_.set_general_threads(std::max<int>(4, std::thread::hardware_concurrency() / 8));
    omq_.set_batch_threads(std::max<int>(4, std::thread::hardware_concurrency() / 2));

    // We listen on a local socket for connections from other local services (web frontend,
    // notification services).
    omq_.listen_plain(
            config.hivemind_sock, [](std::string_view addr, std::string_view /*pk*/, bool /*sn*/) {
                log::info(cat, "Incoming local sock connection from {}", addr);
                return oxenmq::AuthLevel::admin;
            });
    log::info(cat, "Listening for local connections on {}", config.hivemind_sock);

    if (config.hivemind_curve) {
        auto allow_curve_conn = [this](std::string_view addr, std::string_view pk, bool /*sn*/) {
            bool is_admin = false;
            for (const auto& admin : config.hivemind_curve_admin) {
                if (admin.sv() == pk) {
                    is_admin = true;
                    break;
                }
            }
            log::info(cat, "Incoming {} connection from {}", is_admin ? "admin" : "public", addr);
            return is_admin ? oxenmq::AuthLevel::admin : oxenmq::AuthLevel::none;
        };
        omq_.listen_curve(*config.hivemind_curve, std::move(allow_curve_conn));

        std::string log_addr = *config.hivemind_curve;
        if (starts_with(log_addr, "tcp://"))
            log_addr = "curve://{}/{}"_format(
                    log_addr.substr(6), oxenc::to_base32z(omq_.get_pubkey()));
        log::info(cat, "Listening for incoming connections on {}", log_addr);
    }

    // Invoked by our oxend to notify of a new block:
    omq_.add_category("notify", oxenmq::AuthLevel::basic)
            .add_command("block", ExcWrapper{*this, &HiveMind::on_new_block, "on_new_block"});

    omq_.add_category("push", oxenmq::AuthLevel::none, 0, 1000)

            // Adds/updates a subscription.  This is called from the HTTP process to pass along an
            // incoming (re)subscription.  The request must be json such as:
            //
            // {
            //     "pubkey": "05123...",
            //     "session_ed25519": "abc123...",
            //     "subaccount": "03010000def789...",
            //     "subaccount_sig": "14c7b71f...",
            //     "namespaces": [-400,0,1,2,17],
            //     "data": true,
            //     "sig_ts": 1677520760,
            //     "signature": "f8efdd120007...",
            //     "service": "apns",
            //     "service_info": { ... },
            //     "enc_key": "abcdef..." (32 bytes: 64 hex or 43 base64).
            // }
            //
            // or a JSON array of such objects.
            //
            // The `service_info` argument is passed along to the underlying notification provider
            // and must contain whatever info is required to send notifications to the device:
            // typically some device ID, and possibly other data.  It is specific to each
            // notification provider.
            //
            // The reply is JSON; an error looks like:
            //
            //     { "error": 123, "message": "Something getting wrong!" }
            //
            // where "error" is one of the hive/subscription.hpp SUBSCRIBE enum values.
            //
            // On a successful subscription you get back one of:
            //
            //     { "success": true, "added": true, "message": "Subscription successful" }
            //
            //     { "success": true, "updated": true, "message": "Resubscription successful" }
            //
            // If given an array of objects then the response is an array of such return values for
            // each individual subscription item.
            //
            // Note that the "message" strings are subject to change and should not be relied on
            // programmatically; instead rely on the "error" or "success" values.
            .add_request_command(
                    "subscribe", ExcWrapper{*this, &HiveMind::on_subscribe, "on_subscribe"})

            .add_request_command(
                    "unsubscribe", ExcWrapper{*this, &HiveMind::on_unsubscribe, "on_unsubscribe"})

            // end of "push." commands
            ;

    // Commands for local services to talk to us:
    omq_.add_category("admin", oxenmq::AuthLevel::admin)

            // Registers a notification service.  This gets called with a single argument containing
            // the service name(s) (e.g. "apns", "firebase") that should be pushed to this
            // connection when notifications or subscriptions arrive.  (If a single connection
            // provides multiple services it should invoke this endpoint multiple times).
            //
            // The invoking OMQ connection must accept two commands:
            //
            // `notifier.validate` request command.  This is called on an incoming subscription or
            // unsubscription to validate and parse it.  It is passed a two-part message: the
            // service name (e.g. b"apns") that the client requested, and the JSON registration data
            // as supplied by the client.  The return is one of:
            //
            // - [b'0', b'unique service id', b'supplemental data']  (acceptable registration)
            // - [b'0', b'unique service id']   (acceptable, with no supplemental data)
            // - [b'4', b'Error string']  (non-zero code: code and error message returned to the
            //   client)
            //
            // where the unique service id must be a utf8-encoded string that is at least 32
            // characters long and unique for the device/app in question (if the same service id for
            // the same service already exists, the registration is replaced; otherwise it is a new
            // registration). The supplemental data will be stored and passed along when
            // notifications are provided to the following command.  The remote should *not* store
            // local state associated with the registration: instead everything is meant to be
            // stored by the hivemind caller and then passed back in (via the following endpoint).
            //
            // `notifier.push` is a (non-request) command.  This is called when a user is to be
            // notified of an incoming message.  It is a single-part, bencoded dict containing:
            //
            // - '' -- the service name, e.g. b"apns"
            // - '&' -- the unique service id (as was provided by the validate endpoint).
            // - '!' -- supplemental service data, if the validate request returned any; omitted
            //   otherwise.
            // - '^' -- the xchacha20-poly1305encryption key the user gave when registering for
            //   notifications with which the notification payload should be encrypted.
            // - '#' -- the message hash from storage server.
            // - '@' -- the account ID (Session ID or closed group ID) to which the message was sent
            //   (33 bytes).
            // - 'n' -- the swarm namespace to which the message was deposited (-32768 to 32767).
            // - 't' -- the swarm timestamp when the message was created (unix epoch milliseconds).
            // - 'z' -- the message's swarm expiry timestamp (unix epoch milliseconds).
            // - '~' -- the encrypted message data; this field will not be present if the
            //   registration did not request data.
            .add_command(
                    "register_service",
                    ExcWrapper{*this, &HiveMind::on_reg_service, "on_reg_service"})

            // Called periodically to notify us of notifier stats (notifications, failures, etc.)
            .add_command(
                    "service_stats",
                    ExcWrapper{*this, &HiveMind::on_service_stats, "on_service_stats"})

            // Retrieves current statistics
            .add_request_command(
                    "get_stats", ExcWrapper{*this, &HiveMind::on_get_stats, "on_get_stats"})

            // Drops one or more registrations; this is invoked by a notifier when the upstream
            // notification service has indicated that the notification token is no longer valid.
            //
            // Called with two values: the service id (e.g. "apns", "firebase") and a bt-encoded
            // list of unique service ids (as would have been returned by the service's
            // notifier.validate) to remote.  This endpoint is a command (i.e. has no reply).
            .add_command(
                    "drop_registrations",
                    ExcWrapper{*this, &HiveMind::on_drop_registrations, "on_drop_registrations"})

            // end of "admin." commands
            ;

    const auto out_alpn = quic::opt::outbound_alpn("oxenstorage");
    const auto in_alpn = quic::opt::inbound_alpn("spns");

    if (!config.quic_listen.empty()) {
        if (!config.quic_keys)
            throw std::runtime_error{"Configuration error: quic_listen requires quic_keys"};
        creds_in_ = quic::GNUTLSCreds::make_from_ed_seckey(config.quic_keys->sv());
        creds_out_ = creds_in_;

        for (const auto& addr : config.quic_listen) {
            // We only use one address for outbound connections, but it needs to be IPv4 capable
            std::optional<quic::opt::outbound_alpns> maybe_out_alpn;
            if (!quic_out_ &&
                (addr.is_ipv4() || (addr.is_ipv6() && addr.is_any_addr() && addr.dual_stack)))
                maybe_out_alpn = out_alpn;

            auto ep = quic::Endpoint::endpoint(loop_, addr, in_alpn, maybe_out_alpn);

            ep->listen(
                    creds_in_,
                    [this](quic::Connection& c, quic::Endpoint& e, std::optional<int64_t>) {
                        return e.loop.make_shared<quic::BTRequestStream>(
                                c, e, [this](quic::message m) { on_quic_request(m); });
                    });

            if (maybe_out_alpn)
                quic_out_ = ep;
            quic_in_.push_back(std::move(ep));
        }
    } else {
        // TODO: Once all nodes are running the SS version that comes with 11.6.0+ we can just get
        // rid of creds_out_ and remove it from the `connect()` calls to do unauthenticated
        // connections (which are allowed in SS 2.11.1+, which comes with 11.6.0+), but in earlier
        // versions of quic that results in stateless reset-rejected connections.
        //
        // Thus for now, this randomly generated key:
        std::array<unsigned char, crypto_sign_ed25519_PUBLICKEYBYTES> pk;
        std::array<unsigned char, crypto_sign_ed25519_SECRETKEYBYTES> sk;
        crypto_sign_ed25519_keypair(pk.data(), sk.data());
        creds_out_ = quic::GNUTLSCreds::make_from_ed_seckey(
                std::string_view{reinterpret_cast<const char*>(sk.data()), sk.size()});
    }
    if (!quic_out_) {
        // Either we aren't listening, or aren't listening on any IPv4 capable address so add
        // another non-listening endpoint that we can use for outbound connections.
        quic_out_ = quic::Endpoint::endpoint(loop_, quic::Address{}, out_alpn);
    }

    sd_notify(0, "STATUS=Cleaning database");
    log::info(cat, "Performing initial database clean-up");
    db_cleanup();
    sd_notify(0, "STATUS=Loading existing subscriptions");
    try {
        load_saved_subscriptions();
    } catch (const std::exception& e) {
        log::critical(cat, "Failed to load saved subscriptions: {}", e.what());
        throw;
    }

    notify_proc_thread_ = std::thread{[this] { process_notifications(); }};

    loop_.call_get([this] {
        sd_notify(0, "STATUS=Starting OxenMQ");
        log::info(cat, "Starting OxenMQ");
        omq_.start();
        log::info(cat, "Started OxenMQ");

        sd_notify(0, "STATUS=Connecting to oxend");
        log::info(cat, "Connecting to oxend @ {}", config.oxend_rpc.full_address());

        std::promise<void> prom;
        oxend_ = omq_.connect_remote(
                config.oxend_rpc,
                [&prom](auto) { prom.set_value(); },
                [&prom](auto, std::string_view err) {
                    try {
                        throw std::runtime_error{"oxend connection failed: " + std::string{err}};
                    } catch (...) {
                        prom.set_exception(std::current_exception());
                    }
                },
                oxenmq::AuthLevel::basic);

        log::info(cat, "Waiting for oxend connection...");
        prom.get_future().get();

        prom = {};
        omq_.request(oxend_, "ping.ping", [&prom](bool success, std::vector<std::string> data) {
            if (success)
                prom.set_value();
            else
                try {
                    std::string err = "oxend failed to respond to ping:";
                    if (data.empty())
                        data.push_back("(unknown)");
                    for (auto& m : data) {
                        err += ' ';
                        err += m;
                    }
                    throw std::runtime_error{err};
                } catch (...) {
                    prom.set_exception(std::current_exception());
                }
        });

        prom.get_future().get();
        log::info(cat, "Connected to oxend");

        sd_notify(0, "READY=1\nSTATUS=Waiting for notifiers");
    });

    if (config.notifier_wait > 0s) {
        // Wait for notification servers that start up before or alongside us to connect:
        auto wait_until = steady_clock::now() + config.notifier_wait;
        log::info(
                cat,
                "Waiting for notifiers to register (max {})",
                wait_until - steady_clock::now());
        while (!loop_.call_get([this, wait_until] { return notifier_startup_done(wait_until); }))
            std::this_thread::sleep_for(25ms);
        log::info(cat, "Done waiting for notifiers; {} registered", services_.size());
    }

    // Set our ready flag, and process any requests that accumulated while we were starting up.
    set_ready();

    refresh_sns();

    omq_.add_timer([this] { db_cleanup(); }, 30s);

    // This ticker handles re-subscriptions, clearing expiries, etc.; it's on a relatively slow
    // timer because nothing in here is time critical:
    subs_ticker_ = loop_.call_every(10s, [this] { check_subs(); });

    // For updating systemd Status line
    omq_.add_timer([this] { log_stats(); }, 15s);

    log::info(cat, "Startup complete");
}

HiveMind::~HiveMind() {
    if (notify_proc_thread_.joinable()) {
        notify_push_sock().send(zmq::message_t{"QUIT"sv}, zmq::send_flags::none);
        notify_proc_thread_.join();
    }
    loop_.call_get([this] {
        // We destroy the Endpoints first, because during quic_opt_'s destruction it triggers
        // disconnect callbacks which still have captured pointers into the SNode objects living in
        // swarms_/sns_.  We clear quic_in_ at the same time because, although it doesn't have the
        // same callback issue, quic_out_ might be shared with one of the elements in quic_in_ and
        // so could keep it alive if we don't clear it too and it is indeed shared.
        //
        // We transfer the quic_out_ shared ptr into a local variable here so that quic_out_ itself
        // will be empty when the callbacks fire, which allow them to detect that it is during
        // shutdown and alter their behaviour.  (Shared ptr object destruction happens before the
        // pointer is cleared, so without transferring it would still be set during disconnect
        // callbacks).
        auto q = std::move(quic_out_);
        quic_in_.clear();
        q.reset();

        swarms_.clear();
        sns_.clear();
    });
}

zmq::socket_t& HiveMind::notify_push_sock() {
    static thread_local int last_id = -1;
    static thread_local zmq::socket_t* last_socket = nullptr;
    if (last_id != object_id_) {
        std::lock_guard lock{notify_push_mutex_};

        auto& socket = notify_push_[std::this_thread::get_id()];
        if (!socket) {
            socket = std::make_unique<zmq::socket_t>(notification_ctx_, zmq::socket_type::push);
            socket->set(zmq::sockopt::linger, 0);
            socket->connect("inproc://notify_handler");
        }
        last_id = last_id;
        last_socket = socket.get();
    }
    return *last_socket;
}

bool HiveMind::notifier_startup_done(const steady_time& wait_until) {
    // NB: lock is held by the caller

    // If we were told which notifiers to wait for then check to see if they are all present, and if
    // so return early:
    std::vector<std::string_view> missing;
    if (!config.notifiers_expected.empty()) {
        for (const auto& service : config.notifiers_expected) {
            if (!services_.count(service))
                missing.emplace_back(service);
        }
        if (missing.empty()) {
            log::info(cat, "All configured notifiers have registered");
            return true;
        }
    }

    // Otherwise we keep waiting until wait_until
    bool done_waiting = steady_clock::now() > wait_until;

    if (done_waiting && !config.notifiers_expected.empty())
        log::warning(
                cat,
                "Notifier startup timeout reached; did not receive registrations for: {}",
                "{}"_format(fmt::join(missing, ", ")));

    return done_waiting;
}

void HiveMind::set_ready() {
    // Set `ready` with this main mutex held (even though it is atomic!) so that we can be sure that
    // nothing gets added to `deferred_` between the time we set it, and draining it below.
    // (defer_request handles the race: if it gets the lock and `ready` has been flipped to true, it
    // notices and calls right away instead of adding to deferred_).
    {
        std::lock_guard lock{deferred_mutex_};
        ready = true;
    }

    while (!deferred_.empty()) {
        std::move(deferred_.front())();
        deferred_.pop_front();
    }
}
void HiveMind::defer_request(oxenmq::Message&& m, ExcWrapper& callback) {
    {
        std::lock_guard lock{deferred_mutex_};
        if (!ready) {
            deferred_.emplace_back(std::move(m), callback);
            return;
        }
    }
    // Must have flipped between the check and now, so don't actually defer it
    callback(m);
}
void HiveMind::defer_request(quic::message&& m, ExcWrapper& callback) {
    {
        std::lock_guard lock{deferred_mutex_};
        if (!ready) {
            deferred_.emplace_back(std::move(m), callback);
            return;
        }
    }
    // Must have flipped between the check and now, so don't actually defer it
    callback(m);
}
DeferredRequest::DeferredRequest(oxenmq::Message&& m, ExcWrapper& callback) :
        message{std::in_place_type<oxenmq::Message>,
                m.oxenmq,
                std::move(m.conn),
                std::move(m.access),
                std::move(m.remote)},
        callback{callback} {
    auto& msg = std::get<oxenmq::Message>(message);
    data.reserve(m.data.size());
    for (const auto& d : m.data)
        msg.data.emplace_back(data.emplace_back(d));
}
DeferredRequest::DeferredRequest(quic::message&& m, ExcWrapper& callback) :
        message{std::move(m)}, callback{callback} {}

static void json_error(oxenmq::Message& m, hive::SUBSCRIBE err, std::string_view msg) {
    int code = static_cast<int>(err);
    log::debug(cat, "Replying with error code {}: {}", code, msg);
    m.send_reply(nlohmann::json{{"error", code}, {"message", msg}}.dump());
}
static void json_error(quic::message& m, hive::SUBSCRIBE err, std::string_view msg) {
    int code = static_cast<int>(err);
    log::debug(cat, "Replying with error code {}: {}", code, msg);
    m.respond(nlohmann::json{{"error", code}, {"message", msg}}.dump(), /*error=*/true);
}

void ExcWrapper::operator()(oxenmq::Message& m) {
    try {
        (hivemind.*(std::get<0>(meth)))(m);
    } catch (const startup_request_defer&) {
        hivemind.defer_request(std::move(m), *this);
    } catch (const std::exception& e) {
        log::error(cat, "Exception in HiveMind::{}: {}", meth_name, e.what());
        json_error(
                m,
                hive::SUBSCRIBE::INTERNAL_ERROR,
                "An internal error occurred while processing your request");
    }
}
void ExcWrapper::operator()(quic::message& m) {
    try {
        (hivemind.*(std::get<1>(meth)))(m);
    } catch (const startup_request_defer&) {
        hivemind.defer_request(std::move(m), *this);
    } catch (const std::exception& e) {
        log::error(cat, "Exception in HiveMind::{}: {}", meth_name, e.what());
        json_error(
                m,
                hive::SUBSCRIBE::INTERNAL_ERROR,
                "An internal error occurred while processing your request");
    }
}

void HiveMind::on_reg_service(oxenmq::Message& m) {
    if (m.data.size() != 1) {
        log::error(cat, "{}-part data, expected 1", m.data.size());
        return;
    }
    std::string service{m.data[0]};
    if (service.empty()) {
        log::error(cat, "service registration used illegal empty service name");
        return;
    }
    if (service.size() > 32) {
        log::error(cat, "service name too long ({})", service.size());
        return;
    }

    loop_.call([this, cid = m.conn, service = std::move(service)] {
        bool added = false, replaced = false;
        auto [it, ins] = services_.emplace(service, cid);
        if (ins)
            log::info(cat, "'{}' notification service registered", service);
        else if (cid != it->second) {
            it->second = cid;
            log::info(cat, "'{}' notification service reconnected/reregistered", service);
        } else
            log::trace(cat, "'{}' notification service confirmed (already registered)", service);
    });
}

static void set_stat(
        pqxx::work& tx, std::string_view service, std::string_view name, std::string_view val) {
    tx.exec(
              R"(
INSERT INTO service_stats (service, name, val_str) VALUES ($1, $2, $3)
ON CONFLICT (service, name) DO UPDATE
    SET val_str = EXCLUDED.val_str, val_int = NULL)",
              {service, name, val})
            .no_rows();
}
static void set_stat(pqxx::work& tx, std::string_view service, std::string_view name, int64_t val) {
    tx.exec(
              R"(
INSERT INTO service_stats (service, name, val_int) VALUES ($1, $2, $3)
ON CONFLICT (service, name) DO UPDATE
    SET val_str = NULL, val_int = EXCLUDED.val_int)",
              {service, name, val})
            .no_rows();
}
static void increment_stat(
        pqxx::work& tx, std::string_view service, std::string_view name, int64_t incr) {
    tx.exec(
              R"(
INSERT INTO service_stats (service, name, val_int) VALUES ($1, $2, $3)
ON CONFLICT (service, name) DO UPDATE
    SET val_str = NULL, val_int = COALESCE(service_stats.val_int, 0) + EXCLUDED.val_int)",
              {service, name, incr})
            .no_rows();
}

extern "C" inline void message_buffer_destroy(void*, void* hint) {
    delete static_cast<std::string*>(hint);
}

void HiveMind::on_message_notification(quic::message m) {
    // Put the message into a new object, then transfer ownership to the notification processer
    // by sending the pointer value: the processor then picks up the pointer and takes ownership.
    auto* push = new quic::message{std::move(m)};
    uintptr_t ptr = reinterpret_cast<uintptr_t>(push);
    std::string cmd = "PUSH";
    cmd += std::string_view{reinterpret_cast<const char*>(&ptr), sizeof(ptr)};

    notify_push_sock().send(zmq::message_t{cmd}, zmq::send_flags::none);
}

void HiveMind::process_notifications() {
    notify_pull_.bind("inproc://notify_handler");
    std::vector<std::unique_ptr<quic::message>> process;
    zmq::message_t msg;

    constexpr size_t MAX_BATCH = 100;

    auto flags = zmq::recv_flags::dontwait;
    while (true) {
        if (notify_pull_.recv(msg, flags)) {
            auto cmd = msg.to_string_view();
            if (cmd == "QUIT") {
                notify_pull_.close();
                return;
            } else if (cmd.size() == 4 + sizeof(uintptr_t) && cmd.substr(0, 4) == "PUSH"sv) {
                // Read back the pointer and take back ownership
                uintptr_t ptr;
                std::memcpy(&ptr, cmd.data() + 4, sizeof(uintptr_t));
                process.emplace_back().reset(reinterpret_cast<quic::message*>(ptr));
            } else {
                log::error(cat, "Error: received unexpected internal proc command {}", cmd);
            }
            // We got something, so let's keep trying for more until we drain the queue
            flags = zmq::recv_flags::dontwait;
        } else {
            // There was nothing more waiting, so go back to synchronous for the next recv
            flags = zmq::recv_flags::none;
        }

        // Keep going until we either would block, or hit MAX_BATCH
        if (process.empty() || (flags == zmq::recv_flags::dontwait && process.size() < MAX_BATCH))
            continue;

        log::debug(cat, "Processing {} network message notifications", process.size());

        loop_.call_get([&] {
            if (auto now = steady_clock::now(); now >= filter_rotate_time_) {
                filter_rotate_ = std::move(filter_);
                filter_.clear();
                filter_rotate_time_ = now + config.filter_lifetime;
            }

            std::string buf;
            size_t notify_count = 0;

            auto conn = pool_.get();
            pqxx::work tx{conn};

            for (const auto& msg : process) {
                try {
                    oxenc::bt_dict_consumer dict{msg->body()};

                    // Parse oxen-storage-server notification:
                    if (!dict.skip_until("@")) {
                        log::warning(cat, "Unexpected notification: missing account (@)");
                        continue;
                    }
                    auto account_str = dict.consume_string_view();
                    AccountID account;
                    if (account_str.size() != account.SIZE) {
                        log::warning(cat, "Unexpected notification: wrong account size (@)");
                        continue;
                    }
                    std::memcpy(account.data(), account_str.data(), account.size());

                    if (!dict.skip_until("h")) {
                        log::warning(cat, "Unexpected notification: missing msg hash (h)");
                        continue;
                    }
                    auto hash = dict.consume_string_view();
                    if (bool too_small = hash.size() < MSG_HASH_MIN_SIZE;
                        too_small || hash.size() > MSG_HASH_MAX_SIZE) {
                        log::warning(cat, "Unexpected notification: msg hash too small");
                        continue;
                    }

                    if (!dict.skip_until("n")) {
                        log::warning(cat, "Unexpected notification: missing namespace (n)");
                        continue;
                    }
                    auto ns = dict.consume_integer<int16_t>();

                    if (!dict.skip_until("t")) {
                        log::warning(cat, "Unexpected notification: missing message timestamp (t)");
                        continue;
                    }
                    auto timestamp_ms = dict.consume_integer<int64_t>();

                    if (!dict.skip_until("z")) {
                        log::warning(cat, "Unexpected notification: missing message expiry (z)");
                        continue;
                    }
                    auto expiry_ms = dict.consume_integer<int64_t>();

                    auto maybe_data = dict.maybe<std::string_view>("~");

                    log::trace(
                            cat,
                            "Got a notification for {}, msg hash {}, namespace {}, timestamp {}, "
                            "exp {}, data {}B",
                            account.hex(),
                            hash,
                            ns,
                            timestamp_ms,
                            expiry_ms,
                            maybe_data ? fmt::to_string(maybe_data->size()) : "(N/A)");

                    // [(want_data, enc_key, service, svcid, svcdata), ...]
                    std::vector<std::tuple<
                            bool,
                            EncKey,
                            std::string,
                            std::string,
                            std::optional<bstring>>>
                            notifies;
                    std::vector<Blake2B_32> filter_vals;

                    auto result = tx.exec(
                            R"(
SELECT want_data, enc_key, service, svcid, svcdata FROM subscriptions
WHERE account = $1
    AND EXISTS(SELECT 1 FROM sub_namespaces WHERE subscription = id AND namespace = $2))",
                            {account, ns});
                    notifies.reserve(result.size());
                    filter_vals.reserve(result.size());
                    for (auto row : result) {
                        row.to(notifies.emplace_back());
                        auto& [_wd, _ek, service, svcid, _sd] = notifies.back();
                        filter_vals.push_back(blake2b(service, svcid, hash));
                    }

                    if (notifies.empty()) {
                        log::debug(cat, "No active notifications match, ignoring notification");
                        continue;
                    }

                    assert(filter_vals.size() == notifies.size());
                    auto filter_it = filter_vals.begin();
                    for (auto& [want_data, enc_key, service, svcid, svcdata] : notifies) {
                        auto& filt_hash = *filter_it++;

                        if (filter_rotate_.count(filt_hash) || !filter_.insert(filt_hash).second) {
                            log::trace(cat, "Ignoring duplicate notification");
                            continue;
                        } else {
                            log::trace(cat, "Not filtered: {}", filt_hash.hex());
                        }

                        oxenmq::ConnectionID conn;
                        if (auto it = services_.find(service); it != services_.end())
                            conn = it->second;
                        else {
                            log::warning(
                                    cat,
                                    "Notification depends on unregistered service {}, ignoring",
                                    service);
                            continue;
                        }

                        // We overestimate a little here (e.g. allowing for 20 spaces for string
                        // lengths) because a few extra bytes of allocation doesn't really matter.
                        size_t size_needed =
                                2 + 35 +                 // 0: 32:service (or shorter)
                                3 + 21 + svcid.size() +  // 1:& N:svcid
                                3 + 35 +                 // 1:^ 32:enckey
                                3 + 21 + hash.size() +   // 1:# N:hash
                                3 + 36 +                 // 1:@ 33:account
                                3 + 8 +                  // 1:n i-32768e
                                3 + 15 +                 // 1:t i1695078498534e (timestamp)
                                3 + 15 +                 // 1:t i1695078498534e (expiry)
                                (svcdata ? 3 + 21 + svcdata->size() : 0) +
                                (want_data && maybe_data ? 3 + 21 + maybe_data->size() : 0);

                        if (buf.size() < size_needed)
                            buf.resize(size_needed);

                        oxenc::bt_dict_producer dict{buf.data(), buf.data() + buf.size()};

                        try {
                            // NB: ascii sorted keys
                            dict.append("", service);
                            if (svcdata)
                                dict.append("!", as_sv(*svcdata));
                            dict.append("#", hash);
                            dict.append("&", svcid);
                            dict.append("@", account.sv());
                            dict.append("^", enc_key.sv());
                            dict.append("n", ns);
                            dict.append("t", timestamp_ms);
                            dict.append("z", expiry_ms);
                            if (want_data && maybe_data)
                                dict.append("~", *maybe_data);
                        } catch (const std::exception& e) {
                            log::critical(
                                    cat, "failed to build notifier message: bad size estimation?");
                            continue;
                        }

                        log::debug(cat, "Sending push via {} notifier", service);
                        omq_.send(conn, "notifier.push", dict.view());
                        notify_count++;
                    }
                } catch (const std::exception& e) {
                    log::warning(cat, "Failed to process incoming notification: {}", e.what());
                    continue;
                }
            }

            increment_stat(tx, "", "notifications", notify_count);
            increment_stat(tx, "", "pushes", process.size());
            tx.commit();
            pushes_processed_ += process.size();

            process.clear();
        });
    }
}

/// Called from a notifier service periodically to report statistics.
///
/// This should be called with a two-part message: the first part is the service name (e.g.
/// 'apns'); the second part is a bt-encoded dict with content such as:
///
/// {
///     '+notifies': 12,
///     '+failures': 0,
///     'other': 123
/// }
///
/// Integer values using a key beginning with a + will have the local stat (without the +) for
/// the notifier modified by the given integer value; otherwise values will be replaced.  Only
/// integer and string values are permitted (+keys only allow integers).
void HiveMind::on_service_stats(oxenmq::Message& m) {
    if (m.data.size() != 2) {
        log::warning(cat, "Invalid admin.service_stats call: expected 2-part message");
        return;
    }

    auto service = m.data[0];
    if (service.empty()) {
        log::warning(cat, "service status received illegal empty service name");
        return;
    }

    try {
        auto conn = pool_.get();
        pqxx::work tx{conn};
        oxenc::bt_dict_consumer dict{m.data[1]};

        set_stat(tx, "", "last.{}"_format(service), unix_timestamp());
        while (dict) {
            auto key = dict.key();
            if (key.substr(0, 1) == "+") {
                key.remove_prefix(1);
                increment_stat(tx, service, key, dict.consume_integer<int64_t>());
            } else if (dict.is_integer()) {
                set_stat(tx, service, key, dict.consume_integer<int64_t>());
            } else if (dict.is_string()) {
                set_stat(tx, service, key, dict.consume_string_view());
            } else {
                throw std::invalid_argument{
                        "Invalid service status: values must be string or int!"};
            }
        }

        tx.commit();
    } catch (const oxenc::bt_deserialize_invalid_type&) {
        log::warning(cat, "invalid service data: expected int or string data");
    } catch (const std::exception& e) {
        log::warning(cat, "invalid service data: {}", e.what());
    }
}

void HiveMind::get_stats_json(std::function<void(nlohmann::json)> when_ready) {
    auto result = nlohmann::json{};

    {
        auto conn = pool_.get();
        pqxx::work tx{conn};

        for (auto& [service, name, s, i] :
             tx.query<std::string, std::string, std::optional<std::string>, std::optional<int64_t>>(
                     R"(SELECT service, name, val_str, val_int FROM service_stats)")) {
            if (service == "") {
                if (s)
                    result[name] = std::move(*s);
                else {
                    result[name] = *i;
                    if (starts_with(name, "last."))
                        result["alive." + name.substr(5)] =
                                *i > unix_timestamp(system_clock::now() - 1min);
                }
            } else {
                if (s)
                    result["notifier"][service][name] = std::move(*s);
                else
                    result["notifier"][service][name] = *i;
            }
        }

        int64_t total = 0;
        for (const auto& [service, count] : tx.query<std::string, int64_t>(
                     R"(SELECT service, COUNT(*) FROM subscriptions GROUP BY service)")) {
            result["subscriptions"][service] = count;
            total += count;
        }
        result["subscriptions"]["total"] = total;

        tx.commit();
    }

    loop_.call_soon(
            [when_ready = std::move(when_ready), result = std::move(result), this]() mutable {
                size_t n_conns = 0;
                for (auto& sn : sns_)
                    n_conns += sn.second->connected();

                result["block_hash"] = last_block_.first;
                result["block_height"] = last_block_.second;
                result["swarms"] = swarms_.size();
                result["snodes"] = sns_.size();
                result["accounts_monitored"] = subscribers_.size();
                result["connections"] = n_conns;
                result["pending_connections"] = pending_connects_.load();
                result["uptime"] =
                        std::chrono::duration<double>(system_clock::now() - startup_time).count();

                when_ready(std::move(result));
            });
}

void HiveMind::on_get_stats(oxenmq::Message& m) {
    get_stats_json([m = m.send_later()](nlohmann::json stats) { m(stats.dump()); });
}

void HiveMind::log_stats(std::string pre_cmd) {
    get_stats_json([this, pre_cmd = std::move(pre_cmd)](nlohmann::json s) {
        std::list<std::string> notifiers;
        for (auto& [k, v] : s.items())
            if (starts_with(k, "last."))
                if (auto t = v.get<int64_t>(); t >= unix_timestamp(startup_time) &&
                                               t >= unix_timestamp(system_clock::now() - 1min))
                    notifiers.push_back(k.substr(5));

        int64_t total_notifies = 0;
        for (auto& [service, data] : s["notifier"].items())
            if (auto it = data.find("notifies"); it != data.end())
                total_notifies += it->get<int64_t>();

        auto stat_line = fmt::format(
                "SN conns: {}/{} ({} pending); Height: {}; Accts/Subs: {}/{}; svcs: {}; notifies: "
                "{}; "
                "pushes recv'd: {}",
                s["connections"].get<int>(),
                s["snodes"].get<int>(),
                s["pending_connections"].get<int>(),
                s["block_height"].get<int>(),
                s["accounts_monitored"].get<int>(),
                s["subscriptions"]["total"].get<int>(),
                "{}"_format(fmt::join(notifiers, ", ")),
                total_notifies,
                pushes_processed_.load());

        auto sd_out = pre_cmd.empty() ? "STATUS={}"_format(stat_line)
                                      : "{}\nSTATUS={}"_format(pre_cmd, stat_line);
        sd_notify(0, sd_out.c_str());

        if (auto now = std::chrono::steady_clock::now(); now - last_stats_logged >= 4min + 55s) {
            log::info(stats, "Status: {}", stat_line);
            last_stats_logged = now;
        } else {
            log::debug(stats, "Status: {}", stat_line);
        }
    });
}

void HiveMind::on_drop_registrations(oxenmq::Message& m) {
    if (m.data.size() != 2) {
        log::warning(cat, "Invalid admin.drop_registrations call: expected 2-part message");
        return;
    }

    auto service = m.data[0];
    if (service.empty()) {
        log::warning(cat, "admin.drop_registrations received illegal empty service name");
        return;
    }

    oxenc::bt_list_consumer drops{m.data[1]};
    if (drops.is_finished()) {
        log::warning(cat, "admin.drop_registrations called with empty token list");
        return;
    }
    auto conn = pool_.get();
    int reqed = 0, deleted = 0, matched = 0;
    try {
        pqxx::work tx{conn};
        while (!drops.is_finished()) {
            reqed++;
            auto del = tx.exec("DELETE FROM subscriptions WHERE service = $1 AND svcid = $2",
                               {service, drops.consume_string_view()})
                               .no_rows()
                               .affected_rows();
            deleted += del;
            if (del)
                matched++;
        }
        tx.commit();
    } catch (const oxenc::bt_deserialize_invalid_type&) {
        log::warning(
                cat,
                "invalid admin.on_drop_registration request: expected list of service id strings");
        return;
    }

    log::info(
            cat,
            "Dropped {} (of {} requested) {} service IDs, totalling {} account subscriptions",
            matched,
            reqed,
            service,
            deleted);
}

template <std::invocable<std::string> Reply>
static void sub_json_set_one_response(
        Reply& reply,
        nlohmann::json& response,
        size_t i,
        std::atomic<int>& remaining,
        bool multi,
        nlohmann::json val) {
    response[i] = std::move(val);

    if (--remaining == 0) {
        // This is the last response set, so we have to send all the responses
        if (!multi)
            reply(response[0].dump());
        else
            reply(response.dump());
    }
}

void HiveMind::on_notifier_validation(
        nlohmann::json& final_response,
        size_t i,
        std::atomic<int>& remaining,
        bool multi,
        bool success,
        const std::function<void(std::string_view response)>& replier,
        std::string service,
        const SwarmPubkey& pubkey,
        std::shared_ptr<hive::Subscription> sub,
        const std::optional<EncKey>& enc_key,
        std::vector<std::string> data,
        const std::optional<UnsubData>& unsub) {

    // Will have 'error'/'success', 'message', and maybe other things added
    auto response = nlohmann::json::object();
    int code = static_cast<int>(hive::SUBSCRIBE::ERROR);
    std::string message = "Unknown error";

    log::trace(cat, "Received notifier validation ({}/{})", service, success);
    try {
        if (!success) {
            log::critical(
                    cat,
                    "Communication with {} failed: {}",
                    service,
                    "{}"_format(fmt::join(data, " ")));
            if (!data.empty() && data[0] == "TIMEOUT")
                throw hive::subscribe_error{
                        hive::SUBSCRIBE::SERVICE_TIMEOUT,
                        "{} notification service timed out"_format(service)};
            throw hive::subscribe_error{
                    hive::SUBSCRIBE::ERROR,
                    "failed to communicate with {} notification service"_format(service)};
        }

        if (data.size() < 2 || data.size() > 3)
            throw std::invalid_argument{
                    "invalid {}-part response from notification service"_format(data.size())};

        if (int x; parse_int(data[0], x))
            code = x;
        else
            throw std::invalid_argument{"notification service did not give a status code"};

        if (code == static_cast<int>(hive::SUBSCRIBE::OK)) {
            auto service_id = std::move(data[1]);
            if (bool too_short = service_id.size() < SERVICE_ID_MIN_SIZE;
                too_short || service_id.size() > SERVICE_ID_MAX_SIZE)
                throw std::invalid_argument{"service id too {} ({})"_format(
                        too_short ? "short" : "long", service_id.size())};

            code = static_cast<int>(hive::SUBSCRIBE::OK);
            if (!unsub) {  // New/renewed subscription
                assert(sub && enc_key);
                std::optional<std::string> service_data;
                if (data.size() > 2)
                    service_data = std::move(data[2]);
                if (service_data->size() > SERVICE_DATA_MAX_SIZE)
                    throw std::invalid_argument{
                            "service data too long ({})"_format(service_data->size())};
                log::trace(cat, "Adding {} subscription for {}", service, pubkey.id.hex());
                bool newsub = add_subscription(
                        pubkey,
                        std::move(service),
                        std::move(service_id),
                        std::move(service_data),
                        *enc_key,
                        std::move(*sub));

                response[newsub ? "added" : "updated"] = true;
                message = newsub ? "Subscription successful" : "Resubscription successful";
            } else {  // Unsubscribe
                assert(!sub);
                auto& [sig, subaccount, sig_ts] = *unsub;
                bool removed = remove_subscription(
                        pubkey, subaccount, std::move(service), std::move(service_id), sig, sig_ts);

                response["removed"] = removed;
                message = removed ? "Device unsubscribed from push notifications"
                                  : "Device was not subscribed to push notifications";
            }
        } else {
            // leave code at whatever the notifier set it to
            message = std::move(data[1]);
        }
    } catch (const hive::subscribe_error& e) {
        code = e.numeric_code();
        message = e.what();
    } catch (const hive::signature_verify_failure& e) {
        code = static_cast<int>(hive::SUBSCRIBE::ERROR);
        message = e.what();
    } catch (const std::exception& e) {
        code = static_cast<int>(hive::SUBSCRIBE::ERROR);
        log::warning(cat, "Exception encountered during sub/unsub handling: {}", e.what());
        message = "An error occured while processing your request";
    }

    if (code == static_cast<int>(hive::SUBSCRIBE::OK))
        response["success"] = true;
    else
        response["error"] = code;
    if (!message.empty())
        response["message"] = std::move(message);

    sub_json_set_one_response(replier, final_response, i, remaining, multi, std::move(response));
}

std::tuple<SwarmPubkey, std::optional<Subaccount>, int64_t, Signature, std::string, nlohmann::json>
HiveMind::sub_unsub_args(nlohmann::json& args) {

    auto account = from_hex_or_b64<AccountID>(args.at("pubkey").get<std::string_view>());
    std::optional<Ed25519PK> session_ed;
    if (account[0] == static_cast<std::byte>(0x05))
        from_hex_or_b64(session_ed.emplace(), args.at("session_ed25519").get<std::string_view>());
    // SwarmPubkey pubkey{std::move(account), std::move(session_ed)};
    std::optional<Subaccount> subaccount;
    if (auto it = args.find("subaccount"); it != args.end()) {
        auto sig_it = args.find("subaccount_sig");
        if (sig_it == args.end())
            throw std::invalid_argument{"Cannot specify subaccount without subaccount_sig"};

        subaccount.emplace();
        from_hex_or_b64(subaccount->tag, it->get<std::string_view>());
        from_hex_or_b64(subaccount->sig, sig_it->get<std::string_view>());
    }
    auto sig = from_hex_or_b64<Signature>(args.at("signature").get<std::string_view>());

    return {SwarmPubkey{std::move(account), std::move(session_ed)},
            std::move(subaccount),
            args.at("sig_ts").get<int64_t>(),
            std::move(sig),
            args.at("service").get<std::string>(),
            args.at("service_info")};
}

oxenmq::ConnectionID HiveMind::sub_unsub_service_conn(const std::string& service) {
    return loop_.call_get([&] {
        if (auto it = services_.find(service); it != services_.end())
            return it->second;
        throw hive::subscribe_error{
                hive::SUBSCRIBE::SERVICE_NOT_AVAILABLE,
                service + " notification service not currently available"};
    });
}

namespace {

    std::string_view get_body(oxenmq::Message& m) {
        return m.data.at(0);
    }
    std::string_view get_body(quic::message& m) {
        return m.body();
    }

    template <typename M>
    static std::optional<nlohmann::json> parse_sub_unsub(M& m) {
        std::optional<nlohmann::json> args;
        try {
            args = nlohmann::json::parse(get_body(m));
        } catch (const nlohmann::json::exception&) {
            log::debug(cat, "Subscription failed: bad json");
            json_error(m, hive::SUBSCRIBE::BAD_INPUT, "Invalid JSON");
            return std::nullopt;
        } catch (const std::out_of_range&) {
            log::debug(cat, "Subscription failed: no request data provided");
            json_error(m, hive::SUBSCRIBE::BAD_INPUT, "Invalid request: missing request data");
            return std::nullopt;
        }
        if (!(args->is_array() || args->is_object())) {
            log::debug(cat, "Subscription failed: bad json -- expected object or array");
            json_error(
                    m,
                    hive::SUBSCRIBE::BAD_INPUT,
                    "Invalid JSON: expected object or array of objects");
            return std::nullopt;
        }

        return args;
    }

    struct missing_parameter : std::out_of_range {
        missing_parameter(std::string_view key) :
                std::out_of_range{"Missing required parameter '{}'"_format(key)} {}
    };

    nlohmann::json& at(nlohmann::json& obj, std::string_view key) {
        try {
            return obj.at(key);
        } catch (...) {
            throw missing_parameter{key};
        }
    }

}  // namespace

template <typename Message>
void HiveMind::on_sub_unsub_impl(Message& msg, bool subscribe) {
    ready_or_defer();

    nlohmann::json args;
    if (auto a = parse_sub_unsub(msg))
        args = std::move(*a);
    else
        return;

    const bool multi = args.is_array();

    auto response = std::make_shared<nlohmann::json>();
    *response = nlohmann::json::array();
    auto remaining = std::make_shared<std::atomic<int>>(multi ? args.size() : 1);

    if (!multi) {
        // If given an object, convert to a single-element array (to make life easier below)
        auto single = nlohmann::json::array();
        single.push_back(std::move(args));
        args = std::move(single);
    }

    if (args.empty()) {
        json_error(msg, hive::SUBSCRIBE::BAD_INPUT, "Invalid request: {} list cannot be empty");
        return;
    }

    for (auto& e : args)
        response->push_back(nlohmann::json::object());

    std::function<void(std::string_view)> replier;
    if constexpr (std::same_as<Message, oxenmq::Message>)
        replier = msg.send_later();
    else {
        replier = [reqid = msg.rid(),
                   wstr = std::weak_ptr{msg.stream()}](std::string_view response) {
            auto str = wstr.lock();
            if (!str)
                return;
            str->respond(reqid, response);
        };
    }

    for (size_t i = 0; i < args.size(); i++) {
        auto& e = args[i];

        std::optional<std::pair<hive::SUBSCRIBE, std::string>> error;

        try {
            auto [pubkey, subaccount, sig_ts, sig, service, service_info] = sub_unsub_args(e);

            auto conn = sub_unsub_service_conn(service);

            oxenmq::OxenMQ::ReplyCallback reply_handler;

            if (subscribe) {
                auto enc_key = from_hex_or_b64<EncKey>(at(e, "enc_key").get<std::string_view>());
                auto namespaces = at(e, "namespaces").get<std::vector<int16_t>>();

                reply_handler = [this,
                                 response,
                                 i,
                                 remaining,
                                 multi,
                                 service = service,
                                 sub = std::make_shared<hive::Subscription>(  // Throws on bad sig
                                         pubkey,
                                         std::move(subaccount),
                                         at(e, "namespaces").get<std::vector<int16_t>>(),
                                         at(e, "data").get<bool>(),
                                         std::chrono::sys_seconds{std::chrono::seconds{
                                                 at(e, "sig_ts").get<int64_t>()}},
                                         std::move(sig)),
                                 pubkey = pubkey,
                                 enc_key = std::move(enc_key),
                                 replier](bool success, std::vector<std::string> data) mutable {
                    on_notifier_validation(
                            *response,
                            i,
                            *remaining,
                            multi,
                            success,
                            replier,
                            std::move(service),
                            std::move(pubkey),
                            std::move(sub),
                            std::move(enc_key),
                            std::move(data));
                };

                // We handle everything else (including the response) in `_on_notifier_validation`
                // when/if the notifier service comes back to us with the unique identifier:
                omq_.request(
                        conn,
                        "notifier.validate",
                        std::move(reply_handler),
                        service,
                        service_info.dump());
            } else {
                // unsubscribe

                reply_handler = [this,
                                 response,
                                 i,
                                 remaining,
                                 multi,
                                 service = service,
                                 pubkey = pubkey,
                                 unsub = UnsubData{std::move(sig), std::move(subaccount), sig_ts},
                                 replier](bool success, std::vector<std::string> data) mutable {
                    on_notifier_validation(
                            *response,
                            i,
                            *remaining,
                            multi,
                            success,
                            replier,
                            std::move(service),
                            std::move(pubkey),
                            nullptr,
                            std::nullopt,
                            std::move(data),
                            std::move(unsub));
                };
            }

            omq_.request(
                    conn,
                    "notifier.validate",
                    std::move(reply_handler),
                    service,
                    service_info.dump());

        } catch (const missing_parameter& e) {
            log::debug(cat, "Request failed: {}", e.what());
            error = {hive::SUBSCRIBE::BAD_INPUT, e.what()};
        } catch (const hive::subscribe_error& e) {
            error = {e.code, e.what()};
        } catch (const std::exception& e) {
            log::debug(cat, "Exception handling input: {}", e.what());
            error = {hive::SUBSCRIBE::ERROR, e.what()};
        }

        if (error) {
            int code = static_cast<int>(error->first);
            log::debug(
                    cat,
                    "Replying with {}subscribe error code {}: {}",
                    subscribe ? "" : "un",
                    code,
                    error->second);
            sub_json_set_one_response(
                    replier,
                    *response,
                    i,
                    *remaining,
                    multi,
                    nlohmann::json{{"error", code}, {"message", error->second}});
        }
        // Otherwise the reply is getting deferred and handled later in on_notifier_validation
    }
}
template void HiveMind::on_sub_unsub_impl(oxenmq::Message& m, bool subscribe);
template void HiveMind::on_sub_unsub_impl(quic::message& m, bool subscribe);

void HiveMind::on_quic_request(quic::message& m) {
    omq_.job([this, m = std::move(m)]() mutable {
        if (m.endpoint() == "subscribe")
            handle_quic_subscribe(m);
        else if (m.endpoint() == "unsubscribe")
            handle_quic_unsubscribe(m);
        else if (m.endpoint() == "ping")
            m.respond("pong");
        else
            json_error(m, hive::SUBSCRIBE::BAD_INPUT, "No such endpoint '{}'"_format(m.endpoint()));
    });
}

void HiveMind::quic_subscribe(quic::message& m) {
    on_sub_unsub_impl(m, true);
}

void HiveMind::quic_unsubscribe(quic::message& m) {
    on_sub_unsub_impl(m, true);
}

void HiveMind::on_subscribe(oxenmq::Message& m) {
    on_sub_unsub_impl(m, true);
}

void HiveMind::on_unsubscribe(oxenmq::Message& m) {
    on_sub_unsub_impl(m, false);
}

void HiveMind::db_cleanup() {
    auto conn = pool_.get();
    pqxx::work tx{conn};
    tx.exec("DELETE FROM subscriptions WHERE signature_ts <= $1",
            {unix_timestamp(system_clock::now() - SIGNATURE_EXPIRY)})
            .no_rows();
    tx.commit();
}

void HiveMind::refresh_sns() {
    omq_.request(
            oxend_,
            "rpc.get_service_nodes",
            [this](bool success, std::vector<std::string> data) {
                if (success)
                    loop_.call_get([&] { on_sns_response(std::move(data)); });
                else
                    log::warning(
                            cat,
                            "get_service_nodes request failed: {}",
                            "{}"_format(fmt::join(data, " ")));
            },
            _get_sns_params);
}

void HiveMind::on_sns_response(std::vector<std::string> data) {
    try {
        if (data.size() != 2) {
            log::warning(
                    cat,
                    "rpc.get_service_nodes returned unexpected {}-length response",
                    data.size());
            return;
        }
        if (data[0] != "200") {
            log::warning(
                    cat,
                    "rpc.get_service_nodes returned unexpected response {}: {}",
                    data[0],
                    data[1]);
            return;
        }

        nlohmann::json res;
        try {
            res = nlohmann::json::parse(data[1]);
        } catch (const nlohmann::json::exception& e) {
            log::warning(cat, "Failed to parse rpc.get_service_nodes response: {}", e.what());
            return;
        }

        auto sn_st = res["service_node_states"];
        if (!sn_st.is_array()) {
            log::warning(
                    cat,
                    "Unexpected rpc.get_service_nodes response: service_node_states looks "
                    "wrong");
            return;
        }

        bool swarms_changed = false;
        auto new_hash = res.at("block_hash").get<std::string>();
        auto new_height = res.at("height").get<int64_t>();
        if (new_hash != last_block_.first) {
            log::debug(cat, "new block {} @ {}", new_hash, new_height);

            // The block changed, so we need to check for swarm changes as well
            std::set<uint64_t> new_swarm_ids;
            for (auto& sn : sn_st) {
                auto sw_id = sn.at("swarm_id").get<uint64_t>();
                if (sw_id != INVALID_SWARM_ID)
                    new_swarm_ids.insert(sw_id);
            }
            if (!std::equal(
                        new_swarm_ids.begin(),
                        new_swarm_ids.end(),
                        swarm_ids_.begin(),
                        swarm_ids_.end())) {
                swarms_changed = true;

                swarm_ids_.clear();
                swarm_ids_.insert(swarm_ids_.end(), new_swarm_ids.begin(), new_swarm_ids.end());
            }

            last_block_ = {std::move(new_hash), new_height};
        }

        std::unordered_map<Ed25519PK, std::tuple<std::string, uint16_t, uint64_t>> sns;
        sns.reserve(sn_st.size());
        for (const auto& s : sn_st) {
            auto pked = s.at("pubkey_ed25519").get<std::string_view>();
            auto ip = s.at("public_ip").get<std::string_view>();
            auto port = s.at("storage_lmq_port").get<uint16_t>();
            auto swarm = s.at("swarm_id").get<uint64_t>();

            if (pked.size() == 64 && !ip.empty() && ip != "0.0.0.0" && port > 0 &&
                swarm != INVALID_SWARM_ID)
                sns.emplace(
                        std::piecewise_construct,
                        std::forward_as_tuple(from_hex_or_b64<Ed25519PK>(pked)),
                        std::forward_as_tuple(std::move(ip), port, swarm));
        }

        // auto missing_count = sn_st.size() - sns.size();
        log::debug(
                cat, "{} active SNs ({} missing details)", sns.size(), sn_st.size() - sns.size());

        // Anything in self.sns but not in sns is no longer on the network (decommed, dereged,
        // expired), or possibly we lost info for it (from the above).  We're going to
        // disconnect from these (if any are connected).
        int dropped = 0;
        for (auto it = sns_.begin(); it != sns_.end();) {
            const auto& [pk, snode] = *it;
            if (sns.count(pk)) {
                ++it;
                continue;
            }

            log::debug(cat, "Disconnecting {}", pk);
            swarms_[snode->swarm].erase(snode);
            snode->disconnect();
            it = sns_.erase(it);
            dropped++;
        }

        std::unordered_set<std::shared_ptr<hive::SNode>> new_or_changed_sns;

        for (const auto& [pk, details] : sns) {
            const auto& [ip, port, swarm] = details;
            quic::RemoteAddress addr{pk.span<unsigned char>(), ip, port};

            if (auto it = sns_.find(pk); it != sns_.end()) {
                // We already know about this service node from the last update, but it might
                // have changed address or swarm, in which case we want to disconnect and then
                // store it as "new" so that we reconnect to it (if required) later.  (We don't
                // technically have to reconnect if swarm changes, but it simplifies things a
                // bit to do it anyway).
                auto& snode = it->second;
                if (snode->swarm != swarm) {
                    swarms_[snode->swarm].erase(snode);
                    snode->reset_swarm(swarm);
                    swarms_[swarm].insert(snode);
                    new_or_changed_sns.insert(snode);
                }

                // Update the address; this reconnects if the address has changed, does nothing
                // otherwise.
                snode->connect(std::move(addr));
            } else {
                // New snode
                auto snode = loop_.make_shared<hive::SNode>(*this, std::move(addr), swarm);
                sns_.emplace(pk, snode);
                swarms_[swarm].insert(snode);
                new_or_changed_sns.insert(snode);
            }
        }

        for (auto it = swarms_.begin(); it != swarms_.end();) {
            if (it->second.empty())
                it = swarms_.erase(it);
            else
                ++it;
        }

        log::debug(
                cat, "{} new/updated SNs; dropped {} old SNs", new_or_changed_sns.size(), dropped);

        // If we had a change to the network's swarms then we need to trigger a full recheck of
        // swarm membership, ejecting any pubkeys that moved while adding all pubkeys again to
        // be sure they are in each(possibly new) slot.
        if (swarms_changed || !new_or_changed_sns.empty()) {
            int sw_changes = 0;
            // Recalculate the swarm id of all subscribers:
            for (auto& [pk, v] : subscribers_)
                sw_changes += pk.update_swarm(swarm_ids_);

            log::debug(cat, "{} accounts changed swarms", sw_changes);

            oxenmq::Batch<void> batch;
            batch.reserve(swarms_.size());
            for (auto& [swid, snodes] : swarms_) {
                batch.add_job([this, swid = swid, s = &snodes] {
                    // This seems suspicious that we are modifying multiple SN objects from
                    // different threads, but we aren't because each SNode is only inside `swarms_`
                    // once, and so there shouldn't be any overlap across SNs while this batch is
                    // running.
                    for (auto& sn : *s)
                        sn->remove_stale_swarm_members(swarm_ids_);
                    for (auto& [swarmpk, v] : subscribers_)
                        if (swarmpk.swarm == swid)
                            for (auto& sn : *s)
                                sn->add_account(swarmpk);
                });
            }

            std::promise<void> done;
            batch.completion([&done](auto&&) { done.set_value(); });
            omq_.batch(std::move(batch));

            done.get_future().get();
            check_subs();
        }
#if 0  // TODO: this is much slower than the above full scan; investigate
        else if (!new_or_changed_sns.empty()) {
            // Otherwise swarms stayed the same(which means no accounts changed swarms), but
            // snodes might have moved in / out of existing swarms, so re-add any subscribers to
            // swarm changers to ensure they have all the accounts that belong to them.

            std::unordered_map<uint64_t, std::vector<SwarmPubkey>> swarm_subs;
            for (const auto& snode : new_or_changed_sns)
                swarm_subs[snode->swarm];  // default-construction side effect

            for (auto& [swarmpk, v] : subscribers_) {
                if (auto it = swarm_subs.find(swarmpk.swarm); it != swarm_subs.end())
                    it->second.push_back(swarmpk);

                for (const auto& snode : new_or_changed_sns)
                    for (const auto& swarmpk : swarm_subs[snode->swarm])
                        snode->add_account(swarmpk);
            }

            check_subs();
        }
#endif
    } catch (const std::exception& e) {
        log::warning(cat, "An exception occured while processing the SN update: {}", e.what());
    }
}

void HiveMind::check_subs() {
    assert(loop_.inside());

    for (const auto& [pk, snode] : sns_) {
        try {
            snode->check_subs(subscribers_);
        } catch (const std::exception& e) {
            log::warning(cat, "Failed to check subs on {}: {}", pk, e.what());
        }
    }
}

void HiveMind::make_conns() {
    assert(loop_.inside());

    for (const auto& [pk, snode] : sns_) {
        if (pending_connects_ >= config.max_pending_connects)
            return;

        snode->connect();
    }
}

void HiveMind::check_my_subs(hive::SNode& snode) {
    snode.check_subs(subscribers_);
}

void HiveMind::finished_connect() {
    assert(loop_.inside());

    bool try_more = pending_connects_ < config.max_pending_connects;
    log::trace(cat, "finished connection; {}triggering more", try_more ? "" : "not ");
    --pending_connects_;
    if (try_more)
        make_conns();
}

bool HiveMind::allow_connect() {
    if (!quic_out_)
        return false;

    int count = ++pending_connects_;
    if (count > config.max_pending_connects) {
        --pending_connects_;
        return false;
    }
    auto ccount = ++connect_count_;
    log::debug(
            cat,
            "establishing connection (currently have {} pending, {} total connects)",
            count,
            ccount);
    return true;
}

void HiveMind::load_saved_subscriptions() {

    auto conn = pool_.get();
    pqxx::work txn{conn};

    auto [total] = txn.query1<int>("SELECT COUNT(*) FROM subscriptions");

    int n = std::max<int>(1, std::thread::hardware_concurrency() / 4);

    log::info(cat, "Loading {} stored subscriptions from database using {} threads", total, n);

    AccountID jagerman;
    auto jagerman_id = "05fb466d312e1666ad1c84c4ee55b7e034151c0e366a313d95d11436a5f36e1e75"sv;
    oxenc::from_hex(jagerman_id.begin(), jagerman_id.end(), jagerman.begin());

    std::vector<std::pair<
            std::thread,
            std::vector<std::tuple<
                    std::optional<SwarmPubkey>,  // Not optional, but we need to default construct
                    std::optional<Subaccount>,
                    Signature,
                    std::chrono::sys_seconds,
                    bool,
                    std::vector<int16_t>>>>>
            threads;

    threads.resize(n);
    for (auto& [t, rows] : threads)
        // There is some small randomness in how many rows each threads get, so reserve 10% extra
        // the perfectly even value.
        rows.reserve(11 * total / (10 * n));

    for (int i = 0; i < n; i++) {
        threads[i].first = std::thread{[i, n, &rows = threads[i].second, &pool = pool_] {
            auto conn = pool.get();
            pqxx::work txn{conn};

            for (auto [acc, ed, sub_tag, sub_sig, sig_in, sigts_in, wd_in, ns_arr_in] :
                 txn
                         .stream<AccountID,
                                 std::optional<Ed25519PK>,
                                 std::optional<SubaccountTag>,
                                 std::optional<Signature>,
                                 Signature,
                                 int64_t,
                                 bool,
                                 pqxx::array<int16_t>>(R"(
SELECT account, session_ed25519, subaccount_tag, subaccount_sig, signature, signature_ts, want_data,
    ARRAY(SELECT namespace FROM sub_namespaces WHERE subscription = id ORDER BY namespace)
FROM subscriptions
WHERE id % {0} = {1})"_format(n, i))) {

                auto& [swpk, subaccount, sig, sigts, wd, ns_arr] = rows.emplace_back();
                swpk.emplace(acc, ed, /*skip_validation=*/true);
                if (sub_tag && sub_sig) {
                    subaccount.emplace();
                    subaccount->tag = std::move(*sub_tag);
                    subaccount->sig = std::move(*sub_sig);
                }
                sig = std::move(sig_in);
                sigts = std::chrono::sys_seconds{std::chrono::seconds{sigts_in}};
                wd = wd_in;
                ns_arr = std::vector<int16_t>{ns_arr_in.begin(), ns_arr_in.end()};
            }
        }};
    }

    int64_t th_count = 0;
    for (auto& [t, rows] : threads) {
        t.join();
        log::debug(cat, "Thead got {} rows", rows.size());
        th_count += rows.size();
    }

    log::info(cat, "Collected {} rows via threads", th_count);

    steady_clock::time_point now;
    std::chrono::sys_seconds sys_now;
    std::pair<std::chrono::sys_seconds, std::chrono::sys_seconds> sigts_cutoff;
    auto update_clocks = [&] {
        now = steady_clock::now();
        sys_now = std::chrono::floor<std::chrono::seconds>(system_clock::now());
        sigts_cutoff.first = sys_now - hive::Subscription::SIGNATURE_EXPIRY + 5s;
        sigts_cutoff.second = sys_now + hive::Subscription::SIGNATURE_EARLY;
    };
    update_clocks();
    int last_decile = 0;

    int64_t raw_count = 0, count = 0, unique = 0;
    for (auto& [t, rows] : threads) {
        for (auto& [swpk, subaccount, sig, sigts, wd, ns_arr] : rows) {
            raw_count++;

            if (sigts <= sigts_cutoff.first || sigts >= sigts_cutoff.second)
                // Don't try loading entries that are about to expire
                continue;

            // DEBUG
            // if (!std::equal(swpk->id.begin(), swpk->id.begin() + 3, jagerman.begin()))
            //    continue;
            // log::critical(cat, "LOADED {}", swpk->id);

            auto& sub = subscribers_[*swpk];

            // Weed out potential duplicates: if two+ devices are subscribed to the same
            // account with all the same relevant subscription settings then we can just
            // keep whichever one is newer.
            bool dupe = false;
            for (auto& existing : sub) {
                if (existing.is_same(subaccount, ns_arr, wd)) {
                    if (sigts > existing.sig_ts) {
                        existing.sig_ts = sigts;
                        existing.sig = std::move(sig);
                    }
                    dupe = true;
                    break;
                }
            }

            if (!dupe) {
                unique++;
                sub.emplace_back(
                        std::move(*swpk),
                        std::move(subaccount),
                        std::move(ns_arr),
                        wd,
                        sigts,
                        std::move(sig),
                        /*_skip_validation=*/true,
                        sys_now);
            }

            if (++count % 1000 == 0 || raw_count == th_count) {
                update_clocks();
                if (int decile = 10 * raw_count / th_count; decile != last_decile) {
                    log::info(
                            cat,
                            "... processed {}/{} ({}%) subscriptions",
                            raw_count,
                            total,
                            decile * 10);
                    last_decile = decile;
                }
            }
        }
    }

    log::info(
            cat,
            "Done loading saved subscriptions; {} unique subscriptions to {} accounts",
            unique,
            subscribers_.size());
}

bool HiveMind::add_subscription(
        SwarmPubkey pubkey,
        std::string service,
        std::string service_id,
        std::optional<std::string> service_data,
        EncKey enc_key,
        hive::Subscription sub) {

    bool new_sub = false, insert_ns = false;

    auto conn = pool_.get();
    pqxx::work tx{conn};

    auto result = tx.query01<int64_t, int64_t, pqxx::array<int16_t>>(
            R"(
SELECT
    id,
    signature_ts,
    ARRAY(SELECT namespace FROM sub_namespaces WHERE subscription = id ORDER BY namespace)
FROM subscriptions
WHERE
    account = $1 AND service = $2 AND svcid = $3)",
            {pubkey.id, service, service_id});
    int64_t id;
    if (result) {
        auto& [row_id, sig_ts, ns_arr_in] = *result;
        std::vector<int16_t> ns_arr{ns_arr_in.cbegin(), ns_arr_in.cend()};
        id = row_id;

        insert_ns = ns_arr != sub.namespaces;
        log::trace(cat, "updating subscription for {}", pubkey.id.hex());
        tx.exec(
                  R"(
UPDATE subscriptions
SET session_ed25519 = $2, subaccount_tag = $3, subaccount_sig = $4, signature = $5, signature_ts = $6, want_data = $7, enc_key = $8, svcdata = $9
WHERE id = $1
                    )",
                  {id,
                   pubkey.session_ed ? std::optional{pubkey.ed25519} : std::nullopt,
                   sub.subaccount ? std::optional{sub.subaccount->tag} : std::nullopt,
                   sub.subaccount ? std::optional{sub.subaccount->sig} : std::nullopt,
                   sub.sig,
                   sub.sig_ts.time_since_epoch().count(),
                   sub.want_data,
                   enc_key,
                   service_data})
                .no_rows();
        if (insert_ns)
            tx.exec("DELETE FROM sub_namespaces WHERE subscription = $1", {id}).no_rows();
    } else {
        new_sub = true;
        log::trace(cat, "inserting new subscription for {}", pubkey.id.hex());
        auto row = tx.exec(
                             R"(
INSERT INTO subscriptions
    (account, session_ed25519, subaccount_tag, subaccount_sig, signature, signature_ts, want_data, enc_key, service, svcid, svcdata)
VALUES ($1,   $2,              $3,             $4,             $5,        $6,           $7,        $8,      $9,      $10,   $11)
RETURNING id
                )",
                             {pubkey.id,
                              pubkey.session_ed ? std::optional{pubkey.ed25519} : std::nullopt,
                              sub.subaccount ? std::optional{sub.subaccount->tag} : std::nullopt,
                              sub.subaccount ? std::optional{sub.subaccount->sig} : std::nullopt,
                              sub.sig,
                              sub.sig_ts.time_since_epoch().count(),
                              sub.want_data,
                              enc_key,
                              service,
                              service_id,
                              service_data})
                           .one_row();

        id = row[0].as<int64_t>();
        insert_ns = true;
    }

    if (insert_ns)
        for (auto n : sub.namespaces)
            tx.exec(R"(INSERT INTO sub_namespaces (subscription, namespace) VALUES ($1, $2))",
                    {id, n})
                    .no_rows();

    for (const auto& s : {""s, service})
        increment_stat(tx, s, new_sub ? "subscription" : "sub_renew", 1);

    tx.commit();

    return loop_.call_get([&] {
        pubkey.update_swarm(swarm_ids_);

        auto& subscriptions = subscribers_[pubkey];
        bool found_existing = false;
        for (auto& existing : subscriptions) {
            if (existing.is_same(sub)) {
                if (sub.is_newer(existing)) {
                    existing.sig = sub.sig;
                    existing.sig_ts = sub.sig_ts;
                }
                found_existing = true;
                break;
            }
        }
        if (!found_existing)
            subscriptions.push_back(std::move(sub));

        // If this is actually adding a new subscription (and not just renewing an
        // existing one) then we need to force subscription (or resubscription) on all
        // of the account's swarm members to get the subscription active ASAP.
        // (Otherwise don't do anything because we already have an equivalent
        // subscription in place).
        if (new_sub)
            for (auto& sn : swarms_[pubkey.swarm])
                sn->add_account(pubkey, /*force_now=*/true);

        return new_sub;
    });
}

/// Removes a subscription for monitoring.  Returns true if the given pubkey was
/// found and removed; false if not found.
///
/// Will throw if the given data or signatures are incorrect.
///
/// Parameters:
///
/// - pubkey -- the account
/// - subaccount -- if using subaccount authentication then this is the 36-byte subaccount tag.
/// - service -- the subscription service name, e.g. 'apns', 'firebase'.
/// - service_id -- an identifier string that identifies the device/application/etc.
/// This is
///   unique for a given service and pubkey and is generated/extracted by the
///   notification service.
/// - sig_ts -- the integer unix timestamp when the signature was generated; must be
/// within ±24h
/// - signature -- the Ed25519 signature of: UNSUBSCRIBE || PUBKEY_HEX || sig_ts
bool HiveMind::remove_subscription(
        const SwarmPubkey& pubkey,
        const std::optional<Subaccount>& subaccount,
        std::string service,
        std::string service_id,
        const Signature& sig,
        int64_t sig_ts) {

    if (sig_ts < unix_timestamp(system_clock::now() - UNSUBSCRIBE_GRACE) ||
        sig_ts > unix_timestamp(system_clock::now() + UNSUBSCRIBE_GRACE))
        throw std::invalid_argument{"Invalid signature: sig_ts is too far from current time"};

    // "UNSUBSCRIBE" || HEX(ACCOUNT) || SIG_TS
    std::string sig_msg = "UNSUBSCRIBE";
    oxenc::to_hex(pubkey.id.begin(), pubkey.id.end(), std::back_inserter(sig_msg));
    fmt::format_to(std::back_inserter(sig_msg), "{}", sig_ts);

    // Throws on verification failure
    hive::verify_storage_signature(sig_msg, sig, pubkey, subaccount);

    bool removed = false;

    auto conn = pool_.get();
    pqxx::work tx{conn};

    auto result =
            tx.exec(R"(DELETE FROM subscriptions WHERE account = $1 AND service = $2 AND svcid = $3)",
                    {pubkey.id, service, service_id})
                    .no_rows();

    tx.commit();

    // We don't remove the subscription from internal data structures: other devices
    // (with the exact subcription) may be still using it, and so we may still want
    // the notifications; but as long as the row is removed (above) we won't be
    // sending notifications to the device anymore.
    return result.affected_rows() > 0;
}

}  // namespace spns
