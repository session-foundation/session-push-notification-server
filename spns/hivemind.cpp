#include "hivemind.hpp"

#include <fcntl.h>
#include <fmt/chrono.h>
#include <fmt/ranges.h>
#include <fmt/std.h>
#include <oxenc/base32z.h>
#include <oxenc/bt_producer.h>
#include <oxenc/bt_serialize.h>
#include <oxenc/endian.h>
#include <oxenmq/message.h>
#include <sodium/crypto_sign_ed25519.h>
#include <spdlog/common.h>
#include <systemd/sd-daemon.h>
#include <unistd.h>

#include <algorithm>
#include <bit>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <concepts>
#include <cstring>
#include <fstream>
#include <limits>
#include <nlohmann/json.hpp>
#include <oxen/log.hpp>
#include <oxen/quic/btstream.hpp>
#include <oxen/quic/format.hpp>
#include <oxen/quic/gnutls_crypto.hpp>
#include <oxen/quic/opt.hpp>
#include <random>
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

HiveMind::HiveMind(Config conf_in) :
        config{std::move(conf_in)},
        pool_{config.pg_connect},
        omq_impl_{
                std::in_place,
                std::string{config.omq_pubkey.sv()},
                std::string{config.omq_privkey.sv()},
                false,
                nullptr} {

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
                log::debug(cat, "Incoming local sock connection from {}", addr);
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
            log::debug(cat, "Incoming {} connection from {}", is_admin ? "admin" : "public", addr);
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
            //     "truncate": true,
            //     "sig_ts": 1677520760,
            //     "signature": "f8efdd120007...",
            //     "service": "apns",
            //     "service_info": { ... },
            //     "enc_key": "abcdef..." (32 bytes: 64 hex or 43 base64).
            // }
            //
            // or a JSON array of such objects.
            //
            // `truncate` is optional (default false), and matters only with `"data": true`: if
            // true, a message over the body limit (monitor_body_limit) is pushed cut to the limit,
            // with its full size, rather than as its size alone.  It is not part of what the
            // storage servers are asked to monitor, nor of the signature, so a resubscription can
            // change it.
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

            // Registers a notification service.  This is a request command taking two parts: the
            // service name (e.g. "apns", "firebase") that should be pushed to this connection when
            // notifications or subscriptions arrive, and a bencoded dict of:
            //
            // - '' -- the notifier registration protocol version, which must be the hivemind's
            //   (NOTIFIER_PROTOCOL_VERSION, currently 1).
            // - 'max_body' -- the largest message body, in bytes, the notifier can deliver, which
            //   must be at least the hivemind's body limit (monitor_body_limit).
            //
            // Other keys are reserved, and ignored.  (Protocol 0 was register_service, below.)  The
            // reply is empty if the service is registered.  Otherwise it
            // is a message saying why not, which the hivemind also logs as critical: the notifier
            // cannot work with this hivemind, and should not keep trying.  A notifier re-registers
            // periodically, so that a restarted hivemind learns of it again, and should take no
            // reply at all as the hivemind being unavailable rather than as a refusal.  (If a
            // single connection provides multiple services it should invoke this endpoint multiple
            // times).
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
            // - '!' -- supplemental service data, if the validate request returned any; omitted
            //   otherwise.
            // - '#' -- the message hash from storage server.
            // - '&' -- the unique service id (as was provided by the validate endpoint).
            // - '@' -- the account ID (Session ID or closed group ID) to which the message was sent
            //   (33 bytes).
            // - '^' -- the xchacha20-poly1305encryption key the user gave when registering for
            //   notifications with which the notification payload should be encrypted.
            // - 'n' -- the swarm namespace to which the message was deposited (-32768 to 32767).
            // - 't' -- the swarm timestamp when the message was created (unix epoch milliseconds).
            // - 'z' -- the message's swarm expiry timestamp (unix epoch milliseconds).
            // - '}' -- for a registration that requested data, the message's full size in bytes,
            //   present only when the message is over the hivemind's body limit
            //   (monitor_body_limit).
            // - '~' -- the encrypted message data; this field will not be present if the
            //   registration did not request data.  With '}', it is only the message's first part,
            //   cut to the body limit, and present only if the registration asked for truncated
            //   bodies; without it, the message is too large to deliver, and the device should be
            //   told so along with its size.
            //
            // `notifier.ack` is a request command that must reply (with no data) when reached.
            // The hivemind sends one after every PUSH_ACK_INTERVAL pushes and stops sending once
            // PUSH_WINDOW pushes are unacknowledged, so that a notifier is never handed more than
            // it can hold: the `notifier` category's oxenmq queue must hold at least PUSH_WINDOW +
            // 2 commands per service the connection registers (the default of 200 suffices for
            // one).  A notifier without the command never answers, and its pushes stop for good
            // once the window fills.  Pushes the hivemind cannot send are held, in order, until it
            // can, including across a notifier restart.
            .add_request_command(
                    "register_notifier",
                    ExcWrapper{*this, &HiveMind::on_register_notifier, "on_register_notifier"})

            // Deprecated: protocol 0's registration, a plain command with the service name alone.
            // It registers nothing, and only logs, as critical, that the notifier must move to
            // register_notifier.
            .add_command(
                    "register_service",
                    ExcWrapper{
                            *this,
                            &HiveMind::on_obsolete_register_service,
                            "on_obsolete_register_service"})

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

    // Outbound connections present our configured key whether or not we listen: storage servers
    // recognise its pubkey as the privileged push server's, whose monitor sessions get the large
    // limits and a pool of missed notifications of their own.
    creds_out_ = quic::GNUTLSCreds::make_from_ed_seckey(config.quic_keys.sv());

    if (!config.quic_listen.empty()) {
        creds_in_ = creds_out_;

        for (const auto& addr : config.quic_listen) {
            // We only use one address for outbound connections, but it needs to be IPv4 capable
            std::optional<quic::opt::outbound_alpns> maybe_out_alpn;
            if (!quic_out_ &&
                (addr.is_ipv4() || (addr.is_ipv6() && addr.is_any_addr() && addr.dual_stack)))
                maybe_out_alpn = out_alpn;

            auto ep = quic::Endpoint::endpoint(
                    loop_,
                    addr,
                    in_alpn,
                    maybe_out_alpn,
                    quic::opt::allow_gro{},
                    quic::opt::allow_gso{},
                    quic::opt::socket_buffers{.recv = 16_Mi, .send = 2_Mi});

            ep->listen(
                    creds_in_,
                    [this](quic::Connection& c, quic::Endpoint& e, std::optional<int64_t>) {
                        return e.loop.make_shared<quic::BTRequestStream>(
                                c, e, [this](quic::message m) { on_quic_request(m); });
                    },
                    quic::opt::congestion_control::cubic);

            if (maybe_out_alpn)
                quic_out_ = ep;
            quic_in_.push_back(std::move(ep));
        }
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

    jq_.call_get([this] {
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
        while (!notifier_startup_done(wait_until))
            std::this_thread::sleep_for(25ms);
        std::lock_guard lock{services_mutex_};
        log::info(cat, "Done waiting for notifiers; {} registered", services_.size());
    }

    // Set our ready flag, and process any requests that accumulated while we were starting up.
    set_ready();

    subscribe_blocks();
    refresh_sns();

    omq_.add_timer([this] { db_cleanup(); }, 30s);

    // This ticker handles re-subscriptions, clearing expiries, etc.; it's on a relatively slow
    // timer because nothing in here is time critical:
    sub_jq_.add_timer(10s, [this] { check_subs(); });
    sub_jq_.add_timer(5s, [this] { log_coverage_progress(); });
    sub_jq_.add_timer(OXEND_BLOCK_SUB_INTERVAL, [this] { subscribe_blocks(); });
    sub_jq_.add_timer(DUMP_INTERVAL, [this] { save_state(false); });
    // And this one reconnects to nodes whose connection failed or was lost, once their cooldown
    // has passed.
    jq_.add_timer(10s, [this] { make_conns(); });

    // For updating systemd Status line
    omq_.add_timer([this] { log_stats(); }, 2s);

    log::info(cat, "Startup complete");
}

HiveMind::~HiveMind() {
    if (notify_proc_thread_.joinable()) {
        {
            std::lock_guard lock{notify_mutex_};
            notify_quit_ = true;
        }
        notify_cv_.notify_one();
        notify_proc_thread_.join();
    }

    // Stop OxenMQ before anything else: its workers run request handlers and the push failure
    // callback, which use members destroyed below, and they call into loop_, which is about to be
    // torn down.
    omq_impl_.reset();

    // Saved before the endpoints go: their teardown drops every connection, and with them every
    // node's claims.
    sub_jq_.call_get([this] { save_state(true); });

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

        conns_.clear();
    });

    // The subscription thread stops only now: the endpoint teardown above was the last thing that
    // could queue on it (oxenmq is already gone), and it queues on jq_, which must therefore
    // outlive it.  It runs what the teardown queued for it against its members, which are intact
    // until the QUIC loop clears them below, and then drops its timers.
    sub_jq_.stop();

    loop_.call_get([this] {
        swarms_.clear();
        sns_.clear();

        // Last, so that anything the teardown above queued on it (it runs synchronously on the
        // QUIC loop, so nothing queued could have run yet) is dropped rather than left to run
        // against the members destroyed after this, and so that nothing above could hit a stopped
        // queue.  Nothing can queue more once this returns: oxenmq, the processing thread and the
        // subscription thread are gone, and so are the endpoints and nodes.
        jq_.stop();
    });
}

bool HiveMind::notifier_startup_done(const steady_time& wait_until) {
    std::lock_guard lock{services_mutex_};

    // If we were told which notifiers to wait for then check to see if they are all present, and if
    // so return early:
    std::vector<std::string_view> missing;
    if (!config.notifiers_expected.empty()) {
        for (const auto& service : config.notifiers_expected) {
            if (!services_.contains(service))
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

void HiveMind::on_obsolete_register_service(oxenmq::Message& m) {
    log::critical(
            cat,
            "'{}' notifier registered through the obsolete register_service interface (protocol "
            "0); this hivemind requires register_notifier protocol {}",
            m.data.empty() ? "unnamed"sv : m.data[0],
            NOTIFIER_PROTOCOL_VERSION);
}

void HiveMind::on_register_notifier(oxenmq::Message& m) {
    auto refuse = [&m](std::string why) {
        log::critical(cat, "{}", why);
        m.send_reply(std::move(why));
    };

    if (m.data.size() != 2)
        return refuse("malformed {}-part notifier registration, expected 2"_format(m.data.size()));
    std::string service{m.data[0]};
    if (service.empty())
        return refuse("notifier registration used illegal empty service name");
    if (service.size() > 32)
        return refuse("notifier service name too long ({})"_format(service.size()));

    int version;
    int64_t max_body;
    try {
        oxenc::bt_dict_consumer d{m.data[1]};
        version = d.require<int>("");
        max_body = d.require<int64_t>("max_body");
    } catch (const std::exception& e) {
        return refuse("'{}' notifier sent an invalid registration: {}"_format(service, e.what()));
    }
    if (version != NOTIFIER_PROTOCOL_VERSION)
        return refuse(
                "'{}' notifier speaks protocol {}, this hivemind requires {}"_format(
                        service, version, NOTIFIER_PROTOCOL_VERSION));
    if (max_body < config.monitor_body_limit)
        return refuse(
                "'{}' notifier accepts bodies of at most {} B, below the hivemind's body limit of "
                "{} B"_format(service, max_body, config.monitor_body_limit));

    {
        std::lock_guard lock{services_mutex_};
        services_gone_.erase(service);
        auto [it, ins] = services_.emplace(service, m.conn);
        if (ins)
            log::info(cat, "'{}' notification service registered", service);
        else if (m.conn != it->second) {
            it->second = m.conn;
            log::info(cat, "'{}' notification service reconnected/reregistered", service);
        } else {
            log::trace(cat, "'{}' notification service confirmed (already registered)", service);
            m.send_reply();
            return;
        }
    }
    {
        // A new connection has nothing in flight; acks still pending on the old one are ignored.
        std::lock_guard lock{notify_mutex_};
        auto& s = service_pushes_[service];
        s.conn = m.conn;
        s.unacked = 0;
        s.blocked_since.reset();
        drain_ = true;
    }
    notify_cv_.notify_one();
    m.send_reply();
}

void HiveMind::service_gone(const std::string& service, oxenmq::ConnectionID conn) {
    std::lock_guard lock{services_mutex_};
    if (auto it = services_.find(service); it != services_.end() && it->second == conn) {
        services_.erase(it);
        services_gone_.emplace(service, steady_clock::now());
        log::warning(
                cat,
                "'{}' notification service connection lost; holding its pushes until it registers "
                "again",
                service);
    }
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

void HiveMind::on_message_notification(quic::message m) {
    {
        std::lock_guard lock{notify_mutex_};
        notifications_received_++;
        if (notify_queue_bytes_ >= NOTIFY_QUEUE_MAX_BYTES) {
            notifications_dropped_++;
            return;
        }
        notify_queue_bytes_ += m.body().size();
        notify_queue_.push_back(std::move(m));
    }
    notify_cv_.notify_one();
}

void HiveMind::on_monitor_ended(hive::SNode& node, quic::message m) {
    try {
        oxenc::bt_dict_consumer d{m.body()};
        auto account = d.require<std::string_view>("@");
        auto swarm = d.require<std::string_view>("swarm");
        check_moved(account, swarm);
        if (account.size() != AccountID::SIZE)
            return;
        AccountID id;
        std::memcpy(id.data(), account.data(), id.size());
        // Not placed again here: the node ends a monitor when the account leaves its swarm, which
        // we may not have heard of yet, and the account would only be sent back to it.  The move,
        // once our swarm list has it, or else the account's renewal places it afresh.
        if (auto it = subscribers_.find(SwarmPubkey{id, std::nullopt, /*_skip_validation=*/true});
            it != subscribers_.end())
            unclaim(node, it->first);
    } catch (const std::exception& e) {
        log::warning(cat, "Invalid monitor_ended notification: {}", e.what());
    }
}

void HiveMind::check_moved(std::string_view account, std::string_view swarm_hex) {
    AccountID id;
    uint64_t swarm;
    if (account.size() != id.size() ||
        std::from_chars(swarm_hex.data(), swarm_hex.data() + swarm_hex.size(), swarm, 16).ptr !=
                swarm_hex.data() + swarm_hex.size())
        throw std::invalid_argument{"invalid account or swarm"};
    std::memcpy(id.data(), account.data(), id.size());

    auto it = subscribers_.find(SwarmPubkey{id, std::nullopt, /*_skip_validation=*/true});
    if (it == subscribers_.end())
        return;
    if (it->first.swarm == swarm)
        moved_agree_++;
    else {
        log::debug(
                cat,
                "A node places account {} in swarm {:x}, but we place it in {:x}",
                id.hex(),
                swarm,
                it->first.swarm);
        moved_disagree_++;
    }
}

void HiveMind::send_push(
        const std::string& service, const oxenmq::ConnectionID& conn, std::string_view push) {
    omq_.send(
            conn,
            "notifier.push",
            push,
            oxenmq::send_option::queue_failure{[this, service, conn, push = std::string{push}](
                                                       const std::exception* e) {
                if (e)
                    service_gone(service, conn);
                else
                    // nullptr means zmq's send queue was full, which the window keeps far
                    // below.
                    log::error(cat, "zmq refused a push to '{}' despite the ack window", service);
                backlog_push(service, push);
            }});
}

void HiveMind::request_ack(const std::string& service, const oxenmq::ConnectionID& conn) {
    omq_.request(
            conn,
            "notifier.ack",
            [this, service, conn](bool ok, std::vector<std::string> data) {
                if (!ok) {
                    log::critical(
                            cat,
                            "'{}' notifier did not answer notifier.ack ({}); it must provide it "
                            "(see register_notifier), or its pushes stop once {} are "
                            "unacknowledged",
                            service,
                            "{}"_format(fmt::join(data, " ")),
                            PUSH_WINDOW);
                    return;
                }
                bool drain = false;
                {
                    std::lock_guard lock{notify_mutex_};
                    auto it = service_pushes_.find(service);
                    if (it == service_pushes_.end() || it->second.conn != conn)
                        return;
                    auto& s = it->second;
                    s.unacked -= std::min(s.unacked, PUSH_ACK_INTERVAL);
                    if (s.unacked < PUSH_WINDOW)
                        s.blocked_since.reset();
                    drain = !s.backlog.empty();
                    if (drain)
                        drain_ = true;
                }
                if (drain)
                    notify_cv_.notify_one();
            },
            // Effectively none: the notifier answers whenever it gets there, and a connection that
            // dies first is replaced by on_register_notifier(), after which the reply is ignored.
            oxenmq::send_option::request_timeout{24h});
}

void HiveMind::backlog_push(const std::string& service, std::string push) {
    std::lock_guard lock{notify_mutex_};
    auto& s = service_pushes_[service];
    if (s.backlog.size() >= PUSH_BACKLOG_MAX) {
        s.dropped++;
        s.dropped_total++;
        return;
    }
    s.backlog.push_back(std::move(push));
}

void HiveMind::process_notifications() {
    // Backlogged pushes to send this pass: service, connection, push, and whether an ack request
    // follows it.
    std::vector<std::tuple<std::string, oxenmq::ConnectionID, std::string, bool>> drain;
    std::unordered_set<std::string> gone, expired;
    std::string buf;
    int64_t notifications_dropped_logged = 0;

    while (true) {
        // Declared per pass so that its messages are freed here, outside the lock, rather than in
        // the next pass's critical section while the QUIC loop waits to queue more.
        std::vector<quic::message> process;
        {
            std::unique_lock lock{notify_mutex_};
            auto ready = [this] { return notify_quit_ || !notify_queue_.empty() || drain_; };
            bool backlogged =
                    std::any_of(service_pushes_.begin(), service_pushes_.end(), [](const auto& sp) {
                        return !sp.second.backlog.empty();
                    });
            if (backlogged)
                // So that a gone notifier's backlog expires and blocking gets reported even if
                // nothing else wakes us.
                notify_cv_.wait_for(lock, 1s, ready);
            else
                notify_cv_.wait(lock, ready);
            if (notify_quit_)
                return;
            drain_ = false;
            process.swap(notify_queue_);
            notify_queue_bytes_ = 0;
        }

        decltype(services_) services;
        gone.clear();
        expired.clear();
        {
            std::lock_guard lock{services_mutex_};
            services = services_;
            auto now = steady_clock::now();
            for (auto it = services_gone_.begin(); it != services_gone_.end();) {
                if (now - it->second >= NOTIFIER_GONE_LIMIT) {
                    expired.insert(it->first);
                    it = services_gone_.erase(it);
                } else {
                    gone.insert(it->first);
                    ++it;
                }
            }
        }

        drain.clear();
        {
            std::lock_guard lock{notify_mutex_};
            auto now = steady_clock::now();
            for (auto it = service_pushes_.begin(); it != service_pushes_.end();) {
                auto& [service, s] = *it;
                if (s.dropped) {
                    log::warning(
                            cat,
                            "Dropped {} pushes for '{}': too many are already waiting for its "
                            "notifier",
                            s.dropped,
                            service);
                    s.dropped = 0;
                }
                if (expired.contains(service)) {
                    if (!s.backlog.empty())
                        log::warning(
                                cat,
                                "Dropped {} pushes for '{}': its notifier has not registered again",
                                s.backlog.size(),
                                service);
                    it = service_pushes_.erase(it);
                    continue;
                }
                if ((s.blocks || s.blocked_since) && now >= s.next_report) {
                    log::warning(
                            cat,
                            "'{}' notifier filled the push window {} time(s) since last report{}; "
                            "{} pushes backlogged",
                            service,
                            s.blocks,
                            s.blocked_since
                                    ? ", and has not acknowledged for {}"_format(
                                              std::chrono::duration_cast<std::chrono::seconds>(
                                                      now - *s.blocked_since))
                                    : "",
                            s.backlog.size());
                    s.blocks = 0;
                    s.next_report = now + PUSH_BLOCKED_REPORT_INTERVAL;
                }
                if (auto conn_it = services.find(service);
                    conn_it != services.end() && conn_it->second == s.conn) {
                    while (!s.backlog.empty() && s.unacked < PUSH_WINDOW) {
                        ++s.unacked;
                        ++s.sent;
                        drain.emplace_back(
                                service,
                                s.conn,
                                std::move(s.backlog.front()),
                                s.unacked % PUSH_ACK_INTERVAL == 0);
                        s.backlog.pop_front();
                    }
                    if (!s.backlog.empty() && !s.blocked_since) {
                        s.blocked_since = now;
                        ++s.blocks;
                    }
                }
                ++it;
            }
        }

        if (auto dropped = notifications_dropped_.load(); dropped != notifications_dropped_logged) {
            log::warning(
                    cat,
                    "Dropped {} incoming notifications: too many are waiting to be processed",
                    dropped - notifications_dropped_logged);
            notifications_dropped_logged = dropped;
        }

        if (!drain.empty()) {
            log::debug(cat, "Sending {} backlogged pushes", drain.size());
            for (const auto& [service, conn, push, ack] : drain) {
                send_push(service, conn, push);
                if (ack)
                    request_ack(service, conn);
            }
        }

        if (process.empty())
            continue;

        log::debug(cat, "Processing {} network message notifications", process.size());

        if (auto now = steady_clock::now(); now >= filter_rotate_time_) {
            filter_rotate_ = std::move(filter_);
            filter_.clear();
            filter_rotate_time_ = now + config.filter_lifetime;
        }

        // Parse everything first, dropping duplicates, so that one query can look up every account
        // in the batch.  The views point into the message bodies, which `process` keeps alive.
        struct Parsed {
            AccountID account;
            std::string_view hash;
            int16_t ns;
            int64_t timestamp_ms, expiry_ms;
            // The whole body; or, for a message over the body limit, its first part (if any),
            // with the message's full size in full_size.
            std::optional<std::string_view> data;
            std::optional<int64_t> full_size;
            Blake2B_32 filt_hash;
        };
        std::vector<Parsed> parsed;
        parsed.reserve(process.size());
        // Duplicates within the batch; the filters are only updated once the lookup has succeeded,
        // so that a batch put back after a database failure is not then dropped as already seen.
        std::unordered_set<Blake2B_32> seen;
        size_t duplicates = 0;

        for (const auto& msg : process) {
            try {
                oxenc::bt_dict_consumer dict{msg.body()};

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

                // The message's full size, when its body was cut or left out for our body limit.
                auto full_size = dict.maybe<int64_t>("L");

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
                // A node without a monitor session has no body limit and sends the whole body: cut
                // it here as a node with one would, so that every message over the limit is
                // handled the same way whichever node it came from.
                if (auto limit = config.monitor_body_limit;
                    !full_size && maybe_data && maybe_data->size() > (size_t)limit) {
                    full_size = maybe_data->size();
                    maybe_data = maybe_data->substr(0, limit);
                }

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

                auto filt_hash = blake2b(account, hash);
                if (filter_rotate_.contains(filt_hash) || filter_.contains(filt_hash) ||
                    !seen.insert(filt_hash).second) {
                    log::trace(cat, "Ignoring duplicate notification");
                    duplicates++;
                    continue;
                }

                parsed.push_back(
                        {account,
                         hash,
                         ns,
                         timestamp_ms,
                         expiry_ms,
                         maybe_data,
                         full_size,
                         filt_hash});
            } catch (const std::exception& e) {
                log::warning(cat, "Failed to process incoming notification: {}", e.what());
                continue;
            }
        }

        // {account: [(service, svcid, svcdata, enc_key, want_data, want_truncated, namespaces)...]}
        // for every account in the batch, from one query per SUBSCRIPTION_LOOKUP_BATCH accounts.
        std::unordered_map<
                AccountID,
                std::vector<std::tuple<
                        std::string,
                        std::string,
                        std::vector<std::byte>,
                        EncKey,
                        bool,
                        bool,
                        std::vector<int16_t>>>>
                subs;
        try {
            std::vector<AccountID> accounts;
            for (const auto& p : parsed)
                if (subs.try_emplace(p.account).second)
                    accounts.push_back(p.account);

            auto conn = pool_.get();
            pqxx::nontransaction tx{conn};
            for (size_t i = 0; i < accounts.size(); i += SUBSCRIPTION_LOOKUP_BATCH) {
                auto end = std::min(accounts.size(), i + SUBSCRIPTION_LOOKUP_BATCH);
                pqxx::params params;
                std::string placeholders;
                for (size_t j = i; j < end; j++) {
                    params.append(accounts[j]);
                    placeholders += "{}${}"_format(j == i ? "" : ",", j - i + 1);
                }
                for (auto row : tx.exec(
                             R"(
SELECT account, service, svcid, svcdata, enc_key, want_data, want_truncated,
    ARRAY(SELECT namespace FROM sub_namespaces WHERE subscription = id ORDER BY namespace)
FROM subscriptions
WHERE account IN ({}))"_format(placeholders),
                             params)) {
                    auto [account,
                          service,
                          svcid,
                          svcdata,
                          enc_key,
                          want_data,
                          want_truncated,
                          ns_arr] =
                            row.as<AccountID,
                                   std::string,
                                   std::string,
                                   std::optional<std::vector<std::byte>>,
                                   EncKey,
                                   bool,
                                   bool,
                                   pqxx::array<int16_t>>();
                    subs[account].emplace_back(
                            std::move(service),
                            std::move(svcid),
                            svcdata ? std::move(*svcdata) : std::vector<std::byte>{},
                            enc_key,
                            want_data,
                            want_truncated,
                            std::vector<int16_t>{ns_arr.begin(), ns_arr.end()});
                }
            }
        } catch (const std::exception& e) {
            lookup_failures_++;
            // Nothing has been marked seen or sent, so the whole batch can go back, ahead of
            // whatever arrived since, to be tried again once the database is back.
            log::warning(
                    cat,
                    "Failed to look up subscriptions for {} notifications: {}; retrying in {}",
                    parsed.size(),
                    e.what(),
                    NOTIFY_LOOKUP_RETRY);
            std::unique_lock lock{notify_mutex_};
            for (auto& m : notify_queue_)
                process.push_back(std::move(m));
            notify_queue_ = std::move(process);
            for (const auto& m : notify_queue_)
                notify_queue_bytes_ += m.body().size();
            notify_cv_.wait_for(lock, NOTIFY_LOOKUP_RETRY, [this] { return notify_quit_; });
            continue;
        }

        for (const auto& p : parsed)
            filter_.insert(p.filt_hash);

        size_t notify_count = 0;

        for (const auto& [account, hash, ns, timestamp_ms, expiry_ms, data, full_size, filt_hash] :
             parsed) {
            auto subs_it = subs.find(account);
            if (subs_it == subs.end() || subs_it->second.empty()) {
                log::debug(cat, "No active notifications match, ignoring notification");
                continue;
            }

            for (const auto& [service, svcid, svcdata, enc_key, want_data, trunc_ok, namespaces] :
                 subs_it->second) {
                if (!std::binary_search(namespaces.begin(), namespaces.end(), ns))
                    continue;

                auto conn_it = services.find(service);
                if (conn_it == services.end() && !gone.contains(service)) {
                    log::warning(
                            cat,
                            "Notification depends on unregistered service {}, ignoring",
                            service);
                    continue;
                }

                // We overestimate a little here (e.g. allowing for 20 spaces for string
                // lengths) because a few extra bytes of allocation doesn't really matter.
                size_t size_needed = 2 + 35 +                 // 0: 32:service (or shorter)
                                     3 + 21 + svcid.size() +  // 1:& N:svcid
                                     3 + 35 +                 // 1:^ 32:enckey
                                     3 + 21 + hash.size() +   // 1:# N:hash
                                     3 + 36 +                 // 1:@ 33:account
                                     3 + 8 +                  // 1:n i-32768e
                                     3 + 15 +                 // 1:t i1695078498534e (timestamp)
                                     3 + 15 +                 // 1:t i1695078498534e (expiry)
                                     3 + 21 +                 // 1:} i76800e
                                     (svcdata.empty() ? 0 : 3 + 21 + svcdata.size()) +
                                     (want_data && data ? 3 + 21 + data->size() : 0);

                if (buf.size() < size_needed)
                    buf.resize(size_needed);

                oxenc::bt_dict_producer dict{buf.data(), buf.data() + buf.size()};

                try {
                    // NB: ascii sorted keys
                    dict.append("", service);
                    if (!svcdata.empty())
                        dict.append("!", svcdata);
                    dict.append("#", hash);
                    dict.append("&", svcid);
                    dict.append("@", account.sv());
                    dict.append("^", enc_key.sv());
                    dict.append("n", ns);
                    dict.append("t", timestamp_ms);
                    dict.append("z", expiry_ms);
                    if (want_data) {
                        if (full_size)
                            dict.append("}", *full_size);
                        if (data && (!full_size || trunc_ok))
                            dict.append("~", *data);
                    }
                } catch (const std::exception& e) {
                    log::critical(cat, "failed to build notifier message: bad size estimation?");
                    continue;
                }

                // Decided under the lock; the backlog append itself can happen after it, because
                // this thread is the backlog's only consumer.
                bool send = false, ack = false;
                {
                    std::lock_guard lock{notify_mutex_};
                    auto& s = service_pushes_[service];
                    if (conn_it != services.end() && conn_it->second == s.conn &&
                        s.backlog.empty() && s.unacked < PUSH_WINDOW) {
                        send = true;
                        ack = ++s.unacked % PUSH_ACK_INTERVAL == 0;
                        ++s.sent;
                    } else if (s.unacked >= PUSH_WINDOW && !s.blocked_since) {
                        s.blocked_since = steady_clock::now();
                        ++s.blocks;
                    }
                }
                if (send) {
                    log::debug(cat, "Sending push via {} notifier", service);
                    send_push(service, conn_it->second, dict.view());
                    if (ack)
                        request_ack(service, conn_it->second);
                } else
                    backlog_push(service, std::string{dict.view()});
                notify_count++;
            }
        }

        log::debug(
                cat,
                "Processed {} notifications ({} duplicates): {} pushes sent",
                process.size(),
                duplicates,
                notify_count);

        try {
            auto conn = pool_.get();
            pqxx::work tx{conn};
            increment_stat(tx, "", "notifications", notify_count);
            increment_stat(tx, "", "pushes", process.size());
            tx.commit();
        } catch (const std::exception& e) {
            log::warning(cat, "Failed to update notification stats: {}", e.what());
        }
        pushes_processed_ += process.size();
        notifications_unique_ += parsed.size();
        pushes_produced_ += notify_count;
        lookup_batches_++;
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

// Seconds since `t`, or null if there is none.  Absent values are written as nulls by hand: a
// std::optional converts to a json value only from nlohmann::json 3.12.
static nlohmann::json seconds_since(const std::optional<steady_time>& t, steady_time now) {
    if (!t)
        return nullptr;
    return std::chrono::duration<double>(now - *t).count();
}

void HiveMind::get_stats_json(std::function<void(nlohmann::json)> when_ready, StatsDepth depth) {
    bool audit = depth == StatsDepth::audited;
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

        tx.commit();
    }
    {
        std::lock_guard lock{subscription_rows_mutex_};
        int64_t total = 0;
        for (const auto& [service, count] : subscription_rows_)
            if (count > 0) {
                result["subscriptions"][service] = count;
                total += count;
            }
        result["subscriptions"]["total"] = total;
    }

    {
        std::lock_guard lock{notify_mutex_};
        auto now = steady_clock::now();
        for (const auto& [service, s] : service_pushes_) {
            auto& q = result["notifier_queue"][service];
            q["backlog"] = s.backlog.size();
            q["unacked"] = s.unacked;
            q["sent"] = s.sent;
            q["dropped"] = s.dropped_total;
            q["blocked_for"] = seconds_since(s.blocked_since, now);
        }
        result["incoming"] = {
                {"queue", notify_queue_.size()},
                {"queue_bytes", notify_queue_bytes_},
                {"received", notifications_received_.load()},
                {"unique", notifications_unique_.load()},
                {"pushes", pushes_produced_.load()},
                {"dropped", notifications_dropped_.load()},
                {"lookup_batches", lookup_batches_.load()},
                {"lookup_failures", lookup_failures_.load()}};
    }
    {
        std::lock_guard lock{services_mutex_};
        auto& registered = result["notifiers_registered"] = nlohmann::json::array();
        for (const auto& [service, conn] : services_)
            registered.push_back(service);
        auto& gone = result["notifiers_gone"] = nlohmann::json::array();
        for (const auto& [service, since] : services_gone_)
            gone.push_back(service);
        for (const auto& [service, dropped] : registrations_dropped_)
            result["registrations_dropped"][service] = {
                    {"ids", dropped.first}, {"subscriptions", dropped.second}};
    }
    auto [db_idle, db_in_use] = pool_.usage();
    result["db_connections"] = {{"idle", db_idle}, {"in_use", db_in_use}};
    {
        std::ifstream statm{"/proc/self/statm"};
        size_t pages = 0, resident = 0;
        if (statm >> pages >> resident)
            result["rss"] = resident * sysconf(_SC_PAGESIZE);
    }

    sub_jq_.call_soon([when_ready = std::move(when_ready),
                       result = std::move(result),
                       audit,
                       depth,
                       this]() mutable {
        size_t n_conns = 0;
        for (auto& sn : sns_)
            n_conns += sn.second->connected();

        size_t indexed = 0, holding = 0, with_nodes = 0, pending = 0, pending_nodes = 0;
        for (const auto& [id, swarm] : swarms_) {
            indexed += swarm.members.size();
            holding += !swarm.members.empty();
            with_nodes += swarm.nodes > 0;
        }
        for (const auto& [pk, sn] : sns_) {
            pending += sn->due.size();
            pending_nodes += !sn->due.empty() || !sn->scan.done;
        }

        result["block_hash"] = last_block_.first;
        result["block_height"] = last_block_.second;
        result["swarms"] = with_nodes;
        result["snodes"] = sns_.size();
        result["accounts_monitored"] = subscribers_.size();
        result["swarm_index"] = {{"swarms", holding}, {"accounts", indexed}};
        std::unordered_map<uint64_t, Recount> recount;
        if (audit)
            recount = audit_counters();
        auto c = depth == StatsDepth::tick ? Coverage{} : coverage(true, audit);
        if (audit) {
            auto index = coverage();
            for (auto [counter, kept, counted] :
                 {std::tuple{"accounts", index.accounts, c.accounts},
                  std::tuple{"covered accounts", index.covered, c.covered},
                  std::tuple{"under-covered accounts", index.under, c.under},
                  std::tuple{"accounts on none", index.at_zero, c.at_zero},
                  std::tuple{"unsendable accounts", index.unsendable, c.unsendable}})
                if (kept != counted)
                    log::warning(
                            cat,
                            "Coverage: the swarm index gives {} {}, which disagrees with a recount "
                            "of the accounts: {}",
                            kept,
                            counter,
                            counted);
        }
        result["coverage"] = {
                {"redundancy", config.redundancy},
                {"covered_threshold",
                 config.redundancy >= 1 && config.redundancy <= 3 ? config.redundancy : 4},
                {"accounts", c.accounts},
                {"covered", c.covered},
                {"under_covered", c.under},
                {"under_covered_down_only", c.under_down_only},
                {"at_zero", c.at_zero},
                {"on_none",
                 {{"rejected", c.rejected},
                  {"retrying", c.retrying},
                  {"no_node", c.no_node},
                  {"unacknowledged", c.claimed},
                  {"other", c.other}}},
                {"unsendable", c.unsendable},
                {"lapsed", c.lapsed},
                {"on_none_accounts", c.described}};
        // How many accounts each connected node holds.
        size_t load_nodes = 0, load_min = 0, load_max = 0, load_total = 0;
        for (const auto& [pk, sn] : sns_)
            if (sn->up() && sn->slot >= 0) {
                size_t claimed = sn->claimed;
                if (audit) {
                    auto it = recount.find(sn->swarm);
                    claimed = it == recount.end() ? 0 : it->second.claimed[sn->slot];
                }
                load_min = load_nodes ? std::min(load_min, claimed) : claimed;
                load_max = std::max(load_max, claimed);
                load_total += claimed;
                load_nodes++;
            }
        result["node_load"] = {
                {"nodes", load_nodes},
                {"min", load_min},
                {"avg", load_nodes ? double(load_total) / load_nodes : 0.0},
                {"max", load_max}};
        result["state"] = {
                {"file", config.state_file},
                {"saved_ago", seconds_since(state_saved_.when, steady_clock::now())},
                {"bytes", state_saved_.bytes},
                {"accounts", state_saved_.accounts},
                {"snapshot_ms", state_saved_.snapshot_ms},
                {"write_ms", state_saved_.write_ms.load()}};
        result["restored"] = {
                {"age",
                 restored_.age < 0 ? nlohmann::json(nullptr) : nlohmann::json(restored_.age)},
                {"accounts", restored_.accounts},
                {"swarms", restored_.swarms},
                {"nodes", restored_.slots},
                {"nodes_dropped", restored_.slots_dropped}};
        result["placements"] = {
                {"placed", placements_},
                {"by_scans", scan_placements_},
                {"moved", moved_placements_}};
        result["schedule"] = schedule_.size();
        result["pending"] = {
                {"accounts", pending},
                {"nodes", pending_nodes},
                {"requests", requests_in_flight_},
                {"request_cap", config.monitor_requests},
                {"waiting_nodes", send_queue_.size()}};
        int64_t supported = 0, unsupported = 0;
        for (const auto& [pk, sn] : sns_) {
            supported += sn->monitor_sessions() == hive::SNode::MonitorSessions::supported;
            unsupported += sn->monitor_sessions() == hive::SNode::MonitorSessions::unsupported;
        }
        const auto& ss = monitor_session_stats_;
        result["monitor_sessions"] = {
                {"nodes_supporting", supported},
                {"nodes_not_supporting", unsupported},
                {"old_version", ss.old_version},
                {"created", ss.created},
                {"resumed", ss.resumed},
                {"unsupported", ss.unsupported},
                {"failed", ss.failed},
                {"resumed_live", ss.kept},
                {"resumed_ended", ss.ended},
                {"missed_overflow", ss.overflow},
                {"replay_discarded", ss.replay_discarded},
                {"replay_discarded_accounts", ss.replay_discarded_accounts}};
        result["subscriptions_distinct"] = subscription_count_;
        const auto& ms = monitor_stats_;
        result["monitor_requests"] = {
                {"sent", ms.sent},
                {"answered", ms.answered},
                {"failed", ms.failed},
                {"timed_out", ms.timed_out},
                {"wrong_swarm", ms.wrong_swarm},
                {"rejected", ms.rejected}};
        result["accounts_moved"] = moved_total_;
        result["block_age"] = seconds_since(
                last_block_.second < 0 ? std::nullopt : std::optional{last_block_time_},
                steady_clock::now());
        result["connections"] = n_conns;
        result["pending_connections"] = pending_connects_.load();
        result["connections_established"] = connections_established_.load();
        result["uptime"] =
                std::chrono::duration<double>(system_clock::now() - startup_time).count();

        // The last of it is the QUIC loop's, for its nodes' cooldowns and sent bytes.
        jq_.call_soon(
                [this, when_ready = std::move(when_ready), result = std::move(result)]() mutable {
                    int64_t cooling = 0;
                    for (const auto& sn : conns_) {
                        cooling += sn->cooling_down();
                        bytes_sent_ += sn->take_sent_bytes();
                    }
                    result["cooling_down"] = cooling;
                    result["bytes_sent"] = bytes_sent_;
                    result["bytes_received"] = bytes_received_.load();
                    when_ready(std::move(result));
                });
    });
}

// The multi-line periodic status report, from the stats now and at the previous report `dt`
// seconds ago (null at the first), as rates over the interval for what counts up.
static std::string status_report(const nlohmann::json& s, const nlohmann::json& prev, double dt) {
    // The value at `path`, or null where any of it is absent.  Every lookup goes through this: a
    // const json's operator[] asserts that its key exists, and the parts of the stats need not
    // agree on which services there are (one whose stats are left in the database from an earlier
    // run has none of the rest while it is not registered).
    auto get = [](const nlohmann::json& j, const auto&... path) -> const nlohmann::json& {
        static const nlohmann::json null;
        const nlohmann::json* p = &j;
        for (std::string_view k : {std::string_view{path}...}) {
            if (!p->is_object())
                return null;
            auto it = p->find(k);
            if (it == p->end())
                return null;
            p = &*it;
        }
        return *p;
    };
    auto num = [&](const nlohmann::json& j, const auto&... path) -> double {
        const nlohmann::json& v = get(j, path...);
        return v.is_number() ? v.get<double>() : 0;
    };
    auto delta = [&](const auto&... path) { return num(s, path...) - num(prev, path...); };
    auto rate = [&](const auto&... path) { return dt > 0 ? delta(path...) / dt : 0.0; };
    auto duration = [](double secs) {
        auto t = static_cast<int64_t>(secs);
        return t >= 3600 ? "{}h{:02}m"_format(t / 3600, t / 60 % 60)
             : t >= 60   ? "{}m{:02}s"_format(t / 60, t % 60)
                         : "{}s"_format(t);
    };

    // The notifiers' own counters (service_stats) are kept across restarts, so they are compared
    // only with an earlier report's; the hivemind's start from zero at startup, and the first
    // report's figures for those are over the time since.
    bool have_prev = prev.is_object() && !prev.empty();

    std::string out = "Status report, over the last {}:"_format(duration(dt));

    out += "\n  Notifiers:";
    std::vector<std::string> shown, idle;
    for (const auto* key : {"notifiers_registered", "notifiers_gone"})
        if (const auto& names = get(s, key); names.is_array())
            for (const auto& name : names)
                shown.push_back(name.get<std::string>());
    if (shown.empty())
        out += " none";
    std::sort(shown.begin(), shown.end());
    for (const auto& service : shown) {
        bool gone = false;
        if (const auto& names = get(s, "notifiers_gone"); names.is_array())
            gone = std::find(names.begin(), names.end(), service) != names.end();
        auto sent = delta("notifier_queue", service, "sent"),
             unacked = num(s, "notifier_queue", service, "unacked"),
             backlog = num(s, "notifier_queue", service, "backlog"),
             dropped = delta("notifier_queue", service, "dropped");
        double failures = have_prev && get(prev, "notifier", service, "failures").is_number()
                                ? delta("notifier", service, "failures")
                                : 0;
        const auto& blocked = get(s, "notifier_queue", service, "blocked_for");
        // Pushes sent but not yet acknowledged are no sign of activity: below the ack interval
        // some always are.
        if (!gone && sent == 0 && backlog == 0 && dropped == 0 && failures == 0 &&
            !blocked.is_number()) {
            idle.push_back(service);
            continue;
        }
        out += "\n    {}: {:.1f} pushes/s, {} unacked, {} backlogged, {} dropped"_format(
                service, dt > 0 ? sent / dt : 0.0, unacked, backlog, dropped);
        if (failures > 0)
            out += ", {} failures"_format(failures);
        if (blocked.is_number())
            out += "; window blocked {}"_format(duration(blocked.get<double>()));
        if (gone)
            out += "; connection lost";
    }
    if (!idle.empty())
        out += "\n    idle: {}"_format(fmt::join(idle, ", "));

    auto batches = delta("incoming", "lookup_batches");
    out += "\n  Incoming: {:.1f}/s from nodes, {:.1f}/s unique, {:.1f} pushes/s; queue {} ({} B), "
           "{} dropped; lookups {:.2f}/s, {:.1f} per batch, {} failed"_format(
                   rate("incoming", "received"),
                   rate("incoming", "unique"),
                   rate("incoming", "pushes"),
                   num(s, "incoming", "queue"),
                   num(s, "incoming", "queue_bytes"),
                   delta("incoming", "dropped"),
                   rate("incoming", "lookup_batches"),
                   batches > 0 ? delta("incoming", "unique") / batches : 0.0,
                   delta("incoming", "lookup_failures"));

    out += "\n  Subscriptions: {} accounts, {} subscriptions, {} swarms; schedule {}; {} to send; "
           "requests {}/{} in flight, {} nodes waiting, {} sent ({} answered, {} failed, {} timed "
           "out), {} wrong swarm; {} accounts moved"_format(
                   num(s, "accounts_monitored"),
                   num(s, "subscriptions_distinct"),
                   num(s, "swarm_index", "swarms"),
                   num(s, "schedule"),
                   num(s, "pending", "accounts"),
                   num(s, "pending", "requests"),
                   num(s, "pending", "request_cap"),
                   num(s, "pending", "waiting_nodes"),
                   delta("monitor_requests", "sent"),
                   delta("monitor_requests", "answered"),
                   delta("monitor_requests", "failed"),
                   delta("monitor_requests", "timed_out"),
                   delta("monitor_requests", "wrong_swarm"),
                   delta("accounts_moved"));

    out += "\n  Coverage: {}/{} covered (on {}+ nodes; redundancy {}), {} under-covered ({} only "
           "on down nodes), {} on none ({} rejected, {} retrying, {} no node, {} unacknowledged, "
           "{} other), {} unsendable, {} lapsed; node load min/avg/max {}/{:.0f}/{}; placements: "
           "{} direct, {} by scans, {} moved"_format(
                   num(s, "coverage", "covered"),
                   num(s, "coverage", "accounts"),
                   num(s, "coverage", "covered_threshold"),
                   num(s, "coverage", "redundancy"),
                   num(s, "coverage", "under_covered"),
                   num(s, "coverage", "under_covered_down_only"),
                   num(s, "coverage", "at_zero"),
                   num(s, "coverage", "on_none", "rejected"),
                   num(s, "coverage", "on_none", "retrying"),
                   num(s, "coverage", "on_none", "no_node"),
                   num(s, "coverage", "on_none", "unacknowledged"),
                   num(s, "coverage", "on_none", "other"),
                   num(s, "coverage", "unsendable"),
                   num(s, "coverage", "lapsed"),
                   num(s, "node_load", "min"),
                   num(s, "node_load", "avg"),
                   num(s, "node_load", "max"),
                   delta("placements", "placed"),
                   delta("placements", "by_scans"),
                   delta("placements", "moved"));

    out += "\n  State: {}; {}; sessions: {} resumed, {} replays discarded for {} accounts"_format(
            get(s, "state", "saved_ago").is_number()
                    ? "saved {} ago, {} accounts, {:.1f} MB (snapshot {:.0f} ms, write {:.0f} "
                      "ms)"_format(
                              duration(num(s, "state", "saved_ago")),
                              num(s, "state", "accounts"),
                              num(s, "state", "bytes") / 1e6,
                              num(s, "state", "snapshot_ms"),
                              num(s, "state", "write_ms"))
                    : "not saved yet"s,
            get(s, "restored", "age").is_number()
                    ? "restored {} accounts on {} nodes from {} ago, {} nodes dropped"_format(
                              num(s, "restored", "accounts"),
                              num(s, "restored", "nodes"),
                              duration(num(s, "restored", "age")),
                              num(s, "restored", "nodes_dropped"))
                    : "restored nothing"s,
            delta("monitor_sessions", "resumed"),
            delta("monitor_sessions", "replay_discarded"),
            delta("monitor_sessions", "replay_discarded_accounts"));

    out += "\n  Nodes: {}/{} connected, {} connecting, {} cooling down, {} connections made; "
           "{:.1f}/{:.1f} kB/s out/in"_format(
                   num(s, "connections"),
                   num(s, "snodes"),
                   num(s, "pending_connections"),
                   num(s, "cooling_down"),
                   delta("connections_established"),
                   rate("bytes_sent") / 1000,
                   rate("bytes_received") / 1000);

    out += "\n  Process: RSS {:.0f} MB; block {}{}; up {}; db connections {} idle, {} busy"_format(
            num(s, "rss") / 1e6,
            num(s, "block_height"),
            get(s, "block_age").is_number() ? ", {} old"_format(duration(num(s, "block_age")))
                                            : ""s,
            duration(num(s, "uptime")),
            num(s, "db_connections", "idle"),
            num(s, "db_connections", "in_use"));

    if (const auto& accounts = get(s, "coverage", "on_none_accounts");
        accounts.is_array() && !accounts.empty()) {
        out += "\n  Accounts on no node, or unsendable:";
        for (const auto& line : accounts)
            out += "\n    {}"_format(line.get<std::string>());
    }
    return out;
}

void HiveMind::on_get_stats(oxenmq::Message& m) {
    get_stats_json(
            [m = m.send_later()](nlohmann::json stats) { m(stats.dump()); }, StatsDepth::full);
}

void HiveMind::log_stats(std::string pre_cmd) {
    // Decided before the stats are gathered, as only a report has them audited.
    bool report = std::chrono::steady_clock::now() - last_stats_logged >=
                  config.status_report_interval - 1s;
    auto on_stats = [this, pre_cmd = std::move(pre_cmd), report](nlohmann::json s) {
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

        // Due a little early, so that the 2-second tick it goes out with does not slip past it.
        if (auto now = std::chrono::steady_clock::now(); report) {
            double dt = !last_report_
                              ? std::chrono::duration<double>(system_clock::now() - startup_time)
                                        .count()
                              : std::chrono::duration<double>(now - last_report_time_).count();
            log::info(
                    stats,
                    "{}",
                    status_report(s, last_report_ ? *last_report_ : nlohmann::json{}, dt));
            last_report_ = std::make_unique<nlohmann::json>(std::move(s));
            last_report_time_ = now;
            last_stats_logged = now;
        } else {
            log::debug(stats, "Status: {}", stat_line);
        }
    };
    get_stats_json(std::move(on_stats), report ? StatsDepth::audited : StatsDepth::tick);
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
    count_subscription_rows(std::string{service}, -deleted);

    {
        std::lock_guard lock{services_mutex_};
        auto& [ids, subs] = registrations_dropped_[std::string{service}];
        ids += matched;
        subs += deleted;
    }
    log::debug(
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
        bool want_truncated,
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
                if (service_data && service_data->size() > SERVICE_DATA_MAX_SIZE)
                    throw std::invalid_argument{
                            "service data too long ({})"_format(service_data->size())};
                log::trace(cat, "Adding {} subscription for {}", service, pubkey.id.hex());
                bool newsub = add_subscription(
                        pubkey,
                        std::move(service),
                        std::move(service_id),
                        std::move(service_data),
                        *enc_key,
                        want_truncated,
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
    std::lock_guard lock{services_mutex_};
    if (auto it = services_.find(service); it != services_.end())
        return it->second;
    throw hive::subscribe_error{
            hive::SUBSCRIBE::SERVICE_NOT_AVAILABLE,
            service + " notification service not currently available"};
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
                bool want_truncated = false;
                if (auto it = e.find("truncate"); it != e.end())
                    want_truncated = it->get<bool>();

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
                                 want_truncated,
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
                            want_truncated,
                            std::move(data));
                };
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
                            false,
                            std::move(data),
                            std::move(unsub));
                };
            }

            // Everything else (including the response) is handled in on_notifier_validation
            // when/if the notifier service comes back to us with the unique identifier.
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
    on_sub_unsub_impl(m, false);
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
    std::unordered_map<std::string, int64_t> expired;
    // Once a subscription can no longer be sent: then the in-memory one lapses too.
    for (auto [service] : tx.query<std::string>(
                 "DELETE FROM subscriptions WHERE signature_ts < $1 RETURNING service",
                 {unix_timestamp(
                         system_clock::now() - hive::Subscription::SIGNATURE_EXPIRY +
                         hive::Subscription::SIGNATURE_MARGIN)}))
        expired[service]++;
    tx.commit();
    for (const auto& [service, count] : expired)
        count_subscription_rows(service, -count);
}

void HiveMind::count_subscription_rows(const std::string& service, int64_t change) {
    std::lock_guard lock{subscription_rows_mutex_};
    subscription_rows_[service] += change;
}

void HiveMind::subscribe_blocks() {
    omq_.request(oxend_, "sub.block", [](bool success, std::vector<std::string> data) {
        if (!success)
            log::warning(
                    cat,
                    "oxend block subscription request failed: {}",
                    "{}"_format(fmt::join(data, " ")));
    });
}

void HiveMind::refresh_sns() {
    omq_.request(
            oxend_,
            "rpc.get_service_nodes",
            [this](bool success, std::vector<std::string> data) {
                if (success)
                    sub_jq_.call_soon([this, data = std::move(data)]() mutable {
                        on_sns_response(std::move(data));
                    });
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
        std::vector<const SwarmPubkey*> moved;
        hold_dispatch_ = true;
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
                moved = reassign_swarms();
            }

            last_block_ = {std::move(new_hash), new_height};
            last_block_time_ = steady_clock::now();
        }

        using Version = std::optional<std::array<uint16_t, 3>>;
        std::unordered_map<Ed25519PK, std::tuple<std::string, uint16_t, uint64_t, Version>> sns;
        sns.reserve(sn_st.size());
        for (const auto& s : sn_st) {
            auto pked = s.at("pubkey_ed25519").get<std::string_view>();
            auto ip = s.at("public_ip").get<std::string_view>();
            auto port = s.at("storage_lmq_port").get<uint16_t>();
            auto swarm = s.at("swarm_id").get<uint64_t>();
            // Absent for a node whose uptime proof oxend has not seen.
            Version version;
            if (auto v = s.find("storage_server_version");
                v != s.end() && v->is_array() && v->size() == 3)
                version = v->get<std::array<uint16_t, 3>>();

            if (pked.size() == 64 && !ip.empty() && ip != "0.0.0.0" && port > 0 &&
                swarm != INVALID_SWARM_ID)
                sns.emplace(
                        std::piecewise_construct,
                        std::forward_as_tuple(from_hex_or_b64<Ed25519PK>(pked)),
                        std::forward_as_tuple(std::move(ip), port, swarm, version));
        }

        // auto missing_count = sn_st.size() - sns.size();
        log::debug(
                cat, "{} active SNs ({} missing details)", sns.size(), sn_st.size() - sns.size());

        // The QUIC loop connects to each of `addrs` (reconnecting only where the address changed)
        // and disconnects from `gone`.
        std::vector<std::pair<std::shared_ptr<hive::SNode>, quic::RemoteAddress>> addrs;
        std::vector<std::shared_ptr<hive::SNode>> gone;

        // Anything in self.sns but not in sns is no longer on the network (decommed, dereged,
        // expired), or possibly we lost info for it (from the above).  We're going to
        // disconnect from these (if any are connected).
        int dropped = 0;
        for (auto it = sns_.begin(); it != sns_.end();) {
            const auto& [pk, snode] = *it;
            if (sns.contains(pk)) {
                ++it;
                continue;
            }

            log::debug(cat, "Disconnecting {}", pk);
            leave_swarm(*snode);
            gone.push_back(snode);
            it = sns_.erase(it);
            dropped++;
        }

        int new_or_changed = 0;

        for (const auto& [pk, details] : sns) {
            const auto& [ip, port, swarm, version] = details;
            quic::RemoteAddress addr{pk.span<unsigned char>(), ip, port};

            if (auto it = sns_.find(pk); it != sns_.end()) {
                // We already know about this service node from the last update, but it might
                // have changed address or swarm.  A node whose swarm changed loses its claims on
                // the old one's accounts, and scans its new one's.
                auto& snode = it->second;
                snode->version = version;
                if (snode->swarm != swarm) {
                    leave_swarm(*snode);
                    snode->swarm = swarm;
                    join_swarm(*snode);
                    new_or_changed++;
                }

                addrs.emplace_back(snode, std::move(addr));
            } else {
                // New snode; it scans its swarm once it connects.
                auto snode = loop_.make_shared<hive::SNode>(*this, addr, swarm);
                snode->version = version;
                sns_.emplace(pk, snode);
                join_swarm(*snode);
                addrs.emplace_back(std::move(snode), std::move(addr));
                new_or_changed++;
            }
        }

        log::debug(cat, "{} new/updated SNs; dropped {} old SNs", new_or_changed, dropped);

        jq_.call_soon([this, addrs = std::move(addrs), gone = std::move(gone)]() mutable {
            for (auto& snode : gone)
                snode->disconnect();
            conns_.clear();
            for (auto& [snode, addr] : addrs) {
                snode->connect(std::move(addr));
                conns_.push_back(std::move(snode));
            }
        });

        // Placed only now that the nodes are in their own new swarms.
        for (const auto* account : moved)
            place(*account);
        std::erase_if(swarms_, [](const auto& s) {
            return s.second.nodes == 0 && s.second.members.empty();
        });
        // With the first list, once the nodes and accounts are in their swarms.
        if (!restore_tried_) {
            restore_tried_ = true;
            restore_state();
        }
        hold_dispatch_ = false;
        dispatch_requests();

        if (swarms_changed || new_or_changed)
            check_subs();
    } catch (const std::exception& e) {
        log::warning(cat, "An exception occured while processing the SN update: {}", e.what());
    }
    if (hold_dispatch_) {
        hold_dispatch_ = false;
        dispatch_requests();
    }
}

static thread_local std::mt19937_64 rng{std::random_device{}()};

std::chrono::seconds HiveMind::resubscribe_delay() const {
    auto [min, max] = config.renewal_interval
                            ? std::
                                      pair{*config.renewal_interval * 9 / 10,
                                           *config.renewal_interval * 11 / 10}
                            : std::pair{hive::RESUBSCRIBE_MIN, hive::RESUBSCRIBE_MAX};
    return 1s * std::uniform_int_distribution<int64_t>{min.count(), max.count()}(rng);
}

void HiveMind::schedule(const SwarmPubkey& account, system_time when) {
    account.next_due = when;
    schedule_.emplace_back(&account, when);
    std::push_heap(schedule_.begin(), schedule_.end(), schedule_later);
}

std::vector<const SwarmPubkey*>::iterator HiveMind::Swarm::find(const SwarmPubkey& account) {
    auto it = std::lower_bound(
            members.begin(),
            members.end(),
            account.swarm_space,
            [](const SwarmPubkey* a, uint64_t space) { return a->swarm_space < space; });
    for (; it != members.end() && (*it)->swarm_space == account.swarm_space; ++it)
        if (*it == &account)
            return it;
    return members.end();
}

void HiveMind::Swarm::insert(const SwarmPubkey& account) {
    by_claims[std::popcount<uint16_t>(account.sent | account.acked)]++;
    generation++;
    members.insert(
            std::upper_bound(
                    members.begin(),
                    members.end(),
                    account.swarm_space,
                    [](uint64_t space, const SwarmPubkey* a) { return space < a->swarm_space; }),
            &account);
}

void HiveMind::Swarm::erase(const SwarmPubkey& account) {
    if (auto it = find(account); it != members.end()) {
        by_claims[std::popcount<uint16_t>(account.sent | account.acked)]--;
        members.erase(it);
        generation++;
    }
}

void HiveMind::claim(const SwarmPubkey& account, Swarm& swarm, hive::SNode& node) {
    auto claims = std::popcount<uint16_t>(account.sent | account.acked);
    swarm.by_claims[claims]--;
    swarm.by_claims[claims + 1]++;
    account.sent |= static_cast<uint16_t>(1u << node.slot);
    node.claimed++;
}

void HiveMind::release(const SwarmPubkey& account, Swarm& swarm, int slot) {
    auto bit = static_cast<uint16_t>(1u << slot);
    if ((account.sent | account.acked) & bit) {
        auto claims = std::popcount<uint16_t>(account.sent | account.acked);
        swarm.by_claims[claims]--;
        swarm.by_claims[claims - 1]++;
        account.sent &= ~bit;
        account.acked &= ~bit;
        if (auto* node = swarm.slots[slot])
            node->claimed--;
    }
}

void HiveMind::release_all(const SwarmPubkey& account, uint64_t swarm) {
    auto it = swarms_.find(swarm);
    if (it == swarms_.end())
        return;
    for (uint16_t bits = account.sent | account.acked; bits; bits &= bits - 1)
        release(account, it->second, std::countr_zero(bits));
}

void HiveMind::place(const SwarmPubkey& account, uint16_t prev_acked, bool by_scan) {
    auto it = swarms_.find(account.swarm);
    if (it == swarms_.end())
        return;
    auto& swarm = it->second;
    uint16_t claimed_by = account.sent | account.acked;
    int short_by = target(swarm) - std::popcount(claimed_by);
    if (short_by <= 0)
        return;

    struct Candidate {
        hive::SNode* node;
        bool held;
        uint64_t draw;
    };
    std::array<Candidate, SWARM_SLOTS> candidates;
    int n = 0;
    for (int s = 0; s < SWARM_SLOTS; s++)
        if (auto* node = swarm.slots[s]; node && node->settled() && !(claimed_by >> s & 1))
            candidates[n++] = {node, bool(prev_acked >> s & 1), rng()};
    int chosen = std::min(short_by, n);
    std::partial_sort(
            candidates.begin(),
            candidates.begin() + chosen,
            candidates.begin() + n,
            [](const Candidate& a, const Candidate& b) {
                return std::tuple{a.node->claimed, !a.held, a.draw} <
                       std::tuple{b.node->claimed, !b.held, b.draw};
            });

    uint16_t chosen_bits = 0;
    int fresh = 0;
    for (int i = 0; i < chosen; i++) {
        auto& node = *candidates[i].node;
        claim(account, swarm, node);
        node.due.push_back(&account);
        chosen_bits |= static_cast<uint16_t>(1u << node.slot);
        fresh += !candidates[i].held;
        send_pending(node);
    }
    (by_scan ? scan_placements_ : placements_) += chosen;
    if (chosen > 0 && account.unplaced != SwarmPubkey::Unplaced::none) {
        account.unplaced = SwarmPubkey::Unplaced::none;
        unplaced_detail_.erase(&account);
    }
    // A node that did not hold the account before takes the place of one that did, while any of
    // those is left out; beyond them it is an addition, not a move.
    moved_placements_ += std::min(fresh, std::popcount<uint16_t>(prev_acked & ~chosen_bits));
}

void HiveMind::replace(const SwarmPubkey& account) {
    auto prev_acked = account.acked;
    release_all(account, account.swarm);
    place(account, prev_acked);
}

void HiveMind::place_again(const std::vector<const SwarmPubkey*>& accounts) {
    for (const auto* account : accounts)
        if (account->swarm != INVALID_SWARM_ID && account->next_due != SwarmPubkey::UNSCHEDULED)
            place(*account);
}

// Where a scan starts: at a random member, so that the nodes of a swarm woken together do not
// all walk it in step.
static uint64_t scan_start(const std::vector<const SwarmPubkey*>& members) {
    if (members.empty())
        return 0;
    return members[std::uniform_int_distribution<size_t>{0, members.size() - 1}(rng)]->swarm_space;
}

void HiveMind::wake(hive::SNode& node) {
    if (node.slot < 0)
        return;
    node.scan.done = false;
    node.scan.pass = 0;
    node.scan.walked = 0;
    send_pending(node);
}

void HiveMind::wake(Swarm& swarm, const hive::SNode* except) {
    for (auto* node : swarm.slots)
        if (node && node != except)
            wake(*node);
}

void HiveMind::join_swarm(hive::SNode& node) {
    auto& swarm = swarms_[node.swarm];
    auto free = std::find(swarm.slots.begin(), swarm.slots.end(), nullptr);
    if (free == swarm.slots.end()) {
        log::critical(
                cat,
                "{} is node {} of swarm {:x}, which has room for only {}: it is given no "
                "subscriptions",
                node.pubkey,
                swarm.nodes + 1,
                node.swarm,
                SWARM_SLOTS);
        node.slot = -1;
        return;
    }
    *free = &node;
    swarm.nodes++;
    node.slot = free - swarm.slots.begin();
    node.claimed = 0;
    node.due.clear();
    node.scan.cursor = scan_start(swarm.members);
    node.scan.generation = UINT64_MAX;
    // The swarm's target may have grown with it.
    wake(swarm);
}

void HiveMind::clear_slot(Swarm& swarm, hive::SNode& node) {
    if (node.claimed > 0)
        for (const auto* account : swarm.members)
            release(*account, swarm, node.slot);
    assert(node.claimed == 0);
    node.due.clear();
}

void HiveMind::leave_swarm(hive::SNode& node) {
    if (node.slot < 0)
        return;
    auto it = swarms_.find(node.swarm);
    auto& swarm = it->second;
    clear_slot(swarm, node);
    swarm.slots[node.slot] = nullptr;
    swarm.nodes--;
    node.slot = -1;
    node.resuming = false;
    node.scan.done = true;
    if (swarm.nodes == 0 && swarm.members.empty())
        swarms_.erase(it);
    else
        wake(swarm);
}

void HiveMind::drop_claims(hive::SNode& node) {
    node.due.clear();
    node.scan.done = true;
    if (node.slot < 0 || node.claimed == 0)
        return;
    auto& swarm = swarms_.at(node.swarm);
    node.scan.cursor = scan_start(swarm.members);
    node.scan.generation = UINT64_MAX;

    // A node keeps a monitor session, and the monitors on it, while it has no connection: the
    // claims it acknowledged are held for the session to be resumed.  Those it was sent and had
    // not answered go, as the request may never have reached it.  Without a session on the
    // connection (its monitor_session failed), its monitors were the connection's, and went with
    // it, even though our token may still resume the session.
    if (node.resuming || node.session_bound()) {
        node.resuming = true;
        auto bit = static_cast<uint16_t>(1u << node.slot);
        bool released = false;
        for (const auto* account : swarm.members)
            if (account->sent & bit) {
                release(*account, swarm, node.slot);
                released = true;
            }
        if (released)
            wake(swarm, &node);
        return;
    }

    clear_slot(swarm, node);
    // The accounts it held are below their target now, for the others' scans to find.
    wake(swarm, &node);
}

void HiveMind::subscribed(hive::SNode& node, const SwarmPubkey& account) {
    if (node.slot < 0 || account.swarm != node.swarm)
        return;
    auto bit = static_cast<uint16_t>(1u << node.slot);
    if (account.sent & bit) {
        account.sent &= ~bit;
        account.acked |= bit;
        account.acked_at = unix_timestamp(system_clock::now());
    }
}

void HiveMind::unclaim(hive::SNode& node, const SwarmPubkey& account) {
    if (node.slot < 0 || account.swarm != node.swarm)
        return;
    release(account, swarms_.at(node.swarm), node.slot);
}

void HiveMind::refused(hive::SNode& node, const SwarmPubkey& account, std::string error) {
    unclaim(node, account);
    account.unplaced = SwarmPubkey::Unplaced::rejected;
    unplaced_detail_[&account] = std::move(error);
}

void HiveMind::nothing_to_send(hive::SNode& node, const SwarmPubkey& account, bool not_yet_valid) {
    unclaim(node, account);
    if (not_yet_valid)
        return;
    // Lapsed, as its renewal would find it: placed again only if it is subscribed again.
    if (account.unplaced != SwarmPubkey::Unplaced::none) {
        account.unplaced = SwarmPubkey::Unplaced::none;
        unplaced_detail_.erase(&account);
    }
    release_all(account, account.swarm);
    account.next_due = SwarmPubkey::UNSCHEDULED;
}

void HiveMind::retrying(
        hive::SNode& node,
        const std::vector<const SwarmPubkey*>& accounts,
        std::chrono::milliseconds backoff) {
    auto why = "{} failed, placed again after {}"_format(node.pubkey, backoff);
    for (const auto* account : accounts) {
        account->unplaced = SwarmPubkey::Unplaced::retrying;
        unplaced_detail_[account] = why;
    }
}

const SwarmPubkey* HiveMind::next_claim(hive::SNode& node) {
    auto it = swarms_.find(node.swarm);
    if (node.slot < 0 || it == swarms_.end()) {
        node.due.clear();
        node.scan.done = true;
        return nullptr;
    }
    auto& swarm = it->second;
    auto bit = static_cast<uint16_t>(1u << node.slot);

    // The scan walks the members round from where it last stopped, looking first for accounts
    // claimed on no node, then on one, and so on up to one short of the target.  It places each
    // where any placement would go, rather than taking those this node would be chosen for: which
    // nodes those are changes with every claim, and a node passing an account before it became
    // one of them would leave it short.
    auto& scan = node.scan;
    const auto& members = swarm.members;
    int goal = target(swarm);
    while (true) {
        while (!node.due.empty()) {
            const auto* account = node.due.front();
            node.due.pop_front();
            // Not if a renewal or a move has placed it afresh since.
            if ((account->sent & bit) && account->swarm == node.swarm)
                return account;
        }
        if (scan.done || scan.pass >= goal || members.empty())
            break;
        if (scan.walked >= members.size() || swarm.by_claims[scan.pass] == 0) {
            scan.pass++;
            scan.walked = 0;
            continue;
        }
        if (scan.generation != swarm.generation) {
            scan.index = std::lower_bound(
                                 members.begin(),
                                 members.end(),
                                 scan.cursor,
                                 [](const SwarmPubkey* a, uint64_t cursor) {
                                     return a->swarm_space < cursor;
                                 }) -
                         members.begin();
            scan.generation = swarm.generation;
        }
        if (scan.index >= members.size())
            scan.index = 0;
        const auto* account = members[scan.index++];
        // Wraps round to 0 past the last possible swarm_space, as the walk does.
        scan.cursor = account->swarm_space + 1;
        scan.walked++;

        if (std::popcount<uint16_t>(account->sent | account->acked) == scan.pass &&
            account->next_due != SwarmPubkey::UNSCHEDULED)
            place(*account, 0, /*by_scan=*/true);
    }
    scan.done = true;
    return nullptr;
}

std::vector<const SwarmPubkey*> HiveMind::reassign_swarms() {
    auto now = system_clock::now();
    std::vector<const SwarmPubkey*> moved;
    size_t placed = 0, before = schedule_.size();
    for (auto& [pk, subs] : subscribers_) {
        auto old = pk.swarm;
        if (!pk.update_swarm(swarm_ids_))
            continue;
        if (old != INVALID_SWARM_ID)
            release_all(pk, old);
        if (pk.swarm == INVALID_SWARM_ID)
            continue;  // No swarms known at all; placed again once there are

        // An account placed for the first time is subscribed by its nodes' scans as they connect,
        // so only its renewal is scheduled; a moved one is placed on its new swarm at once.
        if (old == INVALID_SWARM_ID) {
            pk.next_due = now + resubscribe_delay();
            schedule_.emplace_back(&pk, pk.next_due);
            placed++;
        } else if (pk.next_due != SwarmPubkey::UNSCHEDULED)
            moved.push_back(&pk);
    }
    // One O(n) heapify instead of a push per account, since the first placement is every account.
    if (schedule_.size() != before)
        std::make_heap(schedule_.begin(), schedule_.end(), schedule_later);

    // Rebuilt rather than edited, as a move takes a large share of the accounts.
    for (auto& [id, swarm] : swarms_) {
        swarm.members.clear();
        swarm.by_claims.fill(0);
        swarm.generation++;
    }
    for (const auto& [pk, subs] : subscribers_)
        if (pk.swarm != INVALID_SWARM_ID) {
            auto& swarm = swarms_[pk.swarm];
            swarm.members.push_back(&pk);
            swarm.by_claims[std::popcount<uint16_t>(pk.sent | pk.acked)]++;
        }
    size_t holding = 0;
    for (auto& [id, swarm] : swarms_) {
        std::sort(swarm.members.begin(), swarm.members.end(), [](const auto* a, const auto* b) {
            return a->swarm_space < b->swarm_space;
        });
        holding += !swarm.members.empty();
    }

    log::info(
            cat,
            "Swarm list changed: {} accounts moved swarm, {} placed for the first time; {} swarms "
            "hold accounts",
            moved.size(),
            placed,
            holding);
    return moved;
}

void HiveMind::check_subs() {
    assert(sub_loop_.inside());

    auto now = system_clock::now();
    auto sig_min =
            now - hive::Subscription::SIGNATURE_EXPIRY + hive::Subscription::SIGNATURE_MARGIN;
    auto sig_max = now + hive::Subscription::SIGNATURE_EARLY;

    size_t due = 0, lapsed = 0;
    while (!schedule_.empty() && schedule_.front().second <= now) {
        std::pop_heap(schedule_.begin(), schedule_.end(), schedule_later);
        auto [account, when] = schedule_.back();
        schedule_.pop_back();
        if (when != account->next_due)
            continue;  // Rescheduled since

        auto it = subscribers_.find(*account);
        if (it == subscribers_.end() ||
            std::none_of(it->second.begin(), it->second.end(), [&](const auto& sub) {
                return sub.sig_ts >= sig_min && sub.sig_ts <= sig_max;
            })) {
            // Nothing left to renew: it is scheduled again if it is subscribed again.
            release_all(*account, account->swarm);
            account->next_due = SwarmPubkey::UNSCHEDULED;
            lapsed++;
            continue;
        }

        replace(*account);
        schedule(*account, now + resubscribe_delay());
        due++;
    }
    if (due || lapsed)
        log::debug(cat, "{} accounts due for (re)subscription; {} lapsed", due, lapsed);

    if (moved_disagree_) {
        log::warning(
                cat,
                "Nodes moved {} accounts to the swarm we place them in, and {} to another; "
                "refreshing the swarm list",
                moved_agree_,
                moved_disagree_);
        refresh_sns();
    } else if (moved_agree_)
        log::debug(cat, "Nodes moved {} accounts to the swarm we place them in", moved_agree_);
    moved_total_ += moved_agree_;
    moved_agree_ = moved_disagree_ = 0;

    for (const auto& [pk, snode] : sns_) {
        try {
            send_pending(*snode);
        } catch (const std::exception& e) {
            log::warning(cat, "Failed to check subs on {}: {}", pk, e.what());
        }
    }
}

std::unordered_map<uint64_t, HiveMind::Recount> HiveMind::audit_counters() const {
    std::unordered_map<uint64_t, Recount> recount;
    for (const auto& [account, subs] : subscribers_) {
        if (account.swarm == INVALID_SWARM_ID)
            continue;
        auto& r = recount[account.swarm];
        r.members++;
        uint16_t bits = account.sent | account.acked;
        r.by_claims[std::popcount(bits)]++;
        for (; bits; bits &= bits - 1)
            r.claimed[std::countr_zero(bits)]++;
    }
    auto check = [](uint64_t id, std::string_view counter, size_t kept, size_t counted) {
        if (kept != counted)
            log::warning(
                    cat,
                    "Swarm {:x}: {} is {}, which disagrees with a recount of its accounts: {}",
                    id,
                    counter,
                    kept,
                    counted);
    };
    static const Recount none;
    for (const auto& [id, swarm] : swarms_) {
        auto it = recount.find(id);
        const auto& r = it == recount.end() ? none : it->second;
        check(id, "its member count", swarm.members.size(), r.members);
        for (int n = 0; n <= SWARM_SLOTS; n++)
            check(id, "by_claims[{}]"_format(n), swarm.by_claims[n], r.by_claims[n]);
        for (int slot = 0; slot < SWARM_SLOTS; slot++)
            check(id,
                  "slot {}'s claim count"_format(slot),
                  swarm.slots[slot] ? swarm.slots[slot]->claimed : 0,
                  r.claimed[slot]);
    }
    for (const auto& [id, r] : recount)
        if (!swarms_.contains(id))
            check(id, "its member count (it is not indexed)", 0, r.members);
    return recount;
}

HiveMind::Coverage HiveMind::coverage(bool detail, bool recount) const {
    Coverage c;
    // The window send_next sends subscriptions in.
    auto now = system_clock::now();
    auto sig_min =
            now - hive::Subscription::SIGNATURE_EXPIRY + hive::Subscription::SIGNATURE_MARGIN;
    auto sig_max = now + hive::Subscription::SIGNATURE_EARLY;
    auto ago = [&](system_time t) {
        return "{:.1f}h"_format(std::chrono::duration<double, std::ratio<3600>>(now - t).count());
    };
    // The accounts on none described, by class, in the order they are listed.
    enum { other, rejected, retrying, no_node, claimed, unsendable, classes };
    constexpr size_t LISTED = 20;
    std::array<std::vector<std::string>, classes> described;
    auto describe = [&](int cls, const SwarmPubkey& account, std::string why) {
        if (detail && described[cls].size() < LISTED)
            described[cls].push_back("{}: {}"_format(account.id.hex(), why));
    };

    // Each swarm's threshold, node count, and connected nodes with slots (as a count and a mask).
    struct SwarmInfo {
        int goal = 1, nodes = 0, up = 0;
        uint16_t up_slots = 0;
    };
    auto info = [&](const Swarm& swarm) {
        SwarmInfo si{covered_threshold(swarm), swarm.nodes};
        for (int i = 0; i < SWARM_SLOTS; i++)
            if (const auto* node = swarm.slots[i]; node && node->up()) {
                si.up++;
                si.up_slots |= static_cast<uint16_t>(1u << i);
            }
        return si;
    };
    auto visit = [&](uint64_t id, const SwarmInfo& si, const SwarmPubkey* account) {
        if (account->next_due == SwarmPubkey::UNSCHEDULED) {
            c.lapsed++;
            return;
        }
        c.accounts++;
        int count = std::popcount(account->acked);
        if (count >= si.goal) {
            c.covered++;
            return;
        }
        if (count > 0) {
            c.under++;
            c.under_down_only += (si.up_slots & ~account->acked) == 0;
            return;
        }

        auto subs = subscribers_.find(*account);
        if (subs == subscribers_.end() || subs->second.empty()) {
            c.unsendable++;
            describe(unsendable, *account, "unsendable: no subscriptions");
            return;
        }
        if (std::none_of(subs->second.begin(), subs->second.end(), [&](const auto& sub) {
                return sub.sig_ts >= sig_min && sub.sig_ts <= sig_max;
            })) {
            c.unsendable++;
            describe(
                    unsendable,
                    *account,
                    "unsendable: none of its {} subscriptions signed within the window"_format(
                            subs->second.size()));
            return;
        }

        c.at_zero++;
        auto text = [&] {
            auto it = unplaced_detail_.find(account);
            return it == unplaced_detail_.end() ? ""s : it->second;
        };
        if (account->unplaced == SwarmPubkey::Unplaced::rejected) {
            c.rejected++;
            describe(rejected, *account, "every entry rejected: {}"_format(text()));
        } else if (account->unplaced == SwarmPubkey::Unplaced::retrying) {
            c.retrying++;
            describe(retrying, *account, "retrying: {}"_format(text()));
        } else if (si.up == 0) {
            c.no_node++;
            describe(
                    no_node,
                    *account,
                    "no connected node with a slot in swarm {:x} ({} nodes)"_format(id, si.nodes));
        } else if (account->sent) {
            c.claimed++;
            describe(
                    claimed,
                    *account,
                    "sent to {} nodes, not yet acknowledged"_format(std::popcount(account->sent)));
        } else {
            c.other++;
            if (detail && described[other].size() < LISTED) {
                std::vector<std::string> signed_;
                for (const auto& sub : subs->second)
                    signed_.push_back(
                            "signed {} ago{}, {} namespaces"_format(
                                    ago(sub.sig_ts),
                                    sub.want_data ? " with data" : "",
                                    sub.namespaces.size()));
                describe(
                        other,
                        *account,
                        "unexplained: sent {:04x}, acked {:04x}, swarm {:x} ({} nodes, {} up), "
                        "due in {}, {} subscriptions ({})"_format(
                                account->sent,
                                account->acked,
                                id,
                                si.nodes,
                                si.up,
                                std::chrono::floor<std::chrono::seconds>(account->next_due - now),
                                subs->second.size(),
                                fmt::join(signed_, "; ")));
            }
        }
    };

    if (!recount) {
        for (const auto& [id, swarm] : swarms_) {
            auto si = info(swarm);
            for (const auto* account : swarm.members)
                visit(id, si, account);
        }
    } else {
        std::unordered_map<uint64_t, SwarmInfo> infos;
        for (const auto& [account, subs] : subscribers_) {
            if (account.swarm == INVALID_SWARM_ID)
                continue;
            auto [it, fresh] = infos.try_emplace(account.swarm);
            if (fresh)
                if (auto sw = swarms_.find(account.swarm); sw != swarms_.end())
                    it->second = info(sw->second);
            visit(account.swarm, it->second, &account);
        }
    }
    for (auto& list : described)
        for (auto& line : list)
            if (c.described.size() < LISTED)
                c.described.push_back(std::move(line));
    return c;
}

void HiveMind::log_coverage_progress() {
    auto c = coverage();
    const auto& was = coverage_logged_;
    bool below = c.under + c.at_zero > 0, was_below = was.under + was.at_zero > 0;
    if ((below || was_below) &&
        (c.accounts != was.accounts || c.covered != was.covered || c.under != was.under ||
         c.under_down_only != was.under_down_only || c.at_zero != was.at_zero))
        log::info(
                cat,
                "Coverage: {}/{} accounts ({:.1f}%) covered, {} under-covered ({} only on down "
                "nodes), {} on none, {} unsendable; {}/{} requests in flight, {} nodes waiting",
                c.covered,
                c.accounts,
                c.accounts ? 100.0 * c.covered / c.accounts : 100.0,
                c.under,
                c.under_down_only,
                c.at_zero,
                c.unsendable,
                requests_in_flight_,
                config.monitor_requests,
                send_queue_.size());
    coverage_logged_ = c;
}

namespace {

    // The saved state (see HiveMind::save_state), all integers little-endian:
    //
    //     "SPNS", version (u8), when saved (i64 unix seconds)
    //     token count (u32), each: node pubkey (32), token (32)
    //     swarm count (u32), each:
    //         swarm id (u64), slot count (u8), each: slot (u8), node pubkey (32)
    //         account count (u32), each: account id (33), acked mask (u16), acked at (u32)
    //
    // Only accounts acknowledged on some node are written.
    constexpr std::string_view STATE_MAGIC = "SPNS";
    constexpr uint8_t STATE_VERSION = 1;

    template <std::integral T>
    void put(std::string& out, T v) {
        v = oxenc::host_to_little(v);
        out.append(reinterpret_cast<const char*>(&v), sizeof v);
    }

    // Reads saved state, throwing on anything truncated.
    struct StateReader {
        std::string_view in;

        std::string_view bytes(size_t n) {
            if (in.size() < n)
                throw std::runtime_error{"truncated"};
            auto r = in.substr(0, n);
            in.remove_prefix(n);
            return r;
        }
        template <std::integral T>
        T get() {
            return oxenc::load_little_to_host<T>(bytes(sizeof(T)).data());
        }
    };

    // Writes `data` to `path` whole: to a temporary file, synced, then renamed over it.
    void write_whole(const std::string& path, std::string_view data) {
        auto tmp = path + ".tmp";
        int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        if (fd < 0)
            throw std::runtime_error{"cannot open {}: {}"_format(tmp, std::strerror(errno))};
        for (size_t done = 0; done < data.size();) {
            auto n = ::write(fd, data.data() + done, data.size() - done);
            if (n < 0 && errno == EINTR)
                continue;
            if (n < 0) {
                auto err = errno;
                ::close(fd);
                throw std::runtime_error{"cannot write {}: {}"_format(tmp, std::strerror(err))};
            }
            done += n;
        }
        if (::fsync(fd) != 0 || ::close(fd) != 0)
            throw std::runtime_error{"cannot sync {}: {}"_format(tmp, std::strerror(errno))};
        if (::rename(tmp.c_str(), path.c_str()) != 0)
            throw std::runtime_error{"cannot rename {}: {}"_format(tmp, std::strerror(errno))};
    }

}  // namespace

void HiveMind::save_state(bool wait) {
    if (config.state_file.empty())
        return;
    if (state_writing_) {
        if (!wait) {
            log::warning(cat, "Not saving placement state: the last save is still being written");
            return;
        }
    }
    if (state_writer_.joinable())
        state_writer_.join();

    auto started = steady_clock::now();
    std::string out;
    out.reserve(32 + 64 * monitor_tokens_.size() + 39 * subscribers_.size());
    out += STATE_MAGIC;
    put<uint8_t>(out, STATE_VERSION);
    put<int64_t>(out, unix_timestamp(system_clock::now()));
    put<uint32_t>(out, monitor_tokens_.size());
    for (const auto& [pk, token] : monitor_tokens_) {
        out += pk.sv();
        out += token.sv();
    }
    size_t accounts = 0, swarms = 0;
    auto swarm_count_at = out.size();
    put<uint32_t>(out, 0);
    for (const auto& [id, swarm] : swarms_) {
        if (swarm.nodes == 0)
            continue;
        swarms++;
        put<uint64_t>(out, id);
        put<uint8_t>(out, swarm.nodes);
        for (int s = 0; s < SWARM_SLOTS; s++)
            if (const auto* node = swarm.slots[s]) {
                put<uint8_t>(out, s);
                out += node->pubkey.sv();
            }
        auto count_at = out.size();
        put<uint32_t>(out, 0);
        uint32_t count = 0;
        for (const auto* account : swarm.members) {
            if (!account->acked)
                continue;
            out += account->id.sv();
            put<uint16_t>(out, account->acked);
            put<uint32_t>(out, account->acked_at);
            count++;
        }
        auto le = oxenc::host_to_little(count);
        std::memcpy(out.data() + count_at, &le, sizeof le);
        accounts += count;
    }
    auto le = oxenc::host_to_little(static_cast<uint32_t>(swarms));
    std::memcpy(out.data() + swarm_count_at, &le, sizeof le);

    state_saved_.when = steady_clock::now();
    state_saved_.bytes = out.size();
    state_saved_.accounts = accounts;
    state_saved_.snapshot_ms =
            std::chrono::duration<double, std::milli>(*state_saved_.when - started).count();

    state_writing_ = true;
    auto write = [this, out = std::move(out), accounts] {
        auto started = steady_clock::now();
        try {
            write_whole(config.state_file, out);
            state_saved_.write_ms =
                    std::chrono::duration<double, std::milli>(steady_clock::now() - started)
                            .count();
            log::info(
                    cat,
                    "Saved placement state of {} accounts ({} B) to {}: snapshot {:.1f}ms, write "
                    "{:.1f}ms",
                    accounts,
                    out.size(),
                    config.state_file,
                    state_saved_.snapshot_ms,
                    state_saved_.write_ms.load());
        } catch (const std::exception& e) {
            log::warning(cat, "Failed to save placement state: {}", e.what());
        }
        state_writing_ = false;
    };
    if (wait)
        write();
    else
        state_writer_ = std::thread{std::move(write)};
}

void HiveMind::restore_state() {
    if (config.state_file.empty())
        return;
    std::string data;
    {
        std::ifstream f{config.state_file, std::ios::binary};
        if (!f) {
            log::info(
                    cat,
                    "No saved placement state ({} not found): every node starts a new monitor "
                    "session and is subscribed afresh",
                    config.state_file);
            return;
        }
        data.assign(std::istreambuf_iterator<char>{f}, {});
    }

    auto now = system_clock::now();
    int64_t saved_at;
    // A pass over the file to check it whole, before a second that applies it.
    auto walk = [&](bool apply) {
        StateReader r{data};
        if (r.bytes(STATE_MAGIC.size()) != STATE_MAGIC)
            throw std::runtime_error{"not a saved state file"};
        if (auto v = r.get<uint8_t>(); v != STATE_VERSION)
            throw std::runtime_error{"unknown version {}"_format(v)};
        saved_at = r.get<int64_t>();
        if (!apply) {
            auto age = now - system_time{std::chrono::seconds{saved_at}};
            if (age > RESUME_MAX_AGE || age < -1min)
                return false;
        }

        std::unordered_map<Ed25519PK, MonitorToken> tokens;
        for (auto n = r.get<uint32_t>(); n > 0; n--) {
            Ed25519PK pk;
            MonitorToken token;
            std::memcpy(pk.data(), r.bytes(pk.size()).data(), pk.size());
            std::memcpy(token.data(), r.bytes(token.size()).data(), token.size());
            tokens.emplace(pk, token);
        }
        for (auto swarms = r.get<uint32_t>(); swarms > 0; swarms--) {
            auto id = r.get<uint64_t>();
            auto sw = swarms_.find(id);
            // This save's slot -> the slot of the same node, if it is still in this swarm.
            std::array<int, SWARM_SLOTS> slot_now;
            slot_now.fill(-1);
            int kept = 0;
            for (auto n = r.get<uint8_t>(); n > 0; n--) {
                auto s = r.get<uint8_t>();
                Ed25519PK pk;
                std::memcpy(pk.data(), r.bytes(pk.size()).data(), pk.size());
                if (s >= SWARM_SLOTS)
                    throw std::runtime_error{"invalid slot {}"_format(s)};
                if (!apply)
                    continue;
                auto it = sns_.find(pk);
                if (sw == swarms_.end() || it == sns_.end() || it->second->swarm != id ||
                    it->second->slot < 0) {
                    restored_.slots_dropped++;
                    continue;
                }
                auto& node = *it->second;
                slot_now[s] = node.slot;
                node.resuming = true;
                if (auto t = tokens.find(pk); t != tokens.end())
                    monitor_tokens_[pk] = t->second;
                kept++;
            }
            if (apply && kept) {
                restored_.swarms++;
                restored_.slots += kept;
            }
            for (auto n = r.get<uint32_t>(); n > 0; n--) {
                AccountID acct_id;
                std::memcpy(acct_id.data(), r.bytes(acct_id.size()).data(), acct_id.size());
                auto acked = r.get<uint16_t>();
                auto acked_at = r.get<uint32_t>();
                if (!apply || !kept)
                    continue;
                auto it = subscribers_.find(
                        SwarmPubkey{acct_id, std::nullopt, /*_skip_validation=*/true});
                if (it == subscribers_.end())
                    continue;
                const auto& account = it->first;
                if (account.swarm != id || account.next_due == SwarmPubkey::UNSCHEDULED)
                    continue;
                bool any = false;
                for (uint16_t bits = acked; bits; bits &= bits - 1)
                    if (auto s = slot_now[std::countr_zero(bits)]; s >= 0) {
                        auto bit = static_cast<uint16_t>(1u << s);
                        if ((account.sent | account.acked) & bit)
                            continue;
                        auto claims = std::popcount<uint16_t>(account.sent | account.acked);
                        sw->second.by_claims[claims]--;
                        sw->second.by_claims[claims + 1]++;
                        account.acked |= bit;
                        sw->second.slots[s]->claimed++;
                        any = true;
                    }
                if (!any)
                    continue;
                restored_.accounts++;
                account.acked_at = acked_at;
                // Renewed as it would have been, which may be now; and at the latest well
                // before its monitors run out.
                auto last = system_time{std::chrono::seconds{acked_at}};
                schedule(
                        account,
                        std::min(
                                last + resubscribe_delay(),
                                last + hive::MONITOR_LIFETIME - RESUME_MARGIN));
            }
        }
        if (!r.in.empty())
            throw std::runtime_error{"{} bytes left over"_format(r.in.size())};
        return true;
    };

    try {
        if (!walk(false)) {
            log::info(
                    cat,
                    "Saved placement state is {} old, more than {}: every node starts a new "
                    "monitor session and is subscribed afresh",
                    std::chrono::floor<std::chrono::seconds>(
                            now - system_time{std::chrono::seconds{saved_at}}),
                    RESUME_MAX_AGE);
            return;
        }
    } catch (const std::exception& e) {
        log::info(
                cat,
                "Saved placement state in {} is unusable ({}): every node starts a new monitor "
                "session and is subscribed afresh",
                config.state_file,
                e.what());
        return;
    }
    walk(true);
    // Only the restored nodes' sessions can be resumed: without the listing, nothing else could
    // be reconciled.
    std::erase_if(monitor_tokens_, [this](const auto& t) {
        auto it = sns_.find(t.first);
        return it == sns_.end() || !it->second->resuming;
    });
    for (const auto& [pk, node] : sns_)
        if (node->resuming && node->claimed == 0)
            node->resuming = false;
    restored_.age = std::chrono::duration<double>(now - system_time{std::chrono::seconds{saved_at}})
                            .count();
    log::info(
            cat,
            "Restored placement state saved {} ago: {} accounts on {} nodes in {} swarms; {} "
            "nodes dropped, having moved swarm or left the network",
            std::chrono::floor<std::chrono::seconds>(
                    now - system_time{std::chrono::seconds{saved_at}}),
            restored_.accounts,
            restored_.slots,
            restored_.swarms,
            restored_.slots_dropped);
}

void HiveMind::abandon_resume(hive::SNode& node) {
    if (!node.resuming)
        return;
    node.resuming = false;
    if (node.slot < 0 || node.claimed == 0)
        return;
    auto& swarm = swarms_.at(node.swarm);
    clear_slot(swarm, node);
    wake(swarm, &node);
}

void HiveMind::monitor_session_started(
        hive::SNode& node,
        const MonitorToken& token,
        bool resumed,
        std::string_view monitors,
        int64_t overflow) {
    auto [it, inserted] = monitor_tokens_.try_emplace(node.pubkey, token);
    bool had_token = !inserted;
    it->second = token;
    if (overflow > 0) {
        log::warning(
                cat,
                "{} discarded {} notifications for us while we were away, more than it holds",
                node.pubkey,
                overflow);
        monitor_session_stats_.overflow += overflow;
    }

    if (!resumed) {
        if (had_token)
            log::info(
                    cat,
                    "{} could not resume our monitor session (it had ended, or our token was "
                    "out of date); subscribing everything in a new one",
                    node.pubkey);
        monitor_session_stats_.created++;
        abandon_resume(node);
        wake(node);
        return;
    }

    // Asked for without its listing: only the monitors that have ended since are listed, and the
    // claims the node holds for the session, restored after a restart or kept across a lost
    // connection, stand.
    monitor_session_stats_.resumed++;
    node.resuming = false;
    size_t ended = 0;
    try {
        oxenc::bt_list_consumer list{monitors};
        while (!list.is_finished()) {
            auto m = list.consume_dict_consumer();
            auto account = m.require<std::string_view>("@");
            if (!m.maybe<int>("errcode"))
                continue;
            ended++;
            if (auto swarm = m.maybe<std::string_view>("swarm"))
                check_moved(account, *swarm);
            AccountID id;
            if (account.size() != id.size())
                continue;
            std::memcpy(id.data(), account.data(), id.size());
            if (auto acct =
                        subscribers_.find(SwarmPubkey{id, std::nullopt, /*_skip_validation=*/true});
                acct != subscribers_.end())
                unclaim(node, acct->first);
        }
    } catch (const std::exception& e) {
        log::warning(
                cat,
                "Invalid monitor list in {}'s monitor_session response ({}); subscribing "
                "everything",
                node.pubkey,
                e.what());
        node.resuming = true;
        abandon_resume(node);
    }
    monitor_session_stats_.kept += node.claimed;
    monitor_session_stats_.ended += ended;
    log::debug(
            cat,
            "Resumed monitor session with {}: {} accounts still subscribed; {} monitors ended",
            node.pubkey,
            node.claimed,
            ended);
    wake(node);
}

void HiveMind::monitor_session_unsupported(hive::SNode& node) {
    monitor_session_stats_.unsupported++;
    abandon_resume(node);
    wake(node);
}

void HiveMind::monitor_session_failed(hive::SNode& node) {
    // The node rotates the token as it composes its reply, so a reply that failed after that
    // leaves us holding a dead token.  One never composed is indistinguishable from it, so the
    // token goes either way, and the next connection starts a new session: one full placement for
    // the node, accepted as rare.
    if (monitor_tokens_.erase(node.pubkey))
        log::info(
                cat,
                "Forgot our monitor session token for {}: its next one starts afresh",
                node.pubkey);
    monitor_session_stats_.failed++;
    abandon_resume(node);
    wake(node);
}

void HiveMind::make_conns() {
    assert(loop_.inside());

    for (const auto& snode : conns_) {
        if (pending_connects_ >= config.max_pending_connects)
            return;

        snode->connect();
    }
}

void HiveMind::on_node_connected(hive::SNode& snode, int gen) {
    if (!snode.connection_up(gen))
        return;
    if (!snode.offers_monitor_sessions()) {
        monitor_session_stats_.old_version++;
        abandon_resume(snode);
        wake(snode);
        return;
    }
    std::optional<MonitorToken> token;
    if (auto it = monitor_tokens_.find(snode.pubkey); it != monitor_tokens_.end())
        token = it->second;
    snode.start_monitor_session(token);
}

void HiveMind::send_pending(hive::SNode& snode) {
    if (!snode.queued && snode.ready_to_send()) {
        snode.queued = true;
        send_queue_.push_back(snode.shared_from_this());
    }
    dispatch_requests();
}

void HiveMind::request_finished() {
    requests_in_flight_--;
    dispatch_requests();
}

void HiveMind::dispatch_requests() {
    if (dispatching_)
        return;
    dispatching_ = true;
    struct Done {
        bool& flag;
        ~Done() { flag = false; }
    } done{dispatching_};
    while (!hold_dispatch_ && requests_in_flight_ < config.monitor_requests &&
           !send_queue_.empty()) {
        auto snode = std::move(send_queue_.front());
        send_queue_.pop_front();
        snode->queued = false;
        if (snode->send_next(subscribers_, [&] { return next_claim(*snode); })) {
            requests_in_flight_++;
            monitor_stats_.sent++;
        }
    }
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
    {
        std::unordered_map<std::string, int64_t> rows;
        constexpr auto query = "SELECT service, COUNT(*) FROM subscriptions GROUP BY service";
        for (auto [service, count] : txn.query<std::string, int64_t>(query))
            rows[service] = count;
        std::lock_guard lock{subscription_rows_mutex_};
        subscription_rows_ = std::move(rows);
    }

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
        sigts_cutoff.first = sys_now - hive::Subscription::SIGNATURE_EXPIRY +
                             hive::Subscription::SIGNATURE_MARGIN;
        sigts_cutoff.second = sys_now + hive::Subscription::SIGNATURE_EARLY;
    };
    update_clocks();
    int last_decile = 0;

    int64_t raw_count = 0, count = 0, unique = 0;
    for (auto& [t, rows] : threads) {
        for (auto& [swpk, subaccount, sig, sigts, wd, ns_arr] : rows) {
            raw_count++;

            if (sigts < sigts_cutoff.first || sigts > sigts_cutoff.second)
                // Not sendable, as send_next would find (and those too old are deleted).
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
    subscription_count_ = unique;
}

bool HiveMind::add_subscription(
        SwarmPubkey pubkey,
        std::string service,
        std::string service_id,
        std::optional<std::string> service_data,
        EncKey enc_key,
        bool want_truncated,
        hive::Subscription sub) {

    auto conn = pool_.get();
    pqxx::work tx{conn};

    // One statement, so that concurrent subscribes for the same device cannot both find no row and
    // then collide on the unique constraint.  xmax is 0 only in a row this statement inserted.
    auto [id, new_sub] = tx.query1<int64_t, bool>(
            R"(
INSERT INTO subscriptions
    (account, session_ed25519, subaccount_tag, subaccount_sig, signature, signature_ts, want_data, want_truncated, enc_key, service, svcid, svcdata)
VALUES ($1,   $2,              $3,             $4,             $5,        $6,           $7,        $8,             $9,      $10,     $11,   $12)
ON CONFLICT (account, service, svcid) DO UPDATE
SET session_ed25519 = EXCLUDED.session_ed25519, subaccount_tag = EXCLUDED.subaccount_tag,
    subaccount_sig = EXCLUDED.subaccount_sig, signature = EXCLUDED.signature,
    signature_ts = EXCLUDED.signature_ts, want_data = EXCLUDED.want_data,
    want_truncated = EXCLUDED.want_truncated, enc_key = EXCLUDED.enc_key, svcdata = EXCLUDED.svcdata
RETURNING id, xmax = 0
            )",
            {pubkey.id,
             pubkey.session_ed ? std::optional{pubkey.ed25519} : std::nullopt,
             sub.subaccount ? std::optional{sub.subaccount->tag} : std::nullopt,
             sub.subaccount ? std::optional{sub.subaccount->sig} : std::nullopt,
             sub.sig,
             sub.sig_ts.time_since_epoch().count(),
             sub.want_data,
             want_truncated,
             enc_key,
             service,
             service_id,
             service_data});
    log::trace(cat, "{} subscription for {}", new_sub ? "inserted" : "updated", pubkey.id.hex());

    bool insert_ns = new_sub;
    if (!new_sub) {
        // A separate statement, and so a fresh snapshot: the upsert holds the row's lock, which any
        // other writer of its namespaces must take first, so this is current until we commit.
        auto [ns_arr] = tx.query1<pqxx::array<int16_t>>(
                "SELECT ARRAY(SELECT namespace FROM sub_namespaces WHERE subscription = $1 ORDER "
                "BY namespace)",
                {id});
        insert_ns = !std::equal(
                ns_arr.cbegin(), ns_arr.cend(), sub.namespaces.cbegin(), sub.namespaces.cend());
        if (insert_ns)
            tx.exec("DELETE FROM sub_namespaces WHERE subscription = $1", {id}).no_rows();
    }

    if (insert_ns)
        for (auto n : sub.namespaces)
            tx.exec(R"(INSERT INTO sub_namespaces (subscription, namespace) VALUES ($1, $2))",
                    {id, n})
                    .no_rows();

    for (const auto& s : {""s, service})
        increment_stat(tx, s, new_sub ? "subscription" : "sub_renew", 1);

    tx.commit();
    if (new_sub)
        count_subscription_rows(service, 1);

    sub_jq_.call_soon([this, new_sub, pubkey = std::move(pubkey), sub = std::move(sub)]() mutable {
        auto [it, inserted] = subscribers_.try_emplace(std::move(pubkey));
        const auto& account = it->first;
        // Before the first swarm list the account stays unplaced, and reassign_swarms() places it
        // along with every other.
        if (inserted && account.update_swarm(swarm_ids_))
            swarms_[account.swarm].insert(account);

        auto& subscriptions = it->second;
        bool found_existing = false, changed = false;
        for (auto& existing : subscriptions) {
            if (existing.is_same(sub)) {
                if (sub.is_newer(existing)) {
                    existing.sig = sub.sig;
                    existing.sig_ts = sub.sig_ts;
                    changed = true;
                }
                found_existing = true;
                break;
            }
        }
        if (!found_existing) {
            subscriptions.push_back(std::move(sub));
            subscription_count_++;
            changed = true;
        }

        // A new device's subscription, or a new or newly signed one, is placed afresh at once, as
        // is any for an account with nothing scheduled (its subscriptions had lapsed, or were not
        // loaded for being about to); a repeat of one already held goes with the account's next
        // scheduled renewal.
        if ((new_sub || changed || account.next_due == SwarmPubkey::UNSCHEDULED) &&
            account.swarm != INVALID_SWARM_ID) {
            replace(account);
            schedule(account, system_clock::now() + resubscribe_delay());
        }
    });

    return new_sub;
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
    if (result.affected_rows() > 0)
        count_subscription_rows(service, -static_cast<int64_t>(result.affected_rows()));

    // We don't remove the subscription from internal data structures: other devices
    // (with the exact subcription) may be still using it, and so we may still want
    // the notifications; but as long as the row is removed (above) we won't be
    // sending notifications to the device anymore.
    return result.affected_rows() > 0;
}

}  // namespace spns
