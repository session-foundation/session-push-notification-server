#include "snode.hpp"

#include <fmt/chrono.h>
#include <fmt/ranges.h>
#include <oxenc/bt_producer.h>
#include <oxenc/bt_serialize.h>

#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstring>
#include <iterator>
#include <memory>
#include <oxen/log.hpp>
#include <oxen/quic/address.hpp>
#include <oxen/quic/format.hpp>
#include <oxen/quic/opt.hpp>
#include <string>

#include "../bytes.hpp"
#include "../hivemind.hpp"
#include "subscription.hpp"

namespace spns::hive {

namespace log = oxen::log;

static auto cat = log::Cat("snode");

using namespace std::literals;

static Ed25519PK remote_pubkey(const quic::RemoteAddress& addr) {
    Ed25519PK pk;
    auto key = addr.view_remote_key();
    assert(key.size() == pk.size());
    std::memcpy(pk.data(), key.data(), pk.size());
    return pk;
}

SNode::SNode(HiveMind& hivemind, quic::RemoteAddress addr, uint64_t swarm) :
        hivemind_{hivemind},
        jq_{hivemind.jq()},
        sub_jq_{hivemind.sub_jq()},
        addr_{std::move(addr)},
        pubkey{remote_pubkey(addr_)},
        swarm{swarm} {}

void SNode::connect() {
    assert(jq_.inside());
    if (conn_)
        return;
    if (cooldown_until_) {
        if (*cooldown_until_ > std::chrono::steady_clock::now())
            return;
        cooldown_until_.reset();
    }
    if (!hivemind_.allow_connect())
        return;

    conn_ = hivemind_.quic_out().connect(
            addr_,
            hivemind_.creds_out(),
            [this](quic::Connection& c) { on_connected(c); },
            [this](quic::Connection& c, uint64_t ec) { on_disconnected(c, ec); },
            quic::opt::keep_alive{10s});
    connecting_ = conn_.get();
    stream_ = conn_->open_stream<quic::BTRequestStream>();
    stream_->register_handler("notify", [this](quic::message msg) { on_notify(std::move(msg)); });
    stream_->register_handler("monitor_ended", [this](quic::message msg) {
        if (auto self = weak_from_this().lock())
            sub_jq_.call_soon([this,
                               self = std::move(self),
                               gen = conn_gen_,
                               msg = std::move(msg)]() mutable {
                // From a connection since lost, whose claims have gone with it.
                if (up_ && gen == gen_)
                    hivemind_.on_monitor_ended(*this, std::move(msg));
            });
    });

    log::debug(
            cat, "Initiated connection to {} @ {}", oxenc::to_hex(addr_.view_remote_key()), addr_);
}

void SNode::connect(quic::RemoteAddress addr) {
    assert(jq_.inside());
    if (addr != addr_) {
        log::debug(cat, "disconnecting; addr changing from {} to {}", addr_, addr);
        disconnect();
        addr_ = std::move(addr);
    }

    connect();
}

void SNode::lost_connection() {
    // weak_from_this() cannot lock while the destructor is running, and by then the subscription
    // thread has already dropped the node.
    if (auto self = weak_from_this().lock())
        sub_jq_.call_soon(
                [this, self = std::move(self), gen = conn_gen_] { connection_down(gen); });
    conn_gen_++;
}

void SNode::disconnect() {
    assert(jq_.inside());
    connected_ = false;
    if (conn_) {
        log::debug(cat, "disconnecting from {}", addr_);
        // Its callbacks, which come later, are for a connection no longer ours, and ignored.
        finish_connecting(conn_.get());
        stream_.reset();
        // Cleared first, so that a close callback fired from inside close_connection() does not
        // count the loss a second time.
        auto conn = std::move(conn_);
        lost_connection();
        conn->close_connection();
    }
}

void SNode::finish_connecting(const quic::Connection* c) {
    if (c && c == connecting_) {
        connecting_ = nullptr;
        hivemind_.finished_connect();
    }
}

void SNode::on_connected(quic::Connection& c) {
    assert(jq_.inside());
    // One we have dropped since (see disconnect()).
    if (&c != conn_.get())
        return;
    log::debug(cat, "Connection established to {}", addr_);
    cooldown_fails_ = 0;
    cooldown_until_.reset();
    connected_ = true;
    finish_connecting(&c);
    hivemind_.count_connection();
    sub_jq_.call_soon([this, self = shared_from_this(), gen = conn_gen_] {
        hivemind_.on_node_connected(*this, gen);
    });
}

void SNode::on_disconnected(quic::Connection& c, uint64_t ec) {
    assert(jq_.inside());
    // One we dropped (see disconnect()), and whose closing arrives after: a deliberate close, not a
    // failure, which must not touch a connection made since in its place.
    if (&c != conn_.get())
        return;
    bool is_failed_connect = !connected_.exchange(false);

    if (hivemind_.has_quic_out()) {
        // If we don't have a quic object that means we're shutting down and this is the callback
        // fired during shutdown, so don't do anything.
        if (is_failed_connect) {
            auto cooldown = cooldown_fails_ >= CONNECT_COOLDOWN.size()
                                  ? CONNECT_COOLDOWN.back()
                                  : CONNECT_COOLDOWN[cooldown_fails_];
            cooldown_until_ = steady_clock::now() + cooldown;
            cooldown_fails_++;

            log::warning(
                    cat,
                    "Connection to {} failed (ec={}).  {} consecutive failure(s); retrying in {}",
                    addr_,
                    ec,
                    cooldown_fails_,
                    cooldown);
        } else {
            log::warning(
                    cat,
                    "Disconnected from {} (ec={}); reconnecting in {}",
                    addr_,
                    ec,
                    RECONNECT_WAIT);
            cooldown_until_ = steady_clock::now() + RECONNECT_WAIT;
            cooldown_fails_ = 0;
        }
    }

    stream_.reset();
    conn_.reset();
    lost_connection();

    if (hivemind_.has_quic_out())
        finish_connecting(&c);
}

uint64_t SNode::take_sent_bytes() {
    assert(jq_.inside());
    if (sampled_gen_ != conn_gen_) {
        sampled_gen_ = conn_gen_;
        sampled_acked_ = 0;
    }
    uint64_t acked = stream_ ? stream_->acked_bytes() : sampled_acked_;
    auto sent = acked - sampled_acked_;
    sampled_acked_ = acked;
    return sent;
}

bool SNode::connection_up(int gen) {
    assert(sub_jq_.inside());
    if (up_ && gen == gen_)
        return false;
    up_ = true;
    gen_ = gen;
    drop_connection_work();
    return true;
}

void SNode::connection_down(int gen) {
    assert(sub_jq_.inside());
    if (!up_ || gen != gen_)
        return;
    up_ = false;
    drop_connection_work();
}

void SNode::drop_connection_work() {
    hivemind_.drop_claims(*this);
    finish_request();
    retry_wait_ = handshake_ = session_bound_ = false;
}

void SNode::finish_request() {
    if (in_flight_) {
        in_flight_ = false;
        hivemind_.request_finished();
    }
}

void SNode::request(
        std::string endpoint,
        std::string body,
        std::chrono::milliseconds timeout,
        ReplyHandler on_reply) {
    assert(sub_jq_.inside());
    jq_.call_soon([self = shared_from_this(),
                   gen = gen_,
                   endpoint = std::move(endpoint),
                   body = std::move(body),
                   timeout,
                   on_reply = std::move(on_reply)]() mutable {
        self->send_request(gen, std::move(endpoint), std::move(body), timeout, std::move(on_reply));
    });
}

void SNode::send_request(
        int gen,
        std::string endpoint,
        std::string body,
        std::chrono::milliseconds timeout,
        ReplyHandler on_reply) {
    assert(jq_.inside());
    if (gen != conn_gen_ || !stream_)
        return;  // That connection is gone, and the subscription thread is told so separately
    stream_->command(
            std::move(endpoint),
            body,
            timeout,
            [wself = weak_from_this(), gen, on_reply = std::move(on_reply)](
                    quic::message response) mutable {
                if (auto self = wself.lock()) {
                    self->hivemind_.count_received(response.body().size());
                    self->sub_jq_.call_soon([self = std::move(self),
                                             gen,
                                             on_reply = std::move(on_reply),
                                             response = std::move(response)]() mutable {
                        if (self->up_ && gen == self->gen_)
                            on_reply(*self, std::move(response));
                    });
                }
            });
}

void SNode::start_monitor_session(const std::optional<MonitorToken>& token) {
    assert(sub_jq_.inside());
    handshake_ = true;
    oxenc::bt_dict_producer req;
    // The body limit is the session's, so creation and every resume state it.  A node without
    // sessions cannot be limited: it sends whole bodies, which the hivemind cuts itself.
    req.append("b", hivemind_.config.monitor_body_limit);
    if (token)
        req.append("l", 0);
    req.append("m", hivemind_.config.resume_replay);
    if (token)
        req.append("t", token->sv());
    // On the stream the node's notifications arrive on, which is what puts its reply ahead of the
    // notifications it replays.
    request("monitor_session",
            std::move(req).str(),
            MONITOR_SESSION_TIMEOUT,
            [](SNode& self, quic::message response) {
                self.on_monitor_session_response(std::move(response));
            });
}

void SNode::on_monitor_session_response(quic::message response) {
    handshake_ = false;
    if (!response) {
        // A node without monitor sessions answers with libquic's unknown endpoint error.
        if (!response.timed_out && response.body().starts_with("Invalid endpoint")) {
            if (monitor_sessions_ != MonitorSessions::unsupported)
                log::warning(
                        cat,
                        "{} reports storage server version {} but does not support monitor "
                        "sessions",
                        pubkey,
                        fmt::join(*version, "."));
            monitor_sessions_ = MonitorSessions::unsupported;
            hivemind_.monitor_session_unsupported(*this);
        } else {
            log::warning(
                    cat,
                    "monitor_session request to {} failed ({}); subscribing without a monitor "
                    "session",
                    pubkey,
                    response.timed_out ? "timeout"sv : response.body());
            hivemind_.monitor_session_failed(*this);
        }
        return;
    }

    try {
        oxenc::bt_dict_consumer d{response.body()};
        // The accounts with more missed notifications than the request's budget, each with how
        // many it discarded in each namespace that had any.
        int64_t discarded = 0, discarded_accounts = 0;
        if (d.skip_until("m"))
            for (auto accounts = d.consume_dict_consumer(); !accounts.is_finished();) {
                for (auto [account, cut] = accounts.next_list_consumer(); !cut.is_finished();) {
                    auto e = cut.consume_dict_consumer();
                    e.require<int>("n");
                    discarded += e.require<int64_t>("o");
                }
                discarded_accounts++;
            }
        auto resumed = d.maybe<int>("r").value_or(0) != 0;
        auto monitors = "le"sv;
        if (d.skip_until("s"))
            monitors = d.consume_list_data();
        auto token_str = d.require<std::string_view>("t");
        MonitorToken token;
        if (token_str.size() != token.size())
            throw std::invalid_argument{"invalid token size {}"_format(token_str.size())};
        std::memcpy(token.data(), token_str.data(), token.size());

        monitor_sessions_ = MonitorSessions::supported;
        session_bound_ = true;
        hivemind_.count_replay_discarded(discarded, discarded_accounts);
        hivemind_.monitor_session_started(*this, token, resumed, monitors);
    } catch (const std::exception& e) {
        log::warning(
                cat,
                "Invalid monitor_session response from {} ({}); subscribing without a "
                "monitor session",
                pubkey,
                e.what());
        hivemind_.monitor_session_failed(*this);
    }
}

bool SNode::send_next(
        const Subscribers& all_subs, const std::function<const SwarmPubkey*()>& next) {
    assert(sub_jq_.inside());
    if (!ready_to_send())
        return false;

    auto now = system_clock::now();
    auto sig_min =
            now - hive::Subscription::SIGNATURE_EXPIRY + hive::Subscription::SIGNATURE_MARGIN;
    auto sig_max = now + hive::Subscription::SIGNATURE_EARLY;

    oxenc::bt_list_producer req;
    std::vector<const SwarmPubkey*> entries;
    size_t accounts = 0;
    while (entries.size() < SUBS_REQUEST_LIMIT) {
        const auto* acct = next();
        if (!acct)
            break;

        auto subs = all_subs.find(*acct);
        if (subs == all_subs.end()) {
            hivemind_.unclaim(*this, *acct);
            continue;
        }

        auto before = entries.size();
        bool not_yet_valid = false;
        for (const auto& sub : subs->second) {
            if (sub.sig_ts < sig_min || sub.sig_ts > sig_max) {
                not_yet_valid |= sub.sig_ts > sig_max;
                continue;
            }

            auto dict = req.append_dict();

            // keys in ascii-sorted order!
            if (acct->session_ed)
                dict.append("P", acct->ed25519.sv());
            if (sub.subaccount) {
                dict.append("S", sub.subaccount->sig.sv());
                dict.append("T", sub.subaccount->tag.sv());
            }
            if (sub.want_data)
                dict.append("d", 1);
            dict.append_list("n").extend(sub.namespaces.cbegin(), sub.namespaces.cend());
            if (!acct->session_ed)
                dict.append("p", acct->id.sv());
            dict.append("s", sub.sig.sv());
            dict.append("t", sub.sig_ts.time_since_epoch().count());

            entries.push_back(acct);
        }
        if (entries.size() != before)
            accounts++;
        else
            hivemind_.nothing_to_send(*this, *acct, not_yet_valid);
    }

    if (entries.empty())
        return false;

    in_flight_ = true;
    request("monitor",
            std::move(req).str(),
            hivemind_.config.monitor_timeout,
            [entries = std::move(entries)](SNode& self, quic::message response) mutable {
                self.on_monitor_response(std::move(entries), std::move(response));
            });

    log::debug(cat, "Submitted (re-)subscriptions of {} accounts to {}", accounts, pubkey);
    return true;
}

void SNode::on_monitor_response(std::vector<const SwarmPubkey*> entries, quic::message response) {
    assert(sub_jq_.inside());
    finish_request();

    // What became of each entry; anything the response does not answer (all of it, for a failed
    // request) is to be tried again.
    enum class Outcome : uint8_t { retry, success, rejected };
    std::vector<Outcome> outcome(entries.size(), Outcome::retry);

    size_t i = 0, good = 0, wrong_swarm = 0, rejected = 0, failed = 0;
    std::string first_rejection;
    // Each rejected entry's error text; sized only once one is rejected.
    std::vector<std::string> errors;
    if (!response) {
        log::warning(
                cat,
                "Subscriptions request of {} subscriptions to {} failed: {}",
                entries.size(),
                pubkey,
                response.timed_out ? "timeout"sv : response.body());
    } else {
        try {
            oxenc::bt_list_consumer results{response.body()};
            for (; i < entries.size() && !results.is_finished(); i++) {
                auto r = results.consume_dict_consumer();
                if (auto code = r.maybe<int>("errcode")) {
                    if (*code == MONITOR_WRONG_SWARM)
                        wrong_swarm++;
                    else if (*code == MONITOR_NO_SWARM_INFO)
                        failed++;
                    else {
                        outcome[i] = Outcome::rejected;
                        if (errors.empty())
                            errors.resize(entries.size());
                        errors[i] = r.maybe<std::string>("error").value_or("");
                        if (!rejected++)
                            first_rejection = errors[i];
                    }
                } else if (r.skip_until("success")) {
                    good++;
                    outcome[i] = Outcome::success;
                } else
                    failed++;
            }
        } catch (const std::exception& e) {
            log::warning(cat, "Failed to parse 'monitor' response from {}: {}", pubkey, e.what());
        }
    }
    failed += entries.size() - i;

    // An account's entries are consecutive.  It is placed again if any of them is to be retried,
    // acknowledged here if any succeeded, and otherwise refused for good.
    std::vector<const SwarmPubkey*> retry;
    for (size_t j = 0; j < entries.size();) {
        const auto* acct = entries[j];
        bool any_retry = false, any_success = false;
        size_t last = j;
        for (; j < entries.size() && entries[j] == acct; j++) {
            any_retry |= outcome[j] == Outcome::retry;
            any_success |= outcome[j] == Outcome::success;
            last = j;
        }
        if (any_retry) {
            hivemind_.unclaim(*this, *acct);
            retry.push_back(acct);
        } else if (any_success)
            hivemind_.subscribed(*this, *acct);
        else
            hivemind_.refused(*this, *acct, std::move(errors[last]));
    }

    hivemind_.count_monitor_reply(
            bool(response), response.timed_out, entries.size(), wrong_swarm, rejected);

    // Log the per-entry outcome of an answered request: a warning if any entry was rejected or
    // failed, and only a debug line if the sole non-successes were wrong-swarm refusals, which
    // are routine while accounts move between swarms.
    if (response && (wrong_swarm || rejected || failed))
        log::log(
                cat,
                rejected || failed ? log::Level::warn : log::Level::debug,
                "Subscriptions request of {} subscriptions to {}: {} succeeded, {} not stored by "
                "its swarm, {} rejected{}, {} failed",
                entries.size(),
                pubkey,
                good,
                wrong_swarm,
                rejected,
                rejected ? " ({})"_format(first_rejection) : "",
                failed);
    else if (response)
        log::debug(cat, "Successful subscription request to {} for {} subscriptions", pubkey, good);

    if (retry.empty()) {
        retry_backoff_ = 0ms;
        hivemind_.send_pending(*this);
    } else
        retry_later(std::move(retry));
}

void SNode::retry_later(std::vector<const SwarmPubkey*> accounts) {
    retry_backoff_ = retry_backoff_ == 0ms ? std::chrono::milliseconds{RETRY_BACKOFF_MIN}
                                           : std::min<std::chrono::milliseconds>(
                                                     2 * retry_backoff_, RETRY_BACKOFF_MAX);
    log::debug(
            cat,
            "Placing {} accounts again in {}, after their failure on {}",
            accounts.size(),
            retry_backoff_,
            pubkey);
    hivemind_.retrying(*this, accounts, retry_backoff_);
    retry_wait_ = true;
    sub_jq_.call_later(
            retry_backoff_, [wself = weak_from_this(), gen = gen_, accounts = std::move(accounts)] {
                auto self = wself.lock();
                if (!self || !self->up_ || gen != self->gen_)
                    return;
                self->retry_wait_ = false;
                self->hivemind_.place_again(accounts);
                self->hivemind_.send_pending(*self);
            });
}

void SNode::on_notify(quic::message msg) {
    hivemind_.count_received(msg.body().size());
    hivemind_.on_message_notification(std::move(msg));
}

}  // namespace spns::hive
