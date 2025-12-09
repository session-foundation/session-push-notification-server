#include "snode.hpp"

#include <fmt/chrono.h>
#include <oxenc/bt_producer.h>

#include <algorithm>
#include <cassert>
#include <chrono>
#include <iterator>
#include <memory>
#include <oxen/log.hpp>
#include <oxen/quic/address.hpp>
#include <oxen/quic/format.hpp>
#include <oxen/quic/opt.hpp>
#include <random>
#include <string>

#include "../bytes.hpp"
#include "../hivemind.hpp"
#include "subscription.hpp"

namespace spns::hive {

namespace log = oxen::log;

static auto cat = log::Cat("snode");

using namespace std::literals;

thread_local std::mt19937_64 rng{std::random_device{}()};

SNode::SNode(HiveMind& hivemind, quic::RemoteAddress addr, uint64_t swarm) :
        hivemind_{hivemind},
        addr_{std::move(addr)},
        swarm_{swarm}

{
    connect();
}

void SNode::connect() {
    assert(hivemind_.loop().inside());
    if (conn_)
        return;
    if (cooldown_until_) {
        if (*cooldown_until_ > std::chrono::steady_clock::now())
            return;
        cooldown_until_.reset();
    }
    if (!hivemind_.allow_connect())
        return;

    conn_ = hivemind_.quic().connect(
            addr_,
            hivemind_.creds(),
            [this](quic::Connection& c) { on_connected(c); },
            [this](quic::Connection& c, uint64_t ec) { on_disconnected(c, ec); },
            quic::opt::keep_alive{10s});
    stream_ = conn_->open_stream<quic::BTRequestStream>();
    stream_->register_handler("notify", [this](quic::message msg) { on_notify(std::move(msg)); });

    log::debug(
            cat, "Initiated connection to {} @ {}", oxenc::to_hex(addr_.view_remote_key()), addr_);
}

void SNode::connect(quic::RemoteAddress addr) {
    assert(hivemind_.loop().inside());
    if (addr != addr_) {
        log::debug(cat, "disconnecting; addr changing from {} to {}", addr_, addr);
        disconnect();
        addr_ = std::move(addr);
    }

    connect();
}

void SNode::disconnect() {
    assert(hivemind_.loop().inside());
    connected_ = false;
    if (conn_) {
        log::debug(cat, "disconnecting from {}", addr_);
        stream_.reset();
        conn_->close_connection();
        conn_.reset();
    }
}

void SNode::on_connected(quic::Connection& c) {
    assert(hivemind_.loop().inside());
    bool no_conn = false;
    log::debug(cat, "Connection established to {}", addr_);
    cooldown_fails_ = 0;
    cooldown_until_.reset();

    if (!conn_) {
        // Our conn got replaced from under us, which probably means we are disconnecting, so do
        // nothing.
        no_conn = true;
    } else {
        // We either just connected or reconnected, so reset any re-subscription times (so that
        // after a reconnection we force a re-subscription for everyone):
        auto now = system_clock::now();
        for (auto& [id, next] : next_)
            next = system_epoch;

        connected_ = true;
    }

    hivemind_.finished_connect();

    if (!no_conn)
        hivemind_.check_my_subs(*this);
}

void SNode::on_disconnected(quic::Connection& c, uint64_t ec) {
    assert(hivemind_.loop().inside());
    bool is_failed_connect = !connected_.exchange(false);

    if (hivemind_.has_quic()) {
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

    if (hivemind_.has_quic() && is_failed_connect)
        hivemind_.finished_connect();
}

/// Adds a new account to be signed up for subscriptions, if it is not already subscribed.
/// The new account's subscription will be submitted to the SS the next time check_subs() is
/// called (either automatically or manually).
///
/// If `force_now` is True then the account is scheduled for subscription at the next update
/// even if already exists.
void SNode::add_account(const SwarmPubkey& account, bool force_now) {
    // This isn't *always* called from directly inside: we also call it in multithreaded batch jobs
    // where we *have* blocked the loop, but do work in threads (and don't touch different SNodes
    // from different worker threads).
    // assert(hivemind_.loop().inside());

    auto [it, inserted] = subs_.insert(account);
    if (inserted)
        next_.emplace_front(*it, system_epoch);
    else if (force_now) {
        // We're asked to treat it as "now", so go look for it in the queue and clear it first,
        // then re-insert at the beginning of the queue.
        for (auto& [acc, next] : next_) {
            if (acc && *acc == account) {
                acc.reset();  // lazy deletion; we'll skip this when draining the queue
                break;
            }
        }
        next_.emplace_front(account, system_epoch);
    }
}

void SNode::reset_swarm(uint64_t new_swarm) {
    assert(hivemind_.loop().inside());

    next_.clear();
    subs_.clear();
    swarm_ = new_swarm;
}

void SNode::remove_stale_swarm_members(const std::vector<uint64_t>& swarm_ids) {
    // We *aren't* actually directly inside the loop when this is called: we are called from a
    // multithreaded batch job where the loop is blocked pending completion of the jobs.
    // assert(hivemind_.loop().inside());

    for (auto& s : subs_)
        s.update_swarm(swarm_ids);
    for (auto& [acc, next] : next_) {
        if (acc && acc->swarm != swarm_) {
            subs_.erase(*acc);
            acc.reset();
        }
    }
}

void SNode::check_subs(
        const std::unordered_map<SwarmPubkey, std::vector<hive::Subscription>>& all_subs) {
    assert(hivemind_.loop().inside());
    // log::trace(cat, "check subs");
    if (!connected_) {
        if (conn_)
            return;  // We're already trying to connect

        // If we failed recently we'll be in cooldown mode for a while, so might not connect
        // right away yet.
        if (cooldown_until_) {
            if (*cooldown_until_ > steady_clock::now())
                return;
            cooldown_until_.reset();
        }

        // We'll get called automatically as soon as the connection gets established, so just
        // make sure we are already connecting and don't do anything else for now.
        connect();
        return;
    }

    auto now = system_clock::now();
    auto req = std::make_optional<oxenc::bt_list_producer>();

    size_t subreq_count = 0, next_added = 0, req_count = 0;

    bool rate_limited = false;

    auto submit_req = [&req, &subreq_count, &rate_limited, this] {
        stream_->command(
                "monitor",
                std::move(*req).str(),
                /*timeout=*/60s,
                [this, expected_count = subreq_count, rate_limited](quic::message response) {
                    if (!response) {
                        log::warning(
                                cat,
                                "Subscriptions request of {} subscriptions to {} failed: {}",
                                expected_count,
                                addr_,
                                response.timed_out ? "timeout"sv : response.body());
                        return;
                    }

                    try {
                        oxenc::bt_list_consumer results{response.body()};
                        int good = 0, bad = 0;
                        while (!results.is_finished()) {
                            auto r = results.consume_dict_consumer();
                            if (r.skip_until("error")) {
                                bad++;
                                log::warning(
                                        cat, "Subscription failure: {}", r.consume_string_view());
                            } else if (r.skip_until("success"))
                                good++;
                        }
                        if (bad || good != expected_count)
                            log::warning(
                                    cat,
                                    "Subscriptions request for {} subscriptions to {} returned {} "
                                    "success, {} failures",
                                    expected_count,
                                    addr_,
                                    good,
                                    bad);
                        else
                            log::debug(
                                    cat,
                                    "Successful subscription request to {} for {} subscriptions",
                                    addr_,
                                    good);

                    } catch (const std::exception& e) {
                        log::warning(
                                cat,
                                "Failed to parse 'monitor' response from {}: {}",
                                addr_,
                                e.what());
                    }

                    // If our previous iteration we stopped because we hit the limit (rather than
                    // because we had nothing more to send) then check again to queue more
                    // immediately:
                    if (rate_limited)
                        hivemind_.loop().call_soon([this] { hivemind_.check_my_subs(*this); });
                });
        // There's currently no exposed way to clear the internal string in a bt producer, so just
        // reset it.  In theory if this is allocation bottlenecked we could revisit this to reuse an
        // external, fixed buffer, but for now just reset it.
        req.emplace();
        subreq_count = 0;
    };

    auto sig_min = now - hive::Subscription::SIGNATURE_EXPIRY + 10s;
    auto sig_max = now + hive::Subscription::SIGNATURE_EARLY;

    while (!next_.empty()) {
        const auto& [maybe_acct, next] = next_.front();
        if (next > now)
            break;

        if (!maybe_acct) {
            next_.pop_front();
            continue;  // lazy deletion; ignore this entry
        }

        const auto& acct = *maybe_acct;

        auto subs = all_subs.find(acct);
        if (subs == all_subs.end()) {
            next_.pop_front();
            continue;
        }

        for (const auto& sub : subs->second) {
            if (sub.sig_ts < sig_min || sub.sig_ts > sig_max)
                continue;

            auto dict = req->append_dict();

            // keys in ascii-sorted order!
            if (acct.session_ed)
                dict.append("P", acct.ed25519.sv());
            if (sub.subaccount) {
                dict.append("S", sub.subaccount->sig.sv());
                dict.append("T", sub.subaccount->tag.sv());
            }
            if (sub.want_data)
                dict.append("d", 1);
            dict.append_list("n").extend(sub.namespaces.cbegin(), sub.namespaces.cend());
            if (!acct.session_ed)
                dict.append("p", acct.id.sv());
            dict.append("s", sub.sig.sv());
            dict.append("t", sub.sig_ts.time_since_epoch().count());

            subreq_count++;
            req_count++;
        }

        auto delay = 1s * std::uniform_int_distribution<int>{
                                  RESUBSCRIBE_MIN.count(), RESUBSCRIBE_MAX.count()}(rng);

        next_.emplace_back(acct, now + delay);
        next_added++;
        next_.pop_front();

        if (subreq_count >= SUBS_REQUEST_LIMIT) {
            rate_limited = true;
            break;
        }
    }

    if (subreq_count)
        submit_req();

    // The randomness of our delay to the next re-subscription means that the tail of the list won't
    // be sorted, so re-sort from the lowest possible value we could have inserted (now +
    // RESUBSCRIBE_MIN) to the end.

    // Everything we didn't touch should already be sorted:
    assert(std::is_sorted(
            next_.begin(), std::prev(next_.end(), next_added), [](const auto& a, const auto& b) {
                return a.second < b.second;
            }));

    auto it = std::partition_point(
            next_.begin(),
            std::prev(next_.end(), next_added),
            [&now](const decltype(next_)::value_type& n) {
                return n.second < now + RESUBSCRIBE_MIN;
            });

    std::sort(it, next_.end(), [](const auto& a, const auto& b) { return a.second < b.second; });

    // Now everything should be sorted:
    assert(std::is_sorted(next_.begin(), next_.end(), [](const auto& a, const auto& b) {
        return a.second < b.second;
    }));

    log::log(
            cat,
            req_count ? log::Level::debug : log::Level::trace,
            "Submitted (re-)subscriptions to {} accounts on {}",
            req_count,
            addr_);
}

void SNode::on_notify(quic::message msg) {
    hivemind_.on_message_notification(std::move(msg));
}

}  // namespace spns::hive
