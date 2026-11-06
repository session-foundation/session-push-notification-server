#pragma once

#include <oxenmq/address.h>

#include <chrono>
#include <optional>
#include <oxen/quic/address.hpp>
#include <string>
#include <unordered_set>

#include "bytes.hpp"

namespace spns {

using namespace std::literals;

struct Config {
    oxenmq::address oxend_rpc;

    std::string pg_connect = "postgresql:///spns";

    // Local listening admin socket
    std::string hivemind_sock = "ipc://./hivemind.sock";
    // Optional curve-enabled listening socket
    std::optional<std::string> hivemind_curve;
    // list of x25519 client pubkeys who shall be treated as admins on the hivemind_curve socket
    std::unordered_set<X25519PK> hivemind_curve_admin;

    // The main hivemind omq listening keypair.  Must be set explicitly.
    X25519PK omq_pubkey;
    X25519SK omq_privkey;

    // Listening address(es) for QUIC
    std::vector<oxen::quic::Address> quic_listen;

    // The Ed25519 keypair to use for QUIC connections.  This is the 64-byte libsodium secret key
    // value (i.e. the 32 byte seed followed by 32 byte pubkey).
    std::optional<Ed25519Secret> quic_keys;

    std::chrono::seconds filter_lifetime = 10min;

    // How long after startup we wait for notifier services to register themselves with us before we
    // connect to the network and start processing user requests.
    std::chrono::milliseconds notifier_wait = 10s;

    // If non-empty then we stop waiting (i.e. before `notifier_wait`) for new notifiers once we
    // have a registered notifier for all of the services in this set.
    std::unordered_set<std::string> notifiers_expected;

    // How many of its swarm's nodes each account is subscribed on, at most the swarm's size: -1
    // for all of them, or a positive number.  Each node delivers every notification for the
    // accounts it holds, so fewer nodes per account means fewer subscriptions to make and renew,
    // and fewer duplicate notifications, at the cost of the account's notifications waiting on
    // fewer nodes' connections.
    int redundancy = -1;

    // How long after a placement an account is placed afresh, if not the hivemind's 45-55 minutes;
    // each renewal is drawn within a tenth either side of it.  For testing, to see renewals
    // within a test's run: it must stay well below the 65 minutes a storage server keeps a
    // monitor.
    std::optional<std::chrono::seconds> renewal_interval;

    // The most monitor requests in flight at once, across all nodes, if not the hivemind's default
    // (MONITOR_REQUESTS_IN_FLIGHT).
    std::optional<int> monitor_requests;

    // How long a monitor request may go unanswered, if not the hivemind's default
    // (MONITOR_TIMEOUT).
    std::optional<std::chrono::milliseconds> monitor_timeout;

    // Maximum connections we will attempt to establish simultaneously (we can have more, we just
    // won't try to open more than this at once until some succeed or fail).  You can set this to 0
    // for a "dry run" mode where no connections at all will be made.
    int max_pending_connects = 500;
};

}  // namespace spns
