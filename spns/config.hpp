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
    // value (i.e. the 32 byte seed followed by 32 byte pubkey).  Must be set: it is presented on
    // every connection to a storage server, and its pubkey is what nodes recognise as the
    // privileged push server's, whose monitor sessions get the large limits and their own pool of
    // missed notifications (an unrecognised key gets a small anonymous session).
    Ed25519Secret quic_keys;

    std::chrono::seconds filter_lifetime = 10min;

    // How long after startup we wait for notifier services to register themselves with us before we
    // connect to the network and start processing user requests.
    std::chrono::milliseconds notifier_wait = 10s;

    // If non-empty then we stop waiting (i.e. before `notifier_wait`) for new notifiers once we
    // have a registered notifier for all of the services in this set.
    std::unordered_set<std::string> notifiers_expected;

    // The most bytes of a message body that reach a device, for subscriptions that want data.
    // Storage servers are asked to cut bodies to it for the whole of each monitor session; a node
    // without sessions cannot be, and sends the whole body, which the hivemind then cuts itself.
    // A bigger message is pushed as its first part, with its full size, to a subscription that
    // opted in to truncated bodies, and as its size alone to the rest.  2,500 bytes is the most a
    // body can be and still fit the push services' payload caps once it is encrypted, padded to a
    // multiple of 256 bytes, base64-encoded and wrapped in their JSON (Huawei rejects a payload
    // over 4,000 bytes; APNs and FCM, over 4,096), so a larger value makes the services reject the
    // notifications of bigger messages, and is only for testing.  Must be positive.
    int64_t monitor_body_limit = 2500;

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

    // Where the hivemind saves which nodes hold each account, and its monitor session tokens,
    // every few minutes and when it stops, for a restart soon after to resume its sessions without
    // having the nodes list every monitor.  Empty to save nothing, and start every node afresh.
    // After a crash, the tokens nodes rotated since the last save are lost, and those nodes start
    // afresh.
    std::string state_file;

    // The most notifications for an account a node keeps while our monitor session with it is
    // detached, and replays when it is resumed, after a reconnection or a quick restart: the
    // newest, the rest being lost, as push notifications are best effort.
    int resume_replay = 10;

    // The most monitor requests in flight at once, across all nodes.  Unthrottled, each node sends
    // its next request as soon as its last is answered, so a cold start puts one from every node
    // (some 2,000) on the uplink together, each crawling towards its timeout while it shares the
    // bandwidth with all the others.  Through a cap they go a few at a time at full speed: 64
    // requests of 500 subscriptions (hive::SUBS_REQUEST_LIMIT), some 5 MB in all, keep a fast
    // uplink busy while any one of them is answered quickly.  A node still has at most one in
    // flight.  Must be positive.
    int monitor_requests = 64;

    // How long a monitor request may go unanswered before it counts as failed.  libquic fails every
    // outstanding request on a stream as soon as the stream or its connection closes
    // (BTRequestStream::closed()), so a lost connection is noticed at once whatever this is: it
    // governs only a connection that stays open without answering.  Behind a saturated uplink a
    // request queued for a minute is slow, not failed, and failing it only puts its subscriptions
    // back on the backlog, so this is long enough to fire only for a node that is wedged.  A wedged
    // node holds one of the monitor_requests slots this long; its back-off after the failure keeps
    // it from taking another at once, and the cap is large enough that a few such nodes leave
    // plenty for the rest.  Must be positive.
    std::chrono::milliseconds monitor_timeout = 10min;

    // How often the multi-line status report is logged.  It goes out with the status tick, every
    // 2 seconds, so it must be at least that.
    std::chrono::seconds status_report_interval = 5min;

    // Maximum connections we will attempt to establish simultaneously (we can have more, we just
    // won't try to open more than this at once until some succeed or fail).  You can set this to 0
    // for a "dry run" mode where no connections at all will be made.
    int max_pending_connects = 500;
};

}  // namespace spns
