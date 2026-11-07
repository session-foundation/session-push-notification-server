#pragma once

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <iterator>
#include <memory>
#include <mutex>
#include <optional>
#include <oxen/quic/btstream.hpp>
#include <oxen/quic/connection.hpp>
#include <oxen/quic/connection_ids.hpp>
#include <oxen/quic/endpoint.hpp>
#include <string_view>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "subscription.hpp"

namespace spns {
class HiveMind;
}

namespace spns::hive {

namespace quic = oxen::quic;

using namespace std::literals;

// Maximum number of subscriptions in a single monitor request to a single SN; if we have more than
// this then we send this many and wait for the response before sending more.  Requests go through
// the hivemind's cap on those in flight (Config::monitor_requests), so a bigger one gains
// nothing, while a small one (some 85 kB) stays well inside the timeout and shares the uplink
// evenly.
inline constexpr size_t SUBS_REQUEST_LIMIT = 500;

// The first storage server version with monitor sessions (oxen-storage-server 2.13.0, the release
// after 2.12.1 that brings the monitor protocol additions).  Only a node reporting at least this in
// its uptime proof is asked for one; an older one, or one whose version oxend does not know, is
// filled in full straight away.
inline constexpr std::array<uint16_t, 3> MONITOR_SESSION_MIN_VERSION = {2, 13, 0};

// How long a monitor_session request may take to be answered; without an answer the connection
// goes on without a monitor session.
inline constexpr auto MONITOR_SESSION_TIMEOUT = 30s;

// A failed or timed out monitor request, and the entries of one that a node could not take for now,
// are queued again after this long, doubling with each consecutive failure up to the maximum.
inline constexpr auto RETRY_BACKOFF_MIN = 2s;
inline constexpr auto RETRY_BACKOFF_MAX = 30s;

// The storage server's per-subscription monitor error codes that are retried, with the node's
// backoff, as are entries the response leaves unanswered: an account the node does not store, and
// its not knowing the swarms at all.  Either is the node's (or its oxend's) view of the swarms
// disagreeing with ours, typically by its being a few seconds behind after a swarm change, and goes
// on being retried as long as the disagreement lasts.  The other codes reject the subscription
// itself, which would only be rejected again, and are dropped.
inline constexpr int MONITOR_WRONG_SWARM = 6;
inline constexpr int MONITOR_NO_SWARM_INFO = 7;

// How long (in seconds) after a successful subscription before we re-subscribe; each subscription
// gets a uniform random value between these two values (to spread out the renewal requests a bit).
inline constexpr std::chrono::seconds RESUBSCRIBE_MIN = 45min;
inline constexpr std::chrono::seconds RESUBSCRIBE_MAX = 55min;

// How long a storage server keeps a monitor after its last renewal.
inline constexpr auto MONITOR_LIFETIME = 65min;

// How long we wait (in seconds) after a failed connection attempt to a snode storage server before
// re-trying the connection; we use the first value after the first failure, the second one after
// the second failure, and so on (if we run off the end we use the last value).
inline constexpr std::array CONNECT_COOLDOWN = {10s, 30s, 60s, 120s};

// How long are a disconnection from a SNode until we attempt to reconnect.  If the reconnection
// fails then we enter the cooldown, above.
inline constexpr auto RECONNECT_WAIT = 1s;

// The hivemind's subscriptions, per account; see HiveMind::subscribers_.
using Subscribers = std::unordered_map<SwarmPubkey, std::vector<Subscription>>;

class SNode : public std::enable_shared_from_this<SNode> {
    // Class managing a connection to a single service node, and what is to be subscribed on it.
    //
    // Two threads share it, each owning its own members: the hivemind's QUIC loop (jq_) owns the
    // connection, and its subscription thread (sub_jq_) owns what is to be sent on it.  Each hands
    // the other work through the other's job queue.

    HiveMind& hivemind_;

    // The hivemind's two queues: the QUIC loop's, and the subscription thread's.
    quic::JobQueue& jq_;
    quic::JobQueue& sub_jq_;

    using system_clock = std::chrono::system_clock;
    using steady_clock = std::chrono::steady_clock;
    using system_time = system_clock::time_point;
    using steady_time = steady_clock::time_point;

    // Touched only from the QUIC loop (jq_), which owns the connection:
    std::shared_ptr<quic::Connection> conn_;
    // The connection attempt holding one of the hivemind's connect slots (see
    // HiveMind::allow_connect), until it is established, fails, or is dropped by disconnect().
    const quic::Connection* connecting_ = nullptr;
    quic::RemoteAddress addr_;
    std::shared_ptr<quic::BTRequestStream> stream_;
    std::optional<steady_time> cooldown_until_;
    int cooldown_fails_ = 0;
    // Incremented as each connection is lost, and handed to the subscription thread with each
    // connection's events, so that it can tell which connection one is about.
    int conn_gen_ = 0;
    // The connection whose stream take_sent_bytes() last sampled, and its acknowledged bytes then.
    int sampled_gen_ = 0;
    uint64_t sampled_acked_ = 0;

    // Read anywhere, written on the QUIC loop.
    std::atomic<bool> connected_ = false;

    // Touched only from the subscription thread (sub_jq_):
    // Whether the subscription thread knows the connection numbered gen_ to be up.
    bool up_ = false;
    int gen_ = 0;
    // Set while a monitor request awaits its reply, holding one of the hivemind's request slots.
    bool in_flight_ = false;
    // Set while a failed request's accounts wait out retry_backoff_ to be placed again; nothing is
    // sent meanwhile.  The backoff is zero after a request that succeeded.
    bool retry_wait_ = false;
    std::chrono::milliseconds retry_backoff_{0};
    // Set while monitor_session awaits its reply on a new connection: monitor requests wait for
    // it, as the node handles requests concurrently and makes a monitor it handles first
    // connection-bound, lost with the connection.
    bool handshake_ = false;
    // Set once monitor_session has answered on the current connection: the monitors sent on it
    // since are the session's, kept by the node when the connection goes.
    bool session_bound_ = false;

  public:
    // What the node's last answer to monitor_session showed of its support for monitor sessions.
    enum class MonitorSessions { unknown, supported, unsupported };

  private:
    MonitorSessions monitor_sessions_ = MonitorSessions::unknown;

  public:
    const Ed25519PK pubkey;

    // The node's swarm; subscription thread (sub_jq_) only.  HiveMind changes it, keeping its
    // swarms_ index in step.
    uint64_t swarm;

    // The storage server version oxend reports for the node, if any; subscription thread
    // (sub_jq_) only.
    std::optional<std::array<uint16_t, 3>> version;

    /// Whether the node's reported version is one with monitor sessions.
    bool offers_monitor_sessions() const {
        return version && *version >= MONITOR_SESSION_MIN_VERSION;
    }

    // Does not connect: the QUIC loop does, by calling connect().
    SNode(HiveMind& hivemind, quic::RemoteAddress addr, uint64_t swarm);

    ~SNode() { disconnect(); }

    // --- Called only from the QUIC loop (jq_) ---

    /// Checks the given address against the current one: if different, it gets replaced, the
    /// current connection (if any) is disconnected, and then we initiate reconnection to the new
    /// address.
    ///
    /// Does nothing if already connected to the given address.
    void connect(quic::RemoteAddress addr);

    /// Initiates a connection, if not already connected or connecting, and not cooling down after
    /// failures, to the current address.
    void connect();

    void disconnect();

    /// Whether the node is waiting out a cooldown before it is connected to again.
    bool cooling_down() const { return cooldown_until_ && *cooldown_until_ > steady_clock::now(); }

    /// The bytes the node has acknowledged receiving from us since the last call; what was sent
    /// on a connection since lost after the last call is not counted.
    uint64_t take_sent_bytes();

    // --- Callable from any thread ---

    bool connected() const { return connected_; }

    // --- Called only from the subscription thread (sub_jq_) ---

    /// Whether the subscription thread has been told of the node's connection, and not of its
    /// loss.
    bool up() const { return up_; }

    /// Whether the node is up and its monitor session settled: until a resumed session's answer
    /// has recorded what the node still holds, anything placed on it might be sent again.
    bool settled() const { return up_ && !handshake_; }

    /// The node's part in its swarm's placements, kept by the hivemind: its slot (its bit in the
    /// swarm's accounts' sent and acked masks), or -1 for none; how many of the swarm's accounts
    /// it claims, always the number with its bit set in either mask; the accounts placed on it,
    /// to send before anything its scan finds; and its coverage scan (see HiveMind::next_claim).
    int slot = -1;
    size_t claimed = 0;
    /// Of those claims, the ones on accounts leaving it (SwarmPubkey::leaving), which no longer
    /// count to its load when accounts are placed.
    size_t leaving = 0;
    /// Set while the node's claims are held for its monitor session to be resumed, restored from
    /// saved state after a restart or kept across a lost connection: they stand until the
    /// session's resumption confirms or refutes them.
    bool resuming = false;
    /// Set while the claims it holds were restored from saved state and its monitor session has
    /// yet to confirm or refute them (see HiveMind::settle_restored).
    bool restored = false;
    std::deque<const SwarmPubkey*> due;
    struct {
        // The swarm_space the scan has reached, so that changes to the swarm's members leave its
        // place alone, and that place's index among them while their generation is unchanged; the
        // claim count it is looking for, and how far round the swarm it has gone looking for it;
        // and whether it has found nothing at any count, when it rests until the hivemind wakes it.
        uint64_t cursor = 0;
        size_t index = 0;
        uint64_t generation = UINT64_MAX;
        int pass = 0;
        size_t walked = 0;
        bool done = true;
    } scan;

    MonitorSessions monitor_sessions() const { return monitor_sessions_; }

    /// Whether the current connection's monitors are on a monitor session, which outlives it.
    bool session_bound() const { return session_bound_; }

    /// Asks the node, on a connection just up, for a monitor session: to resume the one `token`
    /// names, if given, or else a new one.  A resumed session's answer lists only the monitors that
    /// have ended, as the hivemind knows the rest.  Nothing is sent until it answers, after which
    /// the hivemind settles what the session holds and sets the node scanning.
    void start_monitor_session(const std::optional<MonitorToken>& token);

    /// Whether the node may have accounts to send and can send a request for them: it has some
    /// placed on it or its scan has more to look at, it is up, its monitor session settled, and it
    /// is neither awaiting a reply nor backing off after a failure.
    bool ready_to_send() const {
        return up_ && !handshake_ && !in_flight_ && !retry_wait_ && (!due.empty() || !scan.done);
    }

    /// If ready_to_send(), encodes a monitor request of up to SUBS_REQUEST_LIMIT subscriptions for
    /// the accounts `next` gives, each claimed for this node, for the QUIC loop to send, and
    /// returns true; false if `next` gives none.  Called only by the hivemind's dispatcher, which
    /// counts the request as in flight until the node calls its request_finished().  Takes the
    /// hivemind's subscriptions to find each account's in.
    bool send_next(const Subscribers& subs, const std::function<const SwarmPubkey*()>& next);

    /// Whether the node is in the hivemind's dispatch queue, waiting for a request slot.
    bool queued = false;

    /// Updates the subscription thread's record of whether the node's connection is usable, from
    /// the QUIC loop's event that the connection with generation number `gen` is up, dropping the
    /// previous connection's work.  Returns false, changing nothing, if `gen` is already recorded
    /// as up, so that a duplicate event does not fill the node twice.
    bool connection_up(int gen);

    /// Updates the subscription thread's record of whether the node's connection is usable, from
    /// the QUIC loop's event that the connection with generation number `gen` was lost, dropping
    /// its work.  Ignored unless `gen` is the generation currently recorded as up, so that a late
    /// loss event for a connection already replaced cannot knock out its successor.
    void connection_down(int gen);

  private:
    // --- Called only from the QUIC loop (jq_) ---
    void on_connected(quic::Connection& c);

    void on_disconnected(quic::Connection& c, uint64_t errcode);

    // Gives back the connect slot `c` holds, if it holds one.
    void finish_connecting(const quic::Connection* c);

    void on_notify(quic::message msg);

    // Lost the connection numbered conn_gen_: tells the subscription thread, and numbers the next.
    void lost_connection();

    // A reply handler for request(), called on the subscription thread, and only if the reply is
    // to a request on the connection still up.
    using ReplyHandler = std::function<void(SNode&, quic::message)>;

    void send_request(
            int gen,
            std::string endpoint,
            std::string body,
            std::chrono::milliseconds timeout,
            ReplyHandler on_reply);

    // --- Called only from the subscription thread (sub_jq_) ---

    // Has the QUIC loop send a request on the connection up, if it still is when it gets there.
    void request(
            std::string endpoint,
            std::string body,
            std::chrono::milliseconds timeout,
            ReplyHandler on_reply);

    void on_monitor_session_response(quic::message response);

    // `entries` holds the account of each subscription in the request, in order: an account
    // with several subscriptions has several consecutive entries.  An account answered with
    // success is acknowledged on this node; one refused as not stored by the node's swarm, or for
    // its not knowing the swarms, or left unanswered, loses its claim here and is placed again
    // after the backoff (see MONITOR_WRONG_SWARM); one refused otherwise loses its claim.
    void on_monitor_response(std::vector<const SwarmPubkey*> entries, quic::message response);

    // Clears in_flight_, if set, giving its request slot back to the hivemind.
    void finish_request();

    // Drops what belonged to the connection that is gone: its claims on its swarm's accounts, as a
    // new connection's monitors start from nothing, and the request awaiting a reply, which never
    // comes, so its slot goes back to the in-flight cap; and with them the retry, handshake and
    // session state.
    void drop_connection_work();

    // Has the hivemind place `accounts` again once the backoff has passed.
    void retry_later(std::vector<const SwarmPubkey*> accounts);
};

}  // namespace spns::hive
