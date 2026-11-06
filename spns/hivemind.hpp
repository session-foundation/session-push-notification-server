#pragma once

//
// This contains the oxenmq "Hive Mind" process that establishes connections to all the network's
// service nodes, maintaining subscriptions with them for all the users that have enabled push
// notifications and processing incoming message notifications from those SNs.
//
// The hivemind instance runs in its own process and keeps open bidirection oxenmq connections with
// the notifiers (for proxying notifications) and uwsgi processes (for receiving client subscription
// updates).
//

#include <oxenmq/connections.h>
#include <oxenmq/message.h>
#include <oxenmq/oxenmq.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <list>
#include <memory>
#include <mutex>
#include <nlohmann/json_fwd.hpp>
#include <optional>
#include <oxen/quic/btstream.hpp>
#include <oxen/quic/crypto.hpp>
#include <oxen/quic/endpoint.hpp>
#include <oxen/quic/loop.hpp>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "bytes.hpp"
#include "config.hpp"
#include "hive/snode.hpp"
#include "hive/subscription.hpp"
#include "pg.hpp"
#include "swarmpubkey.hpp"
#include "utils.hpp"

namespace spns {

namespace quic = oxen::quic;

using namespace quic::literals;


// How long until we expire subscriptions (relative to the signature timestamp).  This can be no
// more than 14 days (because that's the subscription cutoff for storage server), but can also be
// less.
inline constexpr auto SIGNATURE_EXPIRY = 14 * 24h;

// How much we allow an unsubscribe signature timestamp to be off before we reject it
inline constexpr auto UNSUBSCRIBE_GRACE = 24h;

inline constexpr size_t MSG_HASH_MIN_SIZE = 32;
inline constexpr size_t MSG_HASH_MAX_SIZE = 99;
inline constexpr size_t SERVICE_NAME_MAX_SIZE = 32;
inline constexpr size_t SERVICE_ID_MIN_SIZE = 32;
inline constexpr size_t SERVICE_ID_MAX_SIZE = 999;
inline constexpr size_t SERVICE_DATA_MAX_SIZE = 99'999;
inline constexpr size_t MSG_DATA_MAX_SIZE = 75_ki;  // Storage server limit

// Maximum bytes of incoming message notifications waiting for the processing thread; beyond this
// they are dropped.  Bounds what waits while processing is held up, e.g. by a stalled notifier.
inline constexpr size_t NOTIFY_QUEUE_MAX_BYTES = 256_Mi;

// A batch of notifications looks up its accounts' subscriptions in queries of at most this many
// accounts each.  If the lookup fails, the batch is tried again after this long.
inline constexpr size_t SUBSCRIPTION_LOOKUP_BATCH = 1000;
inline constexpr auto NOTIFY_LOOKUP_RETRY = 1s;

// Maximum pushes held per service while its notifier cannot take them (the window below is full,
// or its connection is gone); beyond this the service's new pushes are dropped.
inline constexpr size_t PUSH_BACKLOG_MAX = 50_k;

// Push flow control.  Every PUSH_ACK_INTERVAL-th push to a service is followed by a notifier.ack
// request, which the notifier answers once it has taken everything queued before it, and pushes to
// the service stop while PUSH_WINDOW are unacknowledged.  The window plus two outstanding acks must
// fit the notifier's oxenmq queue for its category (200 by default; see register_notifier), and
// sits far below zmq's 1000-message send queue so that neither a push nor an ack is ever refused.
inline constexpr size_t PUSH_ACK_INTERVAL = 95;
inline constexpr size_t PUSH_WINDOW = 2 * PUSH_ACK_INTERVAL;

// How often a service whose window has filled is reported.
inline constexpr auto PUSH_BLOCKED_REPORT_INTERVAL = 30s;

// A notifier whose connection failed has this long to register again before its backlog is
// dropped and it is treated as any unregistered service.
inline constexpr auto NOTIFIER_GONE_LIMIT = 5min;

// The notifier registration protocol a notifier must speak to be registered (see
// register_notifier).
inline constexpr int NOTIFIER_PROTOCOL_VERSION = 1;

// An account restored from saved state is renewed at the latest this long before its monitors,
// last renewed when it was last acknowledged, would expire.
inline constexpr auto RESUME_MARGIN = 5min;

// How often the hivemind saves its placements and monitor session tokens (see Config::state_file).
inline constexpr auto DUMP_INTERVAL = 5min;

// How old saved state may be for a restart to resume from it.  A monitor lasts 65 minutes from its
// last renewal and renewals come every 45-55 minutes, so anything acknowledged in the 55 minutes
// before a save made this long ago is live for at least 10 minutes yet.
inline constexpr auto RESUME_MAX_AGE = 10min;

// oxend drops a block subscription that has not been renewed for 30 minutes.
inline constexpr auto OXEND_BLOCK_SUB_INTERVAL = 5min;

// Parameters for our request to get service node data:
inline constexpr auto _get_sns_params = R"({
  "active_only": true,
  "fields": {
    "pubkey_ed25519": true,
    "public_ip": true,
    "storage_lmq_port": true,
    "swarm_id": true,
    "block_hash": true,
    "height": true,
    "storage_server_version": true
  }
})";

// Thrown when startup is not ready; we catch it in ExcWrapper, below, and defer it to be called as
// soon as startup completes.
struct startup_request_defer {};

/// Callable object that wraps a HiveMind on_whatever method, invoking it inside an exception
/// handler that, upon uncaught exception, produces a log error and (if a json request endpoint)
/// replies with a generic error code.
class ExcWrapper {
  private:
    HiveMind& hivemind;
    std::variant<
            void (HiveMind::* const)(oxenmq::Message&),
            void (HiveMind::* const)(quic::message&)>
            meth;
    const std::string meth_name;

  public:
    ExcWrapper(
            HiveMind& hivemind, void (HiveMind::*meth)(oxenmq::Message&), std::string meth_name) :
            hivemind{hivemind}, meth{meth}, meth_name{std::move(meth_name)} {}

    ExcWrapper(HiveMind& hivemind, void (HiveMind::*meth)(quic::message&), std::string meth_name) :
            hivemind{hivemind}, meth{meth}, meth_name{std::move(meth_name)} {}

    void operator()(oxenmq::Message& m);
    void operator()(quic::message& m);
};

// If requests arrive during startup we copy the request here to defer calling until after
// startup completes.
struct DeferredRequest {
    std::variant<oxenmq::Message, quic::message> message;
    std::vector<std::string> data;
    ExcWrapper& callback;

    DeferredRequest(oxenmq::Message&& m, ExcWrapper& callback);
    DeferredRequest(quic::message&& m, ExcWrapper& callback);

    void operator()() && { std::visit(callback, message); }
};

class HiveMind {

  public:
    const Config config;

  private:
    // Message notifications waiting for process_notifications().  The QUIC loop only appends
    // here: a notification is parsed, looked up and sent on the processing thread, so that the
    // QUIC loop keeps reading from every service node however long that takes.
    std::mutex notify_mutex_;
    std::condition_variable notify_cv_;
    std::vector<quic::message> notify_queue_;
    size_t notify_queue_bytes_ = 0;
    std::atomic<int64_t> notifications_dropped_{0};
    bool notify_quit_ = false;

    // Per-service push flow control and backlog.  Guarded by notify_mutex_.
    struct ServicePushes {
        // The connection the counters refer to; on_register_notifier() resets them when it changes.
        oxenmq::ConnectionID conn;
        // Pushes sent on conn not yet covered by a notifier.ack reply.
        size_t unacked = 0;
        // Pushes waiting to be sent because the window is full or the notifier's connection is
        // gone.  Sent, in order, ahead of any new push for the service.
        std::deque<std::string> backlog;
        // Dropped for exceeding PUSH_BACKLOG_MAX, since last reported.
        int64_t dropped = 0;
        // Pushes sent, and dropped for exceeding PUSH_BACKLOG_MAX, since startup.
        int64_t sent = 0, dropped_total = 0;
        // Times the window filled since last reported, and since when it has been full.
        int64_t blocks = 0;
        std::optional<steady_time> blocked_since;
        steady_time next_report{};
    };
    std::unordered_map<std::string, ServicePushes> service_pushes_;
    // Set when a backlog may be sendable again: an ack arrived, or a notifier registered.
    bool drain_ = false;
    void send_push(
            const std::string& service, const oxenmq::ConnectionID& conn, std::string_view push);
    void request_ack(const std::string& service, const oxenmq::ConnectionID& conn);
    // Appends to the service's backlog, or drops it if the backlog is at PUSH_BACKLOG_MAX.
    void backlog_push(const std::string& service, std::string push);

    // OxenMQ server for internal communications, proxied subscriptions, etc.  Held in an optional
    // so that the destructor can tear it down first: its worker threads run request handlers and
    // send_push()'s failure callback, which touch members declared after it.
    std::optional<oxenmq::OxenMQ> omq_impl_;
    oxenmq::OxenMQ& omq_ = *omq_impl_;

    // QUIC endpoint used to connect to service nodes (for receiving pushes)
    quic::Loop loop_;
    // Everything the hivemind itself schedules on the QUIC loop goes through this queue rather
    // than loop_ directly, so that the destructor can stop it, dropping whatever is still queued,
    // before the members those jobs reference are destroyed.  loop_'s own queue only stops in
    // ~Loop.
    quic::JobQueue jq_{loop_};

    // The subscription thread: an event loop of its own, which owns everything about what is to
    // be subscribed where (the members from sns_ to last_block_ below, and each node's queue) and
    // encodes the monitor requests, so that the QUIC loop only does I/O.  A cold start encodes a
    // subscription per account per node, tens of millions of them, and on the QUIC loop that held
    // up every connection for minutes.  The hivemind schedules on it only through sub_jq_, for
    // the same reason as jq_.
    quic::Loop sub_loop_;
    quic::JobQueue sub_jq_{sub_loop_};

    std::shared_ptr<quic::TLSCreds> creds_out_, creds_in_;
    std::list<std::shared_ptr<quic::Endpoint>> quic_in_;
    std::shared_ptr<quic::Endpoint> quic_out_;  // Might be set to one of the elements of quic_in_
                                                // if there is a suitable one for outbound use.

    PGConnPool pool_;

    std::thread notify_proc_thread_;
    std::atomic<int64_t> pushes_processed_{0};

    // Counts since startup, for get_stats and the periodic status report: notifications from the
    // nodes, those left after de-duplication, the pushes they made, the batches they were looked
    // up in and the lookups that failed; connections established to nodes, and the bytes of the
    // messages they sent us.
    std::atomic<int64_t> notifications_received_{0}, notifications_unique_{0}, pushes_produced_{0},
            lookup_batches_{0}, lookup_failures_{0}, connections_established_{0},
            bytes_received_{0};
    // The bytes the nodes have acknowledged receiving from us, as sampled; QUIC loop (jq_) only.
    int64_t bytes_sent_ = 0;

    // The previous status report's stats, and when it was made.  (Behind a pointer only because
    // this header has nlohmann::json just declared.)
    std::unique_ptr<nlohmann::json> last_report_;
    steady_time last_report_time_{};

    // Every node, for make_conns(); QUIC loop (jq_) only.
    std::vector<std::shared_ptr<hive::SNode>> conns_;

    // Touched only from the subscription thread (sub_jq_), from here to last_block_:

    // edpk -> SNode
    std::unordered_map<Ed25519PK, std::shared_ptr<hive::SNode>> sns_;

    // A swarm: the accounts it stores (every key of subscribers_ placed in it), sorted by
    // swarm_space for the nodes' coverage scans; and its nodes, each in the slot whose bit it
    // owns in the accounts' sent and acked masks.
    struct Swarm {
        std::vector<const SwarmPubkey*> members;
        std::array<hive::SNode*, SWARM_SLOTS> slots{};
        int nodes = 0;
        // How many members are claimed by each number of nodes, so that a scan can skip a pass
        // with nothing to find, as every pass short of the last is when the swarm is covered.
        std::array<size_t, SWARM_SLOTS + 1> by_claims{};
        // Changed with every edit to the members, so that a scan can keep its place in them by
        // index between edits, and find it again by swarm_space after one.
        uint64_t generation = 0;

        // The account's place among the members, if it is one.
        std::vector<const SwarmPubkey*>::iterator find(const SwarmPubkey& account);
        void insert(const SwarmPubkey& account);
        void erase(const SwarmPubkey& account);
    };
    // swarmid -> the swarm, for every swarm with an account or a node.
    std::unordered_map<uint64_t, Swarm> swarms_;
    // How many nodes an account in `swarm` is to be subscribed on: the configured redundancy, or
    // every node of the swarm, and never more than the swarm has.
    int target(const Swarm& swarm) const {
        return config.redundancy > 0 ? std::min(config.redundancy, swarm.nodes) : swarm.nodes;
    }
    // The acknowledged nodes an account in `swarm` is reported covered on (see Coverage).
    int covered_threshold(const Swarm& swarm) const { return std::clamp(target(swarm), 1, 4); }

    // Sorted list of all swarm ids
    std::vector<uint64_t> swarm_ids_;

    // {swarmpubkey: [Subscription...]} -- all subscriptions, per account (less dupes).  Keys are
    // never erased, not even once an account has no subscription left: swarms_, schedule_ and the
    // nodes' due lists hold pointers to them.
    hive::Subscribers subscribers_;

    // When each account is next to be placed afresh on its swarm (see place()), as a min-heap on
    // the time (see schedule_later).  An entry is live only while its time equals the
    // account's next_due, so rescheduling an account is pushing a new entry, and an old one is
    // skipped when it comes off the heap.
    //
    // A deque would not do: renewals are due a random 45-55 minutes on, so appending them does not
    // keep it in order, and popping only from the front would hold each one back until everything
    // ahead of it was due too.
    std::vector<std::pair<const SwarmPubkey*, system_time>> schedule_;
    // The heap's ordering: the soonest entry at the front.
    static bool schedule_later(
            const std::pair<const SwarmPubkey*, system_time>& a,
            const std::pair<const SwarmPubkey*, system_time>& b) {
        return a.second > b.second;
    }
    void schedule(const SwarmPubkey& account, system_time when);
    // How long until an account placed now is next renewed: 45-55 minutes (see RESUBSCRIBE_MIN),
    // unless configured otherwise.
    std::chrono::seconds resubscribe_delay() const;

    // Checks a node's word that `account` is now stored by swarm `swarm_hex` (its swarm id in
    // hex) against swarms_, counting the agreements and disagreements for check_subs() to
    // report; a disagreement means our swarm list is stale, and gets it refreshed.
    void check_moved(std::string_view account, std::string_view swarm_hex);
    int64_t moved_agree_ = 0, moved_disagree_ = 0;

    // The token each node last issued us for resuming our monitor session with it.  Saved with the
    // placements (see save_state()), as resuming a session without its listing relies on both.
    std::unordered_map<Ed25519PK, MonitorToken> monitor_tokens_;

    // Writes the swarms' slot tables, every acknowledged placement with when its account was last
    // acknowledged, and the monitor session tokens to Config::state_file, replacing it whole.  The
    // snapshot is taken here; the file is written on a thread of its own, unless `wait`.
    void save_state(bool wait);
    std::thread state_writer_;
    std::atomic<bool> state_writing_ = false;
    // What the last save held, and how long it took: its snapshot here, and its write.
    struct {
        std::optional<steady_time> when;
        size_t bytes = 0, accounts = 0;
        double snapshot_ms = 0;
        std::atomic<double> write_ms = 0;
    } state_saved_;
    // Restores what Config::state_file holds, if it was saved within RESUME_MAX_AGE: the
    // placements on nodes still in the same swarm, the accounts' renewals, and those nodes'
    // tokens, for their sessions to be resumed without a listing.  Run once, with the first
    // service node list.
    void restore_state();
    bool restore_tried_ = false;
    struct {
        double age = -1;
        size_t accounts = 0, swarms = 0, slots = 0, slots_dropped = 0;
    } restored_;
    // Gives up the claims a node holds for its monitor session to be resumed, when it was not
    // resumed after all.
    void abandon_resume(hive::SNode& node);

    // How the nodes' connections have gone for monitor sessions since startup: not offered one for
    // their version; and for monitor_session requests, a new session, a resumed one, a node without
    // sessions (despite its version), or no answer; and for resumed ones, the accounts whose claims
    // stood, the monitors the node reported ended, and the notifications it discarded for overflow
    // while we were away.
    struct {
        int64_t old_version = 0, created = 0, resumed = 0, unsupported = 0, failed = 0;
        int64_t kept = 0, ended = 0, overflow = 0;
        // Missed notifications nodes discarded beyond Config::resume_replay, and the accounts they
        // were for.
        int64_t replay_discarded = 0, replay_discarded_accounts = 0;
    } monitor_session_stats_;

    // The dispatcher of monitor requests: the nodes waiting for one of the Config::monitor_requests
    // slots, in the order they asked, so that slots go round the nodes; and how many are taken.
    std::deque<std::shared_ptr<hive::SNode>> send_queue_;
    int requests_in_flight_ = 0;
    // Sends requests for the queued nodes while slots are free, unless held.  Not reentrant: a
    // node building its request queues nodes as it places accounts on them, and they are sent
    // once it is done.
    void dispatch_requests();
    bool dispatching_ = false;
    // Set while a new service node list is applied: until every node is in its new swarm, one
    // still in its old one would send that swarm's accounts to be refused.
    bool hold_dispatch_ = false;

    // Accounts' coverage, over the accounts with subscriptions to renew: how many there are, how
    // many are acknowledged on as many nodes as their swarm's target, and how many on none.
    //
    // Accounts on none are classed by why, the first that applies: no subscription with a signature
    // within its window, or none at all (unsendable, and not counted as on none); every entry
    // refused for good; waiting out a node's backoff after a failure; no connected node with a slot
    // in its swarm; sent to a node and not yet acknowledged; and anything else.  With `detail`,
    // up to 20 of them are described, one line each, the rarer classes first.
    //
    // What is reported as covered is acknowledged on at least the swarm's target number of nodes or
    // 4, whichever is fewer (covered_threshold()): beyond 4 nodes an account's coverage makes no
    // difference worth reporting, though placement still aims at the target.  Of the accounts on
    // some nodes but fewer, the under-covered, those acknowledged on every connected node of their
    // swarm are short only because the rest are down or have no slot; any others mean placement
    // is lagging.
    struct Coverage {
        size_t accounts = 0, covered = 0, under = 0, under_down_only = 0, at_zero = 0;
        size_t unsendable = 0, rejected = 0, retrying = 0, no_node = 0, claimed = 0, other = 0;
        // Accounts in the index with nothing scheduled (lapsed), which are not counted at all.
        size_t lapsed = 0;
        std::vector<std::string> described;
    };
    Coverage coverage(bool detail = false) const;
    // What a node said when it last gave up an account (Unplaced): the last refusal's text, or the
    // node and its backoff; until the account is placed again.
    std::unordered_map<const SwarmPubkey*, std::string> unplaced_detail_;
    // What log_coverage_progress() last reported, to report only changes.
    Coverage coverage_logged_;
    // While accounts are below their target, logs how many are at it; runs every few seconds.
    void log_coverage_progress();

    // Placements of an account on a node since startup: made by place(), and by nodes' scans; and
    // of place()'s, those that moved a monitor from one node to another.
    int64_t placements_ = 0, scan_placements_ = 0, moved_placements_ = 0;

    // Claims `account`, of `swarm`, for `node`, setting its sent bit.
    static void claim(const SwarmPubkey& account, Swarm& swarm, hive::SNode& node);
    // Clears the bits of the node in `slot` for `account`, if either is set, and its claim.
    static void release(const SwarmPubkey& account, Swarm& swarm, int slot);
    // Releases every claim on the account by a node of swarm `swarm` (its own, or the one it is
    // leaving).
    void release_all(const SwarmPubkey& account, uint64_t swarm);
    // Places `account` on its swarm's connected nodes, their monitor sessions settled, until it is
    // claimed on its target number: the lightest of those not claiming it, ties going first to a
    // node in `prev_acked` (its acked mask before a renewal cleared it, so that a balanced swarm
    // keeps its placements), then at random.  Each is queued with the dispatcher to send it.
    // `by_scan` counts the placements as a node's scan's.
    void place(const SwarmPubkey& account, uint16_t prev_acked = 0, bool by_scan = false);
    // Clears the account's placements and places it afresh.
    void replace(const SwarmPubkey& account);
    // Sets the node's scan going again, and queues it with the dispatcher.
    void wake(hive::SNode& node);
    // Wakes every node of the swarm but `except`: an account in it has fallen below its target, a
    // node has joined or left it, or its target has changed.
    void wake(Swarm& swarm, const hive::SNode* except = nullptr);
    // Gives the node a slot in its swarm, or leaves it without one if the swarm has none free.
    void join_swarm(hive::SNode& node);
    // Clears the node's slot across its swarm's accounts and frees it.
    void leave_swarm(hive::SNode& node);
    // Clears the node's bits across its swarm's accounts, keeping its slot.
    void clear_slot(Swarm& swarm, hive::SNode& node);

    // last block hash & height, and when the hash last changed
    std::pair<std::string, int64_t> last_block_{"", -1};
    steady_time last_block_time_{};

    // How many distinct subscriptions subscribers_ holds.
    size_t subscription_count_ = 0;

    // Monitor requests sent since startup, those answered and those that failed or timed out, and
    // the subscriptions in the answers refused for the wrong swarm or rejected; and the accounts
    // nodes reported moved to the swarm we place them in.
    struct {
        int64_t sent = 0, answered = 0, failed = 0, timed_out = 0, wrong_swarm = 0, rejected = 0;
    } monitor_stats_;
    int64_t moved_total_ = 0;

    std::atomic<int> pending_connects_ = 0;
    std::atomic<int> connect_count_ = 0;

    const std::chrono::system_clock::time_point startup_time = std::chrono::system_clock::now();

    // contains Blake2B(account || msghash) of the notifications already handled: every member of
    // the account's swarm sends us the same one, and only the first is looked up and pushed.
    // Every 10 minutes, we replace filter_rotate_ with filter_, and check both filters for
    // de-duping (so that hashes expire after 10-20 minutes).  (The 10 mins value is configurable).
    // Only used on the notification processing thread.
    std::unordered_set<Blake2B_32> filter_, filter_rotate_;
    steady_time filter_rotate_time_ = steady_clock::now() + config.filter_lifetime;

    // Registered push services: servicename => omq Connectionid to talk to the service
    std::unordered_map<std::string, oxenmq::ConnectionID> services_;
    // Services whose connection failed, and since when: their pushes wait in service_pushes_ for
    // the notifier to register again.
    std::unordered_map<std::string, steady_time> services_gone_;
    // service -> the service ids and subscriptions its notifier has dropped since startup.
    std::unordered_map<std::string, std::pair<int64_t, int64_t>> registrations_dropped_;
    std::mutex services_mutex_;
    void service_gone(const std::string& service, oxenmq::ConnectionID conn);

    // Our connection to a local oxend for block and SN info
    oxenmq::ConnectionID oxend_;

    // Will be set to true once we are ready to start taking requests
    std::atomic<bool> ready{false};

    void ready_or_defer() {
        if (!ready)
            throw startup_request_defer{};
    }
    void set_ready();

    bool notifier_startup_done(const steady_time& wait_until);

    friend class ExcWrapper;
    std::mutex deferred_mutex_;
    std::list<DeferredRequest> deferred_;
    void defer_request(oxenmq::Message&& m, ExcWrapper& callback);
    void defer_request(quic::message&& m, ExcWrapper& callback);

  public:
    HiveMind(Config conf_);

    ~HiveMind();

  private:
    void on_register_notifier(oxenmq::Message& m);
    void on_obsolete_register_service(oxenmq::Message& m);

    void process_notifications();

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
    void on_service_stats(oxenmq::Message& m);

    void get_stats_json(std::function<void(nlohmann::json)> when_ready);

    void on_get_stats(oxenmq::Message& m);

    std::chrono::steady_clock::time_point last_stats_logged = std::chrono::steady_clock::now() - 1h;
    void log_stats(std::string pre_cmd = "WATCHDOG=1"s);

    using UnsubData = std::tuple<Signature, std::optional<Subaccount>, int64_t>;
    void on_notifier_validation(
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
            const std::optional<UnsubData>& unsub = std::nullopt);

    void on_drop_registrations(oxenmq::Message& m);

    std::tuple<
            SwarmPubkey,
            std::optional<Subaccount>,
            int64_t,
            Signature,
            std::string,
            nlohmann::json>
    sub_unsub_args(nlohmann::json& args);

    oxenmq::ConnectionID sub_unsub_service_conn(const std::string& service);

    void on_quic_request(quic::message& m);
    void quic_subscribe(quic::message& m);
    void quic_unsubscribe(quic::message& m);
    ExcWrapper handle_quic_subscribe{*this, &HiveMind::quic_subscribe, "quic_subscribe"};
    ExcWrapper handle_quic_unsubscribe{*this, &HiveMind::quic_unsubscribe, "quic_unsubscribe"};

    void on_subscribe(oxenmq::Message& m);
    void on_unsubscribe(oxenmq::Message& m);
    template <typename Message>
    void on_sub_unsub_impl(Message& m, bool subscribe);

    void db_cleanup();

    void on_new_block(oxenmq::Message&) { refresh_sns(); }
    // Subscribes, or renews our subscription, to oxend's notify.block, which calls refresh_sns().
    void subscribe_blocks();
    void refresh_sns();

    // Called only from the subscription thread (sub_jq_), as is everything else below that
    // touches subscriptions or swarms.
    void on_sns_response(std::vector<std::string> data);

    // Moves every account whose swarm the new swarm_ids_ changes to its new swarm, releasing its
    // placements on the old one, and returns those moved, to be placed once the nodes' own swarms
    // are up to date.  An account placed for the first time is scheduled for renewal.
    std::vector<const SwarmPubkey*> reassign_swarms();

    // Places afresh every account whose renewal is due, reschedules it, and queues the nodes with
    // something to send.  Runs every 10s, and after changes to the network.
    void check_subs();

    // Starts connections to the nodes not connected (or cooling down after failing); QUIC loop
    // (jq_) only.
    void make_conns();

  public:
    /// Called when initiating a connection: if this returns a evaluates-as-true object then the
    /// connection can proceed; if it returns false then the connection should not.
    ///
    /// If this returns true then the caller must call `finished_connect` when done connecting
    /// (whether successful or not).
    bool allow_connect();
    void finished_connect();

    // Accesses the quic endpoint used to connect to SNodes
    quic::Endpoint& quic_out() { return *quic_out_; }

    bool has_quic_out() { return (bool)quic_out_; }

    // Schedules work on the QUIC loop governing SNode connections; see jq_.
    quic::JobQueue& jq() { return jq_; }

    // The subscription thread's queue; see sub_loop_.
    quic::JobQueue& sub_jq() { return sub_jq_; }

    // Returns the creds object for establishing outbound connections: our configured QUIC key,
    // which storage servers recognise as the privileged push server's.
    const std::shared_ptr<quic::TLSCreds>& creds_out() { return creds_out_; }

    // Called by an SNode once its connection numbered `gen` is established, to fill and send its
    // queue.
    void on_node_connected(hive::SNode& snode, int gen);

    // Called with an SNode that may have something to send: queues it for a request slot.
    void send_pending(hive::SNode& snode);

    // The next account for the node's request: the next of those placed on it that it still
    // claims.  With none left, the node's scan walks its swarm for accounts short of their target,
    // the least covered first, and places each on the lightest nodes (see place()), which may or
    // may not include this one, until one is.  Null once there is nothing, when the scan rests
    // until the node is woken.
    const SwarmPubkey* next_claim(hive::SNode& node);

    // Places each account again, after its node backed off from a failure.
    void place_again(const std::vector<const SwarmPubkey*>& accounts);

    // Called by an SNode for an account it has acknowledged a subscription for; and for one whose
    // claim it gives up, refused, failed, or with nothing to send.
    void subscribed(hive::SNode& node, const SwarmPubkey& account);
    void unclaim(hive::SNode& node, const SwarmPubkey& account);
    // Called by an SNode for an account whose every entry it refused for good, `error` being the
    // last refusal's text; and for accounts it is to place again after `backoff`, following a
    // failure.
    void refused(hive::SNode& node, const SwarmPubkey& account, std::string error);
    void retrying(
            hive::SNode& node,
            const std::vector<const SwarmPubkey*>& accounts,
            std::chrono::milliseconds backoff);

    // Called by an SNode whose connection is gone: its claims go with it, and the accounts it held
    // become the other nodes' to cover.
    void drop_claims(hive::SNode& node);

    // Called by an SNode when a request of its ends, freeing its slot.
    void request_finished();

    // Called by an SNode with the answer to its monitor_session request: a session, resumed or new,
    // with its token, the list of its monitors (when resumed) and its count of notifications lost
    // to overflow; or no session, because the node does not support them, or did not answer.
    void monitor_session_started(
            hive::SNode& snode,
            const MonitorToken& token,
            bool resumed,
            std::string_view monitors,
            int64_t overflow);
    void monitor_session_unsupported(hive::SNode& snode);
    void monitor_session_failed(hive::SNode& snode);

    // Called by an SNode with a monitor request's outcome: answered, or else timed out or failed;
    // and for an answer, its subscriptions refused for the wrong swarm and rejected.
    void count_monitor_reply(bool answered, bool timed_out, size_t wrong_swarm, size_t rejected) {
        auto& m = monitor_stats_;
        (answered ? m.answered : timed_out ? m.timed_out : m.failed)++;
        m.wrong_swarm += wrong_swarm;
        m.rejected += rejected;
    }

    // Called by an SNode with what a monitor_session answer said was discarded beyond the replay
    // budget: notifications, and the accounts they were for.
    void count_replay_discarded(int64_t discarded, int64_t accounts) {
        monitor_session_stats_.replay_discarded += discarded;
        monitor_session_stats_.replay_discarded_accounts += accounts;
    }

    // Called by an SNode, on the QUIC loop, for each connection it establishes and each message
    // it receives.
    void count_connection() { connections_established_++; }
    void count_received(size_t bytes) { bytes_received_ += bytes; }

    void load_saved_subscriptions();

    /// Add or updates a subscription for monitoring.  If the given pubkey is already monitored by
    /// the same device then this replaces the existing subscription details with this one,
    /// otherwise it adds a new subscription.
    ///
    /// Will throw if the given data or signatures are incorrect.
    ///
    /// Returns true if the subscription was brand new, false if the subscription
    /// updated/renewed an existing subscription.
    ///
    /// Parameters:
    ///
    /// - pubkey -- the account to monitor
    /// - service -- the subscription service name, e.g. 'apns', 'firebase'.  When
    /// messages are
    ///   received the notification will be forwarded to the given service, if active.
    /// - service_id -- an identifier string that identifies the device/application/etc.
    /// This must
    ///   be unique for a given service and pubkey (if all three match, an existing
    ///   subscription will be replaced).
    /// - service_data -- service data; this will be passed as-is to the service handler
    ///   and contains any extra data (beyond just the service_id) needed for the
    ///   service handler to send the notification to the device.
    /// - enc_key this user's 32-byte encryption key for pushed notifications
    /// - want_truncated -- whether a message over the body limit is pushed as its first part,
    ///   rather than as its size alone, if the subscription wants data
    /// - sub -- the subscription to add
    bool add_subscription(
            SwarmPubkey pubkey,
            std::string service,
            std::string service_id,
            std::optional<std::string> service_data,
            EncKey enc_key,
            bool want_truncated,
            hive::Subscription sub);

    /// Removes a subscription for monitoring.  Returns true if the given pubkey was
    /// found and removed; false if not found.
    ///
    /// Will throw if the given data or signatures are incorrect.
    ///
    /// Parameters:
    ///
    /// - pubkey -- the account
    /// - subaccount -- if using subaccount authentication then this is the 36-byte subaccount tag.
    /// - subaccount_sig -- if `subaccount` is given then this must be given and contains the
    ///   account owner's signature of `subaccount` authorizing it.
    /// - service -- the subscription service name, e.g. 'apns', 'firebase'.
    /// - service_id -- an identifier string that identifies the device/application/etc.  This is
    ///   unique for a given service and pubkey and is generated/extracted by the notification
    ///   service.
    /// - sig_ts -- the integer unix timestamp when the signature was generated; must be within ±24h
    /// - signature -- the Ed25519 signature of: UNSUBSCRIBE || PUBKEY_HEX || sig_ts; this is signed
    ///   by pubkey, unless using subaccounts in which case it's signed by the subaccount ed25519
    ///   key contained in `subaccount`.
    bool remove_subscription(
            const SwarmPubkey& pubkey,
            const std::optional<Subaccount>& subaccount,
            std::string service,
            std::string service_id,
            const Signature& sig,
            int64_t sig_ts);

    // Called from SNode when we get a message notification
    void on_message_notification(quic::message m);

    // Called from SNode when a node has ended a subscription because the account is no longer
    // stored by its swarm.
    void on_monitor_ended(hive::SNode& node, quic::message m);
};

extern template void HiveMind::on_sub_unsub_impl(oxenmq::Message& m, bool subscribe);
extern template void HiveMind::on_sub_unsub_impl(quic::message& m, bool subscribe);

}  // namespace spns
