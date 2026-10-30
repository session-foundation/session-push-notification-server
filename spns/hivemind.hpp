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
#include <shared_mutex>
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

// Maximum pushes held per service for a notifier that is not taking them (its oxenmq queue is
// full, or its connection is gone); beyond this the service's new pushes are dropped.
inline constexpr size_t PUSH_RETRY_MAX = 50_k;

// At most this many of a service's waiting pushes are resent per processing pass.
inline constexpr size_t PUSH_RETRY_BATCH = 500;

// The wait between resends starts at the minimum, doubles up to the maximum while they make no
// headway, and returns to the minimum once the notifier drains.
inline constexpr std::chrono::milliseconds PUSH_RETRY_MIN_WAIT = 10ms;
inline constexpr std::chrono::milliseconds PUSH_RETRY_MAX_WAIT = 1s;

// A notifier whose connection failed has this long to register again before its waiting pushes
// are dropped and it is treated as any unregistered service.  While waiting, its queue is
// rechecked at this interval.
inline constexpr auto NOTIFIER_GONE_LIMIT = 5min;
inline constexpr auto NOTIFIER_GONE_RECHECK = 1s;

// Parameters for our request to get service node data:
inline constexpr auto _get_sns_params = R"({
  "active_only": true,
  "fields": {
    "pubkey_ed25519": true,
    "public_ip": true,
    "storage_lmq_port": true,
    "swarm_id": true,
    "block_hash": true,
    "height": true
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
    // Message notifications waiting for process_notifications().  The loop thread only appends
    // here: a notification is parsed, looked up and sent on the processing thread, so that the
    // loop keeps reading from every service node however long that takes.
    std::mutex notify_mutex_;
    std::condition_variable notify_cv_;
    std::vector<quic::message> notify_queue_;
    size_t notify_queue_bytes_ = 0;
    std::atomic<int64_t> notifications_dropped_{0};
    bool notify_quit_ = false;

    // Pushes waiting for their notifier, per service: those oxenmq had no room for in the
    // notifier's queue (it drops a message rather than wait), and those for a notifier whose
    // connection went away, until it registers again.  process_notifications() resends them to
    // whichever connection the service is on by then, and sends a service's new pushes after them,
    // so one slow notifier holds up only its own pushes.  Guarded by notify_mutex_.
    struct PushRetry {
        std::deque<std::string> pushes;
        // Doubles while resends make no headway, so a notifier that stops reading costs little.
        std::chrono::milliseconds wait = PUSH_RETRY_MIN_WAIT;
        steady_time next{};
        size_t last_size = 0;
        // Dropped for exceeding the per-service limit, since last logged.
        int64_t dropped = 0;
    };
    std::unordered_map<std::string, PushRetry> push_retry_;
    void send_push(const std::string& service, oxenmq::ConnectionID conn, std::string_view push);
    void queue_retry(const std::string& service, std::string push);

    // OxenMQ server for internal communications, proxied subscriptions, etc.  Held in an optional
    // so that the destructor can tear it down first: its worker threads run request handlers and
    // send_push()'s failure callback, which touch members declared after it.
    std::optional<oxenmq::OxenMQ> omq_impl_;
    oxenmq::OxenMQ& omq_ = *omq_impl_;

    // QUIC endpoint used to connect to service nodes (for receiving pushes)
    quic::Loop loop_;
    std::shared_ptr<quic::TLSCreds> creds_out_, creds_in_;
    std::list<std::shared_ptr<quic::Endpoint>> quic_in_;
    std::shared_ptr<quic::Endpoint> quic_out_;  // Might be set to one of the elements of quic_in_
                                                // if there is a suitable one for outbound use.

    PGConnPool pool_;

    std::thread notify_proc_thread_;
    std::atomic<int64_t> pushes_processed_{0};

    // Everything needed to send a push to one subscribed device.
    struct PushTarget {
        std::string service;
        std::string svcid;
        std::vector<std::byte> svcdata;  // Empty if the notifier gave none
        EncKey enc_key;
        bool want_data;
        std::vector<int16_t> namespaces;  // Sorted
        int64_t sig_ts;
    };

    // {account: [PushTarget...]}: an in-memory copy of the subscriptions table, so that a
    // notification is a lookup here rather than a database query.  Every write to that table
    // updates this once committed.
    std::unordered_map<AccountID, std::vector<PushTarget>> push_targets_;
    std::shared_mutex push_targets_mutex_;
    void set_push_target(const AccountID& account, PushTarget target);
    // A subscriptions row a writer deleted.
    struct DroppedTarget {
        AccountID account;
        std::string service;
        std::string svcid;
        int64_t sig_ts;
    };
    // Leaves a target renewed since its row was deleted: the renewal can commit and reach
    // set_push_target() before the deleting writer gets here.
    void drop_push_targets(const std::vector<DroppedTarget>& dropped);

    // edpk -> SNode
    std::unordered_map<Ed25519PK, std::shared_ptr<hive::SNode>> sns_;
    // swarmid -> {SNode...}
    std::unordered_map<uint64_t, std::unordered_set<std::shared_ptr<hive::SNode>>> swarms_;

    // Sorted list of all swarm ids
    std::vector<uint64_t> swarm_ids_;

    // {swarmpubkey: [Subscription...]} -- all subscriptions, per account (less dupes)
    std::unordered_map<SwarmPubkey, std::vector<hive::Subscription>> subscribers_;

    // last block hash & height
    std::pair<std::string, int64_t> last_block_{"", -1};

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
    // Services whose connection failed, and since when: their pushes wait in push_retry_ for the
    // notifier to register again.
    std::unordered_map<std::string, steady_time> services_gone_;
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
    void on_reg_service(oxenmq::Message& m);

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
    void refresh_sns();

    void on_sns_response(std::vector<std::string> data);

    // Re-checks all SN subscriptions for and new subscriptions or needed resubscriptions; must be
    // called on the loop_ thread.
    void check_subs();

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

    // Accesses the quic loop governing SNode connections (and various internals)
    quic::Loop& loop() { return loop_; }

    // Returns the creds object for establishing outbound connections.  TODO: This isn't needed once
    // all nodes are running an updated libquic, but older libquic doesn't allow no-creds
    // connections.
    const std::shared_ptr<quic::TLSCreds>& creds_out() { return creds_out_; }

    // Internal helper called by SNode with itself to dispatch a call back into itself with a
    // reference to the HiveMind's master subscriber container.
    void check_my_subs(hive::SNode& snode);

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
    /// - sub -- the subscription to add
    bool add_subscription(
            SwarmPubkey pubkey,
            std::string service,
            std::string service_id,
            std::optional<std::string> service_data,
            EncKey enc_key,
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
};

extern template void HiveMind::on_sub_unsub_impl(oxenmq::Message& m, bool subscribe);
extern template void HiveMind::on_sub_unsub_impl(quic::message& m, bool subscribe);

}  // namespace spns
