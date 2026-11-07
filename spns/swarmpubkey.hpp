#pragma once

#include <chrono>
#include <cstdint>
#include <limits>
#include <vector>

#include "bytes.hpp"

namespace spns {

inline constexpr uint64_t INVALID_SWARM_ID = std::numeric_limits<uint64_t>::max();

// The most nodes a swarm can hold placements for: one bit each in an account's masks.  Storage
// server swarms are far smaller.
inline constexpr int SWARM_SLOTS = 16;

// The swarm of `swarm_ids` (sorted) that stores an account at `swarm_space`, or INVALID_SWARM_ID
// if there are none.
uint64_t closest_swarm(uint64_t swarm_space, const std::vector<uint64_t>& swarm_ids);

struct SwarmPubkey {
    AccountID id;
    Ed25519PK ed25519;
    bool session_ed = false;  // True if the ed25519 is different from the account id (i.e. for
                              // Session X25519 pubkey accounts).
    // Which nodes of its swarm, one bit per node's slot (see HiveMind::Swarm), have been sent a
    // subscription for the account not yet answered, and which hold one they acknowledged.  A
    // node claims the account while either of its bits is set.
    mutable uint16_t sent = 0, acked = 0;
    static_assert(SWARM_SLOTS == 16);
    // Why a node last gave the account up, for the status report's accounts on no node: it refused
    // every entry for good, or the request failed and the account waits out the node's backoff to
    // be placed again.  Cleared when the account is placed.
    enum class Unplaced : uint8_t { none, rejected, retrying };
    mutable Unplaced unplaced = Unplaced::none;
    // When a node last acknowledged a subscription for the account (unix seconds; 0 for never):
    // what is saved of its renewals, for a restarted hivemind to know how long its monitors last.
    mutable uint32_t acked_at = 0;
    // The slots whose claims were restored from saved state and whose nodes have yet to confirm
    // them by resuming their monitor sessions.  The renewal restored with them stands while any is
    // left, or once one is confirmed (clearing the rest); an account losing the last of them
    // unconfirmed is renewed as if placed when it lost it.
    mutable uint16_t restored = 0;
    uint64_t swarm_space;
    mutable uint64_t swarm;

    // When the account is next due to be (re)subscribed on its swarm (see HiveMind::schedule_), or
    // UNSCHEDULED if it is not scheduled at all.
    static constexpr auto UNSCHEDULED = std::chrono::system_clock::time_point::max();
    mutable std::chrono::system_clock::time_point next_due = UNSCHEDULED;

    bool operator==(const SwarmPubkey& other) const { return id == other.id; }
    bool operator!=(const SwarmPubkey& other) const = default;

    SwarmPubkey(AccountID account_id, std::optional<Ed25519PK> ed, bool _skip_validation = false);

    bool update_swarm(const std::vector<uint64_t>& swarm_ids) const;
};

}  // namespace spns

namespace std {

template <>
struct hash<spns::SwarmPubkey> {
    size_t operator()(const spns::SwarmPubkey& x) const {
        // A random chunk of the inside of the pubkey is already a good hash without
        // needing to otherwise hash the byte string
        static_assert(
                alignof(spns::SwarmPubkey) >= alignof(size_t) &&
                offsetof(spns::SwarmPubkey, id) % sizeof(size_t) == 0);
        return *reinterpret_cast<const size_t*>(x.id.data() + 16);
    }
};

}  // namespace std
