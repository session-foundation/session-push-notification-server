
ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS subaccount_tag BYTEA;
ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS subaccount_sig BYTEA;
ALTER TABLE subscriptions DROP COLUMN IF EXISTS subkey_tag;
ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS want_truncated BOOLEAN NOT NULL DEFAULT FALSE;

-- The hivemind's placements of accounts on storage nodes, saved every 5 minutes and when it stops,
-- each save replacing the last whole: a hivemind started within 10 minutes of the save resumes its
-- monitor sessions with the nodes without having them list every monitor.  When the save was made
-- (unix seconds), in a single row:
CREATE TABLE IF NOT EXISTS placement_state (
    saved_at BIGINT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS placement_state_single_row ON placement_state ((true));

-- The token each storage node (by Ed25519 pubkey) last issued for resuming our monitor session:
CREATE TABLE IF NOT EXISTS monitor_sessions (
    snode BYTEA PRIMARY KEY,
    token BYTEA NOT NULL
);

-- Each swarm's nodes, in the slots whose bits they own in the placements' acked masks.  The swarm
-- id is unsigned 64-bit, stored by its bit pattern.
CREATE TABLE IF NOT EXISTS swarm_slots (
    swarm BIGINT NOT NULL,
    slot SMALLINT NOT NULL,
    snode BYTEA NOT NULL,

    PRIMARY KEY(swarm, slot)
);

-- Every account acknowledged on some node of its swarm: on which slots (a 16-bit mask, stored by
-- its bit pattern), and when it was last acknowledged (unix seconds).
CREATE TABLE IF NOT EXISTS placements (
    account BYTEA PRIMARY KEY,
    acked SMALLINT NOT NULL,
    acked_at BIGINT NOT NULL
);

-- vim:ft=sql
