-- The hivemind's saved placements (see full_schema.sql).  Idempotent, as databases made before
-- migrations were recorded may have them already.

CREATE TABLE IF NOT EXISTS placement_state (
    saved_at BIGINT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS placement_state_single_row ON placement_state ((true));

CREATE TABLE IF NOT EXISTS monitor_sessions (
    snode BYTEA PRIMARY KEY,
    token BYTEA NOT NULL
);

CREATE TABLE IF NOT EXISTS swarm_slots (
    swarm BIGINT NOT NULL,
    slot SMALLINT NOT NULL,
    snode BYTEA NOT NULL,

    PRIMARY KEY(swarm, slot)
);

CREATE TABLE IF NOT EXISTS placements (
    account BYTEA PRIMARY KEY,
    acked SMALLINT NOT NULL,
    acked_at BIGINT NOT NULL
);
