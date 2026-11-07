-- With want_data, whether a message over the body limit is sent cut to it, rather than as its size
-- alone.  Idempotent, as databases made before migrations were recorded may have it already.
ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS want_truncated BOOLEAN NOT NULL DEFAULT FALSE;
