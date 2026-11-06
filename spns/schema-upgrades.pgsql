
ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS subaccount_tag BYTEA;
ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS subaccount_sig BYTEA;
ALTER TABLE subscriptions DROP COLUMN IF EXISTS subkey_tag;
ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS want_truncated BOOLEAN NOT NULL DEFAULT FALSE;

-- vim:ft=sql
