
ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS subaccount_tag BYTEA;
ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS subaccount_sig BYTEA;
ALTER TABLE subscriptions DROP COLUMN IF EXISTS subkey_tag;
ALTER TABLE sub_namespaces ADD COLUMN IF NOT EXISTS want_data BOOLEAN NOT NULL DEFAULT TRUE;

-- vim:ft=sql
