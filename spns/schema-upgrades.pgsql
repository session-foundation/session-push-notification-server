
ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS subaccount_tag BYTEA;
ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS subaccount_sig BYTEA;
ALTER TABLE subscriptions DROP COLUMN IF EXISTS subkey_tag;

-- A device can hold one subscription with message data and one without.  The index takes the name
-- schema.pgsql's UNIQUE constraint gets, so this does nothing on a database created from it.
CREATE UNIQUE INDEX IF NOT EXISTS subscriptions_account_service_svcid_want_data_key
    ON subscriptions(account, service, svcid, want_data);
ALTER TABLE subscriptions DROP CONSTRAINT IF EXISTS subscriptions_account_service_svcid_key;

-- vim:ft=sql
