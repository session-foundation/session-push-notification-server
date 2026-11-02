
ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS subaccount_tag BYTEA;
ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS subaccount_sig BYTEA;
ALTER TABLE subscriptions DROP COLUMN IF EXISTS subkey_tag;

-- A device can hold one subscription per slot.  Existing rows are slot 0.
ALTER TABLE subscriptions
    ADD COLUMN IF NOT EXISTS slot SMALLINT NOT NULL DEFAULT 0 CHECK(slot >= 0);

-- A database may have the (account, service, svcid, want_data) key, under which a device could hold
-- one row with data and one without; both are slot 0 now, so keep the one with data.
DO $$
BEGIN
    IF to_regclass('subscriptions_account_service_svcid_want_data_key') IS NOT NULL THEN
        DELETE FROM subscriptions s USING subscriptions o
        WHERE o.account = s.account AND o.service = s.service AND o.svcid = s.svcid
            AND (o.want_data, o.id) > (s.want_data, s.id);
    END IF;
END
$$;
ALTER TABLE subscriptions
    DROP CONSTRAINT IF EXISTS subscriptions_account_service_svcid_want_data_key;
DROP INDEX IF EXISTS subscriptions_account_service_svcid_want_data_key;

-- The same constraint, under the same name, as schema.pgsql's UNIQUE, so this does nothing on a
-- database created from it.
DO $$
BEGIN
    IF NOT EXISTS(
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'subscriptions'::regclass
            AND conname = 'subscriptions_account_service_svcid_slot_key'
    ) THEN
        ALTER TABLE subscriptions ADD CONSTRAINT subscriptions_account_service_svcid_slot_key
            UNIQUE(account, service, svcid, slot);
    END IF;
END
$$;
ALTER TABLE subscriptions DROP CONSTRAINT IF EXISTS subscriptions_account_service_svcid_key;

-- vim:ft=sql
