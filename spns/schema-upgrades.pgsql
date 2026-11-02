
ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS subaccount_tag BYTEA;
ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS subaccount_sig BYTEA;
ALTER TABLE subscriptions DROP COLUMN IF EXISTS subkey_tag;

-- A device holds one subscription per slot: 0 with data, 1 without (subscription_slot in
-- hivemind.hpp).  The old key allowed one row per device, so no device gets two in a slot.
DO $$
BEGIN
    IF NOT EXISTS(
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'subscriptions' AND column_name = 'slot'
    ) THEN
        ALTER TABLE subscriptions ADD COLUMN slot SMALLINT NOT NULL DEFAULT 0 CHECK(slot >= 0);
        UPDATE subscriptions SET slot = 1 WHERE NOT want_data;
    END IF;
END
$$;

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
