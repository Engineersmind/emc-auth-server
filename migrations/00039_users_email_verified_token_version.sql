-- +goose Up
-- +goose StatementBegin
-- Merge-safety migration: adds email_verified and token_version columns if they
-- do not already exist. On databases that applied 00021 on this branch those
-- columns are already present and every statement here is a no-op.
--
-- This migration exists because 00021 on master uses a different number slot
-- (00021_create_saml_configs.sql). Any master-based database that already has
-- goose version 21 applied will skip 00021_users_email_verified_token_version.sql;
-- this file (version 39) ensures the columns are added on those databases.
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS token_version  INTEGER NOT NULL DEFAULT 1;

-- Remove is_deleted if it still exists (may have been dropped by 00021 already).
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'users' AND column_name = 'is_deleted'
    ) THEN
        UPDATE users SET deleted_at = NOW() WHERE is_deleted = true AND deleted_at IS NULL;
        ALTER TABLE users DROP COLUMN is_deleted;
    END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Only drop if 00021 is not also managing these columns (i.e., on master-based DBs).
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'users' AND column_name = 'is_deleted'
    ) THEN
        ALTER TABLE users ADD COLUMN IF NOT EXISTS is_deleted BOOLEAN NOT NULL DEFAULT false;
        UPDATE users SET is_deleted = true WHERE deleted_at IS NOT NULL;
    END IF;
END $$;

ALTER TABLE users
    DROP COLUMN IF EXISTS email_verified,
    DROP COLUMN IF EXISTS token_version;
-- +goose StatementEnd
