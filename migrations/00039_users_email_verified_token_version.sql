-- +goose Up
-- +goose StatementBegin
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS token_version  INTEGER NOT NULL DEFAULT 1;

-- Migrate is_deleted boolean → deleted_at timestamptz (column added in 00020).
-- Wrapped in a DO block so this is idempotent: databases that already ran the
-- original 00021 (which dropped is_deleted) skip the UPDATE and DROP safely.
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
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_deleted BOOLEAN NOT NULL DEFAULT false;
UPDATE users SET is_deleted = true WHERE deleted_at IS NOT NULL;

ALTER TABLE users
    DROP COLUMN IF EXISTS email_verified,
    DROP COLUMN IF EXISTS token_version;
-- +goose StatementEnd
