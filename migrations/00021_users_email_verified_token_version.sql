-- +goose Up
-- +goose StatementBegin
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS token_version  INTEGER NOT NULL DEFAULT 1;

-- Migrate is_deleted boolean → deleted_at timestamptz (column added in 00020).
-- Existing soft-deleted rows get a deletion timestamp so nothing is lost.
UPDATE users SET deleted_at = NOW() WHERE is_deleted = true AND deleted_at IS NULL;

ALTER TABLE users DROP COLUMN IF EXISTS is_deleted;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_deleted BOOLEAN NOT NULL DEFAULT false;
UPDATE users SET is_deleted = true WHERE deleted_at IS NOT NULL;

ALTER TABLE users
    DROP COLUMN IF EXISTS email_verified,
    DROP COLUMN IF EXISTS token_version;
-- +goose StatementEnd
