-- +goose Up
-- +goose StatementBegin
ALTER TABLE api_keys
    ADD COLUMN IF NOT EXISTS key_prefix   TEXT        NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS last_used_ip INET,
    ADD COLUMN IF NOT EXISTS expires_at   TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW();

-- Backfill key_prefix for existing keys using the first 8 chars of key_hash as a stand-in.
-- New keys will have the real prefix (first 8 chars of the raw key) set at creation time.
UPDATE api_keys SET key_prefix = LEFT(key_hash, 8) WHERE key_prefix = '';

CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys (key_prefix);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_api_keys_prefix;
ALTER TABLE api_keys
    DROP COLUMN IF EXISTS key_prefix,
    DROP COLUMN IF EXISTS last_used_ip,
    DROP COLUMN IF EXISTS expires_at,
    DROP COLUMN IF EXISTS updated_at;
-- +goose StatementEnd
