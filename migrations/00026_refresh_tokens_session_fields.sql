-- +goose Up
-- +goose StatementBegin
ALTER TABLE refresh_tokens
    ADD COLUMN IF NOT EXISTS session_family_id UUID,
    ADD COLUMN IF NOT EXISTS token_version     INTEGER     NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS user_agent        TEXT        NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS ip_address        INET,
    ADD COLUMN IF NOT EXISTS last_used_at      TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW();

-- Each existing row gets its own session family (no grouping retroactively).
UPDATE refresh_tokens SET session_family_id = gen_random_uuid() WHERE session_family_id IS NULL;
ALTER TABLE refresh_tokens ALTER COLUMN session_family_id SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family ON refresh_tokens (session_family_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_active ON refresh_tokens (user_id, tenant_id)
    WHERE revoked_at IS NULL AND deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS brin_refresh_tokens_created ON refresh_tokens USING BRIN (created_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_refresh_tokens_family;
DROP INDEX IF EXISTS idx_refresh_tokens_active;
DROP INDEX IF EXISTS brin_refresh_tokens_created;
ALTER TABLE refresh_tokens
    DROP COLUMN IF EXISTS session_family_id,
    DROP COLUMN IF EXISTS token_version,
    DROP COLUMN IF EXISTS user_agent,
    DROP COLUMN IF EXISTS ip_address,
    DROP COLUMN IF EXISTS last_used_at,
    DROP COLUMN IF EXISTS updated_at;
-- +goose StatementEnd

