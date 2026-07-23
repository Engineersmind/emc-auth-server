-- +goose Up
-- +goose StatementBegin

-- Auth0-grade audit context (issue #66 follow-on). Column additions only — all
-- are constant-default / nullable, so on PostgreSQL 11+ they are metadata-only
-- operations (no table rewrite, no long lock). The supporting indexes are built
-- separately and CONCURRENTLY in 00055 so they never block audit writes on a
-- large table.
--
--   http_status — the HTTP response code served (200/401/403/429…). NULL = unknown.
--   auth_method — the credential/mechanism used (password | google-oauth2 |
--                 totp | client_credentials | api_key | …). Empty for non-
--                 credential events (admin CRUD). Auth0's connection/strategy.
--
-- Tamper-evidence (compliance): each row carries the hash of the previous row
-- and its own content hash, forming a verifiable chain (see internal/audit).
--   row_hash  — SHA-256 over the canonical row content + prev_hash.
--   prev_hash — the row_hash of the immediately preceding row in the chain.
ALTER TABLE audit_logs
    ADD COLUMN IF NOT EXISTS http_status SMALLINT,
    ADD COLUMN IF NOT EXISTS auth_method TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS row_hash    TEXT,
    ADD COLUMN IF NOT EXISTS prev_hash   TEXT;

-- Usage counters backing the Auth0 stats.loginsCount equivalent — snapshotted
-- into metadata.stats at log time. Updated once per successful login.
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS login_count   BIGINT      NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMPTZ;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE users
    DROP COLUMN IF EXISTS last_login_at,
    DROP COLUMN IF EXISTS login_count;
ALTER TABLE audit_logs
    DROP COLUMN IF EXISTS prev_hash,
    DROP COLUMN IF EXISTS row_hash,
    DROP COLUMN IF EXISTS auth_method,
    DROP COLUMN IF EXISTS http_status;
-- +goose StatementEnd
