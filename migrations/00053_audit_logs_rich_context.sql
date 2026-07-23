-- +goose Up
-- +goose StatementBegin

-- Production-grade audit context (issue #66 follow-on). Three additions bring
-- the log up to the industry bar (CloudTrail / Auth0 / Stripe events): an
-- outcome, a request-correlation id, and a flexible metadata payload.
--
--   status      — 'success' | 'failure'. Lets admins/owners filter to just the
--                 things that went wrong. Derived from the action at write time.
--   request_id  — ties an audit row to the same request's zerolog/OTel traces,
--                 so "find this event, then read the full request" is one hop.
--   metadata    — JSONB catch-all for event-specific detail: HTTP method/route,
--                 failure reason, changed fields, MFA method, etc. Secrets are
--                 redacted and the payload is size-capped before it is written.
ALTER TABLE audit_logs
    ADD COLUMN IF NOT EXISTS status     TEXT  NOT NULL DEFAULT 'success',
    ADD COLUMN IF NOT EXISTS request_id TEXT  NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS metadata   JSONB NOT NULL DEFAULT '{}'::jsonb;

-- Failures are the debug target — a small partial index keeps "show me only
-- what failed, newest first" cheap without bloating the common success path.
CREATE INDEX IF NOT EXISTS idx_audit_logs_failures
    ON audit_logs (tenant_id, created_at DESC)
    WHERE status <> 'success';

-- Correlation lookups by request id (partial: most rows have no id yet).
CREATE INDEX IF NOT EXISTS idx_audit_logs_request_id
    ON audit_logs (request_id)
    WHERE request_id <> '';

-- Containment queries over metadata (e.g. metadata @> '{"reason":"..."}').
CREATE INDEX IF NOT EXISTS idx_audit_logs_metadata
    ON audit_logs USING GIN (metadata jsonb_path_ops);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_audit_logs_metadata;
DROP INDEX IF EXISTS idx_audit_logs_request_id;
DROP INDEX IF EXISTS idx_audit_logs_failures;
ALTER TABLE audit_logs
    DROP COLUMN IF EXISTS metadata,
    DROP COLUMN IF EXISTS request_id,
    DROP COLUMN IF EXISTS status;
-- +goose StatementEnd
