-- +goose NO TRANSACTION
--
-- Indexes for the organisation columns added in 00103, built CONCURRENTLY so
-- they never take a write lock on user_sessions or audit_logs. Same pattern as
-- 00055: CONCURRENTLY cannot run inside a transaction, and IF NOT EXISTS keeps a
-- re-run harmless. Drop any INVALID index left by an interrupted build before
-- re-running.
--
-- Both are partial on organization_id IS NOT NULL, so they stay empty — and
-- cost nothing on write — until an application actually enables organisations.

-- Revocation: "every live session in organisation X" (deactivation) and "every
-- live session of user Y in organisation X" (removal, suspension).
-- +goose Up
-- +goose StatementBegin
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_user_sessions_organization
    ON user_sessions (organization_id, user_id)
    WHERE organization_id IS NOT NULL AND revoked_at IS NULL;
-- +goose StatementEnd

-- Organisation-scoped audit queries.
-- +goose StatementBegin
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_logs_organization_created
    ON audit_logs (organization_id, created_at DESC)
    WHERE organization_id IS NOT NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX CONCURRENTLY IF EXISTS idx_audit_logs_organization_created;
-- +goose StatementEnd

-- +goose StatementBegin
DROP INDEX CONCURRENTLY IF EXISTS idx_user_sessions_organization;
-- +goose StatementEnd
