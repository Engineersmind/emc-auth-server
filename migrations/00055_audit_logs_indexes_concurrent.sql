-- +goose NO TRANSACTION
--
-- Indexes for the advanced audit columns (00054), built CONCURRENTLY so they
-- never take a write lock on audit_logs — safe to run against a large, live
-- table. CONCURRENTLY cannot run inside a transaction, hence NO TRANSACTION;
-- each statement runs standalone and goose records them individually.
--
-- IF NOT EXISTS keeps this idempotent. If a CONCURRENTLY build is interrupted
-- it can leave an INVALID index; re-running drops-and-rebuilds via IF NOT EXISTS
-- only when absent, so operators should DROP any INVALID index before re-run.

-- +goose Up
-- +goose StatementBegin
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_logs_auth_method
    ON audit_logs (auth_method, created_at DESC)
    WHERE auth_method <> '';
-- +goose StatementEnd

-- +goose StatementBegin
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_logs_user_action_created
    ON audit_logs (user_id, action, created_at DESC)
    WHERE user_id IS NOT NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX CONCURRENTLY IF EXISTS idx_audit_logs_user_action_created;
-- +goose StatementEnd

-- +goose StatementBegin
DROP INDEX CONCURRENTLY IF EXISTS idx_audit_logs_auth_method;
-- +goose StatementEnd
