-- +goose Up
-- +goose StatementBegin

-- Attribute audit events to the application (oauth_clients row) they occurred
-- under. NULL = tenant-level event with no application context (mirrors
-- users.application_id from migration 00042). Unblocks the per-application
-- Logs tab and dashboard activity feed.
--
-- ON DELETE SET NULL: audit history must outlive the application record
-- (same policy as tenant_id / user_id / agent_id on this table).
ALTER TABLE audit_logs
    ADD COLUMN IF NOT EXISTS application_id BIGINT
    REFERENCES oauth_clients(id) ON DELETE SET NULL;

-- Partial index: only app-attributed rows are indexed — tenant-level events
-- (the majority today) cost nothing, and per-app queries always filter
-- application_id = X ORDER BY created_at DESC.
CREATE INDEX IF NOT EXISTS idx_audit_logs_application_id
    ON audit_logs (application_id, created_at DESC)
    WHERE application_id IS NOT NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_audit_logs_application_id;
ALTER TABLE audit_logs DROP COLUMN IF EXISTS application_id;
-- +goose StatementEnd
