-- +goose Up
-- +goose StatementBegin
ALTER TABLE audit_logs ADD COLUMN agent_id UUID REFERENCES agent_registrations(id) ON DELETE SET NULL;

CREATE INDEX idx_audit_logs_agent_id ON audit_logs (agent_id, created_at DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_audit_logs_agent_id;
ALTER TABLE audit_logs DROP COLUMN IF EXISTS agent_id;
-- +goose StatementEnd
