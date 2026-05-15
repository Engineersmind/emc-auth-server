-- +goose Up
-- +goose StatementBegin
CREATE TABLE audit_logs (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID        REFERENCES tenants(id) ON DELETE SET NULL,
    user_id       UUID        REFERENCES users(id)   ON DELETE SET NULL,
    actor_email   TEXT        NOT NULL DEFAULT '',
    action        TEXT        NOT NULL,
    resource_type TEXT        NOT NULL DEFAULT '',
    resource_id   TEXT        NOT NULL DEFAULT '',
    ip_address    TEXT        NOT NULL DEFAULT '',
    user_agent    TEXT        NOT NULL DEFAULT '',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_logs_tenant_id  ON audit_logs (tenant_id, created_at DESC);
CREATE INDEX idx_audit_logs_user_id    ON audit_logs (user_id,   created_at DESC);
CREATE INDEX idx_audit_logs_action     ON audit_logs (action,    created_at DESC);
CREATE INDEX idx_audit_logs_created_at ON audit_logs (created_at DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS audit_logs;
-- +goose StatementEnd
