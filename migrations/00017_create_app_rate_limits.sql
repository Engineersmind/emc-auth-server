-- +goose Up
-- +goose StatementBegin
CREATE TABLE app_rate_limits (
    app_id              TEXT        PRIMARY KEY,
    tenant_id           BIGINT      NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    requests_per_minute INT         NOT NULL DEFAULT 60,
    burst               INT         NOT NULL DEFAULT 10,
    description         TEXT        NOT NULL DEFAULT '',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_app_rate_limits_tenant_id ON app_rate_limits (tenant_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS app_rate_limits;
-- +goose StatementEnd
