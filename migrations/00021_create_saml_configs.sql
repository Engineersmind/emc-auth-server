-- +goose Up
-- +goose StatementBegin
CREATE TABLE saml_configs (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID        NOT NULL UNIQUE REFERENCES tenants(id) ON DELETE CASCADE,
    entity_id   TEXT        NOT NULL,
    sso_url     TEXT        NOT NULL,
    certificate TEXT        NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_saml_configs_tenant_id ON saml_configs (tenant_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS saml_configs;
-- +goose StatementEnd
