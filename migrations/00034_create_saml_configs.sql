-- +goose Up
-- +goose StatementBegin
CREATE TABLE saml_configs (
    id          BIGINT      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id   BIGINT      NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    entity_id   TEXT        NOT NULL,
    sso_url     TEXT        NOT NULL,
    certificate TEXT        NOT NULL,
    is_enabled  BOOLEAN     NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at  TIMESTAMPTZ
);

-- One SAML config per tenant (partial — allows re-creation after soft-delete).
CREATE UNIQUE INDEX idx_saml_tenant
    ON saml_configs (tenant_id)
    WHERE deleted_at IS NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS saml_configs;
-- +goose StatementEnd
