-- +goose Up
-- +goose StatementBegin
CREATE TABLE signing_keys (
    id              BIGINT      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id       BIGINT      NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    kid             TEXT        NOT NULL,
    algorithm       TEXT        NOT NULL CHECK (algorithm IN ('RS256', 'ES256')),
    public_key      TEXT        NOT NULL,
    private_key_enc TEXT        NOT NULL,
    status          TEXT        NOT NULL DEFAULT 'active'
                                         CHECK (status IN ('active', 'retiring', 'retired')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at      TIMESTAMPTZ
);

CREATE UNIQUE INDEX idx_signing_keys_kid
    ON signing_keys (kid)
    WHERE deleted_at IS NULL;

CREATE INDEX idx_signing_keys_tenant_active
    ON signing_keys (tenant_id)
    WHERE status = 'active' AND deleted_at IS NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS signing_keys;
-- +goose StatementEnd
