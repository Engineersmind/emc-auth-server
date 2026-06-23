-- +goose Up
-- +goose StatementBegin
CREATE TABLE oauth_clients (
    id                 UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id          UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id          TEXT        NOT NULL,
    client_secret_hash TEXT,
    redirect_uris      TEXT[]      NOT NULL DEFAULT '{}',
    grant_types        TEXT[]      NOT NULL DEFAULT '{authorization_code,refresh_token}',
    scopes             TEXT[]      NOT NULL DEFAULT '{openid,profile,email}',
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at         TIMESTAMPTZ
);

CREATE UNIQUE INDEX idx_oauth_clients_client_id
    ON oauth_clients (client_id)
    WHERE deleted_at IS NULL;

CREATE INDEX idx_oauth_clients_tenant
    ON oauth_clients (tenant_id)
    WHERE deleted_at IS NULL;

CREATE TABLE oauth_authorization_codes (
    id                    UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id             UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id             TEXT        NOT NULL,
    user_id               UUID        NOT NULL REFERENCES users(id)   ON DELETE CASCADE,
    code_hash             TEXT        NOT NULL,
    code_challenge        TEXT,
    code_challenge_method TEXT        CHECK (code_challenge_method IN ('S256', 'plain')),
    redirect_uri          TEXT        NOT NULL,
    scopes                TEXT[]      NOT NULL DEFAULT '{}',
    expires_at            TIMESTAMPTZ NOT NULL,
    used_at               TIMESTAMPTZ,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_oauth_codes_hash    ON oauth_authorization_codes (code_hash);
CREATE INDEX        brin_oauth_codes_created ON oauth_authorization_codes USING BRIN (created_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS oauth_authorization_codes;
DROP TABLE IF EXISTS oauth_clients;
-- +goose StatementEnd

