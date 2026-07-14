-- +goose Up
-- +goose StatementBegin

-- Per-application social login provider credentials (issue #64).
--
-- Each tenant application brings its own provider OAuth client (their own
-- Google Cloud project etc.) — one row per (application, provider) pair.
-- Deliberately generic: Microsoft/GitHub later are new rows with a different
-- provider string, not new columns or migrations.
--
-- client_secret_enc is AES-256-GCM encrypted with OAUTH_CLIENT_SECRET_ENCRYPTION_KEY
-- (same scheme as totp_secrets.secret_enc) — never plaintext, never just base64.
--
-- redirect_allow is the exact-match allow-list of post-login redirect targets
-- back to the tenant application (open-redirect prevention). Entries are full
-- absolute URLs; matching is exact string equality, never prefix.
CREATE TABLE identity_provider_configs (
    id                BIGINT      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id         BIGINT      NOT NULL REFERENCES tenants(id)       ON DELETE CASCADE,
    application_id    BIGINT      NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    provider          TEXT        NOT NULL,
    client_id         TEXT        NOT NULL,
    client_secret_enc TEXT        NOT NULL,
    enabled           BOOLEAN     NOT NULL DEFAULT true,
    redirect_allow    TEXT[]      NOT NULL DEFAULT '{}',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX identity_provider_configs_app_provider_key
    ON identity_provider_configs (application_id, provider);

CREATE INDEX idx_identity_provider_configs_tenant
    ON identity_provider_configs (tenant_id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS identity_provider_configs;
-- +goose StatementEnd
