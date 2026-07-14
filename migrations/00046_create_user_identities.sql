-- +goose Up
-- +goose StatementBegin

-- Federated identity links (issue #64, Google login for app-scoped end users).
--
-- One row = one external identity (e.g. a Google account) attached to one
-- local user. Users provisioned through a federated provider get a row here
-- and NO user_credentials row — password login is simply impossible for them,
-- no fake password hash needed (the SAML JIT approach this replaces).
--
-- provider is a plain string ('google', later 'microsoft', 'github') so new
-- providers are additive rows, never schema changes.
CREATE TABLE user_identities (
    id             BIGINT      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id        BIGINT      NOT NULL REFERENCES users(id)         ON DELETE CASCADE,
    tenant_id      BIGINT      NOT NULL REFERENCES tenants(id)       ON DELETE CASCADE,
    application_id BIGINT      NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    provider       TEXT        NOT NULL,
    provider_sub   TEXT        NOT NULL,
    provider_email TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- One external account maps to at most one local user per application —
-- mirrors the per-app email uniqueness split introduced in migration 00042.
CREATE UNIQUE INDEX user_identities_app_provider_sub_key
    ON user_identities (tenant_id, application_id, provider, provider_sub);

-- One user holds at most one identity per provider (no double-linking).
CREATE UNIQUE INDEX user_identities_user_provider_key
    ON user_identities (user_id, provider);

-- Reverse lookup: "which identities does this user have" (profile/unlink UIs).
CREATE INDEX idx_user_identities_user ON user_identities (user_id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS user_identities;
-- +goose StatementEnd
