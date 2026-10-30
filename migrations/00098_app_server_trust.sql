-- +goose Up
-- +goose StatementBegin

-- Server-to-server trust for application backends (S2S rate limiting).
--
-- A product backend calls the /auth/apps/* endpoints for every one of its users
-- from a small set of egress addresses. Two settings let the server treat that
-- traffic for what it is:
--
--   app_server_ips          the backend's egress addresses. A request from one
--                           of them, for that application, skips the per-IP
--                           flood guard; the application quota and the per-user
--                           limits still apply.
--
--   trust_forwarded_ip      whether the application may report the end user's
--                           address in X-EMC-Forwarded-For. Honoured only on a
--                           request whose client secret verified and that came
--                           from one of the registered server IPs.
--
-- Both default to "not trusted", so existing applications behave exactly as
-- before until an administrator opts in.
ALTER TABLE oauth_clients
    ADD COLUMN IF NOT EXISTS trust_forwarded_ip BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS app_server_ips (
    id             BIGINT      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id      BIGINT      NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    application_id BIGINT      NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    cidr           CIDR        NOT NULL,
    description    TEXT        NOT NULL DEFAULT '',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT app_server_ips_app_cidr_key UNIQUE (application_id, cidr)
);

CREATE INDEX IF NOT EXISTS idx_app_server_ips_tenant_app
    ON app_server_ips (tenant_id, application_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS app_server_ips;
ALTER TABLE oauth_clients DROP COLUMN IF EXISTS trust_forwarded_ip;
-- +goose StatementEnd
