-- +goose Up
-- +goose StatementBegin

-- White-label email senders (issue #63 follow-on). Transactional emails (MFA
-- codes) resolve their sender on a priority basis:
--
--   application-level row  →  tenant-level row  →  global SMTP_FROM (env)
--
-- application_id NULL = the tenant-level sender; NOT NULL = an override for
-- that one application. No rows = today's behaviour (global sender), so the
-- feature is pure opt-in. smtp_password_enc is AES-256-GCM encrypted with the
-- server encryption key — never stored or returned in plaintext.

CREATE TABLE IF NOT EXISTS email_sender_settings (
    id                BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id         BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    application_id    BIGINT REFERENCES oauth_clients(id) ON DELETE CASCADE,
    from_address      TEXT NOT NULL,
    smtp_host         TEXT NOT NULL,
    smtp_port         INT  NOT NULL DEFAULT 587 CHECK (smtp_port > 0 AND smtp_port <= 65535),
    smtp_username     TEXT NOT NULL DEFAULT '',
    smtp_password_enc TEXT NOT NULL DEFAULT '',
    is_active         BOOLEAN NOT NULL DEFAULT true,
    updated_by        BIGINT REFERENCES users(id) ON DELETE SET NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- One tenant-level sender per tenant; one override per application.
CREATE UNIQUE INDEX IF NOT EXISTS email_sender_settings_tenant_level_key
    ON email_sender_settings (tenant_id)
    WHERE application_id IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS email_sender_settings_app_key
    ON email_sender_settings (application_id)
    WHERE application_id IS NOT NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE IF EXISTS email_sender_settings;

-- +goose StatementEnd
