-- +goose Up
-- +goose StatementBegin

-- Per-scope email templates (Auth0-style). Each row overrides the built-in
-- default for one (scope, template_type). Resolution mirrors email_sender_settings:
--
--   application-level row  →  tenant-level row  →  built-in default (in code)
--
-- application_id NULL = the tenant-level template; NOT NULL = an override for
-- that one application. No row = built-in default, so the feature is pure opt-in.
-- subject/html_body/text_body are Go-template source (variables like {{.Link}},
-- {{.Code}}, {{.ProductName}}); validated on write.

CREATE TABLE IF NOT EXISTS email_templates (
    id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id      BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    application_id BIGINT REFERENCES oauth_clients(id) ON DELETE CASCADE,
    template_type  TEXT NOT NULL,
    subject        TEXT NOT NULL,
    html_body      TEXT NOT NULL,
    text_body      TEXT NOT NULL DEFAULT '',
    is_active      BOOLEAN NOT NULL DEFAULT true,
    updated_by     BIGINT REFERENCES users(id) ON DELETE SET NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- One tenant-level template per (tenant, type); one override per (application, type).
CREATE UNIQUE INDEX IF NOT EXISTS email_templates_tenant_level_key
    ON email_templates (tenant_id, template_type)
    WHERE application_id IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS email_templates_app_key
    ON email_templates (application_id, template_type)
    WHERE application_id IS NOT NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE IF EXISTS email_templates;

-- +goose StatementEnd
