-- +goose Up
-- +goose StatementBegin

-- Per-application MFA policy (issue #63). One row per application; absence of
-- a row means 'optional' — exactly the pre-feature behaviour, so existing
-- applications are unaffected until an owner/super_admin explicitly sets a
-- mode.
--
--   disabled — new TOTP enrollments are rejected for the application's users.
--              Already-active enrollments still gate login (fail-secure: the
--              server never silently drops a second factor a user set up;
--              admins remove enrollments explicitly via the MFA reset API).
--   optional — users may enroll voluntarily; login challenges only the
--              enrolled (default).
--   required — login without an active enrollment returns an enrollment
--              challenge instead of tokens; users cannot disable their own
--              TOTP while the policy is 'required'.
--
-- A dedicated table (not a column on oauth_clients) so future per-app MFA
-- options (allowed methods, grace periods, remember-device) extend this row
-- without repeated ALTERs on the applications table.

CREATE TABLE IF NOT EXISTS application_mfa_settings (
    application_id BIGINT PRIMARY KEY REFERENCES oauth_clients(id) ON DELETE CASCADE,
    tenant_id      BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    mode           TEXT NOT NULL DEFAULT 'optional'
                   CHECK (mode IN ('disabled', 'optional', 'required')),
    -- Who last changed the policy (owner or super_admin) — audit convenience;
    -- the authoritative trail is audit_logs (admin.mfa_policy_updated).
    updated_by     BIGINT REFERENCES users(id) ON DELETE SET NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_application_mfa_settings_tenant
    ON application_mfa_settings (tenant_id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE IF EXISTS application_mfa_settings;

-- +goose StatementEnd
