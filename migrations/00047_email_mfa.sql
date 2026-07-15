-- +goose Up
-- +goose StatementBegin

-- Email OTP as a second MFA method (issue #63, method expansion).
--
-- allowed_methods: which second-factor methods an application permits its
-- users to enroll ('totp', 'email'). Owners configure this next to the mode;
-- existing rows and the implicit default stay TOTP-only, so nothing changes
-- for current applications until an owner opts in.

ALTER TABLE application_mfa_settings
    ADD COLUMN IF NOT EXISTS allowed_methods TEXT[] NOT NULL DEFAULT '{totp}';

ALTER TABLE application_mfa_settings
    DROP CONSTRAINT IF EXISTS application_mfa_settings_methods_check;

ALTER TABLE application_mfa_settings
    ADD CONSTRAINT application_mfa_settings_methods_check
    CHECK (allowed_methods <@ ARRAY['totp', 'email']::TEXT[]
           AND array_length(allowed_methods, 1) >= 1);

-- Per-user email-OTP enrollment. The verified factor is "control of the
-- account's email inbox"; no secret is stored — login codes are minted per
-- challenge, kept only as SHA-256 hashes in Redis with a short TTL and an
-- attempt budget. is_active=false rows exist between "verification code
-- sent" and "code confirmed".

CREATE TABLE IF NOT EXISTS email_mfa_settings (
    user_id    BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    tenant_id  BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    is_active  BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_email_mfa_settings_tenant
    ON email_mfa_settings (tenant_id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE IF EXISTS email_mfa_settings;
ALTER TABLE application_mfa_settings
    DROP CONSTRAINT IF EXISTS application_mfa_settings_methods_check;
ALTER TABLE application_mfa_settings
    DROP COLUMN IF EXISTS allowed_methods;

-- +goose StatementEnd
