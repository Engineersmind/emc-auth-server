-- +goose Up
-- +goose StatementBegin

-- Passwordless magic-link sign-in (issue #63 follow-on). Per-application
-- opt-in on the auth-policy row:
--
--   magic_link_enabled       — POST /auth/apps/login/magic mints a single-use
--                              15-minute link emailed to the account address.
--   magic_link_redirect_url  — where the link points: the application's own
--                              frontend, which extracts ?token=… and calls
--                              POST /auth/apps/login/magic/verify.
--
-- A magic link replaces only the PASSWORD step. The application's MFA policy
-- still applies after verification (a link click proves inbox control — the
-- same factor as an email OTP — so it never bypasses a TOTP requirement).

ALTER TABLE application_mfa_settings
    ADD COLUMN IF NOT EXISTS magic_link_enabled BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE application_mfa_settings
    ADD COLUMN IF NOT EXISTS magic_link_redirect_url TEXT NOT NULL DEFAULT '';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

ALTER TABLE application_mfa_settings DROP COLUMN IF EXISTS magic_link_redirect_url;
ALTER TABLE application_mfa_settings DROP COLUMN IF EXISTS magic_link_enabled;

-- +goose StatementEnd
