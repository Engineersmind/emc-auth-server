-- Per-application MFA master switch (issue #192, stage 1 of #189).
--
-- mfa_enabled sits ABOVE mode. While it is false the application runs without
-- MFA: no login challenge, no forced enrolment, no new enrolment. Turning it off
-- deletes nothing — mode, allowed_methods, enrolled factors and backup codes all
-- stay, so turning it back on restores exactly the previous behaviour.
--
-- DEFAULT true keeps every existing row's behaviour unchanged, and an
-- application with no row at all is treated as enabled by the service layer.
-- Adding a NOT NULL column with a constant default is metadata-only on
-- PostgreSQL 11+, so this takes no table rewrite.
--
-- Down drops the column: the switch state is lost, and every application falls
-- back to MFA-on, which is the fail-safe direction.

-- +goose Up
-- +goose StatementBegin
ALTER TABLE application_mfa_settings
    ADD COLUMN IF NOT EXISTS mfa_enabled BOOLEAN NOT NULL DEFAULT true;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE application_mfa_settings
    DROP COLUMN IF EXISTS mfa_enabled;
-- +goose StatementEnd
