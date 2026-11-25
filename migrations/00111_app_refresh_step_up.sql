-- Per-application step-up at refresh (issue #197, #189 backlog).
--
-- A change to an application's MFA policy applies at each user's next login;
-- refresh rotation never re-checked it, so a session minted without MFA kept
-- refreshing for up to JWT_REFRESH_TTL after MFA was turned on. With
-- refresh_step_up = true, a refresh is refused (401 step_up_required) when the
-- application now requires MFA of the user and the session's amr lacks 'mfa'.
-- The session is not revoked and the token is not rotated: the user signs in
-- again (with MFA) and the old session simply ages out.
--
-- DEFAULT false keeps every existing application's refresh behaviour exactly
-- as it was; an application with no settings row is treated as false by the
-- service layer. A NOT NULL column with a constant default is metadata-only on
-- PostgreSQL 11+, so this takes no table rewrite.
--
-- Down drops the column: every application falls back to no step-up, the
-- pre-#197 behaviour.

-- +goose Up
-- +goose StatementBegin
ALTER TABLE application_mfa_settings
    ADD COLUMN IF NOT EXISTS refresh_step_up BOOLEAN NOT NULL DEFAULT false;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE application_mfa_settings
    DROP COLUMN IF EXISTS refresh_step_up;
-- +goose StatementEnd
