-- enforce_from grace date for required-mode rollout (issue #198, #189 backlog).
--
-- Turning an application's MFA on under 'required' forces enrolment of every
-- unenrolled user at once. enforce_from gives the rollout a grace period: while
-- NOW() < enforce_from, a user who must use MFA (mode 'required' or covered by
-- a role rule) but has NO active factor still signs in normally, and the login
-- response carries mfa_enrollment_recommended = true plus the date. From
-- enforce_from on, enrolment is forced as before. Users who already have a
-- factor are always challenged: the grace covers enrolment only.
--
-- NULL (the default) means no grace period — today's behaviour for every
-- existing application. Adding a nullable column without a default is
-- metadata-only.
--
-- Down drops the column: every application falls back to immediate
-- enforcement, the pre-#198 behaviour.

-- +goose Up
-- +goose StatementBegin
ALTER TABLE application_mfa_settings
    ADD COLUMN IF NOT EXISTS enforce_from TIMESTAMPTZ NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE application_mfa_settings
    DROP COLUMN IF EXISTS enforce_from;
-- +goose StatementEnd
