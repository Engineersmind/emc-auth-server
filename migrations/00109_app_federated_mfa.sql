-- Per-application federated MFA setting (issue #194, stage 3 of #189).
--
-- Social (Google, GitHub) and passkey sign-ins have never gone through the
-- application MFA gate. federated_mfa makes that a per-application choice:
--
--   trust   — today's behaviour: the identity provider / passkey is accepted
--             as is and tokens are issued without an application MFA step.
--   enforce — the same app MFA gate as password login runs before tokens are
--             issued (OTP challenge or forced enrolment). A passkey that
--             performed user verification already is two factors and
--             satisfies it; a passkey without user verification does not.
--
-- DEFAULT 'trust' keeps every existing application's behaviour unchanged, and
-- an application with no settings row is treated as 'trust' by the service
-- layer. A NOT NULL column with a constant default is metadata-only on
-- PostgreSQL 11+, so this takes no table rewrite. IF NOT EXISTS skips the whole
-- clause, CHECK included, on a re-run.
--
-- Down drops the column: every application falls back to 'trust', which is the
-- pre-#194 behaviour.

-- +goose Up
-- +goose StatementBegin
ALTER TABLE application_mfa_settings
    ADD COLUMN IF NOT EXISTS federated_mfa TEXT NOT NULL DEFAULT 'trust'
        CONSTRAINT application_mfa_settings_federated_mfa_check
        CHECK (federated_mfa IN ('trust', 'enforce'));
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE application_mfa_settings
    DROP COLUMN IF EXISTS federated_mfa;
-- +goose StatementEnd
