-- Per-role allowed MFA methods (issue #199, #189 backlog).
--
-- An application MFA role rule (#195, migration 00110) can now also restrict
-- which second-factor methods satisfy it, e.g. a 'finance-approver' rule that
-- accepts TOTP but not an emailed code. NULL (the default, and every existing
-- rule) means "the application's own allowed_methods" — today's behaviour.
--
-- The service layer requires a non-NULL list to be a non-empty subset of the
-- application's allowed_methods when it is written. The application's list can
-- shrink afterwards; the effective set is then the intersection, and a user
-- left with an empty set is refused (fail closed) rather than let through.
-- Only the non-empty shape is enforced here: the valid method names are
-- already enforced on application_mfa_settings.allowed_methods, which every
-- rule list must be a subset of.
--
-- Down drops the column: every rule falls back to the application's methods,
-- the pre-#199 behaviour.

-- +goose Up
-- +goose StatementBegin
ALTER TABLE application_mfa_role_rules
    ADD COLUMN IF NOT EXISTS allowed_methods TEXT[] NULL
        CONSTRAINT application_mfa_role_rules_allowed_methods_nonempty
        CHECK (allowed_methods IS NULL OR cardinality(allowed_methods) > 0);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE application_mfa_role_rules
    DROP COLUMN IF EXISTS allowed_methods;
-- +goose StatementEnd
