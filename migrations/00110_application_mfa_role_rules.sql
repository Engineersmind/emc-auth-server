-- Role-based MFA rules per application (issue #195, stage 2 of #189).
--
-- A row says: users holding role_id must use MFA on application_id, as if the
-- application's mode were 'required'. Only roles scoped to that application
-- (roles.application_id = application_id) are accepted — the service layer
-- validates it, since a CHECK cannot look at another table. Rules apply only
-- while the application's MFA switch is on and its mode is not 'disabled'.
--
-- role_id is ON DELETE RESTRICT so deleting a role can never silently drop the
-- enforcement that names it. Roles are normally soft-deleted, which an FK
-- cannot see, so DeleteRole also refuses a role that a rule still lists; the FK
-- is the backstop for any hard delete. The application and tenant FKs CASCADE,
-- like application_mfa_settings: a rule means nothing without its application.
--
-- Down drops the table: every rule is lost and role-covered users fall back to
-- the application's mode.

-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS application_mfa_role_rules (
    application_id BIGINT NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    role_id        BIGINT NOT NULL REFERENCES roles(id) ON DELETE RESTRICT,
    tenant_id      BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- Who added the rule; the authoritative trail is audit_logs
    -- (admin.mfa_role_rules_set). SET NULL so losing the account keeps the rule.
    created_by     BIGINT REFERENCES users(id) ON DELETE SET NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (application_id, role_id)
);

-- "Is this role named by any rule" — DeleteRole's guard.
CREATE INDEX IF NOT EXISTS idx_application_mfa_role_rules_role
    ON application_mfa_role_rules (role_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS application_mfa_role_rules;
-- +goose StatementEnd
