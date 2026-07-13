-- +goose Up
-- +goose StatementBegin

-- End-user application roles: an application owner can define roles scoped
-- to their own application (application_id NOT NULL, is_system = false) and
-- mark one as the default assigned at /register. Tenant-management roles
-- (super_admin, owner — both is_system = true) stay application_id IS NULL
-- and are untouched by this migration; they are never eligible to be a
-- "default role" for self-registration.

ALTER TABLE roles ADD COLUMN IF NOT EXISTS application_id BIGINT REFERENCES oauth_clients(id) ON DELETE CASCADE;
ALTER TABLE roles ADD COLUMN IF NOT EXISTS is_default BOOLEAN NOT NULL DEFAULT false;

CREATE INDEX IF NOT EXISTS idx_roles_application_id
    ON roles (application_id)
    WHERE application_id IS NOT NULL;

-- One default role per (tenant, application). Deliberately excludes
-- application_id IS NULL so tenant-management roles can never be flagged
-- default.
CREATE UNIQUE INDEX IF NOT EXISTS roles_one_default_per_app
    ON roles (tenant_id, application_id)
    WHERE is_default = true AND application_id IS NOT NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- WARNING: dropping application_id silently discards which roles were
-- application-scoped and which was each application's default — this is
-- irreversible without an external backup; only run in a rollback where
-- that state is disposable.
DROP INDEX IF EXISTS roles_one_default_per_app;
DROP INDEX IF EXISTS idx_roles_application_id;
ALTER TABLE roles DROP COLUMN IF EXISTS is_default;
ALTER TABLE roles DROP COLUMN IF EXISTS application_id;

-- +goose StatementEnd
