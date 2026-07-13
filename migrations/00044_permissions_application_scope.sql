-- +goose Up
-- +goose StatementBegin

-- Application-scoped permissions (follow-on to 00043's application-scoped
-- roles): an application owner defines that application's own permission
-- catalog, fully isolated from other applications in the tenant.
--
-- application_id IS NULL     = tenant-level permission (the seeded management
--                              catalog: users:read, roles:write, ... held by
--                              owner/super_admin)
-- application_id IS NOT NULL = end-user permission belonging to one application
--
-- Name uniqueness gains the application dimension so two applications in the
-- same tenant can each define e.g. "invoices:read" independently — the same
-- pattern 00042 applied to users and this migration also applies to roles.

ALTER TABLE permissions
    ADD COLUMN IF NOT EXISTS application_id BIGINT
    REFERENCES oauth_clients(id) ON DELETE CASCADE;

DROP INDEX IF EXISTS idx_permissions_name_active;

CREATE UNIQUE INDEX IF NOT EXISTS permissions_tenant_name_tenant_level_key
    ON permissions (tenant_id, name)
    WHERE application_id IS NULL AND deleted_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS permissions_tenant_app_name_key
    ON permissions (tenant_id, application_id, name)
    WHERE application_id IS NOT NULL AND deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_permissions_application_id
    ON permissions (application_id)
    WHERE application_id IS NOT NULL AND deleted_at IS NULL;

-- Roles get the same per-application name isolation. 00043 added
-- roles.application_id but the 00031 unique index still spanned the whole
-- tenant, so two applications could not both define a "viewer" role.
DROP INDEX IF EXISTS idx_roles_name_active;

CREATE UNIQUE INDEX IF NOT EXISTS roles_tenant_name_tenant_level_key
    ON roles (tenant_id, name)
    WHERE application_id IS NULL AND deleted_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS roles_tenant_app_name_key
    ON roles (tenant_id, application_id, name)
    WHERE application_id IS NOT NULL AND deleted_at IS NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS roles_tenant_app_name_key;
DROP INDEX IF EXISTS roles_tenant_name_tenant_level_key;
-- Fails if two applications hold the same role name — resolve manually first.
CREATE UNIQUE INDEX IF NOT EXISTS idx_roles_name_active
    ON roles (tenant_id, name)
    WHERE deleted_at IS NULL;

DROP INDEX IF EXISTS idx_permissions_application_id;
DROP INDEX IF EXISTS permissions_tenant_app_name_key;
DROP INDEX IF EXISTS permissions_tenant_name_tenant_level_key;
-- Fails if two applications hold the same permission name — resolve manually first.
CREATE UNIQUE INDEX IF NOT EXISTS idx_permissions_name_active
    ON permissions (tenant_id, name)
    WHERE deleted_at IS NULL;

ALTER TABLE permissions DROP COLUMN IF EXISTS application_id;

-- +goose StatementEnd
