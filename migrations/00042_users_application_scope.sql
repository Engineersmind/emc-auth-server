-- +goose Up
-- +goose StatementBegin

-- Application-scoped user bases (EMC-005 follow-on):
-- users registered through an authenticated application belong to that
-- application, not just the tenant.
--
-- application_id IS NULL     = tenant-level user (admins, seeded users, first-party SPA)
-- application_id IS NOT NULL = application-scoped user

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS application_id BIGINT
    REFERENCES oauth_clients(id);

-- Migration 31 replaced the original UNIQUE constraint with this
-- soft-delete-aware partial unique index; it has no application_id dimension.
ALTER TABLE users
    DROP CONSTRAINT IF EXISTS users_tenant_id_email_key;

DROP INDEX IF EXISTS idx_users_email_active;

-- Tenant-level users: one active account per email within a tenant (same
-- behavior as before this migration, just scoped to application_id IS NULL).
CREATE UNIQUE INDEX IF NOT EXISTS users_tenant_email_tenant_level_key
    ON users (tenant_id, email)
    WHERE application_id IS NULL
      AND deleted_at IS NULL;

-- Application-scoped users: the same email may exist independently in
-- different applications of the same tenant.
CREATE UNIQUE INDEX IF NOT EXISTS users_tenant_app_email_key
    ON users (tenant_id, application_id, email)
    WHERE application_id IS NOT NULL
      AND deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_users_application_id
    ON users (application_id)
    WHERE application_id IS NOT NULL
      AND deleted_at IS NULL;

-- Login()'s candidate query (internal/auth/service.go) now filters app-scoped
-- attempts with "AND u.application_id = $3" (and tenant-level attempts with
-- "AND u.application_id IS NULL"). application_id must be a key column, not
-- just INCLUDE-d, so Postgres can apply it as an index condition — as an
-- INCLUDE-only column it can only support index-only scans, not narrow the
-- scan itself, which would force scanning every (tenant_id,email) match and
-- filtering by application_id afterward once per-application duplicate emails
-- exist. A trailing key column still serves plain tenant_id+email lookups.
DROP INDEX IF EXISTS idx_users_login_covering;
CREATE INDEX IF NOT EXISTS idx_users_login_covering
    ON users (tenant_id, email, application_id)
    INCLUDE (id, role_id, is_active, email_verified, token_version)
    WHERE deleted_at IS NULL;

-- +goose StatementEnd


-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS idx_users_login_covering;
CREATE INDEX IF NOT EXISTS idx_users_login_covering
    ON users (tenant_id, email)
    INCLUDE (id, role_id, is_active, email_verified, token_version)
    WHERE deleted_at IS NULL;

DROP INDEX IF EXISTS idx_users_application_id;
DROP INDEX IF EXISTS users_tenant_app_email_key;
DROP INDEX IF EXISTS users_tenant_email_tenant_level_key;

-- Restore the migration-31 uniqueness model, not the pre-31 constraint.
-- Fails if per-application duplicate emails exist — resolve manually first.
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_active
    ON users (tenant_id, email)
    WHERE deleted_at IS NULL;

ALTER TABLE users
    DROP COLUMN IF EXISTS application_id;

-- +goose StatementEnd
