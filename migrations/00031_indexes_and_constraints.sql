-- +goose Up
-- +goose StatementBegin

-- ── tenants ───────────────────────────────────────────────────────────────────
-- Replace the global UNIQUE on slug with a partial index so slugs are
-- reusable after soft-delete (deleted_at IS NOT NULL).
ALTER TABLE tenants DROP CONSTRAINT IF EXISTS tenants_slug_key;
CREATE UNIQUE INDEX idx_tenants_slug_active
    ON tenants (slug)
    WHERE deleted_at IS NULL;

ALTER TABLE tenants
    ADD CONSTRAINT chk_tenants_name CHECK (char_length(name) BETWEEN 1 AND 200),
    ADD CONSTRAINT chk_tenants_slug CHECK (slug ~* '^[a-z0-9-]+$');

-- ── users ─────────────────────────────────────────────────────────────────────
-- Replace global unique + non-partial index with a partial unique and
-- a covering index for the login hot path.
DROP INDEX  IF EXISTS idx_users_tenant_email;
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_tenant_id_email_key;

CREATE UNIQUE INDEX idx_users_email_active
    ON users (tenant_id, email)
    WHERE deleted_at IS NULL;

-- Covering index: includes all columns the login query reads so it can be
-- served entirely from the index without a heap fetch.
CREATE INDEX idx_users_login_covering
    ON users (tenant_id, email)
    INCLUDE (id, role_id, is_active, email_verified, token_version)
    WHERE deleted_at IS NULL;

CREATE INDEX idx_users_tenant
    ON users (tenant_id)
    WHERE deleted_at IS NULL;

CREATE INDEX idx_users_role
    ON users (role_id)
    WHERE role_id IS NOT NULL AND deleted_at IS NULL;

ALTER TABLE users
    ADD CONSTRAINT chk_users_email CHECK (email ~* '^[^@]+@[^@]+\.[^@]+$');

-- ── roles ─────────────────────────────────────────────────────────────────────
ALTER TABLE roles DROP CONSTRAINT IF EXISTS roles_tenant_id_name_key;
CREATE UNIQUE INDEX idx_roles_name_active
    ON roles (tenant_id, name)
    WHERE deleted_at IS NULL;

CREATE INDEX idx_roles_tenant
    ON roles (tenant_id)
    WHERE deleted_at IS NULL;

ALTER TABLE roles
    ADD CONSTRAINT chk_roles_name CHECK (char_length(name) BETWEEN 1 AND 100);

-- ── permissions ───────────────────────────────────────────────────────────────
-- 00014 already dropped permissions_name_key and added permissions_tenant_name_key.
-- Replace that global unique with a partial index.
ALTER TABLE permissions DROP CONSTRAINT IF EXISTS permissions_tenant_name_key;
DROP INDEX  IF EXISTS idx_permissions_tenant_id;

CREATE UNIQUE INDEX idx_permissions_name_active
    ON permissions (tenant_id, name)
    WHERE deleted_at IS NULL;

CREATE INDEX idx_permissions_tenant
    ON permissions (tenant_id)
    WHERE deleted_at IS NULL;

ALTER TABLE permissions
    ADD CONSTRAINT chk_permissions_name CHECK (name ~* '^[a-z0-9:_-]+$');

-- ── api_keys ──────────────────────────────────────────────────────────────────
DROP INDEX  IF EXISTS idx_api_keys_tenant_id;
CREATE INDEX idx_api_keys_tenant_active
    ON api_keys (tenant_id)
    WHERE revoked_at IS NULL AND deleted_at IS NULL;

ALTER TABLE api_keys
    ADD CONSTRAINT chk_api_keys_name CHECK (char_length(name) BETWEEN 1 AND 200);

-- ── password_reset_tokens ─────────────────────────────────────────────────────
CREATE INDEX brin_prt_created ON password_reset_tokens USING BRIN (created_at);

-- ── app_rate_limits ───────────────────────────────────────────────────────────
ALTER TABLE app_rate_limits
    ADD CONSTRAINT chk_app_limits_rpm    CHECK (requests_per_minute > 0),
    ADD CONSTRAINT chk_app_limits_burst  CHECK (burst >= 0),
    ADD CONSTRAINT chk_app_limits_app_id CHECK (app_id ~* '^[a-z0-9._-]+$');

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_tenants_slug_active;
ALTER TABLE tenants DROP CONSTRAINT IF EXISTS chk_tenants_name;
ALTER TABLE tenants DROP CONSTRAINT IF EXISTS chk_tenants_slug;
ALTER TABLE tenants ADD CONSTRAINT tenants_slug_key UNIQUE (slug);

DROP INDEX IF EXISTS idx_users_email_active;
DROP INDEX IF EXISTS idx_users_login_covering;
DROP INDEX IF EXISTS idx_users_tenant;
DROP INDEX IF EXISTS idx_users_role;
ALTER TABLE users DROP CONSTRAINT IF EXISTS chk_users_email;
CREATE UNIQUE INDEX idx_users_tenant_email ON users (tenant_id, email);
ALTER TABLE users ADD CONSTRAINT users_tenant_id_email_key UNIQUE (tenant_id, email);

DROP INDEX IF EXISTS idx_roles_name_active;
DROP INDEX IF EXISTS idx_roles_tenant;
ALTER TABLE roles DROP CONSTRAINT IF EXISTS chk_roles_name;
ALTER TABLE roles ADD CONSTRAINT roles_tenant_id_name_key UNIQUE (tenant_id, name);

DROP INDEX IF EXISTS idx_permissions_name_active;
DROP INDEX IF EXISTS idx_permissions_tenant;
ALTER TABLE permissions DROP CONSTRAINT IF EXISTS chk_permissions_name;
ALTER TABLE permissions ADD CONSTRAINT permissions_tenant_name_key UNIQUE (tenant_id, name);
CREATE INDEX idx_permissions_tenant_id ON permissions (tenant_id);

DROP INDEX IF EXISTS idx_api_keys_tenant_active;
ALTER TABLE api_keys DROP CONSTRAINT IF EXISTS chk_api_keys_name;
CREATE INDEX idx_api_keys_tenant_id ON api_keys (tenant_id);

DROP INDEX IF EXISTS brin_prt_created;

ALTER TABLE app_rate_limits DROP CONSTRAINT IF EXISTS chk_app_limits_rpm;
ALTER TABLE app_rate_limits DROP CONSTRAINT IF EXISTS chk_app_limits_burst;
ALTER TABLE app_rate_limits DROP CONSTRAINT IF EXISTS chk_app_limits_app_id;
-- +goose StatementEnd
