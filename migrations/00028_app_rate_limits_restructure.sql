-- +goose Up
-- +goose StatementBegin
-- The original schema used app_id TEXT as the PRIMARY KEY, which caused a global
-- collision bug: two tenants with the same app_id string would conflict.
-- This migration introduces a BIGINT surrogate PK and makes app_id a regular column
-- unique PER tenant (partial unique WHERE deleted_at IS NULL).

-- Step 1: add BIGINT IDENTITY column (auto-populates existing rows)
ALTER TABLE app_rate_limits ADD COLUMN id BIGINT GENERATED ALWAYS AS IDENTITY;

-- Step 2: drop old PK on app_id TEXT
ALTER TABLE app_rate_limits DROP CONSTRAINT app_rate_limits_pkey;

-- Step 3: promote new BIGINT column to PK
ALTER TABLE app_rate_limits ADD PRIMARY KEY (id);

-- Step 4: drop old non-partial tenant index (replaced by partial one below)
DROP INDEX IF EXISTS idx_app_rate_limits_tenant_id;

-- Step 5: partial unique on (tenant_id, app_id) — app_id is now per-tenant unique
CREATE UNIQUE INDEX idx_app_limits_tenant_app
    ON app_rate_limits (tenant_id, app_id)
    WHERE deleted_at IS NULL;

CREATE INDEX idx_app_limits_tenant
    ON app_rate_limits (tenant_id)
    WHERE deleted_at IS NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_app_limits_tenant_app;
DROP INDEX IF EXISTS idx_app_limits_tenant;
ALTER TABLE app_rate_limits DROP CONSTRAINT IF EXISTS app_rate_limits_pkey;
ALTER TABLE app_rate_limits DROP COLUMN IF EXISTS id;
ALTER TABLE app_rate_limits ADD PRIMARY KEY (app_id);
CREATE INDEX idx_app_rate_limits_tenant_id ON app_rate_limits (tenant_id);
-- +goose StatementEnd
