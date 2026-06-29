-- +goose Up
-- +goose StatementBegin
-- Make permissions tenant-scoped (not system-global).
-- Previously, permissions had UNIQUE(name) which meant permission names were
-- shared across all tenants. The corrected model: each tenant defines its own
-- permission set. Two tenants can both have a permission named "invoice:read"
-- independently. The unique constraint is now (tenant_id, name).

-- Step 1: drop the old global unique constraint
ALTER TABLE permissions DROP CONSTRAINT IF EXISTS permissions_name_key;

-- Step 2: add tenant_id column (nullable first so ALTER is safe on any existing rows)
ALTER TABLE permissions ADD COLUMN IF NOT EXISTS tenant_id BIGINT REFERENCES tenants(id) ON DELETE CASCADE;

-- Step 3: remove any orphaned rows that predate this migration (dev-only seed rows)
DELETE FROM permissions WHERE tenant_id IS NULL;

-- Step 4: enforce NOT NULL now that orphaned rows are gone
ALTER TABLE permissions ALTER COLUMN tenant_id SET NOT NULL;

-- Step 5: add per-tenant unique constraint
ALTER TABLE permissions ADD CONSTRAINT permissions_tenant_name_key UNIQUE (tenant_id, name);

-- Step 6: add index for tenant-scoped lookups
CREATE INDEX IF NOT EXISTS idx_permissions_tenant_id ON permissions (tenant_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_permissions_tenant_id;
ALTER TABLE permissions DROP CONSTRAINT IF EXISTS permissions_tenant_name_key;
ALTER TABLE permissions DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE permissions ADD CONSTRAINT permissions_name_key UNIQUE (name);
-- +goose StatementEnd
