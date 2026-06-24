-- +goose Up
-- +goose StatementBegin
ALTER TABLE role_permissions
    ADD COLUMN IF NOT EXISTS tenant_id  BIGINT REFERENCES tenants(id) ON DELETE CASCADE,
    ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

-- Backfill tenant_id from the parent role (denormalized for RLS).
UPDATE role_permissions rp
SET    tenant_id = r.tenant_id
FROM   roles r
WHERE  r.id = rp.role_id AND rp.tenant_id IS NULL;

ALTER TABLE role_permissions ALTER COLUMN tenant_id SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_role_permissions_perm   ON role_permissions (permission_id);
CREATE INDEX IF NOT EXISTS idx_role_permissions_tenant ON role_permissions (tenant_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_role_permissions_perm;
DROP INDEX IF EXISTS idx_role_permissions_tenant;
ALTER TABLE role_permissions
    DROP COLUMN IF EXISTS tenant_id,
    DROP COLUMN IF EXISTS created_at;
-- +goose StatementEnd
