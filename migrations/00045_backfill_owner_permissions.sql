-- +goose Up
-- +goose StatementBegin

-- Backfill the granular tenant-admin permission catalog for tenants created
-- before newer permissions were added to admin.defaultPermissions. Tenant
-- creation seeds the catalog once and attaches it to the auto-created owner
-- role, but was never re-run for existing tenants — leaving e.g. an older
-- tenant's owner without stats:read even though /tenants/:tid/stats requires
-- it. This must stay in sync with defaultPermissions in internal/admin.

WITH catalog(name, description) AS (
    VALUES
        ('users:read',        'Read users in the tenant'),
        ('users:write',       'Create and update users in the tenant'),
        ('roles:read',        'Read roles in the tenant'),
        ('roles:write',       'Create and update roles in the tenant'),
        ('permissions:read',  'Read permissions in the tenant'),
        ('permissions:write', 'Create and update permissions in the tenant'),
        ('apps:read',         'Read applications, API keys, agents, and rate limits in the tenant'),
        ('apps:write',        'Create and update applications, API keys, agents, and rate limits in the tenant'),
        ('audit:read',        'Read the tenant audit log'),
        ('stats:read',        'Read tenant monitoring statistics'),
        ('saml:manage',       'Configure SAML SSO for the tenant')
)
INSERT INTO permissions (tenant_id, application_id, name, description)
SELECT r.tenant_id, NULL, c.name, c.description
FROM roles r
CROSS JOIN catalog c
WHERE r.name = 'owner' AND r.is_system = true
  AND r.application_id IS NULL AND r.deleted_at IS NULL
ON CONFLICT (tenant_id, name) WHERE application_id IS NULL AND deleted_at IS NULL DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id, tenant_id)
SELECT r.id, p.id, r.tenant_id
FROM roles r
JOIN permissions p
  ON p.tenant_id = r.tenant_id
 AND p.application_id IS NULL
 AND p.deleted_at IS NULL
 AND p.name IN ('users:read', 'users:write', 'roles:read', 'roles:write',
                'permissions:read', 'permissions:write', 'apps:read', 'apps:write',
                'audit:read', 'stats:read', 'saml:manage')
WHERE r.name = 'owner' AND r.is_system = true
  AND r.application_id IS NULL AND r.deleted_at IS NULL
ON CONFLICT DO NOTHING;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- Irreversible backfill: there is no record of which permission rows or
-- attachments predate this migration, so removing them could strip
-- permissions that tenants held legitimately. Intentionally a no-op.
SELECT 1;

-- +goose StatementEnd
