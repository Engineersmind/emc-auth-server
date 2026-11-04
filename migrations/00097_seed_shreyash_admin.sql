-- +goose Up
-- +goose StatementBegin

-- One-time additional platform administrator, alongside the seeded
-- admin@emc.local account from RunSeed. Mirrors RunSeed's own pattern:
-- both users.role_id AND a matching user_roles row are set, since #146
-- made user_roles the table loadPermissions actually resolves from — a
-- role_id-only account signs in with zero permissions.
--
-- A real credential is included (bcrypt, cost 12) since there is no
-- existing admin session available to send an invitation through, and
-- forgot-password requires a credential to already exist to reset.
-- Initial password: ChangeMe-Shreyash-01! — change it after first login.
-- Mandatory admin MFA (#150) still applies: first login routes to the
-- forced-enrollment screen like any other new administrator.

INSERT INTO users (tenant_id, email, first_name, last_name, role_id, is_active, email_verified)
SELECT r.tenant_id, 'shreyash+admin01@engineersmind.com', 'Shreyash', 'Admin', r.id, true, true
FROM roles r
WHERE r.name = 'super_admin' AND r.is_system = true
ON CONFLICT (tenant_id, email) WHERE application_id IS NULL AND deleted_at IS NULL DO NOTHING;

INSERT INTO user_credentials (user_id, tenant_id, password_hash)
SELECT u.id, u.tenant_id, '$2b$12$GsM50..lrD.o6Cey1spOo.Cq4jeOSYKnnCKivaZmMkeoKYze3CN3i'
FROM users u
WHERE u.email = 'shreyash+admin01@engineersmind.com'
ON CONFLICT (user_id) DO NOTHING;

INSERT INTO user_roles (user_id, role_id, tenant_id, granted_by)
SELECT u.id, r.id, r.tenant_id, NULL
FROM users u
JOIN roles r ON r.name = 'super_admin' AND r.is_system = true
WHERE u.email = 'shreyash+admin01@engineersmind.com'
ON CONFLICT (user_id, role_id) DO NOTHING;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DELETE FROM user_roles WHERE user_id = (SELECT id FROM users WHERE email = 'shreyash+admin01@engineersmind.com');
DELETE FROM user_credentials WHERE user_id = (SELECT id FROM users WHERE email = 'shreyash+admin01@engineersmind.com');
DELETE FROM users WHERE email = 'shreyash+admin01@engineersmind.com';

-- +goose StatementEnd
