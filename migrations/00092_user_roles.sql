-- +goose Up
-- +goose StatementBegin

-- Multiple roles per user — issue #146, phase 2.
--
-- users.role_id is a single scalar, so a user holds exactly one role and an
-- operator who needs "editor AND approver" has to create an editor_approver
-- role. That composes combinatorially: every new axis doubles the role count,
-- and the resulting bundles record nothing about WHY somebody holds them. No
-- major identity provider ships single-role for this reason.
--
-- ADDITIVE. users.role_id is retained as the PRIMARY role and keeps its meaning:
-- it is what registration's default-role path writes, what the `role` JWT claim
-- carries, and what the ~20 scalar read sites already select. Nothing has to
-- migrate in lockstep with this table, which is what makes the change shippable
-- in one release rather than a coordinated cutover.
--
-- Union semantics only. A user's permissions are the union of every role they
-- hold, deduplicated. No deny rules and no precedence between roles: the moment
-- one role can subtract from another, "why can this user do X" stops being
-- answerable by reading a table and starts requiring a policy evaluation.
CREATE TABLE IF NOT EXISTS user_roles (
    user_id    BIGINT NOT NULL REFERENCES users(id)   ON DELETE CASCADE,
    role_id    BIGINT NOT NULL REFERENCES roles(id)   ON DELETE CASCADE,
    -- Denormalised from users.tenant_id so every read in this codebase can keep
    -- its tenant predicate without a join back to users. User ids are only
    -- unique within a tenant, so a query that filters on user_id alone is a
    -- cross-tenant leak waiting to happen.
    tenant_id  BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Revocation provenance: who granted this, so "remove what the security team
    -- gave them, leave what support gave them" is answerable. SET NULL rather
    -- than CASCADE — losing the grantor's account must never silently revoke the
    -- grants they issued.
    granted_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- (user_id, role_id) is the natural key: holding a role twice is meaningless,
    -- and this makes an add idempotent rather than duplicating a row.
    PRIMARY KEY (user_id, role_id)
);

-- Permission resolution reads every role a user holds on each login, so this is
-- the hot path.
CREATE INDEX IF NOT EXISTS idx_user_roles_user
    ON user_roles (user_id, tenant_id);

-- "Who holds this role" — needed when a role is deleted, to detach and revoke
-- its holders without a sequential scan.
CREATE INDEX IF NOT EXISTS idx_user_roles_role
    ON user_roles (role_id);

-- Backfill: every user who currently holds a role holds it here too, so the new
-- resolution path returns exactly what the old one did on day one. granted_by is
-- NULL because the historic grantor was never recorded — inventing one would be
-- worse than admitting it is unknown.
--
-- Soft-deleted roles and users are excluded: #146 made role deletion soft, and
-- copying a tombstoned grant forward would resurrect permissions the operator
-- already revoked.
INSERT INTO user_roles (user_id, role_id, tenant_id, granted_by, granted_at)
SELECT u.id, u.role_id, u.tenant_id, NULL, COALESCE(u.created_at, NOW())
FROM users u
JOIN roles r ON r.id = u.role_id AND r.deleted_at IS NULL
WHERE u.role_id IS NOT NULL
  AND u.deleted_at IS NULL
ON CONFLICT (user_id, role_id) DO NOTHING;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- Safe to drop: users.role_id was never stopped being written, so the scalar
-- column still holds each user's primary role and resolution falls back to it
-- exactly as before. Roles granted ONLY through this table (never promoted to
-- role_id) are lost, which is the unavoidable cost of reversing a widening.
DROP INDEX IF EXISTS idx_user_roles_role;
DROP INDEX IF EXISTS idx_user_roles_user;
DROP TABLE IF EXISTS user_roles;

-- +goose StatementEnd
