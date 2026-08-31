-- +goose Up
-- +goose StatementBegin

-- Backfill users.role_id for administrators whose grant activated without it.
--
-- ActivateGrant attached the administrative role with
--
--     UPDATE users SET role_id = $1 ... WHERE id = $2 AND tenant_id = $3
--
-- where $3 is the tenant being ADMINISTERED. But users.tenant_id is the
-- account's HOME tenant — where its credentials live — and migration 00078
-- established the two as separate axes. For a cross-tenant grant they differ, so
-- the predicate matched zero rows and role_id was silently left NULL.
--
-- This is the same defect migration 00077 repaired for email_verified, one
-- column over in the same statement. The predicate is dropped in code; this
-- migration fixes the rows already written.
--
-- The consequence was worse than 00077's. Login resolves permissions by joining
-- users.role_id -> role_permissions, so a NULL role_id mints an access token
-- carrying NO permissions. Every permission-gated surface then returned 403 for
-- a legitimately activated administrator. It went unnoticed because switching
-- tenants re-mints through a different path (loadAdminPermissionsForTenant,
-- which resolves by admin role and never reads role_id), so the account worked
-- until the next fresh login.
--
-- Deliberately narrow, in the spirit of 00077:
--
--   * Only accounts with a LIVE, ACTIVATED tenant_admins row are touched. An
--     activated grant is the event that was supposed to set role_id, so this
--     repairs exactly what the broken statement should have written.
--   * Only role_id IS NULL is rewritten. An account that already carries a role
--     is left alone — including one holding a different role than its grant
--     implies, which is a separate question this migration must not decide.
--   * The role is resolved the same way ActivateGrant resolves it: by name,
--     within the ADMINISTERED tenant, tenant-level (application_id IS NULL).
--
-- Where an account holds several activated grants (the cross-tenant case), the
-- grant in the account's OWN home tenant wins; failing that, the oldest grant.
-- users.role_id is one column, so one grant has to win, and the home tenant is
-- the meaningful choice: that column sits beside users.tenant_id and is read by
-- login, which resolves permissions in the account's home tenant. Falling back
-- to the oldest keeps the pick deterministic for an administrator who holds no
-- grant at home. Reach into the other tenants is unaffected — that comes from
-- tenant_admins and admin_grants, not from this column.
--
-- token_version is NOT bumped. Any token minted before this ran carries no
-- permissions and is already useless; invalidating sessions across the estate to
-- replace one broken token with another is a cost with no benefit. Affected
-- administrators pick up their permissions on next login.

UPDATE users u
SET role_id = pick.role_id, updated_at = NOW()
FROM (
    SELECT DISTINCT ON (ta.user_id)
           ta.user_id,
           r.id AS role_id
    FROM tenant_admins ta
    JOIN users tu
      ON tu.id = ta.user_id
    JOIN roles r
      ON r.tenant_id = ta.tenant_id
     AND r.name = ta.admin_role
     AND r.application_id IS NULL
     AND r.deleted_at IS NULL
    WHERE ta.deleted_at IS NULL
      AND ta.activated_at IS NOT NULL
    ORDER BY ta.user_id,
             (ta.tenant_id = tu.tenant_id) DESC,
             ta.created_at ASC
) AS pick
WHERE u.id = pick.user_id
  AND u.role_id IS NULL
  AND u.deleted_at IS NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- Not reversible. Which accounts had role_id set by this migration rather than
-- by their own activation is not recorded, and re-clearing it would restore the
-- zero-permission login this repairs. Down is deliberately a no-op.
SELECT 1;

-- +goose StatementEnd
