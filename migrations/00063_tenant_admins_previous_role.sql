-- +goose Up
-- +goose StatementBegin

-- Remember what role an administrator held before they were promoted, so that
-- withdrawing administration can put it back (issue #97).
--
-- Two problems this fixes, both stemming from InviteTenantAdmin overwriting
-- users.role_id with no record of the previous value:
--
--  1. Removal left the administrative role attached. tenant_admins is
--     soft-deleted, so loadAdminScope stops finding a row and the next token is
--     issued with NO admin_scope — which RequireTenantSelfOrAny deliberately
--     treats as tenant-wide, because a token predating the claim has to keep
--     working. A removed co-owner therefore signed back in holding every
--     tenant-admin permission across the WHOLE tenant, which is strictly more
--     authority than they had while they were a co-owner. Removal escalated.
--
--  2. Promoting an existing tenant user discarded whatever role they already
--     had, and nothing could restore it afterwards.
--
-- NULL means "held no role before promotion", which is also the value used for
-- administrators created by the promotion itself and for owners backfilled by
-- migration 00062. Restoring NULL is the fail-closed outcome: the account keeps
-- existing and keeps its history, but carries no permissions.

ALTER TABLE tenant_admins
    ADD COLUMN IF NOT EXISTS previous_role_id BIGINT REFERENCES roles(id) ON DELETE SET NULL;

-- Repair rows already stranded by the bug: any live tenant-level user still
-- carrying an 'owner' or 'co_owner' role whose administration has been
-- withdrawn. There is no record of what they held before, so they are stripped
-- rather than guessed at — an operator who removed them intended them to stop
-- administering, and re-inviting is one call.
UPDATE users u
SET role_id = NULL, updated_at = NOW()
FROM roles r
WHERE r.id = u.role_id
  AND r.name IN ('owner', 'co_owner')
  AND r.is_system = true
  AND r.application_id IS NULL
  AND u.application_id IS NULL
  AND u.deleted_at IS NULL
  AND NOT EXISTS (
      SELECT 1 FROM tenant_admins ta
      WHERE ta.user_id = u.id AND ta.deleted_at IS NULL
  );

-- +goose StatementEnd


-- +goose Down
-- +goose StatementBegin

-- The stripped roles above are not restored: there is no record of which users
-- the UPDATE touched, and re-attaching an admin role to accounts that no longer
-- administer anything would recreate the escalation this migration closes.
ALTER TABLE tenant_admins DROP COLUMN IF EXISTS previous_role_id;

-- +goose StatementEnd
