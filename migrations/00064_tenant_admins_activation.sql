-- +goose Up
-- +goose StatementBegin

-- An administrative grant does not take effect until the recipient confirms it
-- by email (issue #97).
--
-- Previously a grant was live the moment an operator created it, and for an
-- address that already had a verified account it was live with no notification
-- at all — most visibly when re-adding a previously removed administrator, who
-- regained authority silently. Consent now comes from the grantee, not only
-- from the operator.
--
-- activated_at NULL means "granted but not yet confirmed". Such a row:
--   * contributes no admin_scope to the token (loadAdminScope skips it),
--   * carries no RBAC role — users.role_id is left alone until confirmation, so
--     a pending administrator holds exactly the permissions they held before,
--   * does not satisfy the last-usable-owner guard.
--
-- Backfill: existing live grants are treated as already confirmed when the
-- account is verified, which is the same condition that previously decided
-- whether the listing showed "active". Unverified ones stay NULL and are picked
-- up by the normal confirmation flow. This deliberately does not invalidate
-- working administrators on deploy.

ALTER TABLE tenant_admins
    ADD COLUMN IF NOT EXISTS activated_at TIMESTAMPTZ;

UPDATE tenant_admins ta
SET activated_at = ta.created_at
FROM users u
WHERE u.id = ta.user_id
  AND ta.deleted_at IS NULL
  AND ta.activated_at IS NULL
  AND u.email_verified = true;

CREATE INDEX IF NOT EXISTS idx_tenant_admins_pending
    ON tenant_admins (user_id)
    WHERE activated_at IS NULL AND deleted_at IS NULL;

-- +goose StatementEnd


-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS idx_tenant_admins_pending;
ALTER TABLE tenant_admins DROP COLUMN IF EXISTS activated_at;

-- +goose StatementEnd
