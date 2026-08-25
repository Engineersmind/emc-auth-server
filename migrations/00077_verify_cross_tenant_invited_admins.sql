-- +goose Up
-- +goose StatementBegin

-- Repair accounts that accepted an invitation but were never marked verified.
--
-- InvitationService.Accept updated the recipient with
--
--     WHERE id = $1 AND tenant_id = $2
--
-- where $2 is the tenant the invitation grants administration of. But
-- users.tenant_id is the account's HOME tenant — where its credentials live —
-- and migration 00071 established that the two are different axes. For a
-- cross-tenant invitation they differ, so the predicate matched zero rows: the
-- link was consumed, the administrative grant activated, and email_verified was
-- silently left false.
--
-- The consequence was not cosmetic. countUsableAdmins requires email_verified,
-- so such an owner never counted as usable. A tenant with two accepted owners
-- reported one, and removing the other was refused with last_owner — "appoint
-- another owner first" — when another owner had already been appointed AND had
-- accepted. The tenant was stuck.
--
-- The predicate is dropped in code (the row is identified by the user id carried
-- in the single-use token, so there is no caller-supplied value for a tenant
-- check to defend). This migration fixes the rows already written.
--
-- Deliberately narrow. Only accounts with a USED invitation are touched: a used
-- row means the recipient proved control of the address by following a 256-bit
-- single-use link, which is exactly what verification asserts. An account with no
-- used invitation has proved nothing and is left alone.
--
-- is_active is NOT touched. Accept sets it to (blocked_at IS NULL), and forcing
-- it true here would silently unblock a locked-out account.

UPDATE users u
SET email_verified = true, updated_at = NOW()
WHERE NOT u.email_verified
  AND u.deleted_at IS NULL
  AND EXISTS (
    SELECT 1 FROM user_invitations ui
    WHERE ui.user_id = u.id AND ui.used_at IS NOT NULL
  );

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- Not reversible: which accounts were verified by this migration rather than by
-- their own acceptance is not recorded, and re-clearing the flag would lock
-- legitimately verified administrators out of counting as usable — the very
-- failure this repairs. Down is deliberately a no-op.
SELECT 1;

-- +goose StatementEnd
