package admin

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// ---------------------------------------------------------------------------
// Dual-write bridge to admin_grants (migration 00078).
//
// While ADMIN_GRANTS_ENABLED is off, tenant_admins + tenant_admin_app_scopes
// remain authoritative and admin_grants is a mirror. While it is on, the mirror
// is what resolves every token's reach. Keeping both current means the flag can
// be flipped in either direction without a backfill, which is the whole reason
// step 3 of the plan is reversible.
//
// The mirror is derived, never authored: mirrorAdminGrants reads the legacy rows
// inside the caller's transaction and makes admin_grants match them. That is
// deliberately not the same as translating each individual write — a translation
// has to be correct at six call sites (create, promote, demote, grant, revoke,
// remove) and stays correct only if every future call site remembers. Deriving
// the whole picture for one administrator is idempotent, so a caller that
// forgets to call it leaves a stale mirror rather than a wrong one, and calling
// it twice is free.
//
// Every caller MUST hold the same per-tenant lock the legacy write holds.
// mirrorAdminGrants does not take one: it runs inside a transaction that already
// has it, and acquiring a second would invert the lock order.
// ---------------------------------------------------------------------------

// mirrorAdminGrants makes admin_grants match the tenant_admins state for one
// (tenant, user) pair, inside the caller's transaction.
//
// Call it after any write to tenant_admins or tenant_admin_app_scopes for that
// pair — including soft-deletion, where it is what retires the mirror rows.
//
// The shapes deliberately do not correspond one-to-one:
//
//	legacy owner    → exactly one grant, application_id NULL (absence means all)
//	legacy co_owner → one grant per granted application
//	legacy removed  → every live grant soft-deleted
//
// A co-owner holding zero applications produces zero grants, matching the 00062
// rule that grants only ever narrow: such an administrator has no application
// access at all, and inventing a row here would widen their authority.
func mirrorAdminGrants(ctx context.Context, tx pgx.Tx, tenantID, userID int64) error {
	// The legacy row for this pair, if any. A soft-deleted or absent row means
	// the administrator has no reach, which the retirement branch below handles.
	// activated_at is not read here — the statements below copy it directly from
	// tenant_admins so the mirror cannot drift from the column that decides
	// whether reach exists at all.
	var adminID int64
	var adminRole string
	err := tx.QueryRow(ctx, `
		SELECT id, admin_role
		FROM tenant_admins
		WHERE tenant_id = $1 AND user_id = $2 AND deleted_at IS NULL
	`, tenantID, userID).Scan(&adminID, &adminRole)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return retireAdminGrants(ctx, tx, tenantID, userID)
		}
		return fmt.Errorf("mirror: read tenant admin: %w", err)
	}

	// Retire anything that no longer belongs. Doing this first keeps the unique
	// indexes free for the inserts below — a demoted owner's NULL-application row
	// has to go before co-owner rows can be written, and a promoted co-owner's
	// application rows have to go before the owner row can be.
	//
	// Soft-delete rather than DELETE, so the audit trail of who administered what
	// survives, and so a re-grant does not collide with its own tombstone
	// (admin_grants' unique indexes are partial on deleted_at IS NULL).
	if adminRole == "owner" {
		if _, err = tx.Exec(ctx, `
			UPDATE admin_grants SET deleted_at = NOW(), updated_at = NOW()
			WHERE user_id = $1 AND tenant_id = $2 AND deleted_at IS NULL
			  AND (admin_role <> 'owner' OR application_id IS NOT NULL)
		`, userID, tenantID); err != nil {
			return fmt.Errorf("mirror: retire non-owner grants: %w", err)
		}
		// One owner grant, carrying the legacy activation state so a pending
		// invitation stays pending in the mirror. activated_at is copied rather
		// than recomputed: it is the column that decides whether reach exists at
		// all, and diverging on it would hand a pending administrator authority.
		if _, err = tx.Exec(ctx, `
			INSERT INTO admin_grants (user_id, tenant_id, admin_role, application_id, activated_at)
			SELECT $1, $2, 'owner', NULL, ta.activated_at
			FROM tenant_admins ta WHERE ta.id = $3
			ON CONFLICT DO NOTHING
		`, userID, tenantID, adminID); err != nil {
			return fmt.Errorf("mirror: upsert owner grant: %w", err)
		}
		// An existing owner grant may predate a change in activation state.
		if _, err = tx.Exec(ctx, `
			UPDATE admin_grants g SET activated_at = ta.activated_at, updated_at = NOW()
			FROM tenant_admins ta
			WHERE ta.id = $3 AND g.user_id = $1 AND g.tenant_id = $2
			  AND g.admin_role = 'owner' AND g.application_id IS NULL AND g.deleted_at IS NULL
			  AND (g.activated_at IS NULL) <> (ta.activated_at IS NULL)
		`, userID, tenantID, adminID); err != nil {
			return fmt.Errorf("mirror: sync owner activation: %w", err)
		}
		return nil
	}

	// co_owner: the mirror must name exactly the applications the legacy scopes
	// name. Retire the owner row (if this is a demotion) and any application no
	// longer granted, in one statement per reason so the predicates stay legible.
	if _, err = tx.Exec(ctx, `
		UPDATE admin_grants SET deleted_at = NOW(), updated_at = NOW()
		WHERE user_id = $1 AND tenant_id = $2 AND deleted_at IS NULL
		  AND (
		    admin_role = 'owner'
		    OR application_id IS NULL
		    OR application_id NOT IN (
		        SELECT sc.application_id FROM tenant_admin_app_scopes sc WHERE sc.admin_id = $3)
		  )
	`, userID, tenantID, adminID); err != nil {
		return fmt.Errorf("mirror: retire stale co-owner grants: %w", err)
	}

	if _, err = tx.Exec(ctx, `
		INSERT INTO admin_grants (user_id, tenant_id, admin_role, application_id, activated_at)
		SELECT $1, $2, 'co_owner', sc.application_id, ta.activated_at
		FROM tenant_admin_app_scopes sc
		JOIN tenant_admins ta ON ta.id = sc.admin_id
		WHERE sc.admin_id = $3
		ON CONFLICT DO NOTHING
	`, userID, tenantID, adminID); err != nil {
		return fmt.Errorf("mirror: upsert co-owner grants: %w", err)
	}

	if _, err = tx.Exec(ctx, `
		UPDATE admin_grants g SET activated_at = ta.activated_at, updated_at = NOW()
		FROM tenant_admins ta
		WHERE ta.id = $3 AND g.user_id = $1 AND g.tenant_id = $2
		  AND g.admin_role = 'co_owner' AND g.deleted_at IS NULL
		  AND (g.activated_at IS NULL) <> (ta.activated_at IS NULL)
	`, userID, tenantID, adminID); err != nil {
		return fmt.Errorf("mirror: sync co-owner activation: %w", err)
	}

	return nil
}

// retireAdminGrants soft-deletes every live grant for a (tenant, user) pair.
//
// Used when the legacy administration row is gone — removal, or a user who never
// had one. Scoped to the ONE tenant: a multi-tenant administrator losing their
// grant in tenant B must keep tenant A, which is the whole point of the new
// model and the easiest thing to get wrong here.
func retireAdminGrants(ctx context.Context, tx pgx.Tx, tenantID, userID int64) error {
	if _, err := tx.Exec(ctx, `
		UPDATE admin_grants SET deleted_at = NOW(), updated_at = NOW()
		WHERE user_id = $1 AND tenant_id = $2 AND deleted_at IS NULL
	`, userID, tenantID); err != nil {
		return fmt.Errorf("mirror: retire grants: %w", err)
	}
	return nil
}
