package auth

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ---------------------------------------------------------------------------
// Tenant administration scope resolution (issue #97).
//
// tenant_admins records who administers a tenant, separately from the
// application end users in the same users table. Two tiers live there:
//
//	owner     — every application in the tenant, present and future. Holds no
//	            rows in tenant_admin_app_scopes at all.
//	co_owner  — only the applications named in tenant_admin_app_scopes.
//
// The platform tier (super_admin, tenant:manage) is deliberately absent: it is
// cross-tenant and is authorised by permission, not by membership in any one
// tenant.
// ---------------------------------------------------------------------------

// Admin role values stored in tenant_admins.admin_role. Kept in sync with the
// CHECK constraint in migration 00062.
const (
	AdminRoleOwner   = "owner"
	AdminRoleCoOwner = "co_owner"
)

// activatePendingAdminGrant confirms an administrative grant that was created
// but not yet accepted, and attaches the RBAC role that carries its permissions.
//
// The role is deliberately NOT assigned when the grant is created. Until the
// recipient follows the emailed link the account holds exactly the permissions
// it held before, so an operator alone cannot make someone an administrator —
// most importantly when re-instating someone who was previously removed, which
// used to take effect silently because their address was already verified.
//
// A no-op when there is no pending grant, which is the common case: most
// invitations are ordinary application users.
func activatePendingAdminGrant(ctx context.Context, tx pgx.Tx, userID, tenantID int64) error {
	var adminID int64
	var adminRole string
	err := tx.QueryRow(ctx, `
		SELECT id, admin_role FROM tenant_admins
		WHERE user_id = $1 AND tenant_id = $2 AND deleted_at IS NULL AND activated_at IS NULL
		FOR UPDATE
	`, userID, tenantID).Scan(&adminID, &adminRole)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return fmt.Errorf("look up pending admin grant: %w", err)
	}

	var roleID int64
	err = tx.QueryRow(ctx, `
		SELECT id FROM roles
		WHERE tenant_id = $1 AND name = $2 AND application_id IS NULL AND deleted_at IS NULL
	`, tenantID, adminRole).Scan(&roleID)
	if err != nil {
		// The role is seeded when the grant is created, so its absence means
		// someone deleted it underneath us. Refuse rather than activate a grant
		// that would carry no permissions and look active in the listing.
		return fmt.Errorf("resolve %s role for tenant %d: %w", adminRole, tenantID, err)
	}

	if _, err = tx.Exec(ctx,
		`UPDATE tenant_admins SET activated_at = NOW(), updated_at = NOW() WHERE id = $1`, adminID,
	); err != nil {
		return fmt.Errorf("activate admin grant: %w", err)
	}
	// Mirror the activation into admin_grants (00078), inside this transaction.
	//
	// This is the write that confers authority, so the two models must not
	// disagree on it: a mirror left pending would deny a legitimately activated
	// administrator the moment ADMIN_GRANTS_ENABLED is flipped, and a mirror
	// activated early would hand reach to someone who never accepted.
	if _, err = tx.Exec(ctx, `
		UPDATE admin_grants g SET activated_at = NOW(), updated_at = NOW()
		FROM tenant_admins ta
		WHERE ta.id = $1
		  AND g.user_id = ta.user_id AND g.tenant_id = ta.tenant_id
		  AND g.admin_role = ta.admin_role
		  AND g.deleted_at IS NULL AND g.activated_at IS NULL
	`, adminID); err != nil {
		return fmt.Errorf("activate admin grant mirror: %w", err)
	}
	// token_version is bumped here rather than relying on the caller. Accept
	// bumps it too, but this function is the one that changes what the account
	// may do, so the invalidation belongs with the change: any future caller
	// gets it without having to know to ask.
	//
	// Keyed on the user alone. It previously carried `AND tenant_id = $3`, where
	// $3 is the tenant being ADMINISTERED — but users.tenant_id is the account's
	// HOME tenant, and 00078 established those as separate axes. For a
	// cross-tenant grant they differ, so the predicate matched zero rows: the
	// grant activated while role_id stayed NULL, and login's loadPermissions
	// joins through role_id, so the account minted tokens carrying no
	// permissions at all. Every permission-gated page then 403'd. This is the
	// same defect migration 00077 repaired for email_verified, one column over.
	//
	// Dropping the tenant predicate is safe: userID comes from the tenant_admins
	// row read at the top of this transaction, so it is already the right account.
	res, err := tx.Exec(ctx,
		`UPDATE users SET role_id = $1, token_version = token_version + 1, updated_at = NOW()
		 WHERE id = $2 AND deleted_at IS NULL`, roleID, userID,
	)
	if err != nil {
		return fmt.Errorf("attach administrative role: %w", err)
	}
	// A grant that activates without attaching its role is the exact silent
	// failure above, so refuse rather than commit a half-applied activation.
	if res.RowsAffected() == 0 {
		return fmt.Errorf("attach administrative role: user %d not found", userID)
	}
	// Every live session ends when a grant activates, and unlike the password
	// branch in Accept this is unconditional.
	//
	// It has to be. Accepting without changing the password is the ordinary path
	// for someone already working in the tenant, and it is exactly the path that
	// raises their authority. A refresh token captured before the grant existed
	// would otherwise keep minting access tokens — now carrying admin_scope,
	// because rotation re-reads the grant it was stolen ahead of. Signing an
	// incoming administrator out once is a cheap price for that not being true.
	if err = RevokeAllSessionsTx(ctx, tx, userID, tenantID, RevokeReasonCredentialChange); err != nil {
		return fmt.Errorf("revoke sessions on admin grant activation: %w", err)
	}
	return nil
}

// loadAdminScope resolves a user's administrative reach over their tenant's
// applications, in the form the JWT carries it.
//
// Returns ("", nil) for a user who is not a tenant administrator — the common
// case, and the reason this stays a single indexed lookup that usually misses.
//
// An owner returns (AdminScopeTenant, nil): no application list is produced,
// because an owner's reach is defined by the absence of grants rather than by
// enumerating them. Enumerating would freeze the list at token-issue time, so
// an application created a minute later would be invisible to its own tenant
// owner until they logged in again.
func loadAdminScope(ctx context.Context, pool *pgxpool.Pool, userID, tenantID int64) (string, []string, error) {
	var adminID int64
	var adminRole string
	// activated_at IS NOT NULL: a grant the recipient has not yet confirmed
	// carries no reach at all, matching the fact that it carries no RBAC role.
	err := pool.QueryRow(ctx, `
		SELECT id, admin_role
		FROM tenant_admins
		WHERE user_id = $1 AND tenant_id = $2 AND deleted_at IS NULL AND activated_at IS NOT NULL
	`, userID, tenantID).Scan(&adminID, &adminRole)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil, nil
		}
		return "", nil, fmt.Errorf("load admin scope: %w", err)
	}

	if adminRole == AdminRoleOwner {
		return AdminScopeTenant, nil, nil
	}

	rows, err := pool.Query(ctx, `
		SELECT application_id FROM tenant_admin_app_scopes WHERE admin_id = $1 ORDER BY application_id
	`, adminID)
	if err != nil {
		return "", nil, fmt.Errorf("load admin app grants: %w", err)
	}
	defer rows.Close()

	// Non-nil empty slice, not nil: a co-owner whose last grant was revoked has
	// AdminScopeApps with an empty list, which RequireAppScope denies. Returning
	// nil here would be indistinguishable from "not an administrator" to any
	// caller that checks the slice rather than the scope.
	apps := []string{}
	for rows.Next() {
		var appID int64
		if err := rows.Scan(&appID); err != nil {
			return "", nil, fmt.Errorf("scan admin app grant: %w", err)
		}
		apps = append(apps, strconv.FormatInt(appID, 10))
	}
	if err := rows.Err(); err != nil {
		return "", nil, fmt.Errorf("iterate admin app grants: %w", err)
	}
	return AdminScopeApps, apps, nil
}
