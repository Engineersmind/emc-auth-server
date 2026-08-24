package admin

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// ---------------------------------------------------------------------------
// Privilege-escalation rules for grant writes.
//
// An owner may administer their own tenants, which now includes inviting
// co-owners to them. RequireTenantSelfOrAny already decides WHETHER a caller may
// write here: it admits tenant:manage for any tenant, admits an owner in their
// own tenant, and refuses a co-owner outright (an app-scoped administrator has
// no authority over tenant-level resources). What it cannot express is what an
// owner may write once admitted, because that depends on the CONTENT of the
// request rather than on the route.
//
// The rules below close the gap. Without them, an owner holding users:write can
// mint a peer owner — an account with authority equal to their own, which can in
// turn mint another. Ownership would be unboundedly self-propagating and the
// owner population would stop being auditable.
//
// Every rule is checked against the actor's own grants read from the database,
// never against a value from the request. The route already proved the caller
// may act in this tenant; these decide what the act may be.
// ---------------------------------------------------------------------------

var (
	// ErrOwnerCannotGrantOwnership is returned when a tenant owner tries to
	// create or promote to another owner. Reserved to the platform tier.
	ErrOwnerCannotGrantOwnership = errors.New("only a platform administrator may grant tenant ownership")

	// ErrCannotModifyOwnGrant is returned when an actor targets their own
	// administrative grant.
	ErrCannotModifyOwnGrant = errors.New("an administrator cannot modify their own grant")

	// ErrOwnerCannotRemoveOwner is returned when a tenant owner tries to remove
	// a peer owner. Reserved to the platform tier, for the same reason as
	// ErrOwnerCannotGrantOwnership.
	ErrOwnerCannotRemoveOwner = errors.New("only a platform administrator may remove a tenant owner")
)

// GrantActor is who is performing a grant write, as established by the route.
//
// IsPlatformAdmin comes from the caller holding tenant:manage — the permission
// that RequireTenantSelfOrAny short-circuits on. It is deliberately a separate
// field from the grants: a platform admin holds no tenant_admins row at all (see
// migration 00062's header), so their authority cannot be discovered by looking
// for one.
type GrantActor struct {
	UserID          int64
	IsPlatformAdmin bool
}

// AssertMayGrant checks whether actor may create or modify a grant of role
// targetRole for targetUserID in tenantID.
//
// Call it BEFORE any write, and inside the same transaction that performs the
// write where one exists — an owner whose own grant is revoked concurrently must
// not have their in-flight invitation succeed on a stale read.
func AssertMayGrant(
	ctx context.Context,
	q pgxQuerier,
	actor GrantActor,
	tenantID, targetUserID int64,
	targetRole string,
) error {
	// A platform administrator may grant anything anywhere. This is the tier that
	// creates tenants and their first owner, so restricting it here would leave
	// nobody able to.
	if actor.IsPlatformAdmin {
		// Rule 4 still applies: not even a platform admin may quietly rewrite
		// their own administrative standing, because a self-write is
		// indistinguishable in the audit log from a legitimate one.
		if targetUserID != 0 && actor.UserID == targetUserID {
			return ErrCannotModifyOwnGrant
		}
		return nil
	}

	// Rule 4: nobody modifies their own grant. Checked before the actor's role is
	// even read, because self-modification is refused regardless of tier — an
	// owner must not be able to promote themselves, and must not be able to
	// revoke or narrow themselves into a tenant with no usable owner.
	if targetUserID != 0 && actor.UserID == targetUserID {
		return ErrCannotModifyOwnGrant
	}

	// The actor's own standing in THIS tenant. A multi-tenant administrator may
	// be an owner of tenant A and a co-owner of tenant B, so the question is
	// always "what are you here", never "what are you".
	actorRole, err := grantRoleInTenant(ctx, q, actor.UserID, tenantID)
	if err != nil {
		return err
	}

	switch actorRole {
	case auth.AdminRoleOwner:
		// Rule 1: an owner may create co-owners only. Ownership is conferred by
		// the platform tier alone.
		if targetRole != auth.AdminRoleCoOwner {
			return ErrOwnerCannotGrantOwnership
		}
		return nil

	case auth.AdminRoleCoOwner:
		// Rule 3: a co-owner never writes grants. RequireTenantSelfOrAny should
		// already have refused them — they hold the same permission NAMES as an
		// owner, so only the AdminScopeApps check stops them — but a service that
		// depends on a middleware for a security decision breaks the first time
		// it is called from somewhere else.
		return fmt.Errorf("%w: this account administers specific applications only", ErrForbiddenGrantWrite)

	default:
		// No live grant in this tenant. The route admitted them on :tid matching
		// their token, which a legacy tenant admin predating admin_grants can
		// satisfy; fail closed rather than infer authority from its absence.
		return fmt.Errorf("%w: no administrative grant in this tenant", ErrForbiddenGrantWrite)
	}
}

// AssertMayRemove checks whether actor may remove the administrator identified
// by targetUserID in tenantID.
//
// Separate from AssertMayGrant because removal has a different asymmetry: an
// owner may remove a co-owner they invited, but not a peer owner (rule 5).
func AssertMayRemove(
	ctx context.Context,
	q pgxQuerier,
	actor GrantActor,
	tenantID, targetUserID int64,
) error {
	if actor.UserID == targetUserID {
		return ErrCannotModifyOwnGrant
	}
	if actor.IsPlatformAdmin {
		return nil
	}

	actorRole, err := grantRoleInTenant(ctx, q, actor.UserID, tenantID)
	if err != nil {
		return err
	}
	if actorRole != auth.AdminRoleOwner {
		return fmt.Errorf("%w: only an owner may remove an administrator", ErrForbiddenGrantWrite)
	}

	targetRole, err := grantRoleInTenant(ctx, q, targetUserID, tenantID)
	if err != nil {
		return err
	}
	// Rule 5: removing a peer owner is platform-admin only. Otherwise two owners
	// can race to remove each other, and the loser's tenant is left to whoever
	// committed first.
	if targetRole == auth.AdminRoleOwner {
		return ErrOwnerCannotRemoveOwner
	}
	return nil
}

// ErrForbiddenGrantWrite is the generic refusal for a grant write the actor's
// standing does not permit. Wrapped with a reason at each site so the audit entry
// says which rule fired.
var ErrForbiddenGrantWrite = errors.New("forbidden grant write")

// grantRoleInTenant returns the actor's live, activated admin role in one
// tenant, or "" when they hold none.
//
// Reads admin_grants rather than tenant_admins: this is a new decision with no
// legacy behaviour to preserve, and admin_grants is the only model that can
// answer it for a multi-tenant administrator. An owner row wins over any
// co-owner row, which the ORDER BY guarantees without a second query.
func grantRoleInTenant(ctx context.Context, q pgxQuerier, userID, tenantID int64) (string, error) {
	var role string
	err := q.QueryRow(ctx, `
		SELECT admin_role
		FROM admin_grants
		WHERE user_id = $1 AND tenant_id = $2
		  AND deleted_at IS NULL AND activated_at IS NOT NULL
		ORDER BY (admin_role = 'owner') DESC
		LIMIT 1
	`, userID, tenantID).Scan(&role)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil
		}
		return "", fmt.Errorf("read actor grant role: %w", err)
	}
	return role, nil
}

// pgxQuerier is satisfied by both *pgxpool.Pool and pgx.Tx, so the assertions
// can run either standalone or inside the transaction that performs the write.
// Inside is strongly preferred: see AssertMayGrant.
type pgxQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// compile-time proof that both intended implementations satisfy it.
var (
	_ pgxQuerier = (*pgxpool.Pool)(nil)
	_ pgxQuerier = (pgx.Tx)(nil)
)
