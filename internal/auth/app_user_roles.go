package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

// Application-credentialed role assignment — issue #146.
//
// Lets an application's own backend attach roles to its users after
// registration, authenticating with the client_id/client_secret pair it already
// holds rather than with an administrator's bearer token. Registration assigns
// the application's default role (or none, when no default is configured); this
// is how a user acquires anything beyond it.
//
// THE CREDENTIAL IS THE APPLICATION'S, NOT THE USER'S. A client_secret grants
// authority over every user of that application, so it belongs only on a
// server the operator controls. Shipping it in a SPA or a mobile binary would
// let any user read it out of the bundle and grant themselves any role the
// application defines — which is why this endpoint deliberately has no
// end-user-token equivalent. The application's backend decides who is eligible
// for what; this service enforces that the decision stays inside the
// application's own boundary.
//
// That division is the same one Auth0 draws between its Management API and its
// authentication API, and for the same reason.

// ErrRoleNotInApplication is returned when a requested role name does not exist
// in the authenticated application.
//
// Names the roles that were refused, because the caller is the application's
// own backend acting on roles it defined — a typo in a deployment script is the
// overwhelmingly likely cause, and an opaque failure would leave the operator
// guessing. This is safe precisely because the caller already authenticated as
// the application: it is being told about its own configuration, not probing
// someone else's.
var ErrRoleNotInApplication = errors.New("role not available in this application")

// ErrUserNotInApplication is returned when the user does not belong to the
// authenticated application.
//
// Deliberately indistinguishable from "no such user": an application must not be
// able to discover which user ids exist in a SIBLING application of the same
// tenant by watching which ones return a different error.
var ErrUserNotInApplication = errors.New("user not found in this application")

// AssignAppUserRolesInput is one application-credentialed role assignment.
type AssignAppUserRolesInput struct {
	ClientID     string
	ClientSecret string
	// UserID is a users.id. It is verified to belong to the authenticated
	// application before anything is written.
	UserID int64
	// Roles are role NAMES, not ids. Names are what the `roles` claim carries and
	// what an application's own configuration is written in, so a backend can
	// assign by the same identifier it already knows without a lookup round-trip.
	Roles []string
	// Replace discards the user's existing roles instead of adding to them.
	// Defaults to false — additive, which is what "attach or amend roles after
	// registration" means and what makes a retried request harmless.
	Replace bool
}

// AssignAppUserRolesResult reports the outcome.
type AssignAppUserRolesResult struct {
	UserID int64 `json:"user_id"`
	// Roles is every role the user holds after the call, in grant order.
	Roles []string `json:"roles"`
	// Assigned lists only the roles this call added, so a caller can tell a
	// change from a no-op without diffing.
	Assigned []string `json:"assigned"`
}

// AssignAppUserRoles attaches roles to one of the authenticated application's own
// users.
//
// The validation chain fails closed at every step, in this order:
//
//  1. client_id/client_secret must authenticate an active application.
//  2. The user must belong to THAT application. This is the isolation boundary:
//     two applications in one tenant cannot reach each other's users, so a
//     compromised client secret is confined to the application it belongs to.
//  3. Every requested role must exist in that application, be live, and be
//     non-system. Resolution is scoped to the application's own roles, so a
//     cross-application grant is not merely refused — it is unrepresentable.
//  4. All roles are assigned in ONE transaction. A partial grant on a
//     multi-role request would leave a state nobody asked for and no audit
//     record explains.
//
// Sessions are denied after the commit, so the new permissions reach the user on
// their next request rather than whenever their access token happens to expire.
func (s *AuthService) AssignAppUserRoles(ctx context.Context, in AssignAppUserRolesInput) (*AssignAppUserRolesResult, error) {
	if s.appSvc == nil {
		return nil, fmt.Errorf("application service not configured")
	}
	if in.UserID <= 0 {
		return nil, ErrUserNotInApplication
	}

	// Step 1. Constant-time-equivalent: the secret is compared as a hash inside
	// AuthenticateClient, never in application code.
	tenantID, appRowID, err := s.appSvc.AuthenticateClient(ctx, in.ClientID, in.ClientSecret)
	if err != nil {
		// Passed through as-is. ErrInvalidClient is already generic — it does not
		// distinguish an unknown client_id from a wrong secret, so it cannot be
		// used to enumerate registered clients.
		return nil, err
	}

	names := normaliseRoleNames(in.Roles)
	if len(names) == 0 && !in.Replace {
		// An empty additive request would be a silent no-op that still emitted an
		// audit event and revoked every session. Refusing names the mistake.
		return nil, fmt.Errorf("at least one role is required")
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin assign app user roles tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// Step 2. The user must be THIS application's. Also excludes soft-deleted
	// accounts: a deleted user is gone as far as every other reader is concerned,
	// and re-roling one would leave a grant nothing surfaces.
	var exists bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM users
			WHERE id = $1 AND tenant_id = $2 AND application_id = $3 AND deleted_at IS NULL
		)
	`, in.UserID, tenantID, appRowID).Scan(&exists); err != nil {
		return nil, fmt.Errorf("assign app user roles: lookup user: %w", err)
	}
	if !exists {
		return nil, ErrUserNotInApplication
	}

	// Step 3. Resolve names to ids WITHIN this application only. Scoping the
	// lookup rather than filtering afterwards is what makes a cross-application
	// grant unrepresentable instead of merely refused.
	//
	// is_system is excluded here as well as being impossible via application
	// scope (system roles carry application_id IS NULL): defence in depth, so a
	// future change to how system roles are scoped cannot silently open this path
	// to owner/super_admin.
	rows, err := tx.Query(ctx, `
		SELECT id, name FROM roles
		WHERE tenant_id = $1 AND application_id = $2
		  AND name = ANY($3::TEXT[])
		  AND is_system = false
		  AND deleted_at IS NULL
	`, tenantID, appRowID, names)
	if err != nil {
		return nil, fmt.Errorf("assign app user roles: resolve roles: %w", err)
	}
	resolved := make(map[string]int64, len(names))
	for rows.Next() {
		var id int64
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			rows.Close()
			return nil, fmt.Errorf("assign app user roles: scan role: %w", err)
		}
		resolved[name] = id
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("assign app user roles: iterate roles: %w", err)
	}

	// Every requested name must have resolved. Reporting the missing ones lets an
	// operator fix a deployment script; reporting them is safe because the caller
	// authenticated as the application that owns them.
	var missing []string
	for _, n := range names {
		if _, ok := resolved[n]; !ok {
			missing = append(missing, n)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("%w: %s", ErrRoleNotInApplication, strings.Join(missing, ", "))
	}

	// Step 4. One transaction: all of them, or none.
	if in.Replace {
		if _, err := tx.Exec(ctx,
			`DELETE FROM user_roles WHERE user_id = $1 AND tenant_id = $2`,
			in.UserID, tenantID); err != nil {
			return nil, fmt.Errorf("assign app user roles: clear existing: %w", err)
		}
	}

	// Which names were genuinely new, established before the inserts so a
	// re-issued request reports honestly rather than claiming to have assigned
	// roles the user already held.
	held, err := heldRoleNamesTx(ctx, tx, in.UserID, tenantID)
	if err != nil {
		return nil, err
	}
	heldSet := make(map[string]struct{}, len(held))
	for _, h := range held {
		heldSet[h] = struct{}{}
	}
	assigned := make([]string, 0, len(names))
	for _, n := range names {
		if _, dup := heldSet[n]; !dup {
			assigned = append(assigned, n)
		}
	}

	for _, n := range names {
		// granted_by is NULL: the grantor is an application, not a person, and
		// users.id has nobody to point at. The audit record carries the client_id,
		// which is the honest provenance for a machine-made grant.
		if _, err := tx.Exec(ctx, `
			INSERT INTO user_roles (user_id, role_id, tenant_id, granted_by)
			VALUES ($1, $2, $3, NULL)
			ON CONFLICT (user_id, role_id) DO NOTHING
		`, in.UserID, resolved[n], tenantID); err != nil {
			return nil, fmt.Errorf("assign app user roles: grant %s: %w", n, err)
		}
	}

	// Promote a primary when the user has none, and re-point one left dangling by
	// a replace. users.role_id is what the deprecated `role` claim carries, so a
	// user holding roles with no primary among them would report an empty `role`
	// beside a populated `roles` — a contradiction for any consumer reading both.
	if _, err := tx.Exec(ctx, `
		UPDATE users u SET role_id = (
			SELECT ur.role_id FROM user_roles ur
			JOIN roles r ON r.id = ur.role_id AND r.deleted_at IS NULL
			WHERE ur.user_id = u.id AND ur.tenant_id = u.tenant_id
			ORDER BY ur.granted_at, ur.role_id
			LIMIT 1
		), updated_at = NOW()
		WHERE u.id = $1 AND u.tenant_id = $2
		  AND (u.role_id IS NULL
		       OR NOT EXISTS (SELECT 1 FROM user_roles ur2
		                      WHERE ur2.user_id = u.id AND ur2.role_id = u.role_id))
	`, in.UserID, tenantID); err != nil {
		return nil, fmt.Errorf("assign app user roles: repoint primary: %w", err)
	}

	final, err := heldRoleNamesTx(ctx, tx, in.UserID, tenantID)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit assign app user roles: %w", err)
	}

	// After the commit, never inside it: a denylist entry cannot be rolled back,
	// so denying sessions for a grant that then failed would sign a user out on
	// the strength of a write that never landed.
	//
	// Unconditional, even when nothing changed. A caller that re-issues a request
	// is cheap to serve twice, and the alternative — deciding whether a change was
	// material enough to revoke — is exactly the reasoning that leaves stale
	// permissions in circulation.
	s.DenyUserSessions(ctx, in.UserID, tenantID)

	return &AssignAppUserRolesResult{UserID: in.UserID, Roles: final, Assigned: assigned}, nil
}

// heldRoleNamesTx lists the live roles a user holds, in grant order, inside an
// open transaction.
func heldRoleNamesTx(ctx context.Context, tx pgx.Tx, userID, tenantID int64) ([]string, error) {
	rows, err := tx.Query(ctx, `
		SELECT r.name FROM user_roles ur
		JOIN roles r ON r.id = ur.role_id AND r.deleted_at IS NULL
		WHERE ur.user_id = $1 AND ur.tenant_id = $2
		ORDER BY ur.granted_at, r.id
	`, userID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list held roles: %w", err)
	}
	defer rows.Close()

	names := []string{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, fmt.Errorf("scan held role: %w", err)
		}
		names = append(names, n)
	}
	return names, rows.Err()
}

// normaliseRoleNames trims, drops empties, and deduplicates while preserving the
// caller's order.
//
// Case is NOT folded. Role names are compared exactly everywhere else in this
// codebase and the uniqueness indexes are case-sensitive, so folding here would
// let "Editor" resolve to "editor" through this path alone — a difference in
// behaviour between two ways of granting the same role is precisely the kind of
// inconsistency that turns into a security surprise.
func normaliseRoleNames(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, raw := range in {
		n := strings.TrimSpace(raw)
		if n == "" {
			continue
		}
		if _, dup := seen[n]; dup {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	return out
}
