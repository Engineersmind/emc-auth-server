package auth

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ---------------------------------------------------------------------------
// Multi-tenant administrative reach (migration 00078).
//
// admin_grants replaces the tenant_admins + tenant_admin_app_scopes pair from
// migration 00062, and lifts the constraint that made an administrator
// single-tenant: tenant_admins_user_key was UNIQUE on user_id ALONE, so one
// person could administer exactly one tenant. One person may now own tenant A
// and co-own tenant B at the same time.
//
// One row means "this user administers this much of this tenant":
//
//	application_id IS NULL      every application in the tenant, present and
//	                            future — the owner tier
//	application_id IS NOT NULL  exactly that application — the co-owner tier
//
// Permissions are NOT stored per grant. A co-owner has full authority over each
// application they hold, so the RBAC role is a function of admin_role alone and
// is resolved from the tenant's seeded role. The grant decides WHICH
// applications, never WHAT may be done to them.
//
// This file deliberately does not change the shape of the admin_scope claim.
// loadAdminScopeFromGrants returns exactly what loadAdminScope returns, so a
// token minted before the cutover and one minted after are indistinguishable to
// every guard in internal/api/middleware. That is what makes the rollout
// reversible: see AdminGrantsEnabled below.
// ---------------------------------------------------------------------------

// adminGrantsEnabledEnv gates which model resolves administrative reach.
//
// Off (the default) means loadAdminScope reads the 00062 tables and behaviour is
// byte-identical to before this file existed. On means it reads admin_grants.
// Writes go to BOTH models regardless (see internal/admin), so flipping this
// back is a config change rather than a migration — nothing has to be
// backfilled a second time.
const adminGrantsEnabledEnv = "ADMIN_GRANTS_ENABLED"

// AdminGrantsEnabled reports whether admin_grants is authoritative for reach.
//
// Read from the environment on each call rather than cached: the flag exists to
// be flipped, and during a staged rollout it may be flipped without a restart.
// The cost is one map lookup on a path that already does database work.
func AdminGrantsEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(adminGrantsEnabledEnv))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// loadAdminScopeFromGrants resolves reach from admin_grants.
//
// Contract is identical to loadAdminScope, including the two cases that are easy
// to get subtly wrong:
//
//   - An owner returns (AdminScopeTenant, nil): no application list is produced.
//     Enumerating would freeze the list at token-issue time, so an application
//     created a minute later would be invisible to its own owner until they
//     signed in again. Absence means all — see migration 00078's header for why
//     the alternative fails silently.
//
//   - A co-owner returns a NON-NIL, possibly EMPTY slice. A co-owner whose last
//     grant was revoked is AdminScopeApps with zero applications, which
//     RequireAppScope denies. Returning nil would be indistinguishable from "not
//     an administrator at all", which reads as an ordinary user rather than as a
//     denied one.
//
// Only activated grants count. A grant the recipient has not confirmed carries
// no reach, matching the fact that it carries no RBAC role.
func loadAdminScopeFromGrants(ctx context.Context, pool *pgxpool.Pool, userID, tenantID int64) (string, []string, error) {
	// One indexed pass over this user's live grants in this tenant, ordered so
	// an owner row (application_id IS NULL) is seen first if one exists.
	// idx_admin_grants_user serves the predicate; the tenant is a residual check
	// over rows that are already only this user's.
	rows, err := pool.Query(ctx, `
		SELECT admin_role, application_id
		FROM admin_grants
		WHERE user_id = $1
		  AND tenant_id = $2
		  AND deleted_at IS NULL
		  AND activated_at IS NOT NULL
		ORDER BY application_id NULLS FIRST
	`, userID, tenantID)
	if err != nil {
		return "", nil, fmt.Errorf("load admin grants: %w", err)
	}
	defer rows.Close()

	isAdmin := false
	apps := []string{}
	for rows.Next() {
		var role string
		var appID *int64
		if err := rows.Scan(&role, &appID); err != nil {
			return "", nil, fmt.Errorf("scan admin grant: %w", err)
		}
		isAdmin = true
		// An owner grant ends the question: tenant-wide reach cannot be narrowed
		// by also holding application grants, and the CHECK in 00078 means an
		// owner row never carries an application_id anyway.
		if role == AdminRoleOwner {
			return AdminScopeTenant, nil, nil
		}
		if appID != nil {
			apps = append(apps, strconv.FormatInt(*appID, 10))
		}
	}
	if err := rows.Err(); err != nil {
		return "", nil, fmt.Errorf("iterate admin grants: %w", err)
	}

	if !isAdmin {
		return "", nil, nil
	}
	return AdminScopeApps, apps, nil
}

// resolveAdminScope is the single entry point used by token minting. It picks a
// resolver according to the flag, and — while the flag is OFF — runs the new one
// as a shadow to surface disagreements before they can affect anybody.
//
// The shadow pass is what turns "the backfill looked right" into evidence. The
// static verification in migration 00078 checks the two models agree on rows;
// this checks they agree on the ANSWER, under real traffic, including rows
// written after the migration ran. Flip the flag only once the mismatch log has
// been quiet across a full day.
//
// A method rather than a free function so the mismatch has somewhere to go: the
// whole value of the shadow pass is that a disagreement is loud.
func (s *AuthService) resolveAdminScope(ctx context.Context, userID, tenantID int64) (string, []string, error) {
	if AdminGrantsEnabled() {
		return loadAdminScopeFromGrants(ctx, s.pool, userID, tenantID)
	}

	scope, apps, err := loadAdminScope(ctx, s.pool, userID, tenantID)
	if err != nil {
		return "", nil, err
	}

	// Shadow comparison. A failure here must never affect the caller: the legacy
	// answer is authoritative while the flag is off, and a broken shadow query
	// signing people out would be a self-inflicted outage. Both branches log at
	// a level that will be noticed — a silent shadow is worse than none, because
	// it produces confidence without evidence.
	shadowScope, shadowApps, shadowErr := loadAdminScopeFromGrants(ctx, s.pool, userID, tenantID)
	switch {
	case shadowErr != nil:
		s.logger.Warn().Err(shadowErr).
			Int64("user_id", userID).Int64("tenant_id", tenantID).
			Msg("admin_grants shadow resolution failed; legacy answer used")
	default:
		if diff := adminScopeDiff(scope, apps, shadowScope, shadowApps); diff != "" {
			s.logger.Error().
				Int64("user_id", userID).Int64("tenant_id", tenantID).
				Str("mismatch", diff).
				Msg("admin_grants shadow MISMATCH — do not enable ADMIN_GRANTS_ENABLED until resolved")
		}
	}

	return scope, apps, nil
}

// adminScopeDiff returns a human-readable description of how two resolutions
// differ, or "" when they agree. Application order is not significant — the
// legacy resolver orders by application_id and the new one by the same column,
// but a diff report that fired on ordering alone would be noise.
func adminScopeDiff(legacyScope string, legacyApps []string, newScope string, newApps []string) string {
	if legacyScope != newScope {
		return fmt.Sprintf("scope: legacy=%q new=%q", legacyScope, newScope)
	}
	// Nil vs empty is a real difference for AdminScopeApps (see the contract
	// note above), so compare that explicitly rather than by length alone.
	if (legacyApps == nil) != (newApps == nil) {
		return fmt.Sprintf("apps nilness: legacy_nil=%t new_nil=%t", legacyApps == nil, newApps == nil)
	}
	if len(legacyApps) != len(newApps) {
		return fmt.Sprintf("apps count: legacy=%d new=%d", len(legacyApps), len(newApps))
	}
	l := append([]string(nil), legacyApps...)
	n := append([]string(nil), newApps...)
	sort.Strings(l)
	sort.Strings(n)
	for i := range l {
		if l[i] != n[i] {
			return fmt.Sprintf("apps differ: legacy=%v new=%v", l, n)
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// Grant lookup used by login and the tenant directory.
// ---------------------------------------------------------------------------

// AdminTenantReach is one tenant a user administers, as login and
// /admin/my-tenants report it.
type AdminTenantReach struct {
	TenantID int64
	// Role is AdminRoleOwner or AdminRoleCoOwner.
	Role string
	// Applications is the granted application ids for a co-owner. Empty for an
	// owner, who administers every application in the tenant — the two empties
	// mean opposite things, so read this with Role.
	Applications []int64
}

// ErrNoAdminReach is returned when a user administers no tenant at all.
var ErrNoAdminReach = errors.New("user administers no tenant")

// ListAdminReach returns every tenant a user administers, ordered by tenant id.
//
// This is the query that makes multi-tenant administration visible: it is keyed
// on user_id ALONE and deliberately does not consult any tenant in the caller's
// token. A token is always scoped to one tenant (see resolveAdminScope), but the
// dashboard has to list all of them, so the two questions are answered
// separately — "which tenant is this token for" and "which tenants exist for
// this person".
//
// Served by idx_admin_grants_user. Only activated, live grants are reported: a
// pending invitation is not reach, and showing it would offer a tenant the user
// cannot actually enter.
func ListAdminReach(ctx context.Context, pool *pgxpool.Pool, userID int64) ([]AdminTenantReach, error) {
	rows, err := pool.Query(ctx, `
		SELECT tenant_id, admin_role, application_id
		FROM admin_grants
		WHERE user_id = $1
		  AND deleted_at IS NULL
		  AND activated_at IS NOT NULL
		ORDER BY tenant_id, application_id NULLS FIRST
	`, userID)
	if err != nil {
		return nil, fmt.Errorf("list admin reach: %w", err)
	}
	defer rows.Close()

	// Grants arrive one row per application, so collapse them per tenant. An
	// owner row wins outright: holding tenant-wide reach cannot be narrowed by
	// also appearing with application grants.
	byTenant := map[int64]*AdminTenantReach{}
	order := []int64{}
	for rows.Next() {
		var tenantID int64
		var role string
		var appID *int64
		if err := rows.Scan(&tenantID, &role, &appID); err != nil {
			return nil, fmt.Errorf("scan admin reach: %w", err)
		}
		cur, seen := byTenant[tenantID]
		if !seen {
			cur = &AdminTenantReach{TenantID: tenantID, Role: role}
			byTenant[tenantID] = cur
			order = append(order, tenantID)
		}
		if role == AdminRoleOwner {
			cur.Role = AdminRoleOwner
			cur.Applications = nil
			continue
		}
		if cur.Role == AdminRoleOwner {
			continue
		}
		if appID != nil {
			cur.Applications = append(cur.Applications, *appID)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate admin reach: %w", err)
	}

	out := make([]AdminTenantReach, 0, len(order))
	for _, tid := range order {
		out = append(out, *byTenant[tid])
	}
	return out, nil
}

// HasAdminGrant reports whether a user holds a live, activated grant in a
// tenant. This is the authorization check for /auth/tenant-context: the requested
// tenant comes from the request body, so it must be verified against grants
// rather than trusted.
func HasAdminGrant(ctx context.Context, pool *pgxpool.Pool, userID, tenantID int64) (bool, string, error) {
	var role string
	err := pool.QueryRow(ctx, `
		SELECT admin_role
		FROM admin_grants
		WHERE user_id = $1
		  AND tenant_id = $2
		  AND deleted_at IS NULL
		  AND activated_at IS NOT NULL
		ORDER BY application_id NULLS FIRST
		LIMIT 1
	`, userID, tenantID).Scan(&role)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, "", nil
		}
		return false, "", fmt.Errorf("check admin grant: %w", err)
	}
	return true, role, nil
}

// DefaultAdminTenant picks the tenant an administrator lands in at login.
//
// There is deliberately no tenant-selection screen: a multi-tenant
// administrator is signed straight into one tenant and switches from inside the
// app. The choice prefers an owned tenant, because an owner's reach is the
// broader one and landing in the narrower tier reads as missing access.
//
// Returns ErrNoAdminReach when the user administers nothing, which callers treat
// as "ordinary user" rather than as a failure.
func DefaultAdminTenant(ctx context.Context, pool *pgxpool.Pool, userID int64) (int64, error) {
	var tenantID int64
	err := pool.QueryRow(ctx, `
		SELECT tenant_id
		FROM admin_grants
		WHERE user_id = $1
		  AND deleted_at IS NULL
		  AND activated_at IS NOT NULL
		ORDER BY (admin_role = 'owner') DESC, tenant_id
		LIMIT 1
	`, userID).Scan(&tenantID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, ErrNoAdminReach
		}
		return 0, fmt.Errorf("default admin tenant: %w", err)
	}
	return tenantID, nil
}
