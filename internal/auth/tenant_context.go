package auth

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
)

// ---------------------------------------------------------------------------
// Tenant context switching for multi-tenant administrators (plan step 4).
//
// An administrator may now reach several tenants (migration 00078), but an access
// token names exactly one: claims.TenantID is a scalar, and the two guards that
// authorise tenant-scoped routes compare the path :tid against it
// (middleware/permission.go). So entering a second tenant means holding a token
// minted for that tenant.
//
// This is NOT re-authentication. The caller presents the access token they
// already hold; no password, no second factor, no prompt. What happens is a
// re-mint: the same proven identity, a different tenant written into the claims.
//
// The shape follows what every comparable system does — AWS AssumeRole, GCP's
// project-scoped tokens, Auth0's per-tenant management tokens — for one reason: a
// credential that names one tenant has a blast radius of one tenant. A token
// valid across every tenant an owner reaches would also have to be signed by a
// platform key rather than the tenant's own (see JWTService.issuers), trading a
// boundary that already exists for the removal of one background request.
// ---------------------------------------------------------------------------

var (
	// ErrNoGrantInTenant is returned when the caller holds no live, activated
	// grant in the requested tenant. Deliberately indistinguishable from "that
	// tenant does not exist" to a caller: probing for tenant ids must not be
	// cheaper than not probing.
	ErrNoGrantInTenant = errors.New("no administrative grant in the requested tenant")

	// ErrSameTenant is returned when the caller asks for the tenant they are
	// already in. Not an error condition so much as a wasted round trip, but
	// reported rather than silently re-minting so a client loop is visible.
	ErrSameTenant = errors.New("already in the requested tenant")

	// ErrSwitchAccountUnusable is returned when the account cannot mint a token at
	// all — deactivated or blocked. The block lives on the users row and is not
	// tenant-scoped, so switching tenants must never be a way around it.
	ErrSwitchAccountUnusable = errors.New("account is blocked or inactive")
)

// SwitchTenantContext re-mints an access token for a different tenant the caller
// already administers.
//
// The requested tenant arrives from the request body, so it is verified against
// admin_grants and never trusted: HasAdminGrant is the authorization check, and a
// caller with no live activated grant is refused. A platform administrator
// (tenant:manage) holds no grants at all and is admitted on the permission
// instead — see the platformAdmin branch below.
//
// Sessions are NOT rotated. The user proved who they are at login and that
// session continues; only the tenant written into the claims changes. Reusing the
// session keeps the audit trail continuous — a switch shows up as one identity
// moving between tenants rather than as an unexplained new sign-in.
//
// Four to five sequential round trips (tenant-active, grant, account-usable,
// permissions, and the claim role for a platform admin) rather than one joined
// query, on purpose, and worth naming so the cost is a known trade:
//
//   - The order is a security property, not an accident. Tenant liveness is
//     checked BEFORE the grant so a deactivated tenant is unreachable even by an
//     administrator who still holds one, and the account block is checked after
//     authorization so switching can never be a way around it. A single joined
//     query decides all three at once, which makes that ordering unexpressible.
//   - ErrSwitchAccountUnusable has to stay separable from ErrNoGrantInTenant: a
//     blocked administrator must be told their account is the problem, while a
//     missing grant and a dead tenant deliberately collapse into one answer so
//     probing for tenant ids is no cheaper than not probing.
//
// This is a once-per-switch human action rather than a hot path, and every lookup
// is a primary-key or indexed hit. If it ever shows under load, the tenant and
// user rows are the pair that could merge into one query — the grant check is the
// one that must stay separate, since it is what the ordering above turns on.
func (s *AuthService) SwitchTenantContext(ctx context.Context, userID, currentTenantID, targetTenantID int64, platformAdmin bool, sess sessionContext) (*AuthResult, error) {
	if targetTenantID == currentTenantID {
		return nil, ErrSameTenant
	}

	// The target tenant must exist and be live. Checked before the grant so a
	// deactivated tenant cannot be entered by an administrator who still holds a
	// grant in it.
	var tenantActive bool
	err := s.pool.QueryRow(ctx, `
		SELECT is_active FROM tenants WHERE id = $1 AND deleted_at IS NULL
	`, targetTenantID).Scan(&tenantActive)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNoGrantInTenant
		}
		return nil, fmt.Errorf("load target tenant: %w", err)
	}
	if !tenantActive {
		return nil, ErrNoGrantInTenant
	}

	// Authorization. A platform administrator reaches every tenant by permission
	// rather than by membership, so there is no grant to find — their token's
	// tenant is context (audit attribution, rate-limit keys, which tenant the UI
	// shows) rather than authority, since tenant:manage short-circuits the guard.
	role := ""
	if !platformAdmin {
		ok, grantRole, ghErr := HasAdminGrant(ctx, s.pool, userID, targetTenantID)
		if ghErr != nil {
			return nil, ghErr
		}
		if !ok {
			return nil, ErrNoGrantInTenant
		}
		role = grantRole
	}

	// The account itself must still be usable. A blocked or deactivated
	// administrator must not be able to mint a fresh token by switching tenants —
	// the block lives on the users row and is not tenant-scoped.
	var email string
	var isActive bool
	var blocked *time.Time
	if err = s.pool.QueryRow(ctx, `
		SELECT email, is_active, blocked_at FROM users WHERE id = $1 AND deleted_at IS NULL
	`, userID).Scan(&email, &isActive, &blocked); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("load switching user: %w", err)
	}
	if !isActive || blocked != nil {
		return nil, ErrSwitchAccountUnusable
	}

	// Permissions for the TARGET tenant.
	//
	// loadPermissions cannot serve this: it joins users u ON u.role_id and filters
	// u.tenant_id = $2, which is the home tenant. For an administrator whose home
	// tenant is A, asking it for tenant B returns nothing — the row simply does
	// not match. That is correct for an ordinary user, whose permissions are a
	// property of their single tenant, and wrong for an administrator whose
	// authority comes from a grant in another tenant.
	perms, err := s.loadAdminPermissionsForTenant(ctx, userID, targetTenantID, role, platformAdmin)
	if err != nil {
		return nil, err
	}

	// The role name reported in the claim. A platform administrator keeps whatever
	// their own account carries; a tenant administrator is described by the grant,
	// because that is what decides their authority here.
	claimRole := role
	if platformAdmin {
		if err = s.pool.QueryRow(ctx, `
			SELECT COALESCE(r.name, '') FROM users u
			LEFT JOIN roles r ON r.id = u.role_id WHERE u.id = $1
		`, userID).Scan(&claimRole); err != nil {
			return nil, fmt.Errorf("load platform admin role: %w", err)
		}
	}

	// appID is empty: an administrative token is tenant-level, never scoped to one
	// application, even when the administrator only reaches specific applications
	// within the tenant. That narrowing is admin_scope's job, not the audience's.
	// Set here rather than by the caller so every entry point into a tenant switch
	// gets it, including SwitchTenantContextForClaims. No credential was presented
	// — the switch re-mints on an existing session — so it is deliberately named
	// apart from the grant that authenticated that session, matching the reasoning
	// that keeps amr unstated on this path.
	sess.grant = GrantTenantSwitch

	return s.issueTokenPair(ctx, userID, targetTenantID, email, claimRole, perms, sess, "")
}

// loadAdminPermissionsForTenant resolves the permissions an administrator holds
// in a tenant that may not be their home tenant.
//
// For a platform administrator the answer is their own account's permissions:
// tenant:manage is not granted per tenant, and re-deriving it from a grant would
// find nothing.
//
// For a tenant administrator the answer comes from the TARGET tenant's seeded
// role matching their grant — 'owner' or 'co_owner'. This is what makes the role
// a function of admin_role (plan §1: a co-owner has full authority over each
// application they hold, so permissions never vary per grant) rather than
// something stored per row.
func (s *AuthService) loadAdminPermissionsForTenant(ctx context.Context, userID, tenantID int64, adminRole string, platformAdmin bool) ([]string, error) {
	if platformAdmin {
		// Home-tenant permissions, which is where tenant:manage lives.
		var homeTenant int64
		if err := s.pool.QueryRow(ctx,
			`SELECT tenant_id FROM users WHERE id = $1`, userID,
		).Scan(&homeTenant); err != nil {
			return nil, fmt.Errorf("load home tenant: %w", err)
		}
		return s.loadPermissions(ctx, userID, homeTenant)
	}

	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT p.name
		FROM permissions p
		JOIN role_permissions rp ON rp.permission_id = p.id
		JOIN roles r             ON r.id = rp.role_id
		WHERE r.tenant_id = $1
		  AND r.name = $2
		  AND r.application_id IS NULL
		  AND r.deleted_at IS NULL
		ORDER BY 1
	`, tenantID, adminRole)
	if err != nil {
		return nil, fmt.Errorf("load %s permissions for tenant %d: %w", adminRole, tenantID, err)
	}
	defer rows.Close()

	perms := []string{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("scan admin permission: %w", err)
		}
		perms = append(perms, name)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate admin permissions: %w", err)
	}
	// An administrator whose target tenant never seeded the role would otherwise
	// receive a token with no permissions and a confusing 403 on every route.
	// Refusing here names the actual problem.
	if len(perms) == 0 {
		return nil, fmt.Errorf("tenant %d has no %q role with permissions: %w", tenantID, adminRole, ErrNoGrantInTenant)
	}
	return perms, nil
}

// AdminTenantSummary is one tenant in the "tenants I can reach" listing.
type AdminTenantSummary struct {
	TenantID     int64
	Name         string
	Slug         string
	Role         string
	AppCount     int
	IsPrimary    bool
	Applications []int64
}

// ListReachableTenants returns the tenants an administrator may enter, with the
// display fields the dashboard needs.
//
// Keyed on user_id alone and deliberately independent of any token's tenant: the
// dashboard lists every tenant the person reaches, which is a different question
// from which tenant the current token names. That separation is what lets an
// owner of five tenants see all five immediately after login without any
// switching having happened yet.
//
// Platform administrators are NOT served here — they hold no grants, and their
// answer is "every tenant", which is a paginated listing rather than this one.
// Callers branch on tenant:manage before calling.
func ListReachableTenants(ctx context.Context, pool interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}, userID int64) ([]AdminTenantSummary, error) {
	rows, err := pool.Query(ctx, `
		SELECT g.tenant_id,
		       COALESCE(NULLIF(t.display_name, ''), t.name),
		       t.slug,
		       -- An owner grant wins: tenant-wide reach cannot be narrowed by
		       -- also holding application rows.
		       MAX(CASE WHEN g.admin_role = 'owner' THEN 1 ELSE 0 END) AS is_owner,
		       -- Applications named by co-owner grants. NULL-application owner
		       -- rows contribute nothing, which is what "absence means all" means.
		       --
		       -- ORDER BY inside the aggregate: without it the array order is
		       -- planner-dependent, so two identical calls could report the same
		       -- co-owner's applications in different orders.
		       COALESCE(array_agg(g.application_id ORDER BY g.application_id) FILTER (WHERE g.application_id IS NOT NULL), '{}') AS apps,
		       -- Total applications in the tenant, for an owner's count.
		       --
		       -- deleted_at IS NULL to match admin.ListOwnedTenants' app_count.
		       -- Without it a soft-deleted application still counted here, so the
		       -- same tenant reported one number in the switcher and a smaller one
		       -- in the tenant table. Suspended (is_active = false) applications
		       -- ARE counted, by both: they still exist and are administrable,
		       -- unlike deleted ones.
		       (SELECT COUNT(*) FROM oauth_clients oc
		         WHERE oc.tenant_id = g.tenant_id AND oc.deleted_at IS NULL) AS tenant_apps,
		       bool_or(t.primary_admin_grant_id = g.id) AS is_primary
		FROM admin_grants g
		JOIN tenants t ON t.id = g.tenant_id
		WHERE g.user_id = $1
		  AND g.deleted_at IS NULL
		  AND g.activated_at IS NOT NULL
		  AND t.deleted_at IS NULL
		  AND t.is_active
		GROUP BY g.tenant_id, t.display_name, t.name, t.slug
		-- Alphabetical, and deliberately NOT newest-first.
		--
		-- This feeds the tenant SWITCHER, where the reader is looking for a tenant
		-- they already know by name. A stable A–Z order is what lets that become
		-- muscle memory; ordering by creation date moves every entry each time a
		-- tenant is added. The tenant TABLE takes the opposite view for the
		-- opposite reason — see admin.ListOwnedTenants.
		--
		-- LOWER() because a bare ORDER BY name sorted case-sensitively here, which
		-- put every capitalised name before every lowercase one:
		--
		--   Acme Corp, EMC, Outreach, Senie, angcvjbc…, pdf, revi
		--
		-- Nobody reads that as alphabetical — "pdf" belongs between Outreach and
		-- revi, not after every capital letter. Tenant names are operator-typed and
		-- inconsistently cased by nature, so the ordering has to ignore case.
		--
		-- tenant_id as the tie-break so two tenants sharing a name still come back
		-- in a stable order rather than whatever the planner produces.
		ORDER BY LOWER(t.name), g.tenant_id
	`, userID)
	if err != nil {
		return nil, fmt.Errorf("list reachable tenants: %w", err)
	}
	defer rows.Close()

	out := []AdminTenantSummary{}
	for rows.Next() {
		var s AdminTenantSummary
		var isOwner int
		var apps []int64
		var tenantApps int
		var isPrimary *bool
		if err := rows.Scan(&s.TenantID, &s.Name, &s.Slug, &isOwner, &apps, &tenantApps, &isPrimary); err != nil {
			return nil, fmt.Errorf("scan reachable tenant: %w", err)
		}
		s.IsPrimary = isPrimary != nil && *isPrimary
		if isOwner == 1 {
			s.Role = AdminRoleOwner
			// An owner administers every application, so the count is the
			// tenant's, and no list is reported — enumerating would imply the set
			// is fixed, which is exactly what absence means all avoids.
			s.AppCount = tenantApps
			s.Applications = nil
		} else {
			s.Role = AdminRoleCoOwner
			s.Applications = apps
			s.AppCount = len(apps)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate reachable tenants: %w", err)
	}
	return out, nil
}

// TenantIDString is a small helper so handlers can compare a path parameter to a
// claim without repeating the parse-and-compare dance.
func TenantIDString(id int64) string { return strconv.FormatInt(id, 10) }

// ReachableTenants is the AuthService entry point for the dashboard listing.
//
// A method rather than a bare function so handlers need no access to the pool:
// the query belongs with the model, and exposing the pool for one listing is how
// tenant predicates start getting written in the HTTP layer.
func (s *AuthService) ReachableTenants(ctx context.Context, userID int64) ([]AdminTenantSummary, error) {
	return ListReachableTenants(ctx, s.pool, userID)
}

// AllTenantsForPlatformAdmin lists every live tenant, for a caller holding
// tenant:manage.
//
// Separate from ReachableTenants because the two answer different questions from
// different sources: a platform administrator holds no admin_grants rows at all
// (it is a platform tier, not a membership in any one tenant — see migration
// 00062), so their reach cannot be derived from grants.
//
// Paginated, unlike the grant-derived listing: "every tenant" may be thousands,
// where an administrator's own grants are a handful.
func (s *AuthService) AllTenantsForPlatformAdmin(ctx context.Context, limit, offset int) ([]AdminTenantSummary, int, error) {
	if limit < 1 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	if offset < 0 {
		offset = 0
	}

	var total int
	if err := s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM tenants WHERE deleted_at IS NULL AND is_active`,
	).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count tenants: %w", err)
	}

	rows, err := s.pool.Query(ctx, `
		SELECT t.id,
		       COALESCE(NULLIF(t.display_name, ''), t.name),
		       t.slug,
		       -- deleted_at IS NULL for the same reason as ListReachableTenants
		       -- above: every application count in the product excludes
		       -- soft-deleted rows, and a platform administrator must not be the
		       -- one listing that disagrees.
		       (SELECT COUNT(*) FROM oauth_clients oc
		         WHERE oc.tenant_id = t.id AND oc.deleted_at IS NULL)
		FROM tenants t
		WHERE t.deleted_at IS NULL AND t.is_active
		-- Alphabetical, matching ListReachableTenants above: a platform admin sees
		-- the same switcher in the same order as anyone else, and here the stable
		-- order also matters for pagination — ordering by a mutable column would
		-- let rows shift between pages as tenants are created.
		--
		-- LOWER() for the same reason as above: a bare name sort is case-sensitive
		-- here and files every capitalised tenant before every lowercase one.
		ORDER BY LOWER(t.name), t.id
		LIMIT $1 OFFSET $2
	`, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("list all tenants: %w", err)
	}
	defer rows.Close()

	out := []AdminTenantSummary{}
	for rows.Next() {
		var a AdminTenantSummary
		if err := rows.Scan(&a.TenantID, &a.Name, &a.Slug, &a.AppCount); err != nil {
			return nil, 0, fmt.Errorf("scan tenant: %w", err)
		}
		// A platform administrator is not an owner or co-owner of anything; the
		// tier is reported as-is rather than borrowing a grant role it does not
		// hold.
		a.Role = "platform_admin"
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate tenants: %w", err)
	}
	return out, total, nil
}

// SwitchTenantContextForClaims is the handler-facing entry point.
//
// Exists so the HTTP layer never constructs a sessionContext: that type carries
// the authentication-time facts (amr, auth_time, persistence) that must be
// preserved across a re-mint, and a handler assembling it by hand is how one of
// them comes to be dropped.
//
// sessionID is claims.SessionID (the OIDC "sid"). An empty value means the token
// predates session tracking or has no session — client-credentials and agent
// tokens — and a fresh session row is created rather than the switch failing.
//
// amr is deliberately NOT re-stated here. The user authenticated at login and
// that is what the session row already records; a tenant change is not an
// authentication event and must not claim to be one.
func (s *AuthService) SwitchTenantContextForClaims(
	ctx context.Context,
	userID, currentTenantID, targetTenantID int64,
	platformAdmin bool,
	sessionID string,
) (*AuthResult, error) {
	sess := sessionContext{}
	if sessionID != "" {
		if sid, err := strconv.ParseInt(sessionID, 10, 64); err == nil {
			sess.sessionID = &sid
		}
	}
	return s.SwitchTenantContext(ctx, userID, currentTenantID, targetTenantID, platformAdmin, sess)
}
