package auth_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// ---------------------------------------------------------------------------
// Multi-tenant administrative reach (migration 00071).
//
// The property under test is the one migration 00062 made unrepresentable: one
// person administering more than one tenant, at different tiers. Everything else
// here exists to prove that widening reach did not also widen it sideways — an
// owner of tenant A must still be nobody in tenant B.
// ---------------------------------------------------------------------------

type grantsEnv struct {
	ctx  context.Context
	pool *pgxpool.Pool
	// Two tenants, each with two applications, so a co-owner can hold some
	// applications and not others and the difference is observable.
	tenantA, tenantB int64
	appA1, appA2     int64
	appB1, appB2     int64
}

func newGrantsEnv(t *testing.T) *grantsEnv {
	t.Helper()
	pool := testhelper.NewTestDB(t)
	testhelper.CleanupTables(t, pool)
	e := &grantsEnv{ctx: context.Background(), pool: pool}

	e.tenantA = e.seedTenant(t, "grants-a")
	e.tenantB = e.seedTenant(t, "grants-b")
	e.appA1 = e.seedApp(t, e.tenantA, "a1")
	e.appA2 = e.seedApp(t, e.tenantA, "a2")
	e.appB1 = e.seedApp(t, e.tenantB, "b1")
	e.appB2 = e.seedApp(t, e.tenantB, "b2")
	return e
}

func (e *grantsEnv) seedTenant(t *testing.T, slug string) int64 {
	t.Helper()
	var id int64
	unique := fmt.Sprintf("%s-%d", slug, time.Now().UnixNano())
	if err := e.pool.QueryRow(e.ctx, `
		INSERT INTO tenants (name, slug, jwt_secret, is_active)
		VALUES ($1, $1, 'test-secret-not-used-for-signing', true)
		RETURNING id
	`, unique).Scan(&id); err != nil {
		t.Fatalf("seed tenant %s: %v", slug, err)
	}
	return id
}

func (e *grantsEnv) seedApp(t *testing.T, tenantID int64, name string) int64 {
	t.Helper()
	var id int64
	unique := fmt.Sprintf("%s-%d", name, time.Now().UnixNano())
	if err := e.pool.QueryRow(e.ctx, `
		INSERT INTO oauth_clients
		    (tenant_id, client_id, name, redirect_uris, grant_types, scopes,
		     app_type, require_pkce, first_party)
		VALUES ($1, $2, $2, ARRAY['https://x/cb'], ARRAY['authorization_code'],
		        ARRAY['openid'], 'spa', true, true)
		RETURNING id
	`, tenantID, unique).Scan(&id); err != nil {
		t.Fatalf("seed app %s: %v", name, err)
	}
	return id
}

// seedAdminUser creates a TENANT-LEVEL user (application_id NULL), the only kind
// that may hold a grant.
func (e *grantsEnv) seedAdminUser(t *testing.T, homeTenant int64, label string) int64 {
	t.Helper()
	var id int64
	email := fmt.Sprintf("%s-%d@grants.test", label, time.Now().UnixNano())
	if err := e.pool.QueryRow(e.ctx, `
		INSERT INTO users (tenant_id, application_id, email, first_name, last_name,
		                   is_active, email_verified)
		VALUES ($1, NULL, $2, 'G', 'T', true, true)
		RETURNING id
	`, homeTenant, email).Scan(&id); err != nil {
		t.Fatalf("seed admin user %s: %v", label, err)
	}
	return id
}

// grant inserts an activated grant. appID nil means an owner grant.
func (e *grantsEnv) grant(t *testing.T, userID, tenantID int64, role string, appID *int64) {
	t.Helper()
	if _, err := e.pool.Exec(e.ctx, `
		INSERT INTO admin_grants (user_id, tenant_id, admin_role, application_id, activated_at)
		VALUES ($1, $2, $3, $4, NOW())
	`, userID, tenantID, role, appID); err != nil {
		t.Fatalf("grant %s in tenant %d: %v", role, tenantID, err)
	}
}

// TestAdminGrants_OwnerOfOneTenantCoOwnerOfAnother is THE requirement: a single
// identity holding different tiers in two tenants at once.
//
// Under migration 00062 this was unrepresentable — tenant_admins_user_key was
// UNIQUE on user_id alone, so the second grant could not exist.
func TestAdminGrants_OwnerOfOneTenantCoOwnerOfAnother(t *testing.T) {
	e := newGrantsEnv(t)
	user := e.seedAdminUser(t, e.tenantA, "multi")

	e.grant(t, user, e.tenantA, auth.AdminRoleOwner, nil)
	e.grant(t, user, e.tenantB, auth.AdminRoleCoOwner, &e.appB1)

	reach, err := auth.ListAdminReach(e.ctx, e.pool, user)
	if err != nil {
		t.Fatalf("ListAdminReach: %v", err)
	}
	if len(reach) != 2 {
		t.Fatalf("reach = %d tenants, want 2 (%+v)", len(reach), reach)
	}

	byTenant := map[int64]auth.AdminTenantReach{}
	for _, r := range reach {
		byTenant[r.TenantID] = r
	}

	a, ok := byTenant[e.tenantA]
	if !ok {
		t.Fatalf("tenant A absent from reach: %+v", reach)
	}
	if a.Role != auth.AdminRoleOwner {
		t.Errorf("tenant A role = %q, want %q", a.Role, auth.AdminRoleOwner)
	}
	// An owner enumerates no applications: absence means all, so that an
	// application created later is reachable without re-issuing the token.
	if len(a.Applications) != 0 {
		t.Errorf("tenant A applications = %v, want empty (owner reach is tenant-wide)", a.Applications)
	}

	b, ok := byTenant[e.tenantB]
	if !ok {
		t.Fatalf("tenant B absent from reach: %+v", reach)
	}
	if b.Role != auth.AdminRoleCoOwner {
		t.Errorf("tenant B role = %q, want %q", b.Role, auth.AdminRoleCoOwner)
	}
	if len(b.Applications) != 1 || b.Applications[0] != e.appB1 {
		t.Errorf("tenant B applications = %v, want [%d]", b.Applications, e.appB1)
	}
}

// TestAdminGrants_ScopeIsResolvedPerTenant is the isolation property. The same
// user resolves to tenant-wide reach in one tenant and to a narrow application
// list in the other — and to nothing at all in a tenant they do not administer.
func TestAdminGrants_ScopeIsResolvedPerTenant(t *testing.T) {
	e := newGrantsEnv(t)
	user := e.seedAdminUser(t, e.tenantA, "scoped")
	third := e.seedTenant(t, "grants-c")

	e.grant(t, user, e.tenantA, auth.AdminRoleOwner, nil)
	e.grant(t, user, e.tenantB, auth.AdminRoleCoOwner, &e.appB1)
	e.grant(t, user, e.tenantB, auth.AdminRoleCoOwner, &e.appB2)

	// Tenant A: owner ⇒ tenant-wide, no application list.
	scope, apps := e.mustResolve(t, user, e.tenantA)
	if scope != auth.AdminScopeTenant {
		t.Errorf("tenant A scope = %q, want %q", scope, auth.AdminScopeTenant)
	}
	if apps != nil {
		t.Errorf("tenant A apps = %v, want nil", apps)
	}

	// Tenant B: co-owner ⇒ exactly the two granted applications, and nothing
	// from tenant A leaks in.
	scope, apps = e.mustResolve(t, user, e.tenantB)
	if scope != auth.AdminScopeApps {
		t.Errorf("tenant B scope = %q, want %q", scope, auth.AdminScopeApps)
	}
	if len(apps) != 2 {
		t.Fatalf("tenant B apps = %v, want 2 entries", apps)
	}
	for _, got := range apps {
		if got == fmt.Sprint(e.appA1) || got == fmt.Sprint(e.appA2) {
			t.Errorf("tenant B apps %v contain a tenant A application — cross-tenant leak", apps)
		}
	}

	// A tenant they administer not at all: no scope, which reads as "ordinary
	// user" and is what denies them everything administrative.
	scope, apps = e.mustResolve(t, user, third)
	if scope != "" || apps != nil {
		t.Errorf("unadministered tenant scope = (%q, %v), want (\"\", nil)", scope, apps)
	}
}

// TestAdminGrants_RevokedCoOwnerIsDeniedNotAnonymous covers the distinction that
// is easy to collapse: a co-owner whose last application was revoked must remain
// an administrator with an EMPTY application list, not stop being one.
//
// AdminScopeApps with zero entries is denied by RequireAppScope. A nil scope
// would instead read as "not an administrator", which several guards treat as a
// legacy tenant-wide caller — the opposite of the intent.
func TestAdminGrants_RevokedCoOwnerIsDeniedNotAnonymous(t *testing.T) {
	e := newGrantsEnv(t)
	user := e.seedAdminUser(t, e.tenantB, "revoked")
	e.grant(t, user, e.tenantB, auth.AdminRoleCoOwner, &e.appB1)

	// Revoke the only application, exactly as the mirror does: soft-delete.
	if _, err := e.pool.Exec(e.ctx, `
		UPDATE admin_grants SET deleted_at = NOW()
		WHERE user_id = $1 AND tenant_id = $2 AND application_id = $3
	`, user, e.tenantB, e.appB1); err != nil {
		t.Fatalf("revoke grant: %v", err)
	}

	scope, apps := e.mustResolve(t, user, e.tenantB)
	// With every grant retired there is no live row at all, so the honest answer
	// is "not an administrator here" — reach is gone, and the account falls back
	// to whatever non-administrative permissions it holds.
	if scope != "" {
		t.Errorf("scope after revoking the last grant = %q, want \"\"", scope)
	}
	if apps != nil {
		t.Errorf("apps after revoking the last grant = %v, want nil", apps)
	}

	// But while ANY co-owner grant survives, the list is non-nil even if the
	// caller holds nothing they can act on in a given application.
	e.grant(t, user, e.tenantB, auth.AdminRoleCoOwner, &e.appB2)
	scope, apps = e.mustResolve(t, user, e.tenantB)
	if scope != auth.AdminScopeApps {
		t.Errorf("scope = %q, want %q", scope, auth.AdminScopeApps)
	}
	if apps == nil {
		t.Error("apps = nil for a live co-owner; must be non-nil so an empty list denies rather than reads as non-admin")
	}
}

// TestAdminGrants_PendingGrantCarriesNoReach: a grant the recipient has not
// accepted must confer nothing, matching the fact that it attaches no RBAC role.
func TestAdminGrants_PendingGrantCarriesNoReach(t *testing.T) {
	e := newGrantsEnv(t)
	user := e.seedAdminUser(t, e.tenantA, "pending")

	if _, err := e.pool.Exec(e.ctx, `
		INSERT INTO admin_grants (user_id, tenant_id, admin_role, application_id, activated_at)
		VALUES ($1, $2, 'owner', NULL, NULL)
	`, user, e.tenantA); err != nil {
		t.Fatalf("seed pending grant: %v", err)
	}

	scope, apps := e.mustResolve(t, user, e.tenantA)
	if scope != "" || apps != nil {
		t.Errorf("pending grant resolved to (%q, %v), want (\"\", nil)", scope, apps)
	}

	reach, err := auth.ListAdminReach(e.ctx, e.pool, user)
	if err != nil {
		t.Fatalf("ListAdminReach: %v", err)
	}
	if len(reach) != 0 {
		t.Errorf("pending grant appears in reach %+v; a tenant the user cannot enter must not be listed", reach)
	}
}

// TestAdminGrants_OwnerGrantWinsOverApplicationGrants: holding tenant-wide reach
// cannot be narrowed by also holding application rows. The CHECK in 00071 stops
// an owner row from carrying an application, but a stale co-owner row alongside a
// fresh owner row is representable, and must resolve to tenant-wide.
func TestAdminGrants_OwnerGrantWinsOverApplicationGrants(t *testing.T) {
	e := newGrantsEnv(t)
	user := e.seedAdminUser(t, e.tenantA, "promoted")

	e.grant(t, user, e.tenantA, auth.AdminRoleCoOwner, &e.appA1)
	e.grant(t, user, e.tenantA, auth.AdminRoleOwner, nil)

	scope, apps := e.mustResolve(t, user, e.tenantA)
	if scope != auth.AdminScopeTenant {
		t.Errorf("scope = %q, want %q (an owner grant is tenant-wide regardless of leftover app rows)", scope, auth.AdminScopeTenant)
	}
	if apps != nil {
		t.Errorf("apps = %v, want nil", apps)
	}

	reach, err := auth.ListAdminReach(e.ctx, e.pool, user)
	if err != nil {
		t.Fatalf("ListAdminReach: %v", err)
	}
	if len(reach) != 1 || reach[0].Role != auth.AdminRoleOwner || len(reach[0].Applications) != 0 {
		t.Errorf("reach = %+v, want one owner entry with no applications", reach)
	}
}

// TestAdminGrants_HasGrantAndDefaultTenant covers the two lookups the login and
// switch-tenant paths depend on.
func TestAdminGrants_HasGrantAndDefaultTenant(t *testing.T) {
	e := newGrantsEnv(t)
	user := e.seedAdminUser(t, e.tenantB, "default")

	// Nothing yet: no reach, and no tenant to land in.
	if _, err := auth.DefaultAdminTenant(e.ctx, e.pool, user); err == nil {
		t.Error("DefaultAdminTenant on a non-administrator returned no error, want ErrNoAdminReach")
	}

	// Co-owner of B only.
	e.grant(t, user, e.tenantB, auth.AdminRoleCoOwner, &e.appB1)
	ok, role, err := auth.HasAdminGrant(e.ctx, e.pool, user, e.tenantB)
	if err != nil {
		t.Fatalf("HasAdminGrant: %v", err)
	}
	if !ok || role != auth.AdminRoleCoOwner {
		t.Errorf("HasAdminGrant(B) = (%t, %q), want (true, %q)", ok, role, auth.AdminRoleCoOwner)
	}
	// A tenant they do not administer must not be enterable — this is the check
	// that stops /auth/switch-tenant trusting a tenant id from the request body.
	if ok, _, err = auth.HasAdminGrant(e.ctx, e.pool, user, e.tenantA); err != nil {
		t.Fatalf("HasAdminGrant(A): %v", err)
	} else if ok {
		t.Error("HasAdminGrant(A) = true for a tenant with no grant — switch-tenant would admit it")
	}

	// Now also owner of A. The default prefers the owned tenant, because landing
	// in the narrower tier reads as missing access.
	e.grant(t, user, e.tenantA, auth.AdminRoleOwner, nil)
	got, err := auth.DefaultAdminTenant(e.ctx, e.pool, user)
	if err != nil {
		t.Fatalf("DefaultAdminTenant: %v", err)
	}
	if got != e.tenantA {
		t.Errorf("DefaultAdminTenant = %d, want tenant A (%d) — owned tenants are preferred", got, e.tenantA)
	}
}

func (e *grantsEnv) mustResolve(t *testing.T, userID, tenantID int64) (string, []string) {
	t.Helper()
	scope, apps, err := auth.LoadAdminScopeFromGrantsForTest(e.ctx, e.pool, userID, tenantID)
	if err != nil {
		t.Fatalf("resolve admin scope (user %d, tenant %d): %v", userID, tenantID, err)
	}
	return scope, apps
}
