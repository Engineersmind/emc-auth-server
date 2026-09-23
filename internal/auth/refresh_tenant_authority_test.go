package auth_test

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// The authority rule RefreshWithLock applies when rotating a refresh token.
//
// Kept as SQL rather than exercised through a full login-switch-refresh flow on
// purpose: the bug it guards was a WHERE clause, the fix is a WHERE clause, and
// a behavioural test would prove the same thing through four layers that can
// each mask it. Copied verbatim from service.go so a change there without a
// change here fails loudly instead of silently widening who may refresh.
//
// Keep in sync with internal/auth/service.go — RefreshWithLock's user load.
const refreshAuthoritySQL = `
	SELECT count(*)
	FROM users u
	WHERE u.id = $1
	  AND u.is_active = true
	  AND u.deleted_at IS NULL
	  AND (
	      u.tenant_id = $2
	   OR EXISTS (
	          SELECT 1 FROM admin_grants g
	          WHERE g.user_id = u.id
	            AND g.tenant_id = $2
	            AND g.deleted_at IS NULL
	            AND g.activated_at IS NOT NULL
	      )
	   OR EXISTS (
	          SELECT 1
	          FROM roles pr
	          JOIN role_permissions prp ON prp.role_id = pr.id
	          JOIN permissions pp       ON pp.id = prp.permission_id
	          WHERE pr.id = u.role_id
	            AND pr.tenant_id = u.tenant_id
	            AND pr.deleted_at IS NULL
	            AND pr.application_id IS NULL
	            AND pp.application_id IS NULL
	            AND pp.name = 'tenant:manage'
	      )
	  )
`

func mayRefreshInto(t *testing.T, pool *pgxpool.Pool, userID, tenantID int64) bool {
	t.Helper()

	// The PRODUCTION rule. Previously this ran refreshAuthoritySQL, a verbatim
	// copy — so a change to service.go alone left every test here green, and the
	// mutation evidence only ever showed the copy was self-consistent (raised in
	// review on #143).
	allowed, err := auth.ExportedRefreshUserLoad(pool, testhelper.TestLogger(), context.Background(), userID, tenantID)
	if err != nil {
		t.Fatalf("refresh authority: %v", err)
	}

	// The copy is kept as a SECOND signal: it catches the two rules drifting
	// apart semantically, which a behavioural check would not notice. A
	// disagreement means service.go and this file no longer describe the same
	// rule, and the test says which.
	var n int
	if err := pool.QueryRow(context.Background(), refreshAuthoritySQL, userID, tenantID).Scan(&n); err != nil {
		t.Fatalf("authority query: %v", err)
	}
	if (n > 0) != allowed {
		t.Errorf("the production rule and the copy in this file disagree (production=%v, copy=%v) — one of them changed without the other", allowed, n > 0)
	}
	return allowed
}

/*
 * The bug this fixture reproduces.
 *
 * Switching tenants mints a refresh token stamped with the TARGET tenant, while
 * `users` holds one row per person carrying their HOME tenant. The old lookup
 * asked for `u.id = $1 AND u.tenant_id = $2` and therefore asked for a row that
 * cannot exist — so every administrator who had switched tenants was logged out
 * the moment their 15-minute access token expired, with the server answering
 * 500 "user not found or inactive".
 *
 * Three tenants and four users, because the rule has three independent arms and
 * one of them (tenant:manage) is the arm that the obvious fix — "look up the
 * grant instead" — would have missed entirely.
 */
type authorityFixture struct {
	platformTenant int64 // holds tenant:manage
	grantedTenant  int64 // grants admin rights to grantAdmin
	otherTenant    int64 // unrelated to everyone

	platformAdmin int64 // home = platformTenant, holds tenant:manage
	grantAdmin    int64 // home = otherTenant, activated grant in grantedTenant
	pendingAdmin  int64 // home = otherTenant, grant NOT yet activated
	endUser       int64 // home = otherTenant, no grants, no platform role
}

func newAuthorityFixture(t *testing.T, pool *pgxpool.Pool) authorityFixture {
	t.Helper()
	ctx := context.Background()
	var f authorityFixture

	mkTenant := func(slug string) int64 {
		var id int64
		// jwt_secret is NOT NULL: legacy per-tenant HS256 signing predates the
		// per-tenant RSA keys and the column is still required. Any value does —
		// nothing in these tests mints a token.
		if err := pool.QueryRow(ctx, `
			INSERT INTO tenants (slug, name, is_active, jwt_secret)
			VALUES ($1, $1, true, 'authority-fixture-not-used')
			RETURNING id
		`, slug).Scan(&id); err != nil {
			t.Fatalf("insert tenant %s: %v", slug, err)
		}
		return id
	}

	f.platformTenant = mkTenant("authz-platform")
	f.grantedTenant = mkTenant("authz-granted")
	f.otherTenant = mkTenant("authz-other")

	// The platform role: a tenant-level role (application_id IS NULL) carrying
	// tenant:manage. This is what identifies the platform tier — not a slug and
	// not the lowest id, matching resolveRegistrationTenant's reasoning.
	var platformRole int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO roles (tenant_id, name) VALUES ($1, 'authz-super') RETURNING id
	`, f.platformTenant).Scan(&platformRole); err != nil {
		t.Fatalf("insert platform role: %v", err)
	}
	var managePerm int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO permissions (tenant_id, name, description)
		VALUES ($1, 'tenant:manage', 'authority fixture')
		RETURNING id
	`, f.platformTenant).Scan(&managePerm); err != nil {
		t.Fatalf("insert tenant:manage: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO role_permissions (role_id, permission_id, tenant_id) VALUES ($1, $2, $3)
	`, platformRole, managePerm, f.platformTenant); err != nil {
		t.Fatalf("grant tenant:manage: %v", err)
	}

	mkUser := func(email string, tenantID int64, roleID *int64) int64 {
		var id int64
		// No credential columns: the authority rule reads identity and tenant
		// only, and these users never authenticate. tenant_id and email are the
		// only NOT NULL columns without a default.
		if err := pool.QueryRow(ctx, `
			INSERT INTO users (email, tenant_id, role_id, is_active)
			VALUES ($1, $2, $3, true)
			RETURNING id
		`, email, tenantID, roleID).Scan(&id); err != nil {
			t.Fatalf("insert user %s: %v", email, err)
		}
		return id
	}

	f.platformAdmin = mkUser("authz-platform-admin@test.local", f.platformTenant, &platformRole)
	f.grantAdmin = mkUser("authz-grant-admin@test.local", f.otherTenant, nil)
	f.pendingAdmin = mkUser("authz-pending-admin@test.local", f.otherTenant, nil)
	f.endUser = mkUser("authz-end-user@test.local", f.otherTenant, nil)

	if _, err := pool.Exec(ctx, `
		INSERT INTO admin_grants (user_id, tenant_id, admin_role, activated_at)
		VALUES ($1, $2, 'owner', NOW())
	`, f.grantAdmin, f.grantedTenant); err != nil {
		t.Fatalf("insert activated grant: %v", err)
	}
	// An invitation that was sent and never accepted. activated_at IS NULL is
	// what HasAdminGrant refuses, and this arm must refuse it identically — an
	// unaccepted invitation is not authority.
	if _, err := pool.Exec(ctx, `
		INSERT INTO admin_grants (user_id, tenant_id, admin_role, activated_at)
		VALUES ($1, $2, 'owner', NULL)
	`, f.pendingAdmin, f.grantedTenant); err != nil {
		t.Fatalf("insert pending grant: %v", err)
	}

	return f
}

func setupAuthority(t *testing.T) (*pgxpool.Pool, authorityFixture) {
	t.Helper()
	if os.Getenv("DATABASE_URL") == "" {
		t.Skip("DATABASE_URL not set — skipping refresh authority tests")
	}
	pool := testhelper.NewTestDB(t)
	t.Cleanup(func() { testhelper.CleanupTables(t, pool) })
	return pool, newAuthorityFixture(t, pool)
}

// TestRefreshAuthority_HomeTenant is the end-user arm, and the one that must not
// have moved: an ordinary user's token tenant always equals their home tenant,
// so this is the path every non-admin rotation takes.
func TestRefreshAuthority_HomeTenant(t *testing.T) {
	pool, f := setupAuthority(t)

	if !mayRefreshInto(t, pool, f.endUser, f.otherTenant) {
		t.Error("an end user cannot refresh in their own tenant — every ordinary session is broken")
	}
}

// TestRefreshAuthority_EndUserCannotCrossTenants is the security gate the fix had
// to preserve. Widening the tenant condition carelessly — dropping it, or
// matching on the token alone — would let a tampered or stolen token rotate into
// a tenant its owner has no business in.
func TestRefreshAuthority_EndUserCannotCrossTenants(t *testing.T) {
	pool, f := setupAuthority(t)

	for name, tenant := range map[string]int64{
		"the platform tenant": f.platformTenant,
		"a granted tenant":    f.grantedTenant,
	} {
		if mayRefreshInto(t, pool, f.endUser, tenant) {
			t.Errorf("an end user was allowed to refresh into %s — tenant isolation is broken", name)
		}
	}
}

// TestRefreshAuthority_PlatformAdminReachesEveryTenant is the arm the obvious fix
// would have missed.
//
// A platform administrator holds no admin_grants row at all — their authority is
// tenant:manage, not membership — so "resolve the grant instead of the tenant"
// would still have locked out exactly the account that reported the logout.
func TestRefreshAuthority_PlatformAdminReachesEveryTenant(t *testing.T) {
	pool, f := setupAuthority(t)

	var grants int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM admin_grants WHERE user_id = $1`, f.platformAdmin).Scan(&grants); err != nil {
		t.Fatalf("count grants: %v", err)
	}
	if grants != 0 {
		t.Fatalf("fixture drift: the platform admin holds %d grants, so this test would pass "+
			"through the grant arm and prove nothing about tenant:manage", grants)
	}

	for name, tenant := range map[string]int64{
		"their own tenant": f.platformTenant,
		"a foreign tenant": f.otherTenant,
		"a granted tenant": f.grantedTenant,
	} {
		if !mayRefreshInto(t, pool, f.platformAdmin, tenant) {
			t.Errorf("a platform administrator cannot refresh in %s — this is the reported bug", name)
		}
	}
}

// TestRefreshAuthority_ActivatedGrant covers the tenant-admin arm: authority in a
// tenant that is not their home.
func TestRefreshAuthority_ActivatedGrant(t *testing.T) {
	pool, f := setupAuthority(t)

	if !mayRefreshInto(t, pool, f.grantAdmin, f.grantedTenant) {
		t.Error("an administrator with an activated grant cannot refresh in that tenant")
	}
	// Their home tenant still works — a grant adds reach, it does not move them.
	if !mayRefreshInto(t, pool, f.grantAdmin, f.otherTenant) {
		t.Error("a grant holder lost access to their own home tenant")
	}
	// And the grant does not spill into tenants that did not issue it.
	if mayRefreshInto(t, pool, f.grantAdmin, f.platformTenant) {
		t.Error("a grant in one tenant admitted refresh in another — grants are not transitive")
	}
}

// TestRefreshAuthority_PendingGrantIsNotAuthority pins activated_at.
//
// An invitation that was sent and never accepted must not authorise a rotation.
// HasAdminGrant already refuses it; this arm has to agree, or the two gates
// disagree about who may act where.
func TestRefreshAuthority_PendingGrantIsNotAuthority(t *testing.T) {
	pool, f := setupAuthority(t)

	if mayRefreshInto(t, pool, f.pendingAdmin, f.grantedTenant) {
		t.Error("an unaccepted admin invitation authorised a refresh — activated_at is not being checked")
	}
}

// TestRefreshAuthority_RevokedGrantEndsTheSession is the security improvement the
// fix buys rather than merely preserves.
//
// The authority is re-evaluated on EVERY rotation, so soft-deleting a grant ends
// that administrator's session at the next refresh — within the access token's
// 15 minutes — instead of letting it ride to the absolute cap.
func TestRefreshAuthority_RevokedGrantEndsTheSession(t *testing.T) {
	pool, f := setupAuthority(t)

	if !mayRefreshInto(t, pool, f.grantAdmin, f.grantedTenant) {
		t.Fatal("fixture: the grant should be live before it is revoked")
	}

	if _, err := pool.Exec(context.Background(),
		`UPDATE admin_grants SET deleted_at = NOW() WHERE user_id = $1 AND tenant_id = $2`,
		f.grantAdmin, f.grantedTenant); err != nil {
		t.Fatalf("revoke grant: %v", err)
	}

	if mayRefreshInto(t, pool, f.grantAdmin, f.grantedTenant) {
		t.Error("a revoked grant still authorised a refresh — the session outlives the authority")
	}
}

// TestRefreshAuthority_DeactivatedUserIsRefused proves the account-level gates
// survived the rewrite. is_active and deleted_at are the checks that stop a
// suspended administrator minting a fresh token, and they sit outside the
// three-way tenant test precisely so no arm can bypass them.
func TestRefreshAuthority_DeactivatedUserIsRefused(t *testing.T) {
	pool, f := setupAuthority(t)
	ctx := context.Background()

	if _, err := pool.Exec(ctx, `UPDATE users SET is_active = false WHERE id = $1`, f.platformAdmin); err != nil {
		t.Fatalf("deactivate: %v", err)
	}
	if mayRefreshInto(t, pool, f.platformAdmin, f.platformTenant) {
		t.Error("a deactivated platform administrator could still refresh")
	}

	if _, err := pool.Exec(ctx,
		`UPDATE users SET is_active = true, deleted_at = NOW() WHERE id = $1`, f.platformAdmin); err != nil {
		t.Fatalf("soft delete: %v", err)
	}
	if mayRefreshInto(t, pool, f.platformAdmin, f.platformTenant) {
		t.Error("a soft-deleted platform administrator could still refresh")
	}
}
