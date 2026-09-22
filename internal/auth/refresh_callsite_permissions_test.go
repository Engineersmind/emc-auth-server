// refresh_callsite_permissions_test.go — the permission load at each widened
// call site.
//
// # Why these are separate from the existing authority tests
//
// TestRefreshPermissionsMatchTheSwitch already asserts that
// permissionsForRefresh agrees with the switch. It passed throughout, because
// permissionsForRefresh was never the broken part: two of the three paths that
// had their IDENTITY check widened to tenantAuthorityPredicate went on calling
// loadPermissions, which answers from the user's HOME role no matter which
// tenant it is asked about.
//
// Widening who may rotate, without widening where their permissions come from,
// is precisely the shape of #142 — and it survived a review, a fix and a test
// suite because every test pointed at the helper rather than at the call sites.
// So these tests assert what a caller actually resolves. Raised in review on
// #143 against Refresh() and checkGraceWindow().
package auth_test

import (
	"context"
	"testing"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
	"github.com/jackc/pgx/v5/pgxpool"
)

// grantAdminWithNarrowerRole gives the grant fixture's administrator a real
// permission in the granted tenant, so "the right answer" and "the home-role
// answer" are distinguishable.
//
// The distinction is the test: grantAdmin's home tenant carries no role at all,
// so loadPermissions returns an empty set for them, while the granted tenant's
// owner role carries apps:write. A call site using the wrong loader therefore
// resolves nothing rather than resolving something subtly different — the same
// silent loss of authority #142 reported.
func grantAdminWithNarrowerRole(t *testing.T, pool *pgxpool.Pool, grantedTenant int64) {
	t.Helper()
	ctx := context.Background()

	var roleID, permID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO roles (tenant_id, name) VALUES ($1, 'owner') RETURNING id`,
		grantedTenant).Scan(&roleID); err != nil {
		t.Fatalf("insert owner role: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO permissions (tenant_id, name, description)
		 VALUES ($1, 'apps:write', 'call-site fixture') RETURNING id`,
		grantedTenant).Scan(&permID); err != nil {
		t.Fatalf("insert permission: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO role_permissions (role_id, permission_id, tenant_id) VALUES ($1, $2, $3)`,
		roleID, permID, grantedTenant); err != nil {
		t.Fatalf("grant permission to role: %v", err)
	}
}

// seedLiveSession creates a session and a live refresh token for it, which is
// what checkGraceWindow requires before it will answer at all.
func seedLiveSession(t *testing.T, pool *pgxpool.Pool, userID, tenantID int64) int64 {
	t.Helper()
	ctx := context.Background()

	// token_hash is UNIQUE, so it is keyed on the test rather than a constant —
	// otherwise the second test to run in a shared database collides.
	tokenHash := "call-site-fixture-" + t.Name()

	var sessionID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO user_sessions (user_id, tenant_id, auth_time,
		                           idle_expires_at, absolute_expires_at)
		VALUES ($1, $2, NOW(), NOW() + INTERVAL '1 hour', NOW() + INTERVAL '8 hours')
		RETURNING id
	`, userID, tenantID).Scan(&sessionID); err != nil {
		t.Fatalf("insert session: %v", err)
	}

	// created_at inside the grace period is the point — checkGraceWindow only
	// answers for a token rotated within the last few seconds.
	//
	// session_family_id is NOT NULL and self-referential for the first token of
	// a family, which is what a freshly issued one is; the production code sets
	// it to the row's own id the same way.
	var tokenID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO refresh_tokens (user_id, tenant_id, session_id, token_hash,
		                            session_family_id, expires_at, created_at)
		VALUES ($1, $2, $3, $4, 0, NOW() + INTERVAL '30 days', NOW())
		RETURNING id
	`, userID, tenantID, sessionID, tokenHash).Scan(&tokenID); err != nil {
		t.Fatalf("insert refresh token: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE refresh_tokens SET session_family_id = id WHERE id = $1`, tokenID); err != nil {
		t.Fatalf("set session family: %v", err)
	}
	return sessionID
}

// The grace path is the most immediate of the two: GraceResult.Permissions is
// applied to the in-flight request directly through graceToAuthClaims, with no
// token minting or signature verification in between. A wrong permission set
// here is not a bad token to be rejected later — it is the authority the
// request is served with.
//
// Reached from RefreshWithLock whenever a concurrent rotation loses the Redis
// lock, so two tabs racing a refresh is enough to hit it.
func TestGraceWindowPermissionsMatchTheGrant(t *testing.T) {
	pool, f := setupAuthority(t)
	ctx := context.Background()

	grantAdminWithNarrowerRole(t, pool, f.grantedTenant)
	sessionID := seedLiveSession(t, pool, f.grantAdmin, f.grantedTenant)

	got, err := auth.ExportedCheckGraceWindow(
		pool, testhelper.TestLogger(), ctx, f.grantAdmin, f.grantedTenant, sessionID)
	if err != nil {
		t.Fatalf("checkGraceWindow: %v", err)
	}

	want, err := auth.ExportedPermissionsForRefresh(
		pool, testhelper.TestLogger(), ctx, f.grantAdmin, f.grantedTenant)
	if err != nil {
		t.Fatalf("permissionsForRefresh: %v", err)
	}

	// Agreement with the rule, not a fixed list: whatever the rotation rule
	// resolves, the grace path must resolve the same thing.
	if !samePermissions(got, want) {
		t.Errorf("grace window resolved %v, want %v — the grace path applies the wrong "+
			"authority directly to the in-flight request", got, want)
	}

	// And the fixture must be able to tell the two loaders apart, or the
	// assertion above would hold for the broken version too.
	if !hasPerm(got, "apps:write") {
		t.Errorf("grace window resolved %v, want apps:write from the granted tenant's "+
			"owner role — a granted administrator loses their permissions mid-request", got)
	}
}

// The home-tenant arm must not have moved. Every ordinary session takes it, and
// widening the grace path's loader must not change what a normal user gets.
func TestGraceWindowPermissionsUnchangedForHomeTenant(t *testing.T) {
	pool, f := setupAuthority(t)
	ctx := context.Background()

	sessionID := seedLiveSession(t, pool, f.endUser, f.otherTenant)

	got, err := auth.ExportedCheckGraceWindow(
		pool, testhelper.TestLogger(), ctx, f.endUser, f.otherTenant, sessionID)
	if err != nil {
		t.Fatalf("checkGraceWindow: %v", err)
	}

	want, err := auth.ExportedLoadPermissions(
		pool, testhelper.TestLogger(), ctx, f.endUser, f.otherTenant)
	if err != nil {
		t.Fatalf("loadPermissions: %v", err)
	}

	if !samePermissions(got, want) {
		t.Errorf("grace window resolved %v for an ordinary user in their own tenant, want %v — "+
			"the common path changed", got, want)
	}
}

// A platform administrator's authority lives on their home role, where
// tenant:manage is. Reaching a foreign tenant by permission rather than by
// grant, they must keep it across the grace path.
func TestGraceWindowPermissionsCarryPlatformAuthority(t *testing.T) {
	pool, f := setupAuthority(t)
	ctx := context.Background()

	sessionID := seedLiveSession(t, pool, f.platformAdmin, f.otherTenant)

	got, err := auth.ExportedCheckGraceWindow(
		pool, testhelper.TestLogger(), ctx, f.platformAdmin, f.otherTenant, sessionID)
	if err != nil {
		t.Fatalf("checkGraceWindow: %v", err)
	}

	if !hasPerm(got, "tenant:manage") {
		t.Errorf("grace window resolved %v for a platform administrator in a foreign tenant, "+
			"want tenant:manage — the account that reported #142 loses authority mid-request", got)
	}
}

// samePermissions compares two permission sets irrespective of order.
func samePermissions(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[string]int{}
	for _, p := range a {
		seen[p]++
	}
	for _, p := range b {
		seen[p]--
		if seen[p] < 0 {
			return false
		}
	}
	return true
}
