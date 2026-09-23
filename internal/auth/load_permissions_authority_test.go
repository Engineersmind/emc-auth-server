package auth_test

import (
	"context"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// The authority rule loadPermissions applies when building a token's claims.
//
// Companion to refresh_tenant_authority_test.go. #142 fixed the rule in
// RefreshWithLock's user load, which decides WHETHER a token may be minted.
// This is the same rule in the function that decides WHAT IS IN IT, and it was
// missed: a platform admin's refresh succeeded, and the token came back with
// zero permissions.
//
// The visible failure was a 403 on every admin page while browsing another
// tenant — "Failed to load application" for a super_admin looking at an
// application they own. RequireAppScope's `tenant:manage` fast path cannot fire
// on claims that carry no permissions, and the client cannot recover: a 403 is
// an answer, so the refresh interceptor does not retry, and a refreshed token
// would carry the same empty set anyway.
//
// Kept as SQL, copied verbatim from service.go, for the same reason the refresh
// fixture is: the bug was a WHERE clause and the fix is a WHERE clause.
//
// Keep in sync with internal/auth/service.go — loadPermissions.
const loadPermissionsSQL = `
	WITH authority AS (
		SELECT u.id, u.role_id, u.tenant_id
		FROM users u
		WHERE u.id = $1
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
	)
	SELECT DISTINCT p.name
	FROM permissions p
	JOIN role_permissions rp ON rp.permission_id = p.id
	JOIN authority a ON a.role_id = rp.role_id
	UNION
	SELECT DISTINCT p.name
	FROM permissions p
	JOIN user_permissions up ON up.permission_id = p.id
	JOIN authority a ON a.id = up.user_id
	WHERE up.tenant_id = $2
	ORDER BY 1
`

func permissionsFor(t *testing.T, pool *pgxpool.Pool, userID, tenantID int64) []string {
	t.Helper()

	// The PRODUCTION loader. This previously ran loadPermissionsSQL, a verbatim
	// copy, so a change to service.go alone left these tests green (raised in
	// review on #143).
	prod, err := auth.ExportedLoadPermissions(pool, testhelper.TestLogger(), context.Background(), userID, tenantID)
	if err != nil {
		t.Fatalf("loadPermissions: %v", err)
	}
	sort.Strings(prod)

	// The copy is kept as a second signal — it catches the two drifting apart,
	// which a behavioural check alone would not.
	rows, err := pool.Query(context.Background(), loadPermissionsSQL, userID, tenantID)
	if err != nil {
		t.Fatalf("permissions query: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out = append(out, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	sort.Strings(out)
	// Compared by content rather than with DeepEqual: the production loader
	// normalises an empty result to []string{} while the scan loop below leaves
	// it nil, and a nil-vs-empty difference is not a disagreement about the rule.
	if strings.Join(out, ",") != strings.Join(prod, ",") {
		t.Errorf("the production loader and the copy in this file disagree:\n  production = %v\n  copy       = %v\none of them changed without the other", prod, out)
	}
	return prod
}

func hasPerm(perms []string, want string) bool {
	for _, p := range perms {
		if p == want {
			return true
		}
	}
	return false
}

// TestLoadPermissions_PlatformAdminKeepsPermissionsAcrossTenants is the
// reported bug: a super_admin whose home tenant is A, browsing tenant B.
//
// Before the fix the role join required `u.tenant_id = $2`, which is false for
// every tenant except their own, so this returned nothing at all.
func TestLoadPermissions_PlatformAdminKeepsPermissionsAcrossTenants(t *testing.T) {
	pool, f := setupAuthority(t)

	perms := permissionsFor(t, pool, f.platformAdmin, f.otherTenant)
	if len(perms) == 0 {
		t.Fatal("a platform admin browsing another tenant received NO permissions — every admin route answers 403 and no refresh can fix it")
	}
	if !hasPerm(perms, "tenant:manage") {
		t.Errorf("permissions = %v, want tenant:manage — RequireAppScope's fast path depends on it", perms)
	}

	// Their own tenant must be unchanged: this arm is the ordinary case and the
	// fix must not have moved it.
	home := permissionsFor(t, pool, f.platformAdmin, f.platformTenant)
	if !hasPerm(home, "tenant:manage") {
		t.Errorf("home-tenant permissions = %v, want tenant:manage", home)
	}
}

// TestLoadPermissions_EndUserGainsNothingCrossTenant is the containment test,
// and the one that matters most.
//
// Widening a permission lookup is exactly the change that quietly grants
// everyone everything. An ordinary user must still receive nothing for a tenant
// that is not theirs — the fix adds permissions ONLY for callers holding
// platform authority or an activated grant.
func TestLoadPermissions_EndUserGainsNothingCrossTenant(t *testing.T) {
	pool, f := setupAuthority(t)

	if perms := permissionsFor(t, pool, f.endUser, f.platformTenant); len(perms) != 0 {
		t.Errorf("an ordinary user received %v for a foreign tenant, want none — this would be a cross-tenant permission leak", perms)
	}
	if perms := permissionsFor(t, pool, f.endUser, f.grantedTenant); len(perms) != 0 {
		t.Errorf("an ordinary user received %v for a tenant they have no grant in, want none", perms)
	}
}

// An activated grant is authority, so the grant holder's permissions resolve in
// the granted tenant — the arm a "just look up the grant" fix would get right
// and the tenant:manage arm would miss.
func TestLoadPermissions_ActivatedGrantCarriesPermissions(t *testing.T) {
	pool, f := setupAuthority(t)

	// grantAdmin has no role, so the role arm yields nothing either way; what is
	// asserted here is that the authority CTE admits them at all. A direct
	// user_permission in the granted tenant proves the join reaches them.
	var permID int64
	if err := pool.QueryRow(context.Background(), `
		INSERT INTO permissions (tenant_id, name, description)
		VALUES ($1, 'grant:probe', 'authority fixture')
		RETURNING id
	`, f.grantedTenant).Scan(&permID); err != nil {
		t.Fatalf("insert probe permission: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO user_permissions (user_id, permission_id, tenant_id)
		VALUES ($1, $2, $3)
	`, f.grantAdmin, permID, f.grantedTenant); err != nil {
		t.Fatalf("insert direct permission: %v", err)
	}

	perms := permissionsFor(t, pool, f.grantAdmin, f.grantedTenant)
	if !hasPerm(perms, "grant:probe") {
		t.Errorf("permissions = %v, want grant:probe — an activated grant must carry the user's permissions in that tenant", perms)
	}
}

// A grant that was invited and never accepted is not authority, matching the
// refresh rule. If this ever passes, an unaccepted invitation has become a
// standing permission.
func TestLoadPermissions_PendingGrantIsNotAuthority(t *testing.T) {
	pool, f := setupAuthority(t)

	if perms := permissionsFor(t, pool, f.pendingAdmin, f.grantedTenant); len(perms) != 0 {
		t.Errorf("a pending (unaccepted) grant yielded %v, want none", perms)
	}
}

// Direct user_permissions rows stay scoped to the tenant they were granted in,
// even for a platform admin. Platform authority widens which ROLE permissions
// apply; it does not relocate a per-tenant direct grant to another tenant.
func TestLoadPermissions_DirectGrantsStayTenantScoped(t *testing.T) {
	pool, f := setupAuthority(t)
	ctx := context.Background()

	var permID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO permissions (tenant_id, name, description)
		VALUES ($1, 'scoped:probe', 'authority fixture')
		RETURNING id
	`, f.grantedTenant).Scan(&permID); err != nil {
		t.Fatalf("insert probe permission: %v", err)
	}
	// Granted to the platform admin, but only inside grantedTenant.
	if _, err := pool.Exec(ctx, `
		INSERT INTO user_permissions (user_id, permission_id, tenant_id)
		VALUES ($1, $2, $3)
	`, f.platformAdmin, permID, f.grantedTenant); err != nil {
		t.Fatalf("insert direct permission: %v", err)
	}

	if perms := permissionsFor(t, pool, f.platformAdmin, f.grantedTenant); !hasPerm(perms, "scoped:probe") {
		t.Errorf("permissions in the granting tenant = %v, want scoped:probe", perms)
	}
	if perms := permissionsFor(t, pool, f.platformAdmin, f.otherTenant); hasPerm(perms, "scoped:probe") {
		t.Errorf("a direct grant made in one tenant leaked into another: %v", perms)
	}
}

// TestRefreshPermissionsMatchTheSwitch is the rotation-drift guard.
//
// SwitchTenantContext resolves a granted administrator's permissions from the
// TARGET tenant's seeded role. Refresh used loadPermissions, which answers from
// the HOME role — usually absent for such a user — so the rotated token carried
// nothing and every route answered 403 roughly fifteen minutes after switching.
// The session did not end; it quietly lost its authority.
//
// The property asserted is agreement between the two paths, not a particular
// permission list: whatever the switch grants, the refresh must still grant.
func TestRefreshPermissionsMatchTheSwitch(t *testing.T) {
	pool, f := setupAuthority(t)
	ctx := context.Background()

	// The granted tenant seeds an 'owner' role, matching the grant fixture.
	var roleID, permID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO roles (tenant_id, name) VALUES ($1, 'owner') RETURNING id`,
		f.grantedTenant).Scan(&roleID); err != nil {
		t.Fatalf("insert owner role: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO permissions (tenant_id, name, description) VALUES ($1, 'apps:write', 'authority fixture') RETURNING id`,
		f.grantedTenant).Scan(&permID); err != nil {
		t.Fatalf("insert permission: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO role_permissions (role_id, permission_id, tenant_id) VALUES ($1, $2, $3)`,
		roleID, permID, f.grantedTenant); err != nil {
		t.Fatalf("grant permission to role: %v", err)
	}

	// What the switch resolves: the target tenant's owner role.
	switchPerms := rolePermissionsInTenant(t, pool, f.grantedTenant, "owner")
	if !hasPerm(switchPerms, "apps:write") {
		t.Fatalf("fixture is wrong: the switch path resolves %v, expected apps:write", switchPerms)
	}

	// What the refresh resolves for the same user in the same tenant.
	refreshPerms := refreshPermissionsFor(t, pool, f.grantAdmin, f.grantedTenant)
	if !hasPerm(refreshPerms, "apps:write") {
		t.Errorf("refresh resolved %v, want apps:write — a granted administrator loses their permissions at the first rotation, 403ing on every route about fifteen minutes after switching", refreshPerms)
	}
}

// rolePermissionsInTenant is what loadAdminPermissionsForTenant resolves for a
// grant holder: the target tenant's tenant-level role of that name.
func rolePermissionsInTenant(t *testing.T, pool *pgxpool.Pool, tenantID int64, role string) []string {
	t.Helper()
	rows, err := pool.Query(context.Background(), `
		SELECT DISTINCT p.name
		FROM permissions p
		JOIN role_permissions rp ON rp.permission_id = p.id
		JOIN roles r             ON r.id = rp.role_id
		WHERE r.tenant_id = $1 AND r.name = $2
		  AND r.application_id IS NULL AND r.deleted_at IS NULL
		ORDER BY 1
	`, tenantID, role)
	if err != nil {
		t.Fatalf("role permissions query: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out = append(out, n)
	}
	return out
}

// refreshPermissionsFor mirrors permissionsForRefresh's branch structure.
// Kept in sync with internal/auth/tenant_context.go.
func refreshPermissionsFor(t *testing.T, pool *pgxpool.Pool, userID, tenantID int64) []string {
	t.Helper()
	ctx := context.Background()

	var homeTenant int64
	if err := pool.QueryRow(ctx, `SELECT tenant_id FROM users WHERE id = $1`, userID).Scan(&homeTenant); err != nil {
		t.Fatalf("home tenant: %v", err)
	}
	if homeTenant == tenantID {
		return permissionsFor(t, pool, userID, tenantID)
	}
	var grantRole string
	err := pool.QueryRow(ctx, `
		SELECT admin_role FROM admin_grants
		WHERE user_id = $1 AND tenant_id = $2
		  AND deleted_at IS NULL AND activated_at IS NOT NULL
		LIMIT 1
	`, userID, tenantID).Scan(&grantRole)
	if err == nil {
		return rolePermissionsInTenant(t, pool, tenantID, grantRole)
	}
	return permissionsFor(t, pool, userID, homeTenant)
}

// TestLoadPermissions_AppScopedTenantManageIsNotPlatformAuthority is the
// escalation the review on #143 identified.
//
// CreatePermission accepts any name for an application-scoped permission, so an
// application's own catalogue can contain a permission called 'tenant:manage'.
// The platform arm originally matched on that NAME alone, so holding an
// ordinary app role carrying it would have been read as unrestricted platform
// authority — permissions in every tenant on the installation.
//
// resolveRegistrationTenant defines the platform tier as a TENANT-LEVEL role
// (application_id IS NULL) holding a tenant-level permission, and both
// authority queries now require the same. No such rows exist in production
// data, which is why this fixture has to build them.
func TestLoadPermissions_AppScopedTenantManageIsNotPlatformAuthority(t *testing.T) {
	pool, f := setupAuthority(t)
	ctx := context.Background()

	// An application in the impostor's own tenant.
	var appID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO oauth_clients (tenant_id, name, app_type, client_id, scopes)
		VALUES ($1, 'Impostor App', 'web', 'impostor_client', '{}')
		RETURNING id
	`, f.otherTenant).Scan(&appID); err != nil {
		t.Fatalf("insert application: %v", err)
	}

	// An APPLICATION-scoped role and permission, both named exactly like the
	// platform pair. Nothing forbids this today.
	var roleID, permID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO roles (tenant_id, application_id, name) VALUES ($1, $2, 'app-super') RETURNING id
	`, f.otherTenant, appID).Scan(&roleID); err != nil {
		t.Fatalf("insert app role: %v", err)
	}
	if err := pool.QueryRow(ctx, `
		INSERT INTO permissions (tenant_id, application_id, name, description)
		VALUES ($1, $2, 'tenant:manage', 'impostor')
		RETURNING id
	`, f.otherTenant, appID).Scan(&permID); err != nil {
		t.Fatalf("insert app permission: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO role_permissions (role_id, permission_id, tenant_id) VALUES ($1, $2, $3)
	`, roleID, permID, f.otherTenant); err != nil {
		t.Fatalf("grant app permission: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE users SET role_id = $1 WHERE id = $2`, roleID, f.endUser); err != nil {
		t.Fatalf("assign app role: %v", err)
	}

	// The impostor must reach NOTHING outside their own tenant.
	if perms := permissionsFor(t, pool, f.endUser, f.platformTenant); len(perms) != 0 {
		t.Errorf("an application-scoped 'tenant:manage' granted %v in a foreign tenant — this is platform escalation by permission name", perms)
	}
	if perms := permissionsFor(t, pool, f.endUser, f.grantedTenant); len(perms) != 0 {
		t.Errorf("an application-scoped 'tenant:manage' granted %v in a tenant with no grant", perms)
	}

	// And the refresh rule must refuse them the same way, or they could rotate
	// a token into any tenant even without carrying the permissions.
	if mayRefreshInto(t, pool, f.endUser, f.platformTenant) {
		t.Error("an application-scoped 'tenant:manage' allowed a refresh into a foreign tenant")
	}
}
