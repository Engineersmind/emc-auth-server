package auth_test

import (
	"context"
	"testing"

	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// Multi-role permission resolution and session scoping — issue #146, phases 2-4.
//
// The question these answer is the one the whole change exists for: a user who
// holds two roles must receive the UNION of both roles' permissions in their
// token, deduplicated, and a session may be narrowed to a subset of those roles
// without ever being able to widen beyond what the account holds.
//
// Asserted against a real minted and verified token rather than against the
// resolver, because the claim is what enforcement reads and a resolver that is
// right while the claim is wrong helps nobody.

// grantRole inserts a role carrying one permission and returns its id. The
// permission name doubles as the marker the assertions look for.
func grantRole(t *testing.T, f roleFixture, roleName, permName string) int64 {
	t.Helper()
	ctx := context.Background()

	var appID int64
	if err := f.pool.QueryRow(ctx,
		`SELECT id FROM oauth_clients WHERE client_id = $1`, f.app.ClientID).Scan(&appID); err != nil {
		t.Fatalf("fetch app id: %v", err)
	}

	var permID int64
	if err := f.pool.QueryRow(ctx, `
		INSERT INTO permissions (tenant_id, name, description) VALUES ($1, $2, '')
		RETURNING id
	`, f.tenantID, permName).Scan(&permID); err != nil {
		t.Fatalf("insert permission %s: %v", permName, err)
	}

	var roleID int64
	if err := f.pool.QueryRow(ctx, `
		INSERT INTO roles (tenant_id, application_id, name, is_system, is_default, created_at)
		VALUES ($1, $2, $3, false, false, NOW())
		RETURNING id
	`, f.tenantID, appID, roleName).Scan(&roleID); err != nil {
		t.Fatalf("insert role %s: %v", roleName, err)
	}
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO role_permissions (role_id, permission_id, tenant_id) VALUES ($1, $2, $3)
	`, roleID, permID, f.tenantID); err != nil {
		t.Fatalf("grant %s to %s: %v", permName, roleName, err)
	}
	return roleID
}

// holdRole records a grant directly, standing in for the admin API so these
// tests exercise resolution rather than the admin service.
func holdRole(t *testing.T, f roleFixture, userID int64, roleID int64) {
	t.Helper()
	if _, err := f.pool.Exec(context.Background(), `
		INSERT INTO user_roles (user_id, role_id, tenant_id, granted_by)
		VALUES ($1, $2, $3, NULL)
		ON CONFLICT (user_id, role_id) DO NOTHING
	`, userID, roleID, f.tenantID); err != nil {
		t.Fatalf("record role grant: %v", err)
	}
}

func TestLogin_UnionsPermissionsAcrossEveryRoleHeld(t *testing.T) {
	f := newRoleFixture(t, "multi-role-app", "widgets:read")
	ctx := context.Background()

	email := uniqueEmail("union")
	f.registerAndLogin(t, email)

	// Registration gave the default "viewer" role (widgets:read). Add a second
	// role carrying a different permission.
	var uid int64
	if err := f.pool.QueryRow(ctx, `SELECT id FROM users WHERE email = $1`, email).Scan(&uid); err != nil {
		t.Fatalf("fetch user id: %v", err)
	}
	holdRole(t, f, uid, grantRole(t, f, "editor", "widgets:write"))

	login, err := f.svc.Login(ctx, auth.LoginInput{
		ClientID: f.app.ClientID, ClientSecret: f.app.ClientSecret,
		Email: email, Password: "Password123!",
	})
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	after, err := f.jwtSvc.Verify(ctx, login.Token.AccessToken)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	// THE headline assertion: both roles' permissions, in one token. Before phase
	// 2 the second role could not have been held at all.
	if !hasPerm(after.Permissions, "widgets:read") || !hasPerm(after.Permissions, "widgets:write") {
		t.Errorf("token permissions = %v, want both widgets:read (viewer) and widgets:write (editor)", after.Permissions)
	}
	// And the roles claim reports both, primary first.
	if len(after.Roles) != 2 || after.Roles[0] != "viewer" || after.Roles[1] != "editor" {
		t.Errorf("token roles = %v, want [viewer editor]", after.Roles)
	}
	// The deprecated scalar keeps carrying the primary, unchanged by the addition.
	if after.Role != "viewer" {
		t.Errorf("token role = %q, want the primary %q to stay stable", after.Role, "viewer")
	}
}

func TestLogin_DeduplicatesPermissionsSharedByTwoRoles(t *testing.T) {
	f := newRoleFixture(t, "dedup-app", "widgets:read")
	ctx := context.Background()

	email := uniqueEmail("dedup")
	f.registerAndLogin(t, email)
	var uid int64
	if err := f.pool.QueryRow(ctx, `SELECT id FROM users WHERE email = $1`, email).Scan(&uid); err != nil {
		t.Fatalf("fetch user id: %v", err)
	}

	// A second role carrying the SAME permission as the first.
	var permID int64
	if err := f.pool.QueryRow(ctx,
		`SELECT id FROM permissions WHERE tenant_id = $1 AND name = 'widgets:read'`,
		f.tenantID).Scan(&permID); err != nil {
		t.Fatalf("fetch existing permission: %v", err)
	}
	var appID int64
	if err := f.pool.QueryRow(ctx,
		`SELECT id FROM oauth_clients WHERE client_id = $1`, f.app.ClientID).Scan(&appID); err != nil {
		t.Fatalf("fetch app id: %v", err)
	}
	var dupRole int64
	if err := f.pool.QueryRow(ctx, `
		INSERT INTO roles (tenant_id, application_id, name, is_system, is_default, created_at)
		VALUES ($1, $2, 'auditor', false, false, NOW()) RETURNING id
	`, f.tenantID, appID).Scan(&dupRole); err != nil {
		t.Fatalf("insert auditor role: %v", err)
	}
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO role_permissions (role_id, permission_id, tenant_id) VALUES ($1, $2, $3)
	`, dupRole, permID, f.tenantID); err != nil {
		t.Fatalf("grant shared permission: %v", err)
	}
	holdRole(t, f, uid, dupRole)

	login, err := f.svc.Login(ctx, auth.LoginInput{
		ClientID: f.app.ClientID, ClientSecret: f.app.ClientSecret,
		Email: email, Password: "Password123!",
	})
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	claims, err := f.jwtSvc.Verify(ctx, login.Token.AccessToken)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	// Union semantics, not concatenation: a permission two roles both grant
	// appears once. A duplicate would bloat every token and break any consumer
	// treating the claim as a set.
	n := 0
	for _, p := range claims.Permissions {
		if p == "widgets:read" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("widgets:read appears %d times in %v, want exactly once", n, claims.Permissions)
	}
}

func TestLogin_ScopedSessionNarrowsToTheRequestedRole(t *testing.T) {
	f := newRoleFixture(t, "scoped-app", "widgets:read")
	ctx := context.Background()

	email := uniqueEmail("scoped")
	f.registerAndLogin(t, email)
	var uid int64
	if err := f.pool.QueryRow(ctx, `SELECT id FROM users WHERE email = $1`, email).Scan(&uid); err != nil {
		t.Fatalf("fetch user id: %v", err)
	}
	holdRole(t, f, uid, grantRole(t, f, "editor", "widgets:write"))

	// Ask for a session scoped to viewer alone, though the account holds both.
	login, err := f.svc.Login(ctx, auth.LoginInput{
		ClientID: f.app.ClientID, ClientSecret: f.app.ClientSecret,
		Email: email, Password: "Password123!",
		Roles: []string{"viewer"},
	})
	if err != nil {
		t.Fatalf("Login(scoped) error = %v", err)
	}
	claims, err := f.jwtSvc.Verify(ctx, login.Token.AccessToken)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if !hasPerm(claims.Permissions, "widgets:read") {
		t.Errorf("token permissions = %v, want the requested viewer's widgets:read", claims.Permissions)
	}
	// The narrowing is the point: the editor role is held but not active, so its
	// permission must be absent.
	if hasPerm(claims.Permissions, "widgets:write") {
		t.Errorf("token permissions = %v, want widgets:write EXCLUDED by the viewer-scoped session", claims.Permissions)
	}
	if len(claims.ActiveRoles) != 1 || claims.ActiveRoles[0] != "viewer" {
		t.Errorf("active_roles = %v, want [viewer]", claims.ActiveRoles)
	}
	// roles still reports everything the ACCOUNT holds, so a consumer can tell
	// "holds only viewer" from "holds both but asked for viewer".
	if len(claims.Roles) != 2 {
		t.Errorf("roles = %v, want both roles the account holds", claims.Roles)
	}
}

func TestLogin_RefusesAScopeTheUserDoesNotHold(t *testing.T) {
	f := newRoleFixture(t, "widen-app", "widgets:read")
	ctx := context.Background()

	email := uniqueEmail("widen")
	f.registerAndLogin(t, email)

	// The entire security property of session scoping. Without the check, any
	// caller could ask for a role they do not hold and be handed it.
	_, err := f.svc.Login(ctx, auth.LoginInput{
		ClientID: f.app.ClientID, ClientSecret: f.app.ClientSecret,
		Email: email, Password: "Password123!",
		Roles: []string{"owner"},
	})
	if err == nil {
		t.Fatal("Login(unheld role) succeeded; a session must never be widened by asking")
	}
	// Generic on purpose: a specific error would turn the login endpoint into an
	// oracle for which roles exist and who holds them.
	if err.Error() != "invalid credentials" {
		t.Errorf("Login(unheld role) error = %q, want the generic %q", err.Error(), "invalid credentials")
	}
}

func TestRefresh_KeepsAScopedSessionNarrowed(t *testing.T) {
	f := newRoleFixture(t, "scope-refresh-app", "widgets:read")
	ctx := context.Background()

	email := uniqueEmail("scope-refresh")
	f.registerAndLogin(t, email)
	var uid int64
	if err := f.pool.QueryRow(ctx, `SELECT id FROM users WHERE email = $1`, email).Scan(&uid); err != nil {
		t.Fatalf("fetch user id: %v", err)
	}
	holdRole(t, f, uid, grantRole(t, f, "editor", "widgets:write"))

	login, err := f.svc.Login(ctx, auth.LoginInput{
		ClientID: f.app.ClientID, ClientSecret: f.app.ClientSecret,
		Email: email, Password: "Password123!",
		Roles: []string{"viewer"},
	})
	if err != nil {
		t.Fatalf("Login(scoped) error = %v", err)
	}

	rotated, err := f.svc.Refresh(ctx, login.Token.RefreshToken)
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	claims, err := f.jwtSvc.Verify(ctx, rotated.AccessToken)
	if err != nil {
		t.Fatalf("Verify(rotated) error = %v", err)
	}

	// A refresh that silently restored the full set would make scoping a
	// privilege escalation reachable by waiting: scope down, rotate once, come
	// back holding everything.
	if hasPerm(claims.Permissions, "widgets:write") {
		t.Errorf("rotated permissions = %v, want the session to stay narrowed to viewer", claims.Permissions)
	}
	if len(claims.ActiveRoles) != 1 || claims.ActiveRoles[0] != "viewer" {
		t.Errorf("rotated active_roles = %v, want [viewer] carried across the rotation", claims.ActiveRoles)
	}
}

func TestRefresh_UnscopedSessionKeepsTheFullUnion(t *testing.T) {
	f := newRoleFixture(t, "unscoped-refresh-app", "widgets:read")
	ctx := context.Background()

	email := uniqueEmail("unscoped-refresh")
	f.registerAndLogin(t, email)
	var uid int64
	if err := f.pool.QueryRow(ctx, `SELECT id FROM users WHERE email = $1`, email).Scan(&uid); err != nil {
		t.Fatalf("fetch user id: %v", err)
	}
	holdRole(t, f, uid, grantRole(t, f, "editor", "widgets:write"))

	login, err := f.svc.Login(ctx, auth.LoginInput{
		ClientID: f.app.ClientID, ClientSecret: f.app.ClientSecret,
		Email: email, Password: "Password123!",
	})
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	rotated, err := f.svc.Refresh(ctx, login.Token.RefreshToken)
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	claims, err := f.jwtSvc.Verify(ctx, rotated.AccessToken)
	if err != nil {
		t.Fatalf("Verify(rotated) error = %v", err)
	}

	// The counterweight: NULL active_roles must mean "unscoped", not "scoped to
	// nothing". Getting this backwards would empty every ordinary session's
	// permissions on its first rotation.
	if !hasPerm(claims.Permissions, "widgets:read") || !hasPerm(claims.Permissions, "widgets:write") {
		t.Errorf("rotated permissions = %v, want the full union preserved across rotation", claims.Permissions)
	}
	if len(claims.ActiveRoles) != 0 {
		t.Errorf("rotated active_roles = %v, want empty for an unscoped session", claims.ActiveRoles)
	}
}
