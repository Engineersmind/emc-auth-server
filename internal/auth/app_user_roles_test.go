package auth_test

import (
	"context"
	"errors"
	"strconv"
	"testing"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// Application-credentialed role assignment — issue #146.
//
// The flow: a user registers against an application and picks up its default
// role (or none); the application's backend then attaches further roles with its
// client credentials; the next login carries the updated roles and permissions.
//
// Most of these tests are about what the endpoint REFUSES, because the thing
// being guarded is an application credential that can re-role any of its users:
// a hole here is a privilege escalation, not a bug report.

// appRoleFixture is a fixture plus a second application in the same tenant, so
// the cross-application boundary can actually be tested rather than assumed.
type appRoleFixture struct {
	roleFixture
	otherApp *auth.AppResult
}

func newAppRoleFixture(t *testing.T, name string) appRoleFixture {
	t.Helper()
	f := newRoleFixture(t, name, "widgets:read")

	appSvc := auth.NewApplicationService(f.pool, testhelper.TestLogger())
	other, err := appSvc.CreateApplication(context.Background(), f.tenantID, name+"-sibling", "web", nil)
	if err != nil {
		t.Fatalf("CreateApplication(sibling) error = %v", err)
	}
	return appRoleFixture{roleFixture: f, otherApp: other}
}

// registerUser creates a user through the real registration path and returns
// their id, so these tests exercise the same rows a live registration writes.
func (f appRoleFixture) registerUser(t *testing.T, email string) int64 {
	t.Helper()
	if _, err := f.svc.Register(context.Background(), auth.RegisterInput{
		ClientID: f.app.ClientID, ClientSecret: f.app.ClientSecret,
		Email: email, Password: "Password123!",
	}); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	var id int64
	if err := f.pool.QueryRow(context.Background(),
		`SELECT id FROM users WHERE email = $1`, email).Scan(&id); err != nil {
		t.Fatalf("fetch registered user id: %v", err)
	}
	return id
}

func TestAssignAppUserRoles_AttachesRolesAfterRegistration(t *testing.T) {
	f := newAppRoleFixture(t, "app-roles")
	ctx := context.Background()

	email := uniqueEmail("app-assign")
	userID := f.registerUser(t, email)
	grantRole(t, f.roleFixture, "editor", "widgets:write")
	grantRole(t, f.roleFixture, "approver", "widgets:approve")

	res, err := f.svc.AssignAppUserRoles(ctx, auth.AssignAppUserRolesInput{
		ClientID: f.app.ClientID, ClientSecret: f.app.ClientSecret,
		UserID: userID, Roles: []string{"editor", "approver"},
	})
	if err != nil {
		t.Fatalf("AssignAppUserRoles() error = %v", err)
	}

	// Additive by default: the registration-time default role survives alongside
	// the two just attached.
	if len(res.Roles) != 3 {
		t.Errorf("roles after assignment = %v, want the default plus editor and approver", res.Roles)
	}
	if len(res.Assigned) != 2 {
		t.Errorf("assigned = %v, want exactly the two newly attached roles", res.Assigned)
	}

	// The whole point of the flow: the next login carries them.
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
	for _, want := range []string{"widgets:read", "widgets:write", "widgets:approve"} {
		if !hasPerm(claims.Permissions, want) {
			t.Errorf("token permissions = %v, want %s from the assigned roles", claims.Permissions, want)
		}
	}
	if len(claims.Roles) != 3 {
		t.Errorf("token roles = %v, want all three", claims.Roles)
	}
}

func TestAssignAppUserRoles_RefusesWrongSecret(t *testing.T) {
	f := newAppRoleFixture(t, "app-roles-secret")
	ctx := context.Background()

	userID := f.registerUser(t, uniqueEmail("app-secret"))
	grantRole(t, f.roleFixture, "editor", "widgets:write")

	// The credential is what stands between any caller and re-roling every user
	// of the application.
	_, err := f.svc.AssignAppUserRoles(ctx, auth.AssignAppUserRolesInput{
		ClientID: f.app.ClientID, ClientSecret: "sk_not_the_real_secret",
		UserID: userID, Roles: []string{"editor"},
	})
	if !errors.Is(err, auth.ErrInvalidClient) {
		t.Errorf("AssignAppUserRoles(wrong secret) error = %v, want ErrInvalidClient", err)
	}
	if held := heldRoleNamesFor(t, f.roleFixture, userID); len(held) != 1 {
		t.Errorf("held roles = %v after a refused call, want only the registration default", held)
	}
}

func TestAssignAppUserRoles_RefusesAnotherApplicationsUser(t *testing.T) {
	f := newAppRoleFixture(t, "app-roles-isolation")
	ctx := context.Background()

	// A user of the SIBLING application, in the same tenant.
	otherEmail := uniqueEmail("sibling-user")
	if _, err := f.svc.Register(ctx, auth.RegisterInput{
		ClientID: f.otherApp.ClientID, ClientSecret: f.otherApp.ClientSecret,
		Email: otherEmail, Password: "Password123!",
	}); err != nil {
		t.Fatalf("Register(sibling app) error = %v", err)
	}
	var otherUserID int64
	if err := f.pool.QueryRow(ctx, `SELECT id FROM users WHERE email = $1`, otherEmail).Scan(&otherUserID); err != nil {
		t.Fatalf("fetch sibling user id: %v", err)
	}
	grantRole(t, f.roleFixture, "editor", "widgets:write")

	// THE isolation boundary. Same tenant, valid credentials — and still refused,
	// because the user belongs to a different application. Without this, one
	// compromised client secret would reach every user in the tenant.
	_, err := f.svc.AssignAppUserRoles(ctx, auth.AssignAppUserRolesInput{
		ClientID: f.app.ClientID, ClientSecret: f.app.ClientSecret,
		UserID: otherUserID, Roles: []string{"editor"},
	})
	if !errors.Is(err, auth.ErrUserNotInApplication) {
		t.Errorf("AssignAppUserRoles(sibling app's user) error = %v, want ErrUserNotInApplication", err)
	}
}

func TestAssignAppUserRoles_RefusesAnotherApplicationsRole(t *testing.T) {
	f := newAppRoleFixture(t, "app-roles-crossrole")
	ctx := context.Background()

	userID := f.registerUser(t, uniqueEmail("crossrole"))

	// A role defined in the SIBLING application.
	var otherAppID int64
	if err := f.pool.QueryRow(ctx,
		`SELECT id FROM oauth_clients WHERE client_id = $1`, f.otherApp.ClientID).Scan(&otherAppID); err != nil {
		t.Fatalf("fetch sibling app id: %v", err)
	}
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO roles (tenant_id, application_id, name, is_system, is_default, created_at)
		VALUES ($1, $2, 'foreign-editor', false, false, NOW())
	`, f.tenantID, otherAppID); err != nil {
		t.Fatalf("insert sibling role: %v", err)
	}

	// Resolution is scoped to the authenticated application's own roles, so a
	// cross-application grant is unrepresentable rather than merely refused.
	_, err := f.svc.AssignAppUserRoles(ctx, auth.AssignAppUserRolesInput{
		ClientID: f.app.ClientID, ClientSecret: f.app.ClientSecret,
		UserID: userID, Roles: []string{"foreign-editor"},
	})
	if !errors.Is(err, auth.ErrRoleNotInApplication) {
		t.Errorf("AssignAppUserRoles(sibling app's role) error = %v, want ErrRoleNotInApplication", err)
	}
}

func TestAssignAppUserRoles_RefusesSystemRole(t *testing.T) {
	f := newAppRoleFixture(t, "app-roles-system")
	ctx := context.Background()

	userID := f.registerUser(t, uniqueEmail("escalate"))

	// super_admin is tenant-level (application_id IS NULL) and is_system, so it
	// fails the application scope AND the is_system filter. Both are deliberate:
	// an application credential must never be a route to platform authority.
	_, err := f.svc.AssignAppUserRoles(ctx, auth.AssignAppUserRolesInput{
		ClientID: f.app.ClientID, ClientSecret: f.app.ClientSecret,
		UserID: userID, Roles: []string{"super_admin"},
	})
	if !errors.Is(err, auth.ErrRoleNotInApplication) {
		t.Errorf("AssignAppUserRoles(system role) error = %v, want ErrRoleNotInApplication", err)
	}
}

func TestAssignAppUserRoles_IsAtomicAcrossTheWholeRequest(t *testing.T) {
	f := newAppRoleFixture(t, "app-roles-atomic")
	ctx := context.Background()

	userID := f.registerUser(t, uniqueEmail("atomic"))
	grantRole(t, f.roleFixture, "editor", "widgets:write")

	// One good role, one that does not exist. A partial grant would leave a state
	// nobody asked for and no audit record explains.
	_, err := f.svc.AssignAppUserRoles(ctx, auth.AssignAppUserRolesInput{
		ClientID: f.app.ClientID, ClientSecret: f.app.ClientSecret,
		UserID: userID, Roles: []string{"editor", "no-such-role"},
	})
	if !errors.Is(err, auth.ErrRoleNotInApplication) {
		t.Fatalf("AssignAppUserRoles(partly unknown) error = %v, want ErrRoleNotInApplication", err)
	}
	held := heldRoleNamesFor(t, f.roleFixture, userID)
	for _, h := range held {
		if h == "editor" {
			t.Error("editor was granted despite the request failing; the write was not atomic")
		}
	}
}

func TestAssignAppUserRoles_IsIdempotent(t *testing.T) {
	f := newAppRoleFixture(t, "app-roles-idem")
	ctx := context.Background()

	userID := f.registerUser(t, uniqueEmail("idem"))
	grantRole(t, f.roleFixture, "editor", "widgets:write")

	first, err := f.svc.AssignAppUserRoles(ctx, auth.AssignAppUserRolesInput{
		ClientID: f.app.ClientID, ClientSecret: f.app.ClientSecret,
		UserID: userID, Roles: []string{"editor"},
	})
	if err != nil {
		t.Fatalf("AssignAppUserRoles() first call error = %v", err)
	}
	if len(first.Assigned) != 1 {
		t.Errorf("first call assigned = %v, want [editor]", first.Assigned)
	}

	second, err := f.svc.AssignAppUserRoles(ctx, auth.AssignAppUserRolesInput{
		ClientID: f.app.ClientID, ClientSecret: f.app.ClientSecret,
		UserID: userID, Roles: []string{"editor"},
	})
	if err != nil {
		t.Fatalf("AssignAppUserRoles() second call error = %v", err)
	}
	// A retried request must succeed, and must report honestly that it changed
	// nothing rather than claiming a grant it did not make.
	if len(second.Assigned) != 0 {
		t.Errorf("second call assigned = %v, want empty on a repeat", second.Assigned)
	}
	if len(second.Roles) != len(first.Roles) {
		t.Errorf("roles grew from %v to %v on a repeated call", first.Roles, second.Roles)
	}
}

func TestAssignAppUserRoles_ReplaceModeDiscardsTheRest(t *testing.T) {
	f := newAppRoleFixture(t, "app-roles-replace")
	ctx := context.Background()

	userID := f.registerUser(t, uniqueEmail("replace"))
	grantRole(t, f.roleFixture, "editor", "widgets:write")
	grantRole(t, f.roleFixture, "approver", "widgets:approve")

	if _, err := f.svc.AssignAppUserRoles(ctx, auth.AssignAppUserRolesInput{
		ClientID: f.app.ClientID, ClientSecret: f.app.ClientSecret,
		UserID: userID, Roles: []string{"editor"},
	}); err != nil {
		t.Fatalf("AssignAppUserRoles(add) error = %v", err)
	}

	res, err := f.svc.AssignAppUserRoles(ctx, auth.AssignAppUserRolesInput{
		ClientID: f.app.ClientID, ClientSecret: f.app.ClientSecret,
		UserID: userID, Roles: []string{"approver"}, Replace: true,
	})
	if err != nil {
		t.Fatalf("AssignAppUserRoles(replace) error = %v", err)
	}
	if len(res.Roles) != 1 || res.Roles[0] != "approver" {
		t.Errorf("roles after replace = %v, want [approver] alone", res.Roles)
	}

	// The primary must follow: leaving role_id pointing at a role the user no
	// longer holds would keep its name in the deprecated `role` claim.
	var primary *int64
	if err := f.pool.QueryRow(ctx, `SELECT role_id FROM users WHERE id = $1`, userID).Scan(&primary); err != nil {
		t.Fatalf("read primary role: %v", err)
	}
	if primary == nil {
		t.Fatal("primary role is NULL after replace, but the user holds a role")
	}
	var primaryName string
	if err := f.pool.QueryRow(ctx, `SELECT name FROM roles WHERE id = $1`, *primary).Scan(&primaryName); err != nil {
		t.Fatalf("read primary role name: %v", err)
	}
	if primaryName != "approver" {
		t.Errorf("primary role = %q after replace, want %q", primaryName, "approver")
	}
}

func TestAssignAppUserRoles_RefusesUnknownUser(t *testing.T) {
	f := newAppRoleFixture(t, "app-roles-nouser")
	ctx := context.Background()
	grantRole(t, f.roleFixture, "editor", "widgets:write")

	// Same error a sibling application's user produces, so the two cases are
	// indistinguishable and user ids cannot be probed.
	_, err := f.svc.AssignAppUserRoles(ctx, auth.AssignAppUserRolesInput{
		ClientID: f.app.ClientID, ClientSecret: f.app.ClientSecret,
		UserID: 999999999, Roles: []string{"editor"},
	})
	if !errors.Is(err, auth.ErrUserNotInApplication) {
		t.Errorf("AssignAppUserRoles(unknown user) error = %v, want ErrUserNotInApplication", err)
	}
}

// heldRoleNamesFor lists the live roles a user holds, in grant order.
func heldRoleNamesFor(t *testing.T, f roleFixture, userID int64) []string {
	t.Helper()
	rows, err := f.pool.Query(context.Background(), `
		SELECT r.name FROM user_roles ur
		JOIN roles r ON r.id = ur.role_id AND r.deleted_at IS NULL
		WHERE ur.user_id = $1
		ORDER BY ur.granted_at, r.id
	`, userID)
	if err != nil {
		t.Fatalf("query held roles for %s: %v", strconv.FormatInt(userID, 10), err)
	}
	defer rows.Close()
	names := []string{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatalf("scan held role: %v", err)
		}
		names = append(names, n)
	}
	return names
}
