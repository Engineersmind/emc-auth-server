package admin_test

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/engineersmind/emc-auth-server/internal/admin"
	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/store"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// adminFixture bundles a ready-to-use admin.Service with the seed tenant and
// a freshly created application, plus the pool for assertions that need to
// read rows the Service doesn't expose directly (e.g. the seeded owner role).
type adminFixture struct {
	pool *pgxpool.Pool
	svc  *admin.Service
	// mail records the invitations the service dispatched. A real invitation
	// service is wired rather than left nil, because the flows under test now
	// refuse to run without one: an administrator who cannot be told they are
	// one is an inert row, so CreateTenant and InviteTenantAdmin fail closed.
	mail     *testhelper.RecordingMailer
	tenantID int64
	appID    int64
}

// newAdminFixture seeds the "emc" tenant and creates an application within it.
func newAdminFixture(t *testing.T) adminFixture {
	t.Helper()
	pool := testhelper.NewTestDB(t)
	logger := testhelper.TestLogger()
	ctx := context.Background()

	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}
	t.Cleanup(func() { testhelper.CleanupTables(t, pool) })

	var tenantID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM tenants WHERE slug = 'emc' AND deleted_at IS NULL`).Scan(&tenantID); err != nil {
		t.Fatalf("fetch seed tenant id: %v", err)
	}

	appSvc := auth.NewApplicationService(pool, logger)
	app, err := appSvc.CreateApplication(ctx, tenantID, "admin-fixture-app-"+time.Now().Format("150405.000000000"), "web", nil)
	if err != nil {
		t.Fatalf("CreateApplication() error = %v", err)
	}
	var appID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM oauth_clients WHERE client_id = $1`, app.ClientID).Scan(&appID); err != nil {
		t.Fatalf("fetch app id: %v", err)
	}

	mail := &testhelper.RecordingMailer{}
	invSvc := auth.NewInvitationService(pool, mail, "https://console.test", logger)
	svc := admin.New(pool, nil, logger).WithInvitations(invSvc)

	return adminFixture{pool: pool, svc: svc, mail: mail, tenantID: tenantID, appID: appID}
}

// seedSystemRoleID returns the id of the tenant-level system role that
// RunSeed guarantees exists in the seed tenant (super_admin). Tests must not
// rely on an 'owner' role — that is only created by CreateTenant, not by the
// seed, so it is absent on a fresh CI database.
func seedSystemRoleID(t *testing.T, f adminFixture) int64 {
	t.Helper()
	var id int64
	if err := f.pool.QueryRow(context.Background(),
		`SELECT id FROM roles WHERE tenant_id = $1 AND name = 'super_admin' AND is_system = true`,
		f.tenantID,
	).Scan(&id); err != nil {
		t.Fatalf("fetch seed system role id: %v", err)
	}
	return id
}

func parseID(t *testing.T, id string) int64 {
	t.Helper()
	n, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		t.Fatalf("parse id %q: %v", id, err)
	}
	return n
}

func TestCreateRole_ApplicationScoped(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	role, err := f.svc.CreateRole(ctx, f.tenantID, &f.appID, "viewer", nil)
	if err != nil {
		t.Fatalf("CreateRole() error = %v", err)
	}
	if role.ApplicationID == nil {
		t.Fatal("CreateRole() ApplicationID is nil, want the app id")
	}
	if role.IsSystem {
		t.Error("CreateRole() IsSystem = true, want false for an end-user role")
	}
	if role.IsDefault {
		t.Error("CreateRole() IsDefault = true, want false until explicitly set")
	}

	roles, err := f.svc.ListRoles(ctx, f.tenantID, &f.appID)
	if err != nil {
		t.Fatalf("ListRoles() error = %v", err)
	}
	if len(roles) != 1 || roles[0].ID != role.ID {
		t.Errorf("ListRoles(appID) = %+v, want just the created role", roles)
	}
}

func TestSetDefaultRole_ClearsPriorDefault(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	roleA, err := f.svc.CreateRole(ctx, f.tenantID, &f.appID, "viewer", nil)
	if err != nil {
		t.Fatalf("CreateRole(viewer) error = %v", err)
	}
	roleB, err := f.svc.CreateRole(ctx, f.tenantID, &f.appID, "editor", nil)
	if err != nil {
		t.Fatalf("CreateRole(editor) error = %v", err)
	}

	if err := f.svc.SetDefaultRole(ctx, f.tenantID, f.appID, parseID(t, roleA.ID)); err != nil {
		t.Fatalf("SetDefaultRole(roleA) error = %v", err)
	}
	if err := f.svc.SetDefaultRole(ctx, f.tenantID, f.appID, parseID(t, roleB.ID)); err != nil {
		t.Fatalf("SetDefaultRole(roleB) error = %v", err)
	}

	roles, err := f.svc.ListRoles(ctx, f.tenantID, &f.appID)
	if err != nil {
		t.Fatalf("ListRoles() error = %v", err)
	}
	var defaults int
	for _, r := range roles {
		if r.IsDefault {
			defaults++
			if r.ID != roleB.ID {
				t.Errorf("default role = %q, want roleB %q", r.ID, roleB.ID)
			}
		}
	}
	if defaults != 1 {
		t.Errorf("found %d default roles, want exactly 1 (SetDefaultRole must clear the prior default)", defaults)
	}
}

func TestSetDefaultRole_RejectsSystemRole(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	systemRoleID := seedSystemRoleID(t, f)

	err := f.svc.SetDefaultRole(ctx, f.tenantID, f.appID, systemRoleID)
	if !errors.Is(err, admin.ErrSystemRole) {
		t.Errorf("SetDefaultRole(system role) error = %v, want ErrSystemRole", err)
	}
}

func TestSetDefaultRole_RejectsRoleFromAnotherApplication(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	otherAppID := f.appID + 1_000_000 // guaranteed not to match f.appID
	role, err := f.svc.CreateRole(ctx, f.tenantID, &f.appID, "viewer", nil)
	if err != nil {
		t.Fatalf("CreateRole() error = %v", err)
	}

	if err := f.svc.SetDefaultRole(ctx, f.tenantID, otherAppID, parseID(t, role.ID)); !errors.Is(err, admin.ErrSystemRole) {
		t.Errorf("SetDefaultRole(mismatched app) error = %v, want ErrSystemRole", err)
	}
}

// TestPermissions_ApplicationScoped covers the isolated per-application
// permission catalog: create, list scoping, update, and the same-name-in-
// two-scopes freedom granted by migration 00044.
func TestPermissions_ApplicationScoped(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	appPerm, err := f.svc.CreatePermission(ctx, f.tenantID, &f.appID, "invoices:read", "app-scoped")
	if err != nil {
		t.Fatalf("CreatePermission(app) error = %v", err)
	}
	if appPerm.ApplicationID == nil {
		t.Fatal("CreatePermission(app) ApplicationID is nil")
	}

	// Same name at tenant level must not collide with the app-scoped one.
	if _, err := f.svc.CreatePermission(ctx, f.tenantID, nil, "invoices:read", "tenant-level"); err != nil {
		t.Fatalf("CreatePermission(tenant, same name) error = %v — scopes must be independent", err)
	}

	// Duplicate within the same application must collide.
	if _, err := f.svc.CreatePermission(ctx, f.tenantID, &f.appID, "invoices:read", "dup"); !errors.Is(err, admin.ErrAlreadyExists) {
		t.Errorf("CreatePermission(app, dup name) error = %v, want ErrAlreadyExists", err)
	}

	// App-scoped listing returns only that application's catalog.
	perms, err := f.svc.ListPermissions(ctx, f.tenantID, &f.appID)
	if err != nil {
		t.Fatalf("ListPermissions(app) error = %v", err)
	}
	if len(perms) != 1 || perms[0].ID != appPerm.ID {
		t.Errorf("ListPermissions(app) = %+v, want just the app-scoped permission", perms)
	}

	// Update: rename + description, scoped to the application.
	appPermID := parseID(t, appPerm.ID)
	updated, err := f.svc.UpdatePermission(ctx, f.tenantID, &f.appID, appPermID, "invoices:view", "renamed")
	if err != nil {
		t.Fatalf("UpdatePermission error = %v", err)
	}
	if updated.Name != "invoices:view" || updated.Description != "renamed" {
		t.Errorf("UpdatePermission result = %+v, want renamed", updated)
	}

	// Scope mismatch: updating the app permission through a wrong app filter → not found.
	wrongApp := f.appID + 1_000_000
	if _, err := f.svc.UpdatePermission(ctx, f.tenantID, &wrongApp, appPermID, "x", ""); !errors.Is(err, admin.ErrNotFound) {
		t.Errorf("UpdatePermission(wrong app) error = %v, want ErrNotFound", err)
	}
}

// TestRolePermissionIsolation verifies a role can only hold permissions from
// its own scope — its application for app roles.
func TestRolePermissionIsolation(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	tenantPerm, err := f.svc.CreatePermission(ctx, f.tenantID, nil, "tenant:thing", "")
	if err != nil {
		t.Fatalf("CreatePermission(tenant) error = %v", err)
	}
	appPerm, err := f.svc.CreatePermission(ctx, f.tenantID, &f.appID, "app:thing", "")
	if err != nil {
		t.Fatalf("CreatePermission(app) error = %v", err)
	}

	// Attaching a tenant-level permission to an app role must be rejected.
	if _, err := f.svc.CreateRole(ctx, f.tenantID, &f.appID, "leaky", []int64{parseID(t, tenantPerm.ID)}); !errors.Is(err, admin.ErrPermissionScope) {
		t.Errorf("CreateRole(app role, tenant perm) error = %v, want ErrPermissionScope", err)
	}

	// Attaching the app's own permission succeeds.
	role, err := f.svc.CreateRole(ctx, f.tenantID, &f.appID, "clean", []int64{parseID(t, appPerm.ID)})
	if err != nil {
		t.Fatalf("CreateRole(app role, app perm) error = %v", err)
	}

	// Replacing the set with an out-of-scope permission must also be rejected.
	if err := f.svc.UpdateRolePermissions(ctx, f.tenantID, parseID(t, role.ID), []int64{parseID(t, tenantPerm.ID)}); !errors.Is(err, admin.ErrPermissionScope) {
		t.Errorf("UpdateRolePermissions(app role, tenant perm) error = %v, want ErrPermissionScope", err)
	}
}

// TestUpdateRoleName covers rename semantics including system-role protection.
func TestUpdateRoleName(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	role, err := f.svc.CreateRole(ctx, f.tenantID, &f.appID, "veiwer", nil) // deliberate typo
	if err != nil {
		t.Fatalf("CreateRole error = %v", err)
	}
	renamed, err := f.svc.UpdateRoleName(ctx, f.tenantID, f.appID, parseID(t, role.ID), "viewer")
	if err != nil {
		t.Fatalf("UpdateRoleName error = %v", err)
	}
	if renamed.Name != "viewer" {
		t.Errorf("UpdateRoleName name = %q, want %q", renamed.Name, "viewer")
	}

	// System roles (super_admin/owner) must not be renameable through this path.
	systemRoleID := seedSystemRoleID(t, f)
	if _, err := f.svc.UpdateRoleName(ctx, f.tenantID, f.appID, systemRoleID, "hijacked"); !errors.Is(err, admin.ErrNotFound) {
		t.Errorf("UpdateRoleName(system role) error = %v, want ErrNotFound", err)
	}
}

// TestRoleNameIsolationAcrossApps verifies two applications can define the
// same role name independently (00044 partial unique indexes).
func TestRoleNameIsolationAcrossApps(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	appSvc := auth.NewApplicationService(f.pool, testhelper.TestLogger())
	appB, err := appSvc.CreateApplication(ctx, f.tenantID, "iso-app-b-"+time.Now().Format("150405.000000000"), "web", nil)
	if err != nil {
		t.Fatalf("CreateApplication(appB) error = %v", err)
	}
	var appBID int64
	if err := f.pool.QueryRow(ctx, `SELECT id FROM oauth_clients WHERE client_id = $1`, appB.ClientID).Scan(&appBID); err != nil {
		t.Fatalf("fetch appB id: %v", err)
	}

	if _, err := f.svc.CreateRole(ctx, f.tenantID, &f.appID, "viewer", nil); err != nil {
		t.Fatalf("CreateRole(appA viewer) error = %v", err)
	}
	if _, err := f.svc.CreateRole(ctx, f.tenantID, &appBID, "viewer", nil); err != nil {
		t.Errorf("CreateRole(appB viewer) error = %v — role names must be isolated per application", err)
	}
	// Duplicate within the SAME app must still collide.
	if _, err := f.svc.CreateRole(ctx, f.tenantID, &f.appID, "viewer", nil); !errors.Is(err, admin.ErrAlreadyExists) {
		t.Errorf("CreateRole(appA viewer dup) error = %v, want ErrAlreadyExists", err)
	}
}

// TestUsers_ApplicationScoped covers the isolated per-application user base:
// scoped create/list/get, and role assignment restricted to the user's own
// application.
func TestUsers_ApplicationScoped(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	appUser, err := f.svc.CreateUser(ctx, f.tenantID, &f.appID, "appuser@iso.test", "Password123!", "App", "User", nil)
	if err != nil {
		t.Fatalf("CreateUser(app) error = %v", err)
	}
	if appUser.ApplicationID == nil {
		t.Fatal("CreateUser(app) ApplicationID is nil")
	}
	tenantUser, err := f.svc.CreateUser(ctx, f.tenantID, nil, "tenantuser@iso.test", "Password123!", "Tenant", "User", nil)
	if err != nil {
		t.Fatalf("CreateUser(tenant) error = %v", err)
	}

	// App-scoped listing must contain only the app's own user.
	page, err := f.svc.ListUsers(ctx, f.tenantID, &f.appID, "", 1, 50)
	if err != nil {
		t.Fatalf("ListUsers(app) error = %v", err)
	}
	if len(page.Users) != 1 || page.Users[0].ID != appUser.ID {
		t.Errorf("ListUsers(app) = %+v, want just the app user", page.Users)
	}

	// Scoped get: the tenant-level user is invisible through the app scope.
	tenantUserID := parseID(t, tenantUser.ID)
	if _, err := f.svc.GetUser(ctx, f.tenantID, &f.appID, tenantUserID); !errors.Is(err, admin.ErrNotFound) {
		t.Errorf("GetUser(app scope, tenant user) error = %v, want ErrNotFound", err)
	}

	// Role assignment must stay inside the user's application.
	appRole, err := f.svc.CreateRole(ctx, f.tenantID, &f.appID, "member", nil)
	if err != nil {
		t.Fatalf("CreateRole(app) error = %v", err)
	}
	appUserID := parseID(t, appUser.ID)
	if err := f.svc.AssignUserRole(ctx, f.tenantID, &f.appID, appUserID, parseID(t, appRole.ID)); err != nil {
		t.Fatalf("AssignUserRole(app user, app role) error = %v", err)
	}
	// A tenant-level role on an app user must be rejected. Uses a NON-system
	// tenant-level role deliberately: a system one is now refused by the
	// is_system check before the scope check runs, which would make this assert
	// the wrong guard.
	tenantRole, err := f.svc.CreateRole(ctx, f.tenantID, nil, "tenant-analyst", nil)
	if err != nil {
		t.Fatalf("CreateRole(tenant-level) error = %v", err)
	}
	if err := f.svc.AssignUserRole(ctx, f.tenantID, nil, appUserID, parseID(t, tenantRole.ID)); !errors.Is(err, admin.ErrRoleScope) {
		t.Errorf("AssignUserRole(app user, tenant-level role) error = %v, want ErrRoleScope", err)
	}
	// App role on a tenant-level user must be rejected too.
	if err := f.svc.AssignUserRole(ctx, f.tenantID, nil, tenantUserID, parseID(t, appRole.ID)); !errors.Is(err, admin.ErrRoleScope) {
		t.Errorf("AssignUserRole(tenant user, app role) error = %v, want ErrRoleScope", err)
	}

	// CreateUser with a role from another scope must be rejected.
	if _, err := f.svc.CreateUser(ctx, f.tenantID, &f.appID, "appuser2@iso.test", "Password123!", "", "", ptrInt64(parseID(t, tenantRole.ID))); !errors.Is(err, admin.ErrRoleScope) {
		t.Errorf("CreateUser(app user, tenant-level role) error = %v, want ErrRoleScope", err)
	}
}

// TestSystemRolesAreNotAssignable is the guard on the one path that could hand
// out administrative authority without going through an invitation.
//
// Administrative roles are attached by auth.activatePendingAdminGrant when the
// recipient accepts, alongside the tenant_admins row that records the grant.
// Assigning one directly produces an account that holds every admin permission
// but has NO tenant_admins row, so:
//
//   - loadAdminScope returns "", and an absent admin_scope claim is read as
//     tenant-wide by RequireTenantSelfOrAny;
//   - the activation gate added in migration 00064 never runs;
//   - the account appears in neither the tenant's administrator list nor the
//     platform directory, both of which read tenant_admins.
//
// In the platform's own seeded tenant the reachable system role is super_admin,
// which carries tenant:manage — authority over every tenant, not just this one.
func TestSystemRolesAreNotAssignable(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	systemRoleID := seedSystemRoleID(t, f)

	victim, err := f.svc.CreateUser(ctx, f.tenantID, nil, "escalate@iso.test", "Password123!", "", "", nil)
	if err != nil {
		t.Fatalf("CreateUser(tenant-level) error = %v", err)
	}

	// Re-roling an existing tenant-level user.
	if err := f.svc.AssignUserRole(ctx, f.tenantID, nil, parseID(t, victim.ID), systemRoleID); !errors.Is(err, admin.ErrSystemRole) {
		t.Errorf("AssignUserRole(tenant user, system role) error = %v, want ErrSystemRole", err)
	}

	// And the same thing in one step at creation, which is the same bypass
	// minus a call.
	if _, err := f.svc.CreateUser(ctx, f.tenantID, nil, "escalate2@iso.test", "Password123!", "", "", &systemRoleID); !errors.Is(err, admin.ErrSystemRole) {
		t.Errorf("CreateUser(tenant user, system role) error = %v, want ErrSystemRole", err)
	}

	// The refusal must leave nothing behind: no role attached to the account
	// that already existed.
	var roleID *int64
	if err := f.pool.QueryRow(ctx, `SELECT role_id FROM users WHERE id = $1`, parseID(t, victim.ID)).Scan(&roleID); err != nil {
		t.Fatalf("read back victim role: %v", err)
	}
	if roleID != nil {
		t.Errorf("role_id = %d after a refused assignment, want NULL", *roleID)
	}
}

func ptrInt64(v int64) *int64 { return &v }

// TestRolesOneDefaultPerApp_UniqueIndex verifies the DB-level guard: two
// default roles cannot coexist for the same (tenant, application) even if
// application code is bypassed.
func TestRolesOneDefaultPerApp_UniqueIndex(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	if _, err := f.pool.Exec(ctx, `
		INSERT INTO roles (tenant_id, application_id, name, is_system, is_default, created_at)
		VALUES ($1, $2, 'first-default', false, true, NOW())
	`, f.tenantID, f.appID); err != nil {
		t.Fatalf("insert first default role: %v", err)
	}

	_, err := f.pool.Exec(ctx, `
		INSERT INTO roles (tenant_id, application_id, name, is_system, is_default, created_at)
		VALUES ($1, $2, 'second-default', false, true, NOW())
	`, f.tenantID, f.appID)
	if err == nil {
		t.Fatal("second default-role insert succeeded, want unique index violation")
	}
}

// TestUpdateTenantIsPatchNotReplace pins the patch semantics of UpdateTenant.
//
// It used to be replace-style: every column was assigned unconditionally, so a
// caller updating only the name blanked domain and region, and wrote plan = ''
// into a NOT NULL column that has no CHECK constraint — leaving a tenant on a
// plan outside free/pro/enterprise. An edit form that exposes just name and
// display_name is exactly such a caller, which is why this is pinned.
func TestUpdateTenantIsPatchNotReplace(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	created, err := f.svc.CreateTenant(ctx, admin.CreateTenantInput{
		Name:        "Patch Probe",
		Slug:        "patch-probe",
		DisplayName: "Patch Probe Display",
		Domain:      "patch.example.com",
		Region:      "us-east",
		Plan:        "pro",
		OwnerEmail:  "patch-owner@example.com",
	})
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	tenantID, err := strconv.ParseInt(created.Tenant.ID, 10, 64)
	if err != nil {
		t.Fatalf("parse tenant id: %v", err)
	}

	// The exact shape the edit card sends: name + display_name only.
	updated, err := f.svc.UpdateTenant(ctx, tenantID, admin.UpdateTenantInput{
		Name:        "Patch Probe Renamed",
		DisplayName: "Renamed Display",
	})
	if err != nil {
		t.Fatalf("UpdateTenant: %v", err)
	}

	if updated.Name != "Patch Probe Renamed" {
		t.Errorf("Name = %q, want %q", updated.Name, "Patch Probe Renamed")
	}
	if updated.DisplayName == nil || *updated.DisplayName != "Renamed Display" {
		t.Errorf("DisplayName = %v, want %q", updated.DisplayName, "Renamed Display")
	}
	// The untouched fields must survive.
	if updated.Domain == nil || *updated.Domain != "patch.example.com" {
		t.Errorf("Domain = %v, want it preserved as patch.example.com", updated.Domain)
	}
	if updated.Region == nil || *updated.Region != "us-east" {
		t.Errorf("Region = %v, want it preserved as us-east", updated.Region)
	}
	if updated.Plan != "pro" {
		t.Errorf("Plan = %q, want it preserved as pro", updated.Plan)
	}
}

// TestUpdateTenantRejectsEmptyInput covers the no-op guard: with patch semantics
// an all-empty input matches every column to itself, so without the guard the
// write would succeed while changing nothing the caller asked for.
func TestUpdateTenantRejectsEmptyInput(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	if _, err := f.svc.UpdateTenant(ctx, f.tenantID, admin.UpdateTenantInput{}); err == nil {
		t.Fatal("UpdateTenant with empty input = nil error, want a refusal")
	}
}
