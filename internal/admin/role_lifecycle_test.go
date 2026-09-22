package admin_test

import (
	"context"
	"errors"
	"testing"

	"github.com/engineersmind/emc-auth-server/internal/admin"
)

// Role lifecycle under soft delete — issue #146.
//
// DeleteRole had no test coverage at all before this file: the four DELETE
// routes funnelled into one service method that nothing exercised, so the
// conversion from a hard DELETE to a soft delete had no safety net. These tests
// pin the three FK cascades the soft delete had to take over by hand, plus the
// assignability rules that only matter once a deleted role's row survives.

// roleHolderCount reports how many live users still point at roleID.
func roleHolderCount(t *testing.T, f adminFixture, roleID int64) int {
	t.Helper()
	var n int
	if err := f.pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM users WHERE role_id = $1`, roleID,
	).Scan(&n); err != nil {
		t.Fatalf("count role holders: %v", err)
	}
	return n
}

// rolePermissionCount reports how many grants survive for roleID.
func rolePermissionCount(t *testing.T, f adminFixture, roleID int64) int {
	t.Helper()
	var n int
	if err := f.pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM role_permissions WHERE role_id = $1`, roleID,
	).Scan(&n); err != nil {
		t.Fatalf("count role permissions: %v", err)
	}
	return n
}

// newUserOnRole creates an application user holding roleID and returns its id.
func newUserOnRole(t *testing.T, f adminFixture, email string, roleID *int64) int64 {
	t.Helper()
	u, err := f.svc.CreateUser(context.Background(), f.tenantID, &f.appID,
		email, "Sup3r-Secret-Pw!", "Test", "User", roleID)
	if err != nil {
		t.Fatalf("CreateUser(%s) error = %v", email, err)
	}
	return parseID(t, u.ID)
}

func TestDeleteRole_SoftDeletesAndDetachesHolders(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	role, err := f.svc.CreateRole(ctx, f.tenantID, &f.appID, "editor", nil)
	if err != nil {
		t.Fatalf("CreateRole() error = %v", err)
	}
	roleID := parseID(t, role.ID)
	holderA := newUserOnRole(t, f, "holder-a@example.com", &roleID)
	holderB := newUserOnRole(t, f, "holder-b@example.com", &roleID)

	holders, err := f.svc.DeleteRole(ctx, f.tenantID, roleID)
	if err != nil {
		t.Fatalf("DeleteRole() error = %v", err)
	}

	// The returned ids are what the audit record is built from; without them a
	// deletion leaves no answer to "who lost what".
	if len(holders) != 2 {
		t.Fatalf("DeleteRole() returned %d holders, want 2", len(holders))
	}
	if holders[0] != holderA || holders[1] != holderB {
		t.Errorf("DeleteRole() holders = %v, want [%d %d] in id order", holders, holderA, holderB)
	}

	// The row survives — that is the whole point of going soft — but carries a
	// deleted_at, so every filtered read drops it.
	var deletedAt *string
	if err := f.pool.QueryRow(ctx,
		`SELECT deleted_at::text FROM roles WHERE id = $1`, roleID,
	).Scan(&deletedAt); err != nil {
		t.Fatalf("role row should survive a soft delete: %v", err)
	}
	if deletedAt == nil {
		t.Error("DeleteRole() left deleted_at NULL; the role was not soft-deleted")
	}

	// Standing in for FK1 (ON DELETE SET NULL), which a soft delete does not fire.
	// Left undone, holders keep pointing at the tombstone and its name reaches the
	// JWT `role` claim.
	if n := roleHolderCount(t, f, roleID); n != 0 {
		t.Errorf("%d users still point at the deleted role; want 0 (FK1 stand-in failed)", n)
	}
}

func TestDeleteRole_RevokesPermissionsRatherThanPreservingThem(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	// Application-scoped, to match the role: a role may only hold permissions
	// from its own application.
	perm, err := f.svc.CreatePermission(ctx, f.tenantID, &f.appID, "documents:write", "edit documents")
	if err != nil {
		t.Fatalf("CreatePermission() error = %v", err)
	}
	permID := parseID(t, perm.ID)

	role, err := f.svc.CreateRole(ctx, f.tenantID, &f.appID, "editor", []int64{permID})
	if err != nil {
		t.Fatalf("CreateRole() error = %v", err)
	}
	roleID := parseID(t, role.ID)
	if rolePermissionCount(t, f, roleID) == 0 {
		t.Fatal("precondition: the role should hold a permission before deletion")
	}

	if _, err := f.svc.DeleteRole(ctx, f.tenantID, roleID); err != nil {
		t.Fatalf("DeleteRole() error = %v", err)
	}

	// Standing in for FK2 (ON DELETE CASCADE). This is the dangerous one: the
	// permission resolver walks users.role_id -> role_permissions, so grants that
	// outlive their role keep being handed out and deleting a role would GRANT
	// permissions rather than revoke them.
	if n := rolePermissionCount(t, f, roleID); n != 0 {
		t.Errorf("%d permission grants survived the deleted role; want 0 (FK2 stand-in failed)", n)
	}
}

func TestDeleteRole_ClearsPreviousRoleReferences(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	// Tenant-level, not application-scoped: a tenant_admins row may only name a
	// tenant-level user, and previous_role_id holds the role such a user carried
	// before promotion.
	role, err := f.svc.CreateRole(ctx, f.tenantID, nil, "analyst", nil)
	if err != nil {
		t.Fatalf("CreateRole() error = %v", err)
	}
	roleID := parseID(t, role.ID)
	u, err := f.svc.CreateUser(ctx, f.tenantID, nil,
		"demoted@example.com", "Sup3r-Secret-Pw!", "Demoted", "User", &roleID)
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	userID := parseID(t, u.ID)

	// tenant_admins.previous_role_id is what RemoveTenantAdmin restores when an
	// administrator is stripped. Written directly: reaching it through the
	// invitation flow would test that flow, not this cleanup.
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO tenant_admins (tenant_id, user_id, admin_role, previous_role_id, activated_at)
		VALUES ($1, $2, 'co_owner', $3, NOW())
	`, f.tenantID, userID, roleID); err != nil {
		t.Fatalf("seed tenant_admins row: %v", err)
	}

	if _, err := f.svc.DeleteRole(ctx, f.tenantID, roleID); err != nil {
		t.Fatalf("DeleteRole() error = %v", err)
	}

	// Standing in for FK3 (ON DELETE SET NULL). Left dangling, RemoveTenantAdmin
	// restores a deleted role onto a de-administered user — defeating the
	// escalation fix migration 00063 exists to provide.
	var previous *int64
	if err := f.pool.QueryRow(ctx,
		`SELECT previous_role_id FROM tenant_admins WHERE tenant_id = $1 AND user_id = $2`,
		f.tenantID, userID,
	).Scan(&previous); err != nil {
		t.Fatalf("read previous_role_id: %v", err)
	}
	if previous != nil {
		t.Errorf("previous_role_id = %d after the role was deleted; want NULL (FK3 stand-in failed)", *previous)
	}
}

func TestDeleteRole_HidesTheRoleFromEveryReadPath(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	role, err := f.svc.CreateRole(ctx, f.tenantID, &f.appID, "editor", nil)
	if err != nil {
		t.Fatalf("CreateRole() error = %v", err)
	}
	roleID := parseID(t, role.ID)

	if _, err := f.svc.DeleteRole(ctx, f.tenantID, roleID); err != nil {
		t.Fatalf("DeleteRole() error = %v", err)
	}

	roles, err := f.svc.ListRoles(ctx, f.tenantID, &f.appID)
	if err != nil {
		t.Fatalf("ListRoles() error = %v", err)
	}
	for _, r := range roles {
		if r.ID == role.ID {
			t.Error("ListRoles() still returns the deleted role; the admin UI would offer it")
		}
	}

	// A second delete must not report success: it would write a second audit
	// record for a role nobody holds.
	if _, err := f.svc.DeleteRole(ctx, f.tenantID, roleID); !errors.Is(err, admin.ErrNotFound) {
		t.Errorf("second DeleteRole() error = %v, want ErrNotFound", err)
	}
}

func TestDeleteRole_RefusesSystemRoles(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	sysRole := seedSystemRoleID(t, f)
	if _, err := f.svc.DeleteRole(ctx, f.tenantID, sysRole); !errors.Is(err, admin.ErrNotFound) {
		t.Fatalf("DeleteRole(system role) error = %v, want ErrNotFound", err)
	}

	var deletedAt *string
	if err := f.pool.QueryRow(ctx,
		`SELECT deleted_at::text FROM roles WHERE id = $1`, sysRole,
	).Scan(&deletedAt); err != nil {
		t.Fatalf("read system role: %v", err)
	}
	if deletedAt != nil {
		t.Error("a system role was soft-deleted; the is_system guard did not hold")
	}
}

func TestAssignUserRole_RefusesDeletedRole(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	keep, err := f.svc.CreateRole(ctx, f.tenantID, &f.appID, "viewer", nil)
	if err != nil {
		t.Fatalf("CreateRole(viewer) error = %v", err)
	}
	keepID := parseID(t, keep.ID)
	gone, err := f.svc.CreateRole(ctx, f.tenantID, &f.appID, "editor", nil)
	if err != nil {
		t.Fatalf("CreateRole(editor) error = %v", err)
	}
	goneID := parseID(t, gone.ID)

	userID := newUserOnRole(t, f, "assignee@example.com", &keepID)
	if _, err := f.svc.DeleteRole(ctx, f.tenantID, goneID); err != nil {
		t.Fatalf("DeleteRole() error = %v", err)
	}

	// Latent before #146, because a hard-deleted row could not be looked up at
	// all. The moment the row survives, the missing deleted_at predicate makes it
	// fully assignable again.
	if err := f.svc.AssignUserRole(ctx, f.tenantID, &f.appID, userID, goneID); !errors.Is(err, admin.ErrNotFound) {
		t.Errorf("AssignUserRole(deleted role) error = %v, want ErrNotFound", err)
	}
}

func TestCreateUser_RefusesDeletedRole(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	role, err := f.svc.CreateRole(ctx, f.tenantID, &f.appID, "editor", nil)
	if err != nil {
		t.Fatalf("CreateRole() error = %v", err)
	}
	roleID := parseID(t, role.ID)
	if _, err := f.svc.DeleteRole(ctx, f.tenantID, roleID); err != nil {
		t.Fatalf("DeleteRole() error = %v", err)
	}

	// The same defect as AssignUserRole by another door, and one the original
	// audit missed.
	if _, err := f.svc.CreateUser(ctx, f.tenantID, &f.appID,
		"fresh@example.com", "Sup3r-Secret-Pw!", "Fresh", "User", &roleID,
	); !errors.Is(err, admin.ErrNotFound) {
		t.Errorf("CreateUser(deleted role) error = %v, want ErrNotFound", err)
	}
}

func TestSetDefaultRole_RefusesDeletedRole(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	role, err := f.svc.CreateRole(ctx, f.tenantID, &f.appID, "editor", nil)
	if err != nil {
		t.Fatalf("CreateRole() error = %v", err)
	}
	roleID := parseID(t, role.ID)
	if _, err := f.svc.DeleteRole(ctx, f.tenantID, roleID); err != nil {
		t.Fatalf("DeleteRole() error = %v", err)
	}

	// A deleted role made default would be handed to every user who registers
	// against this application afterwards.
	if err := f.svc.SetDefaultRole(ctx, f.tenantID, f.appID, roleID); !errors.Is(err, admin.ErrNotFound) {
		t.Errorf("SetDefaultRole(deleted role) error = %v, want ErrNotFound", err)
	}
}

func TestSetDefaultRole_SucceedsAfterTheCurrentDefaultIsDeleted(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	first, err := f.svc.CreateRole(ctx, f.tenantID, &f.appID, "viewer", nil)
	if err != nil {
		t.Fatalf("CreateRole(viewer) error = %v", err)
	}
	firstID := parseID(t, first.ID)
	if err := f.svc.SetDefaultRole(ctx, f.tenantID, f.appID, firstID); err != nil {
		t.Fatalf("SetDefaultRole(viewer) error = %v", err)
	}
	if _, err := f.svc.DeleteRole(ctx, f.tenantID, firstID); err != nil {
		t.Fatalf("DeleteRole() error = %v", err)
	}

	second, err := f.svc.CreateRole(ctx, f.tenantID, &f.appID, "editor", nil)
	if err != nil {
		t.Fatalf("CreateRole(editor) error = %v", err)
	}
	secondID := parseID(t, second.ID)

	// The trap this migration exists for. roles_one_default_per_app carried no
	// deleted_at predicate, so a soft-deleted role still holding is_default kept
	// the (tenant, application) slot and this call died on a 23505 that no
	// statement could clear — the application could never have a default role
	// again, silently ending role assignment at registration.
	if err := f.svc.SetDefaultRole(ctx, f.tenantID, f.appID, secondID); err != nil {
		t.Fatalf("SetDefaultRole() after deleting the prior default: %v", err)
	}

	var defaults int
	if err := f.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM roles
		WHERE tenant_id = $1 AND application_id = $2 AND is_default = true AND deleted_at IS NULL
	`, f.tenantID, f.appID).Scan(&defaults); err != nil {
		t.Fatalf("count default roles: %v", err)
	}
	if defaults != 1 {
		t.Errorf("%d live default roles for the application, want exactly 1", defaults)
	}
}

func TestCreateRole_ReusesTheNameOfADeletedRole(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	first, err := f.svc.CreateRole(ctx, f.tenantID, &f.appID, "editor", nil)
	if err != nil {
		t.Fatalf("CreateRole() error = %v", err)
	}
	if _, err := f.svc.DeleteRole(ctx, f.tenantID, parseID(t, first.ID)); err != nil {
		t.Fatalf("DeleteRole() error = %v", err)
	}

	// The classic soft-delete trap, already closed: 00044's name-uniqueness
	// indexes are partial on deleted_at IS NULL, so a tombstone does not reserve
	// its name. Pinned because a later migration that rebuilt those indexes
	// without the predicate would make deletion irreversible from the UI.
	if _, err := f.svc.CreateRole(ctx, f.tenantID, &f.appID, "editor", nil); err != nil {
		t.Fatalf("CreateRole() reusing a deleted role's name: %v", err)
	}
}
