package admin_test

import (
	"context"
	"errors"
	"testing"

	"github.com/engineersmind/emc-auth-server/internal/admin"
)

// Multiple roles per user — issue #146, phase 2.
//
// The question these answer is "can a user hold two roles, and do they get both
// roles' permissions". Everything else here is a consequence of that: which role
// the deprecated `role` claim carries when there are several, what happens to the
// primary when it is the one revoked, and whether the additive path can be used
// to acquire an administrative role the replacing path refuses.

// heldRoleNames returns the roles a user holds, in grant order.
func heldRoleNames(t *testing.T, f adminFixture, userID int64) []string {
	t.Helper()
	rows, err := f.pool.Query(context.Background(), `
		SELECT r.name FROM user_roles ur
		JOIN roles r ON r.id = ur.role_id AND r.deleted_at IS NULL
		WHERE ur.user_id = $1
		ORDER BY ur.granted_at, r.id
	`, userID)
	if err != nil {
		t.Fatalf("query held roles: %v", err)
	}
	defer rows.Close()
	names := []string{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatalf("scan role name: %v", err)
		}
		names = append(names, n)
	}
	return names
}

// primaryRoleID returns users.role_id, or nil when the user holds no primary.
func primaryRoleID(t *testing.T, f adminFixture, userID int64) *int64 {
	t.Helper()
	var id *int64
	if err := f.pool.QueryRow(context.Background(),
		`SELECT role_id FROM users WHERE id = $1`, userID).Scan(&id); err != nil {
		t.Fatalf("read primary role: %v", err)
	}
	return id
}

func TestAddUserRole_UserHoldsBothRoles(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	viewer, err := f.svc.CreateRole(ctx, f.tenantID, &f.appID, "viewer", nil)
	if err != nil {
		t.Fatalf("CreateRole(viewer) error = %v", err)
	}
	editor, err := f.svc.CreateRole(ctx, f.tenantID, &f.appID, "editor", nil)
	if err != nil {
		t.Fatalf("CreateRole(editor) error = %v", err)
	}
	viewerID, editorID := parseID(t, viewer.ID), parseID(t, editor.ID)

	userID := newUserOnRole(t, f, "multi@example.com", &viewerID)
	if err := f.svc.AddUserRole(ctx, f.tenantID, &f.appID, userID, editorID, nil); err != nil {
		t.Fatalf("AddUserRole() error = %v", err)
	}

	// The headline behaviour: adding composes rather than replacing. Before phase
	// 2 the second grant would have overwritten the first.
	held := heldRoleNames(t, f, userID)
	if len(held) != 2 || held[0] != "viewer" || held[1] != "editor" {
		t.Errorf("held roles = %v, want [viewer editor]", held)
	}

	// The primary is NOT reshuffled by an unrelated addition — the deprecated
	// `role` claim has to stay stable for consumers that have not migrated.
	if p := primaryRoleID(t, f, userID); p == nil || *p != viewerID {
		t.Errorf("primary role = %v, want the originally assigned viewer (%d)", p, viewerID)
	}
}

func TestAddUserRole_IsIdempotent(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	role, err := f.svc.CreateRole(ctx, f.tenantID, &f.appID, "editor", nil)
	if err != nil {
		t.Fatalf("CreateRole() error = %v", err)
	}
	roleID := parseID(t, role.ID)
	userID := newUserOnRole(t, f, "idem@example.com", nil)

	for i := 0; i < 3; i++ {
		// A client retrying a timed-out request must not have to tell "it worked"
		// from "it already worked".
		if err := f.svc.AddUserRole(ctx, f.tenantID, &f.appID, userID, roleID, nil); err != nil {
			t.Fatalf("AddUserRole() call %d error = %v", i+1, err)
		}
	}
	if held := heldRoleNames(t, f, userID); len(held) != 1 {
		t.Errorf("held roles = %v after three identical grants, want exactly one", held)
	}
}

func TestAddUserRole_PromotesPrimaryWhenUserHadNone(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	role, err := f.svc.CreateRole(ctx, f.tenantID, &f.appID, "editor", nil)
	if err != nil {
		t.Fatalf("CreateRole() error = %v", err)
	}
	roleID := parseID(t, role.ID)
	userID := newUserOnRole(t, f, "noprimary@example.com", nil)
	if p := primaryRoleID(t, f, userID); p != nil {
		t.Fatalf("precondition: user should start with no primary role, got %d", *p)
	}

	if err := f.svc.AddUserRole(ctx, f.tenantID, &f.appID, userID, roleID, nil); err != nil {
		t.Fatalf("AddUserRole() error = %v", err)
	}

	// Otherwise the user holds roles with no primary among them, and the `role`
	// claim stays empty while `roles` is populated — a contradiction for any
	// consumer reading both.
	if p := primaryRoleID(t, f, userID); p == nil || *p != roleID {
		t.Errorf("primary role = %v, want %d promoted from the only grant", p, roleID)
	}
}

func TestAddUserRole_RefusesSystemRole(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	userID := newUserOnRole(t, f, "escalate@example.com", nil)
	sysRole := seedSystemRoleID(t, f)

	// The additive path must not become a second door to the escalation the
	// replacing path already refuses: an administrative role acquired here would
	// carry every admin permission with no tenant_admins row behind it.
	if err := f.svc.AddUserRole(ctx, f.tenantID, nil, userID, sysRole, nil); !errors.Is(err, admin.ErrSystemRole) {
		t.Errorf("AddUserRole(system role) error = %v, want ErrSystemRole", err)
	}
	if held := heldRoleNames(t, f, userID); len(held) != 0 {
		t.Errorf("held roles = %v after a refused system-role grant, want none", held)
	}
}

func TestAddUserRole_RefusesCrossApplicationRole(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	tenantRole, err := f.svc.CreateRole(ctx, f.tenantID, nil, "analyst", nil)
	if err != nil {
		t.Fatalf("CreateRole(tenant-level) error = %v", err)
	}
	userID := newUserOnRole(t, f, "scoped@example.com", nil)

	// Application isolation survives the additive path: an app's user may only
	// ever hold that app's roles.
	if err := f.svc.AddUserRole(ctx, f.tenantID, &f.appID, userID, parseID(t, tenantRole.ID), nil); !errors.Is(err, admin.ErrRoleScope) {
		t.Errorf("AddUserRole(tenant-level role onto an app user) error = %v, want ErrRoleScope", err)
	}
}

func TestRemoveUserRole_LeavesTheOtherRoles(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	viewer, err := f.svc.CreateRole(ctx, f.tenantID, &f.appID, "viewer", nil)
	if err != nil {
		t.Fatalf("CreateRole(viewer) error = %v", err)
	}
	editor, err := f.svc.CreateRole(ctx, f.tenantID, &f.appID, "editor", nil)
	if err != nil {
		t.Fatalf("CreateRole(editor) error = %v", err)
	}
	viewerID, editorID := parseID(t, viewer.ID), parseID(t, editor.ID)

	userID := newUserOnRole(t, f, "revoke@example.com", &viewerID)
	if err := f.svc.AddUserRole(ctx, f.tenantID, &f.appID, userID, editorID, nil); err != nil {
		t.Fatalf("AddUserRole() error = %v", err)
	}
	if err := f.svc.RemoveUserRole(ctx, f.tenantID, &f.appID, userID, editorID); err != nil {
		t.Fatalf("RemoveUserRole() error = %v", err)
	}

	if held := heldRoleNames(t, f, userID); len(held) != 1 || held[0] != "viewer" {
		t.Errorf("held roles = %v after revoking editor, want [viewer]", held)
	}
}

func TestRemoveUserRole_PromotesTheNextGrantWhenThePrimaryGoes(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	viewer, err := f.svc.CreateRole(ctx, f.tenantID, &f.appID, "viewer", nil)
	if err != nil {
		t.Fatalf("CreateRole(viewer) error = %v", err)
	}
	editor, err := f.svc.CreateRole(ctx, f.tenantID, &f.appID, "editor", nil)
	if err != nil {
		t.Fatalf("CreateRole(editor) error = %v", err)
	}
	viewerID, editorID := parseID(t, viewer.ID), parseID(t, editor.ID)

	userID := newUserOnRole(t, f, "promote@example.com", &viewerID)
	if err := f.svc.AddUserRole(ctx, f.tenantID, &f.appID, userID, editorID, nil); err != nil {
		t.Fatalf("AddUserRole() error = %v", err)
	}

	// Revoke the PRIMARY. Leaving role_id pointing at a revoked role would keep
	// its name in the `role` claim; NULLing it would drop a user who still holds
	// a role to no primary at all. Neither is right, so the survivor is promoted.
	if err := f.svc.RemoveUserRole(ctx, f.tenantID, &f.appID, userID, viewerID); err != nil {
		t.Fatalf("RemoveUserRole(primary) error = %v", err)
	}
	if p := primaryRoleID(t, f, userID); p == nil || *p != editorID {
		t.Errorf("primary role = %v after revoking the primary, want the surviving editor (%d)", p, editorID)
	}
}

func TestRemoveUserRole_ClearsPrimaryWhenNothingSurvives(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	role, err := f.svc.CreateRole(ctx, f.tenantID, &f.appID, "editor", nil)
	if err != nil {
		t.Fatalf("CreateRole() error = %v", err)
	}
	roleID := parseID(t, role.ID)
	userID := newUserOnRole(t, f, "last@example.com", &roleID)

	if err := f.svc.RemoveUserRole(ctx, f.tenantID, &f.appID, userID, roleID); err != nil {
		t.Fatalf("RemoveUserRole() error = %v", err)
	}
	if p := primaryRoleID(t, f, userID); p != nil {
		t.Errorf("primary role = %d after revoking the only role, want NULL", *p)
	}
}

func TestRemoveUserRole_RefusesARoleTheUserDoesNotHold(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	held, err := f.svc.CreateRole(ctx, f.tenantID, &f.appID, "viewer", nil)
	if err != nil {
		t.Fatalf("CreateRole(viewer) error = %v", err)
	}
	other, err := f.svc.CreateRole(ctx, f.tenantID, &f.appID, "editor", nil)
	if err != nil {
		t.Fatalf("CreateRole(editor) error = %v", err)
	}
	heldID := parseID(t, held.ID)
	userID := newUserOnRole(t, f, "notheld@example.com", &heldID)

	// Reporting success would confirm an operator's belief about who holds what
	// when that belief is wrong.
	if err := f.svc.RemoveUserRole(ctx, f.tenantID, &f.appID, userID, parseID(t, other.ID)); !errors.Is(err, admin.ErrNotFound) {
		t.Errorf("RemoveUserRole(unheld role) error = %v, want ErrNotFound", err)
	}
}

func TestAssignUserRole_StillReplacesTheWholeSet(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	viewer, err := f.svc.CreateRole(ctx, f.tenantID, &f.appID, "viewer", nil)
	if err != nil {
		t.Fatalf("CreateRole(viewer) error = %v", err)
	}
	editor, err := f.svc.CreateRole(ctx, f.tenantID, &f.appID, "editor", nil)
	if err != nil {
		t.Fatalf("CreateRole(editor) error = %v", err)
	}
	approver, err := f.svc.CreateRole(ctx, f.tenantID, &f.appID, "approver", nil)
	if err != nil {
		t.Fatalf("CreateRole(approver) error = %v", err)
	}
	viewerID, editorID := parseID(t, viewer.ID), parseID(t, editor.ID)

	userID := newUserOnRole(t, f, "replace@example.com", &viewerID)
	if err := f.svc.AddUserRole(ctx, f.tenantID, &f.appID, userID, editorID, nil); err != nil {
		t.Fatalf("AddUserRole() error = %v", err)
	}

	// PUT .../role has meant replacement since long before user_roles existed.
	// Quietly turning it additive would change what every existing caller does,
	// so it clears the set and leaves exactly the named role.
	if err := f.svc.AssignUserRole(ctx, f.tenantID, &f.appID, userID, parseID(t, approver.ID), nil); err != nil {
		t.Fatalf("AssignUserRole() error = %v", err)
	}
	if held := heldRoleNames(t, f, userID); len(held) != 1 || held[0] != "approver" {
		t.Errorf("held roles = %v after a replacing assignment, want [approver]", held)
	}
}

func TestListUserRoles_ReportsProvenanceAndPrimary(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	viewer, err := f.svc.CreateRole(ctx, f.tenantID, &f.appID, "viewer", nil)
	if err != nil {
		t.Fatalf("CreateRole(viewer) error = %v", err)
	}
	editor, err := f.svc.CreateRole(ctx, f.tenantID, &f.appID, "editor", nil)
	if err != nil {
		t.Fatalf("CreateRole(editor) error = %v", err)
	}
	viewerID, editorID := parseID(t, viewer.ID), parseID(t, editor.ID)

	grantor := newUserOnRole(t, f, "grantor@example.com", nil)
	userID := newUserOnRole(t, f, "listed@example.com", &viewerID)
	if err := f.svc.AddUserRole(ctx, f.tenantID, &f.appID, userID, editorID, &grantor); err != nil {
		t.Fatalf("AddUserRole() error = %v", err)
	}

	roles, err := f.svc.ListUserRoles(ctx, f.tenantID, &f.appID, userID)
	if err != nil {
		t.Fatalf("ListUserRoles() error = %v", err)
	}
	if len(roles) != 2 {
		t.Fatalf("ListUserRoles() returned %d roles, want 2", len(roles))
	}
	if !roles[0].IsPrimary || roles[1].IsPrimary {
		t.Errorf("is_primary = [%v %v], want the first (viewer) alone", roles[0].IsPrimary, roles[1].IsPrimary)
	}
	// Provenance is the reason a join table beats an array column: "who granted
	// this" is what makes a targeted revocation possible later.
	if roles[1].GrantedBy == nil {
		t.Error("granted_by is nil on the editor grant; provenance was not recorded")
	}
	if roles[0].GrantedBy != nil {
		t.Error("granted_by is set on the registration-time grant; it should be unknown, not invented")
	}
}
