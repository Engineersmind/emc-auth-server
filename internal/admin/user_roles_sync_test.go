package admin_test

import (
	"context"
	"testing"
)

// users.role_id and user_roles must never disagree — PR #148 review.
//
// #146 phase 2 made user_roles authoritative for permission resolution while
// keeping users.role_id as the primary role. That split has one failure mode,
// and it is silent: a writer that sets role_id without inserting the matching
// user_roles row produces an account that DISPLAYS a role and resolves none of
// its permissions. The login succeeds, every permission-gated route 403s, and
// nothing in the logs names the cause.
//
// The review found four such writers. This file pins the invariant itself rather
// than each fix, so a fifth writer added later fails here instead of in
// production. The auth-side writers (registration, OAuth JIT, SAML JIT, admin
// grant activation) are covered in internal/auth; these are the admin paths.

// assertRolesInSync fails when users.role_id is set but absent from user_roles,
// which is the desync that costs an account its permissions.
func assertRolesInSync(t *testing.T, f adminFixture, userID int64, label string) {
	t.Helper()
	var roleID *int64
	if err := f.pool.QueryRow(context.Background(), `SELECT role_id FROM users WHERE id = $1`, userID).Scan(&roleID); err != nil {
		t.Fatalf("%s: read role_id: %v", label, err)
	}
	if roleID == nil {
		return // no primary role is a legitimate state; nothing to mirror
	}
	var held bool
	if err := f.pool.QueryRow(context.Background(),
		`SELECT EXISTS (SELECT 1 FROM user_roles WHERE user_id = $1 AND role_id = $2)`,
		userID, *roleID,
	).Scan(&held); err != nil {
		t.Fatalf("%s: read user_roles: %v", label, err)
	}
	if !held {
		t.Errorf("%s: users.role_id = %d but no user_roles row holds it — "+
			"this account would authenticate with no permissions at all", label, *roleID)
	}
}

func TestCreateUser_MirrorsInitialRoleIntoUserRoles(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	role, err := f.svc.CreateRole(ctx, f.tenantID, &f.appID, "editor", nil)
	if err != nil {
		t.Fatalf("CreateRole() error = %v", err)
	}
	roleID := parseID(t, role.ID)

	// A user created WITH a role must hold it in both places, or they sign in
	// displaying "editor" and carrying none of its permissions.
	userID := newUserOnRole(t, f, "created-with-role@example.com", &roleID)
	assertRolesInSync(t, f, userID, "CreateUser with a role")

	held := heldRoleNames(t, f, userID)
	if len(held) != 1 || held[0] != "editor" {
		t.Errorf("held roles = %v, want [editor] mirrored from the initial role", held)
	}
}

func TestCreateUser_WithoutRoleHoldsNothing(t *testing.T) {
	f := newAdminFixture(t)

	// The counterweight: no role means no user_roles row either. A mirror that
	// fired unconditionally would invent a grant nobody made.
	userID := newUserOnRole(t, f, "created-roleless@example.com", nil)
	assertRolesInSync(t, f, userID, "CreateUser without a role")

	if held := heldRoleNames(t, f, userID); len(held) != 0 {
		t.Errorf("held roles = %v for a user created with no role, want none", held)
	}
}

func TestAssignUserRole_LeavesTheTwoInSync(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	first, err := f.svc.CreateRole(ctx, f.tenantID, &f.appID, "viewer", nil)
	if err != nil {
		t.Fatalf("CreateRole(viewer) error = %v", err)
	}
	second, err := f.svc.CreateRole(ctx, f.tenantID, &f.appID, "editor", nil)
	if err != nil {
		t.Fatalf("CreateRole(editor) error = %v", err)
	}
	firstID := parseID(t, first.ID)

	userID := newUserOnRole(t, f, "reassigned@example.com", &firstID)
	if err := f.svc.AssignUserRole(ctx, f.tenantID, &f.appID, userID, parseID(t, second.ID), nil); err != nil {
		t.Fatalf("AssignUserRole() error = %v", err)
	}
	assertRolesInSync(t, f, userID, "AssignUserRole")
}

func TestRemoveUserRole_LeavesTheTwoInSync(t *testing.T) {
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

	userID := newUserOnRole(t, f, "partly-revoked@example.com", &viewerID)
	if err := f.svc.AddUserRole(ctx, f.tenantID, &f.appID, userID, editorID, nil); err != nil {
		t.Fatalf("AddUserRole() error = %v", err)
	}
	// Revoke the PRIMARY: role_id gets repointed at the survivor, and that
	// survivor must be one the user genuinely holds.
	if err := f.svc.RemoveUserRole(ctx, f.tenantID, &f.appID, userID, viewerID); err != nil {
		t.Fatalf("RemoveUserRole() error = %v", err)
	}
	assertRolesInSync(t, f, userID, "RemoveUserRole of the primary")
}

func TestDeleteRole_LeavesSurvivingHoldersInSync(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	doomed, err := f.svc.CreateRole(ctx, f.tenantID, &f.appID, "doomed", nil)
	if err != nil {
		t.Fatalf("CreateRole(doomed) error = %v", err)
	}
	survivor, err := f.svc.CreateRole(ctx, f.tenantID, &f.appID, "survivor", nil)
	if err != nil {
		t.Fatalf("CreateRole(survivor) error = %v", err)
	}
	doomedID, survivorID := parseID(t, doomed.ID), parseID(t, survivor.ID)

	userID := newUserOnRole(t, f, "holder@example.com", &doomedID)
	if err := f.svc.AddUserRole(ctx, f.tenantID, &f.appID, userID, survivorID, nil); err != nil {
		t.Fatalf("AddUserRole() error = %v", err)
	}

	// Deleting the primary role must repoint role_id at the survivor AND leave
	// the user_roles row for it intact, not merely clear one of the two.
	if _, err := f.svc.DeleteRole(ctx, f.tenantID, doomedID); err != nil {
		t.Fatalf("DeleteRole() error = %v", err)
	}
	assertRolesInSync(t, f, userID, "DeleteRole of a holder's primary")

	held := heldRoleNames(t, f, userID)
	if len(held) != 1 || held[0] != "survivor" {
		t.Errorf("held roles = %v after deleting the primary, want [survivor]", held)
	}
}
