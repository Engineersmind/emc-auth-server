package auth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/engineersmind/emc-auth-server/internal/admin"
	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// DeleteRole racing an in-flight organisation grant — issue #220.
//
// The grant paths used to read roles without a lock, so a grant that resolved
// the role before DeleteRole's UPDATE and inserted its organization_member_roles
// row after DeleteRole's omr delete committed a grant on a deleted role — an
// orphan. The orphan then counted as held in assignRolesTx: a new role reusing
// the name could never be assigned, and the dead grant counted toward the
// 20-role cap.
//
// Like the other race tests in this package these are deterministic, not
// probabilistic: each parks one side on a lock the other holds, so the old code
// fails every run rather than some runs.

// orgRole inserts a live, non-system application role and returns its id.
func orgRole(t *testing.T, f orgFixture, name string) int64 {
	t.Helper()
	var id int64
	if err := f.pool.QueryRow(context.Background(), `
		INSERT INTO roles (tenant_id, application_id, name, is_system, is_default, created_at)
		VALUES ($1, $2, $3, false, false, NOW())
		RETURNING id
	`, f.tenantID, f.scope.AppRowID, name).Scan(&id); err != nil {
		t.Fatalf("insert role %s: %v", name, err)
	}
	return id
}

// grantOrgRole records an organisation grant directly, standing in for a grant
// the service committed earlier.
func grantOrgRole(t *testing.T, f orgFixture, org *auth.Organization, userID, roleID int64) {
	t.Helper()
	if _, err := f.pool.Exec(context.Background(), `
		INSERT INTO organization_member_roles (organization_id, user_id, role_id, application_id, tenant_id)
		VALUES ($1, $2, $3, $4, $5)
	`, org.RowID(), userID, roleID, f.scope.AppRowID, f.tenantID); err != nil {
		t.Fatalf("insert organisation grant: %v", err)
	}
}

// orgGrantCount counts the grant rows pointing at roleID.
func orgGrantCount(t *testing.T, f orgFixture, roleID int64) int {
	t.Helper()
	var n int
	if err := f.pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM organization_member_roles WHERE role_id = $1`, roleID,
	).Scan(&n); err != nil {
		t.Fatalf("count organisation grants: %v", err)
	}
	return n
}

// Delete first: the grant's role read lands behind DeleteRole's uncommitted
// UPDATE. With the read locked FOR SHARE the grant waits, re-checks
// deleted_at on the post-delete version and fails with ErrRoleNotInApplication.
// Without the lock it sails through and inserts behind the delete's back.
func TestOrganizations_GrantRacingDeleteRoleSeesTheDelete(t *testing.T) {
	f := newOrgFixture(t, "org-del-first", auth.OrganizationsModeOptional)
	roleID := orgRole(t, f, "approver")
	uid := f.registerUser(t, uniqueEmail("grant-late"))
	acme := f.createOrg(t, "acme")
	f.addMember(t, acme, uid)
	ctx := context.Background()

	// tx A holds DeleteRole's soft-delete UPDATE — the statement that takes
	// FOR NO KEY UPDATE on the role row — open while the grant runs.
	txA, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer txA.Rollback(ctx) //nolint:errcheck
	if _, err := txA.Exec(ctx, `
		UPDATE roles SET deleted_at = NOW(), is_default = false, updated_at = NOW()
		WHERE id = $1 AND tenant_id = $2 AND is_system = false AND deleted_at IS NULL
	`, roleID, f.tenantID); err != nil {
		t.Fatalf("soft-delete role: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := f.orgs.AssignMemberRoles(ctx, f.scope, acme.ID, uid, []string{"approver"}, false, nil)
		done <- err
	}()
	// The grant is in flight once it blocks: on the locked role read (the fix)
	// or on the grant insert's foreign-key check against the role row the
	// delete still holds (the defect). Either waits on a Lock running a query
	// that names roles.
	waitForLockWait(t, f.pool, "roles")

	// DeleteRole's omr delete ran while the grant was still uncommitted — the
	// exact window the orphan slipped through.
	if _, err := txA.Exec(ctx,
		`DELETE FROM organization_member_roles WHERE role_id = $1 AND tenant_id = $2`,
		roleID, f.tenantID); err != nil {
		t.Fatalf("delete role grants: %v", err)
	}
	if err := txA.Commit(ctx); err != nil {
		t.Fatalf("commit delete: %v", err)
	}

	select {
	case err := <-done:
		if !errors.Is(err, auth.ErrRoleNotInApplication) {
			t.Errorf("AssignMemberRoles() racing a delete error = %v, want ErrRoleNotInApplication", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("AssignMemberRoles() did not return after the delete committed")
	}

	if n := orgGrantCount(t, f, roleID); n != 0 {
		t.Errorf("%d grant(s) point at the deleted role; an orphan now shadows its name", n)
	}
}

// Grant first: the grant holds the role lock when DeleteRole starts, so the
// delete's UPDATE waits for the grant to commit — and then its holder
// collection and omr delete see the grant it parked behind.
func TestOrganizations_DeleteRoleCollectsAGrantCommittedMidDelete(t *testing.T) {
	f := newOrgFixture(t, "org-grant-first", auth.OrganizationsModeOptional)
	roleID := orgRole(t, f, "approver")
	uid := f.registerUser(t, uniqueEmail("grant-first"))
	acme := f.createOrg(t, "acme")
	f.addMember(t, acme, uid)
	ctx := context.Background()
	adminSvc := admin.New(f.pool, nil, testhelper.TestLogger())

	// An uncommitted row on the grant's primary key parks the grant's
	// INSERT ... ON CONFLICT inside its transaction — after it has taken its
	// role lock on the fix, holding nothing on the defect — for exactly as
	// long as this transaction stays open.
	blocker, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin blocker: %v", err)
	}
	defer blocker.Rollback(ctx) //nolint:errcheck
	if _, err := blocker.Exec(ctx, `
		INSERT INTO organization_member_roles (organization_id, user_id, role_id, application_id, tenant_id)
		VALUES ($1, $2, $3, $4, $5)
	`, acme.RowID(), uid, roleID, f.scope.AppRowID, f.tenantID); err != nil {
		t.Fatalf("hold grant key: %v", err)
	}

	grantDone := make(chan error, 1)
	go func() {
		_, err := f.orgs.AssignMemberRoles(ctx, f.scope, acme.ID, uid, []string{"approver"}, false, nil)
		grantDone <- err
	}()
	waitForLockWait(t, f.pool, "organization_member_roles")

	type deleteResult struct {
		holders []int64
		err     error
	}
	delDone := make(chan deleteResult, 1)
	go func() {
		holders, err := adminSvc.DeleteRole(ctx, f.tenantID, roleID)
		delDone <- deleteResult{holders, err}
	}()

	// Release the grant only once the delete is parked on the grant's role
	// lock (the fix) or has already finished (the defect, where nothing makes
	// it wait). Releasing earlier could let the grant commit before the
	// delete's holder read even on the fix.
	var del deleteResult
	deleteReturned := false
	deadline := time.Now().Add(10 * time.Second)
	for {
		select {
		case del = <-delDone:
			deleteReturned = true
		default:
		}
		if deleteReturned {
			break
		}
		var waiting bool
		if err := f.pool.QueryRow(ctx, `
			SELECT EXISTS (SELECT 1 FROM pg_stat_activity
			               WHERE wait_event_type = 'Lock' AND query LIKE '%SET deleted_at%')
		`).Scan(&waiting); err != nil {
			t.Fatalf("poll pg_stat_activity: %v", err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("DeleteRole neither waited on the grant's role lock nor completed within 10s")
		}
		time.Sleep(20 * time.Millisecond)
	}

	if err := blocker.Rollback(ctx); err != nil {
		t.Fatalf("release blocker: %v", err)
	}
	if err := <-grantDone; err != nil {
		t.Fatalf("AssignMemberRoles() error = %v", err)
	}
	if !deleteReturned {
		select {
		case del = <-delDone:
		case <-time.After(10 * time.Second):
			t.Fatal("DeleteRole() did not return after the grant committed")
		}
	}
	if del.err != nil {
		t.Fatalf("DeleteRole() error = %v", del.err)
	}

	// The grant committed before the delete's holder collection only if the
	// delete waited on it: the member must appear in the audit record, and no
	// grant row may survive.
	found := false
	for _, h := range del.holders {
		if h == uid {
			found = true
		}
	}
	if !found {
		t.Errorf("DeleteRole() holders = %v, want the mid-delete grant holder %d", del.holders, uid)
	}
	if n := orgGrantCount(t, f, roleID); n != 0 {
		t.Errorf("%d grant(s) point at the deleted role; an orphan now shadows its name", n)
	}
}

// Defence in depth for orphans the race already left behind: a grant pointing
// at a deleted role must not count as held, so a new role reusing the name is
// assignable.
func TestOrganizations_OrphanedGrantDoesNotShadowANewSameNamedRole(t *testing.T) {
	f := newOrgFixture(t, "org-orphan", auth.OrganizationsModeOptional)
	uid := f.registerUser(t, uniqueEmail("orphan-shadow"))
	acme := f.createOrg(t, "acme")
	f.addMember(t, acme, uid)
	ctx := context.Background()

	// An orphan the way #220 made one: a live grant whose role was then
	// soft-deleted, as a DeleteRole racing the grant left behind. Written
	// directly because the service now prevents new orphans — this pins what
	// an existing one may no longer do.
	dead := orgRole(t, f, "editor")
	grantOrgRole(t, f, acme, uid, dead)
	if _, err := f.pool.Exec(ctx,
		`UPDATE roles SET deleted_at = NOW() WHERE id = $1`, dead); err != nil {
		t.Fatalf("soft-delete the granted role: %v", err)
	}
	live := orgRole(t, f, "editor")

	res, err := f.orgs.AssignMemberRoles(ctx, f.scope, acme.ID, uid, []string{"editor"}, false, nil)
	if err != nil {
		t.Fatalf("AssignMemberRoles() error = %v", err)
	}
	// The orphan's name satisfies "already held" only while the held-roles
	// query lacks the deleted_at predicate: the call then reports success with
	// nothing assigned, and the member holds the dead grant forever.
	if len(res.Assigned) != 1 || res.Assigned[0] != "editor" {
		t.Errorf("assigned = %v, want [editor]; the orphan shadowed the new role", res.Assigned)
	}
	if len(res.Roles) != 1 || res.Roles[0] != "editor" {
		t.Errorf("member roles = %v, want [editor]", res.Roles)
	}
	if n := orgGrantCount(t, f, live); n != 1 {
		t.Errorf("%d grant(s) point at the new role, want 1", n)
	}
}

// The same orphan must not count toward MaxOrganizationRolesPerMember either:
// 19 live grants plus one orphan leaves room for one more.
func TestOrganizations_OrphanedGrantDoesNotCountTowardTheRoleCap(t *testing.T) {
	f := newOrgFixture(t, "org-orphan-cap", auth.OrganizationsModeOptional)
	uid := f.registerUser(t, uniqueEmail("orphan-cap"))
	acme := f.createOrg(t, "acme")
	f.addMember(t, acme, uid)
	ctx := context.Background()

	for _, name := range []string{
		"role-01", "role-02", "role-03", "role-04", "role-05",
		"role-06", "role-07", "role-08", "role-09", "role-10",
		"role-11", "role-12", "role-13", "role-14", "role-15",
		"role-16", "role-17", "role-18", "role-19",
	} {
		grantOrgRole(t, f, acme, uid, orgRole(t, f, name))
	}
	dead := orgRole(t, f, "ghost")
	grantOrgRole(t, f, acme, uid, dead)
	if _, err := f.pool.Exec(ctx,
		`UPDATE roles SET deleted_at = NOW() WHERE id = $1`, dead); err != nil {
		t.Fatalf("soft-delete the granted role: %v", err)
	}
	orgRole(t, f, "role-20")

	// Counted as held, the orphan is the 20th and this is ErrOrganizationRoleLimitReached;
	// filtered, the member has 19 and the twentieth live role fits the cap.
	res, err := f.orgs.AssignMemberRoles(ctx, f.scope, acme.ID, uid, []string{"role-20"}, false, nil)
	if err != nil {
		t.Fatalf("AssignMemberRoles() error = %v, want the twentieth live role to fit", err)
	}
	if len(res.Assigned) != 1 || res.Assigned[0] != "role-20" {
		t.Errorf("assigned = %v, want [role-20]", res.Assigned)
	}
}
