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

// Lock ordering — issue #220, second round.
//
// The locks the tests above added can deadlock against each other when two
// transactions take more than one roles row in different orders: Postgres
// aborts one side with 40P01, surfacing as a random 500 on a grant, an
// acceptance, an RBAC import or a SetDefaultRole call. The rule these tests
// pin is that every multi-row roles lock is taken in ONE statement ordered by
// id, the order runRBACImport already used. Each test parks a second
// transaction (X) on the lower-id row — playing the id-ordered locker — while
// the service call runs, then has X take the higher-id row: on the fix that
// lock comes straight through because the service is itself waiting on the
// row X holds; on the old code the pair deadlocks and one side returns 40P01
// (or X's lock_timeout fires).

// why: #220 — an existing-user acceptance locked the invitation's roles
// ORDER BY name, so with alpha created after zeta it held alpha's higher-id
// row while waiting on zeta's lower-id one — the reverse of an id-ordered
// locker's order, and a deadlock. The fix takes them in ONE statement ordered
// by id, so acceptance simply waits on the row X holds.
func TestOrganizations_AcceptInvitationExistingUserLocksRolesInIDOrder(t *testing.T) {
	f := newOrgFixture(t, "org-acc-id-order", auth.OrganizationsModeOptional)
	zetaID := orgRole(t, f, "zeta")   // lower id
	alphaID := orgRole(t, f, "alpha") // higher id — name order inverts id order
	f.createOrg(t, "acme")
	email := uniqueEmail("accept-id-order")
	uid := f.registerUser(t, email)
	ctx := context.Background()

	inv, err := f.orgs.CreateInvitation(ctx, f.scope, "acme", auth.CreateOrganizationInvitationInput{
		Email: email, Roles: []string{"alpha", "zeta"},
	})
	if err != nil {
		t.Fatalf("CreateInvitation() error = %v", err)
	}

	// X plays the id-ordered roles locker (runRBACImport's shape): FOR NO KEY
	// UPDATE on zeta first, then — once acceptance is parked on it — alpha.
	txX, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin locker: %v", err)
	}
	defer txX.Rollback(ctx) //nolint:errcheck
	if _, err := txX.Exec(ctx, `SET LOCAL lock_timeout = '5s'`); err != nil {
		t.Fatalf("set lock_timeout: %v", err)
	}
	if _, err := txX.Exec(ctx, `SELECT id FROM roles WHERE id = $1 FOR NO KEY UPDATE`, zetaID); err != nil {
		t.Fatalf("lock zeta: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := f.orgs.AcceptInvitation(ctx, auth.AcceptOrganizationInvitationInput{
			Token: inv.Token, ExistingUserID: &uid, AppRowID: f.scope.AppRowID,
		})
		done <- err
	}()
	waitForLockWait(t, f.pool, "roles")

	if _, err := txX.Exec(ctx, `SELECT id FROM roles WHERE id = $1 FOR NO KEY UPDATE`, alphaID); err != nil {
		t.Fatalf("lock alpha: %v; acceptance must not be holding it", err)
	}
	if err := txX.Commit(ctx); err != nil {
		t.Fatalf("commit locker: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("AcceptInvitation() error = %v, want nil once the locker commits", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("AcceptInvitation() did not return after the locker committed")
	}
}

// why: #220 — a new-account acceptance locked the application's default role
// inside createInvitedUser and the invitation's roles afterwards in
// liveRoleNames: two statements. With a default created later than the
// invitation's role the transaction held the higher-id row while waiting on
// the lower-id one an id-ordered locker held — a deadlock ORDER BY on either
// statement alone could not fix. The fix locks both in ONE statement ordered
// by id before the account is written.
func TestOrganizations_AcceptInvitationNewAccountLocksDefaultInIDOrder(t *testing.T) {
	f := newOrgFixture(t, "org-acc-def-order", auth.OrganizationsModeOptional)
	approverID := orgRole(t, f, "approver") // lower id: the invitation's role
	memberID := orgRole(t, f, "member")     // higher id: becomes the default
	f.createOrg(t, "acme")
	ctx := context.Background()

	// Make the later-created role the application's default; the fixture's own
	// default has to yield the one-default-per-app slot first.
	if _, err := f.pool.Exec(ctx, `
		UPDATE roles SET is_default = false
		WHERE tenant_id = $1 AND application_id = $2 AND is_default = true
	`, f.tenantID, f.scope.AppRowID); err != nil {
		t.Fatalf("clear fixture default: %v", err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE roles SET is_default = true WHERE id = $1`, memberID); err != nil {
		t.Fatalf("set member as default: %v", err)
	}

	inv, err := f.orgs.CreateInvitation(ctx, f.scope, "acme", auth.CreateOrganizationInvitationInput{
		Email: uniqueEmail("accept-def-order"), Roles: []string{"approver"},
	})
	if err != nil {
		t.Fatalf("CreateInvitation() error = %v", err)
	}

	txX, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin locker: %v", err)
	}
	defer txX.Rollback(ctx) //nolint:errcheck
	if _, err := txX.Exec(ctx, `SET LOCAL lock_timeout = '5s'`); err != nil {
		t.Fatalf("set lock_timeout: %v", err)
	}
	if _, err := txX.Exec(ctx, `SELECT id FROM roles WHERE id = $1 FOR NO KEY UPDATE`, approverID); err != nil {
		t.Fatalf("lock approver: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := f.orgs.AcceptInvitation(ctx, auth.AcceptOrganizationInvitationInput{
			Token: inv.Token, Password: "Password123!",
		})
		done <- err
	}()
	waitForLockWait(t, f.pool, "roles")

	if _, err := txX.Exec(ctx, `SELECT id FROM roles WHERE id = $1 FOR NO KEY UPDATE`, memberID); err != nil {
		t.Fatalf("lock member: %v; acceptance must not be holding it", err)
	}
	if err := txX.Commit(ctx); err != nil {
		t.Fatalf("commit locker: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("AcceptInvitation() error = %v, want nil once the locker commits", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("AcceptInvitation() did not return after the locker committed")
	}
}

// why: #220 — SetDefaultRole's two UPDATEs locked old-default-then-target,
// which is descending id order whenever the new default's id is lower: a
// grant path that already held FOR SHARE on the target deadlocked against the
// clear-UPDATE. The fix locks both rows in ONE statement ordered by id before
// the lookup.
func TestOrganizations_SetDefaultRoleDoesNotDeadlockWithIDOrderedGrant(t *testing.T) {
	f := newOrgFixture(t, "org-setdef-order", auth.OrganizationsModeOptional)
	aID := orgRole(t, f, "a") // lower id — becomes the default
	bID := orgRole(t, f, "b") // higher id — the current default
	ctx := context.Background()

	// b is the current default; the fixture's own default yields its slot.
	if _, err := f.pool.Exec(ctx, `
		UPDATE roles SET is_default = false
		WHERE tenant_id = $1 AND application_id = $2 AND is_default = true
	`, f.tenantID, f.scope.AppRowID); err != nil {
		t.Fatalf("clear fixture default: %v", err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE roles SET is_default = true WHERE id = $1`, bID); err != nil {
		t.Fatalf("set b as default: %v", err)
	}

	// X plays a grant path holding FOR SHARE in id order: a first, then b.
	txX, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin locker: %v", err)
	}
	defer txX.Rollback(ctx) //nolint:errcheck
	if _, err := txX.Exec(ctx, `SET LOCAL lock_timeout = '5s'`); err != nil {
		t.Fatalf("set lock_timeout: %v", err)
	}
	if _, err := txX.Exec(ctx, `SELECT id FROM roles WHERE id = $1 FOR SHARE`, aID); err != nil {
		t.Fatalf("lock a: %v", err)
	}

	adminSvc := admin.New(f.pool, nil, testhelper.TestLogger())
	done := make(chan error, 1)
	go func() {
		done <- adminSvc.SetDefaultRole(ctx, f.tenantID, f.scope.AppRowID, aID)
	}()
	waitForLockWait(t, f.pool, "roles")

	if _, err := txX.Exec(ctx, `SELECT id FROM roles WHERE id = $1 FOR SHARE`, bID); err != nil {
		t.Fatalf("lock b: %v; SetDefaultRole must not be holding it", err)
	}
	if err := txX.Commit(ctx); err != nil {
		t.Fatalf("commit locker: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("SetDefaultRole() error = %v, want nil once the locker commits", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("SetDefaultRole() did not return after the locker committed")
	}

	var aDefault, bDefault bool
	if err := f.pool.QueryRow(ctx, `SELECT is_default FROM roles WHERE id = $1`, aID).Scan(&aDefault); err != nil {
		t.Fatalf("read a's default flag: %v", err)
	}
	if err := f.pool.QueryRow(ctx, `SELECT is_default FROM roles WHERE id = $1`, bID).Scan(&bDefault); err != nil {
		t.Fatalf("read b's default flag: %v", err)
	}
	if !aDefault || bDefault {
		t.Errorf("after SetDefaultRole(a): a is_default = %v, b is_default = %v; want true/false", aDefault, bDefault)
	}
}

// why: #220 — AssignMemberRoles resolves the requested roles through
// resolveApplicationRoles, which took FOR SHARE on the rows in whatever order
// the plan returned. Against an id-ordered locker that order is the deadlock
// coin flip; the fix orders by id so the two sides serialise. (Whether the
// old query happened to come out in id order depended on the planner, so this
// test can pass by luck on the old code — the SQL-order unit test is the
// deterministic guard for it.)
func TestOrganizations_AssignMemberRolesLocksRolesInIDOrder(t *testing.T) {
	f := newOrgFixture(t, "org-amr-id-order", auth.OrganizationsModeOptional)
	zetaID := orgRole(t, f, "zeta")   // lower id
	alphaID := orgRole(t, f, "alpha") // higher id — name order inverts id order
	uid := f.registerUser(t, uniqueEmail("amr-order"))
	acme := f.createOrg(t, "acme")
	f.addMember(t, acme, uid)
	ctx := context.Background()

	txX, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin locker: %v", err)
	}
	defer txX.Rollback(ctx) //nolint:errcheck
	if _, err := txX.Exec(ctx, `SET LOCAL lock_timeout = '5s'`); err != nil {
		t.Fatalf("set lock_timeout: %v", err)
	}
	if _, err := txX.Exec(ctx, `SELECT id FROM roles WHERE id = $1 FOR NO KEY UPDATE`, zetaID); err != nil {
		t.Fatalf("lock zeta: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := f.orgs.AssignMemberRoles(ctx, f.scope, acme.ID, uid, []string{"alpha", "zeta"}, false, nil)
		done <- err
	}()
	waitForLockWait(t, f.pool, "roles")

	if _, err := txX.Exec(ctx, `SELECT id FROM roles WHERE id = $1 FOR NO KEY UPDATE`, alphaID); err != nil {
		t.Fatalf("lock alpha: %v; the grant must not be holding it", err)
	}
	if err := txX.Commit(ctx); err != nil {
		t.Fatalf("commit locker: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("AssignMemberRoles() error = %v, want nil once the locker commits", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("AssignMemberRoles() did not return after the locker committed")
	}
}
