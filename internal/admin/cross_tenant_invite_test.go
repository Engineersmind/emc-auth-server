package admin_test

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/engineersmind/emc-auth-server/internal/admin"
	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// ---------------------------------------------------------------------------
// Cross-tenant invitations: one identity, N tenants.
//
// The bug these pin: InviteTenantAdmin looked its recipient up with
// "WHERE tenant_id = $1 AND email = $2", so inviting an address that already
// existed in ANOTHER tenant found nothing and created a second users row. The
// result was two parallel accounts sharing only an email string — separate
// password hashes, separate MFA enrolments, separate audit history. Both
// passwords worked, each signing the operator in as a different person who
// administered exactly one tenant, and switching to the other was refused
// because neither identity held a grant there.
//
// The lookup is now across tenants, so the second invitation grants the existing
// person instead of duplicating them.
// ---------------------------------------------------------------------------

// TestInviteTenantAdmin_SecondTenantGrantsExistingIdentity is the regression
// test. One address, two tenants, and exactly ONE users row must exist after.
func TestInviteTenantAdmin_SecondTenantGrantsExistingIdentity(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	tenantA, _ := newAdminTenant(t, f, "xtenant-a")
	tenantB, _ := newAdminTenant(t, f, "xtenant-b")
	appB := newTenantApp(t, f, tenantB, "xtenant-b-app")

	const email = "multi@xtenant.example"

	// Owner of tenant A, created the ordinary way.
	firstRes, err := f.svc.InviteTenantAdmin(ctx, admin.InviteTenantAdminInput{
		TenantID: tenantA, Email: email, Role: auth.AdminRoleOwner,
	})
	if err != nil {
		t.Fatalf("InviteTenantAdmin(tenant A owner): %v", err)
	}
	if firstRes.Action != "invited" {
		t.Errorf("first invitation action = %q, want invited", firstRes.Action)
	}

	var firstUserID int64
	if err = f.pool.QueryRow(ctx, `
		SELECT id FROM users WHERE email = $1 AND application_id IS NULL AND deleted_at IS NULL
	`, email).Scan(&firstUserID); err != nil {
		t.Fatalf("look up created user: %v", err)
	}

	// The same address, invited to a DIFFERENT tenant as a co-owner. Before the
	// fix this created a second users row with its own credentials.
	secondRes, err := f.svc.InviteTenantAdmin(ctx, admin.InviteTenantAdminInput{
		TenantID: tenantB, Email: email,
		Role: auth.AdminRoleCoOwner, ApplicationIDs: []int64{appB},
	})
	if err != nil {
		t.Fatalf("InviteTenantAdmin(tenant B co-owner): %v", err)
	}
	// "grants_added", not "invited": the person already existed, so nothing was
	// created — administration was added to who they already were.
	if secondRes.Action != "grants_added" {
		t.Errorf("second invitation action = %q, want grants_added (the identity already existed)", secondRes.Action)
	}

	// THE assertion. Two rows here is the duplicate-account bug.
	var userRows int
	if err = f.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM users WHERE email = $1 AND application_id IS NULL AND deleted_at IS NULL
	`, email).Scan(&userRows); err != nil {
		t.Fatalf("count users: %v", err)
	}
	if userRows != 1 {
		t.Fatalf("users rows for %s = %d, want 1 — a second invitation must grant the existing identity, not duplicate it", email, userRows)
	}

	// One identity, two administrations.
	var tenantIDs []int64
	rows, err := f.pool.Query(ctx, `
		SELECT tenant_id FROM tenant_admins
		WHERE user_id = $1 AND deleted_at IS NULL ORDER BY tenant_id
	`, firstUserID)
	if err != nil {
		t.Fatalf("query administrations: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var tid int64
		if err = rows.Scan(&tid); err != nil {
			t.Fatalf("scan administration: %v", err)
		}
		tenantIDs = append(tenantIDs, tid)
	}
	if len(tenantIDs) != 2 {
		t.Errorf("administrations for user %d = %v, want both tenant %d and %d", firstUserID, tenantIDs, tenantA, tenantB)
	}
}

// TestInviteTenantAdmin_CrossTenantMirrorsBothGrants: the admin_grants mirror
// must carry both administrations, since it is what resolves reach once
// ADMIN_GRANTS_ENABLED is on.
//
// A mirror that held only the home tenant would look correct in the legacy model
// and silently drop the second tenant the moment the flag flipped.
func TestInviteTenantAdmin_CrossTenantMirrorsBothGrants(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	tenantA, _ := newAdminTenant(t, f, "mirror-a")
	tenantB, _ := newAdminTenant(t, f, "mirror-b")
	appB := newTenantApp(t, f, tenantB, "mirror-b-app")
	const email = "mirror@xtenant.example"

	if _, err := f.svc.InviteTenantAdmin(ctx, admin.InviteTenantAdminInput{
		TenantID: tenantA, Email: email, Role: auth.AdminRoleOwner,
	}); err != nil {
		t.Fatalf("invite owner in A: %v", err)
	}
	if _, err := f.svc.InviteTenantAdmin(ctx, admin.InviteTenantAdminInput{
		TenantID: tenantB, Email: email,
		Role: auth.AdminRoleCoOwner, ApplicationIDs: []int64{appB},
	}); err != nil {
		t.Fatalf("invite co-owner in B: %v", err)
	}

	var userID int64
	if err := f.pool.QueryRow(ctx,
		`SELECT id FROM users WHERE email = $1 AND application_id IS NULL AND deleted_at IS NULL`, email,
	).Scan(&userID); err != nil {
		t.Fatalf("look up user: %v", err)
	}

	type grant struct {
		tenantID int64
		role     string
		appID    *int64
	}
	rows, err := f.pool.Query(ctx, `
		SELECT tenant_id, admin_role, application_id FROM admin_grants
		WHERE user_id = $1 AND deleted_at IS NULL ORDER BY tenant_id
	`, userID)
	if err != nil {
		t.Fatalf("query admin_grants: %v", err)
	}
	defer rows.Close()
	var grants []grant
	for rows.Next() {
		var g grant
		if err = rows.Scan(&g.tenantID, &g.role, &g.appID); err != nil {
			t.Fatalf("scan grant: %v", err)
		}
		grants = append(grants, g)
	}

	if len(grants) != 2 {
		t.Fatalf("admin_grants for user %d = %+v, want 2 (owner of %d, co_owner in %d)", userID, grants, tenantA, tenantB)
	}
	// Owner in A carries NO application: absence means all.
	if grants[0].tenantID != tenantA || grants[0].role != auth.AdminRoleOwner || grants[0].appID != nil {
		t.Errorf("grant in tenant A = %+v, want owner with no application", grants[0])
	}
	// Co-owner in B names exactly the granted application.
	if grants[1].tenantID != tenantB || grants[1].role != auth.AdminRoleCoOwner ||
		grants[1].appID == nil || *grants[1].appID != appB {
		t.Errorf("grant in tenant B = %+v, want co_owner of application %d", grants[1], appB)
	}
}

// TestInviteTenantAdmin_CrossTenantDoesNotRestoreForeignRole: removal must not
// re-attach a role from the administrator's HOME tenant.
//
// previousRoleID exists so that withdrawing administration puts back whatever the
// account held before. For a cross-tenant invitation there is nothing to put back
// — users.role_id names a role in another tenant, and restoring it would attach a
// foreign tenant's role, carrying permissions nobody granted here.
func TestInviteTenantAdmin_CrossTenantDoesNotRestoreForeignRole(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	tenantA, _ := newAdminTenant(t, f, "foreign-a")
	tenantB, _ := newAdminTenant(t, f, "foreign-b")
	appB := newTenantApp(t, f, tenantB, "foreign-b-app")

	// An ordinary user in tenant A, holding a real non-admin role there.
	u, err := f.svc.CreateUser(ctx, tenantA, nil, "worker@foreign.example", "Str0ngPass!", "W", "Orker", nil)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	userID := parseID(t, u.ID)

	var homeRoleID *int64
	if err = f.pool.QueryRow(ctx, `SELECT role_id FROM users WHERE id = $1`, userID).Scan(&homeRoleID); err != nil {
		t.Fatalf("read home role: %v", err)
	}

	// Invited as a co-owner of tenant B — a different tenant entirely.
	res, err := f.svc.InviteTenantAdmin(ctx, admin.InviteTenantAdminInput{
		TenantID: tenantB, Email: "worker@foreign.example",
		Role: auth.AdminRoleCoOwner, ApplicationIDs: []int64{appB},
	})
	if err != nil {
		t.Fatalf("InviteTenantAdmin(cross-tenant): %v", err)
	}

	// previous_role_id must be NULL: tenant A's role is not tenant B's to restore.
	var previousRoleID *int64
	if err = f.pool.QueryRow(ctx, `
		SELECT previous_role_id FROM tenant_admins WHERE id = $1
	`, parseID(t, res.Admin.ID)).Scan(&previousRoleID); err != nil {
		t.Fatalf("read previous_role_id: %v", err)
	}
	if previousRoleID != nil {
		t.Errorf("previous_role_id = %d, want NULL — a role from the home tenant (%v) must not be restorable in tenant %d",
			*previousRoleID, homeRoleID, tenantB)
	}
}

// TestCreateTenant_SameOwnerEmailReusesIdentity is the regression test for the
// path an operator actually walks: creating two tenants and naming the same owner.
//
// CreateTenant used to INSERT the owner blindly, with no lookup at all, so the
// second tenant minted a parallel account. That is what produced the reported
// symptom — two passwords both working, and each tenant unreachable from the
// other — and it is a different code path from InviteTenantAdmin, which had the
// same defect and was fixed separately.
func TestCreateTenant_SameOwnerEmailReusesIdentity(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()
	const owner = "shared-owner@createtenant.example"

	first, err := f.svc.CreateTenant(ctx, admin.CreateTenantInput{
		Name: "First Co", Slug: uniqueSlug("first"), OwnerEmail: owner,
	})
	if err != nil {
		t.Fatalf("CreateTenant(first): %v", err)
	}
	second, err := f.svc.CreateTenant(ctx, admin.CreateTenantInput{
		Name: "Second Co", Slug: uniqueSlug("second"), OwnerEmail: owner,
	})
	if err != nil {
		t.Fatalf("CreateTenant(second): %v", err)
	}

	// ONE identity. Two rows here is the duplicate-account bug: two password
	// hashes, two MFA enrolments, two audit histories for one person.
	var userRows int
	if err = f.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM users
		WHERE email = $1 AND application_id IS NULL AND deleted_at IS NULL
	`, owner).Scan(&userRows); err != nil {
		t.Fatalf("count owner rows: %v", err)
	}
	if userRows != 1 {
		t.Fatalf("users rows for %s = %d, want 1 — the second tenant must reuse the identity, not duplicate it", owner, userRows)
	}

	var userID int64
	if err = f.pool.QueryRow(ctx, `
		SELECT id FROM users WHERE email = $1 AND application_id IS NULL AND deleted_at IS NULL
	`, owner).Scan(&userID); err != nil {
		t.Fatalf("look up owner: %v", err)
	}

	// And that one identity owns BOTH tenants, in both models.
	firstID, secondID := parseID(t, first.Tenant.ID), parseID(t, second.Tenant.ID)
	for _, m := range []struct {
		table string
		query string
	}{
		{"tenant_admins", `SELECT tenant_id FROM tenant_admins WHERE user_id = $1 AND deleted_at IS NULL ORDER BY tenant_id`},
		{"admin_grants", `SELECT tenant_id FROM admin_grants WHERE user_id = $1 AND deleted_at IS NULL ORDER BY tenant_id`},
	} {
		rows, qErr := f.pool.Query(ctx, m.query, userID)
		if qErr != nil {
			t.Fatalf("query %s: %v", m.table, qErr)
		}
		var got []int64
		for rows.Next() {
			var tid int64
			if err = rows.Scan(&tid); err != nil {
				rows.Close()
				t.Fatalf("scan %s: %v", m.table, err)
			}
			got = append(got, tid)
		}
		rows.Close()
		if len(got) != 2 || got[0] != minID(firstID, secondID) || got[1] != maxID(firstID, secondID) {
			t.Errorf("%s for user %d = %v, want both %d and %d", m.table, userID, got, firstID, secondID)
		}
	}
}

// TestCreateTenant_SameOwnerKeepsOneCredential: the point of reusing the identity
// is that there is only ever one password to get wrong.
func TestCreateTenant_SameOwnerKeepsOneCredential(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()
	const owner = "one-password@createtenant.example"

	if _, err := f.svc.CreateTenant(ctx, admin.CreateTenantInput{
		Name: "Cred One", Slug: uniqueSlug("cred-one"), OwnerEmail: owner,
	}); err != nil {
		t.Fatalf("CreateTenant(first): %v", err)
	}
	if _, err := f.svc.CreateTenant(ctx, admin.CreateTenantInput{
		Name: "Cred Two", Slug: uniqueSlug("cred-two"), OwnerEmail: owner,
	}); err != nil {
		t.Fatalf("CreateTenant(second): %v", err)
	}

	// At most one credential row, ever — and zero here, because a freshly created
	// owner has no password until they accept the invitation.
	var creds int
	if err := f.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM user_credentials c
		JOIN users u ON u.id = c.user_id
		WHERE u.email = $1 AND u.deleted_at IS NULL
	`, owner).Scan(&creds); err != nil {
		t.Fatalf("count credentials: %v", err)
	}
	if creds > 1 {
		t.Errorf("credential rows for %s = %d; two passwords for one address is the reported bug", owner, creds)
	}
}

func uniqueSlug(prefix string) string {
	return prefix + "-" + strconv.FormatInt(time.Now().UnixNano(), 10)
}

func minID(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func maxID(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// TestListOwnedTenants_ReturnsEveryAdministeredTenant is the regression test for
// the symptom "I created three tenants but only see one".
//
// ListOwnedTenants used to resolve tenants by joining users.tenant_id — one row
// per users record. That was only ever right by accident: while a second tenant
// meant a second parallel account for the same address, three tenants produced
// three users rows and the join produced three tenants. Once duplicate identities
// were fixed (one person, one account, N grants) the same query returned exactly
// ONE tenant — the administrator's HOME tenant, where their credentials live,
// which says nothing about what they administer.
//
// It now reads admin_grants, which is the only table that answers reach.
func TestListOwnedTenants_ReturnsEveryAdministeredTenant(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()
	const owner = "three-tenants@owned.example"

	// Three tenants, one owner email — exactly the reported scenario.
	want := map[string]bool{}
	for _, name := range []string{"Owned One", "Owned Two", "Owned Three"} {
		res, err := f.svc.CreateTenant(ctx, admin.CreateTenantInput{
			Name: name, Slug: uniqueSlug("owned"), OwnerEmail: owner,
		})
		if err != nil {
			t.Fatalf("CreateTenant(%s): %v", name, err)
		}
		want[res.Tenant.ID] = true
	}

	// One identity, as the duplicate fix guarantees.
	var userRows int
	if err := f.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM users
		WHERE email = $1 AND application_id IS NULL AND deleted_at IS NULL
	`, owner).Scan(&userRows); err != nil {
		t.Fatalf("count users: %v", err)
	}
	if userRows != 1 {
		t.Fatalf("users rows = %d, want 1", userRows)
	}

	// CreateTenant leaves the grant PENDING until the invitation is accepted, and
	// an unaccepted grant is deliberately not reach — so activate them the way
	// acceptance does before asserting on the listing.
	if _, err := f.pool.Exec(ctx, `
		UPDATE admin_grants SET activated_at = NOW()
		WHERE user_id = (SELECT id FROM users WHERE email = $1 AND deleted_at IS NULL)
		  AND activated_at IS NULL
	`, owner); err != nil {
		t.Fatalf("activate grants: %v", err)
	}

	owned, err := f.svc.ListOwnedTenants(ctx, owner)
	if err != nil {
		t.Fatalf("ListOwnedTenants: %v", err)
	}
	if len(owned) != 3 {
		t.Fatalf("ListOwnedTenants returned %d tenant(s), want 3 — the home-tenant join is the bug", len(owned))
	}
	for _, got := range owned {
		if !want[got.ID] {
			t.Errorf("unexpected tenant %s (%s) in the listing", got.ID, got.Name)
		}
		if got.Role != auth.AdminRoleOwner {
			t.Errorf("tenant %s role = %q, want %q — the role must come from the grant, not users.role_id",
				got.Name, got.Role, auth.AdminRoleOwner)
		}
	}
}

// TestListOwnedTenants_ExcludesPendingGrants: a tenant the caller cannot yet enter
// must not be listed. Showing it produces a row that 403s when clicked.
func TestListOwnedTenants_ExcludesPendingGrants(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()
	const owner = "pending-only@owned.example"

	if _, err := f.svc.CreateTenant(ctx, admin.CreateTenantInput{
		Name: "Pending Co", Slug: uniqueSlug("pending"), OwnerEmail: owner,
	}); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}

	// Deliberately NOT activated: this is the state CreateTenant leaves behind
	// until the owner follows the emailed link.
	owned, err := f.svc.ListOwnedTenants(ctx, owner)
	if err != nil {
		t.Fatalf("ListOwnedTenants: %v", err)
	}
	if len(owned) != 0 {
		t.Errorf("ListOwnedTenants returned %d tenant(s) for an unaccepted invitation, want 0", len(owned))
	}
}

// ---------------------------------------------------------------------------
// An invitation may only ADD reach.
//
// The bug these pin: upsertTenantAdmin changed admin_role on ANY difference, in
// either direction. Inviting an existing OWNER as a co-owner of one application
// therefore wrote admin_role = 'co_owner', the grants mirror deleted their
// NULL-application row (the one that means "every application") in favour of an
// app-scoped row, and revokeAdminScopeTokens fired because live reach had
// narrowed. An owner who added themselves as a co-owner silently demoted
// themselves to a single application and was signed out — with no confirmation
// and no way back, since SetTenantAdminGrants refuses owners and no role-change
// endpoint exists.
// ---------------------------------------------------------------------------

// TestInviteTenantAdmin_OwnerCannotBeInvitedAsCoOwner is the regression test.
func TestInviteTenantAdmin_OwnerCannotBeInvitedAsCoOwner(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	tenantID, _ := newAdminTenant(t, f, "demote-guard")
	appID := newTenantApp(t, f, tenantID, "demote-guard-app")

	const email = "owner@demote-guard.example"
	if _, err := f.svc.InviteTenantAdmin(ctx, admin.InviteTenantAdminInput{
		TenantID: tenantID, Email: email, Role: auth.AdminRoleOwner,
	}); err != nil {
		t.Fatalf("InviteTenantAdmin(owner): %v", err)
	}

	// The exact action a verified owner performs when adding themselves as a
	// co-owner of one of their own applications.
	_, err := f.svc.InviteTenantAdmin(ctx, admin.InviteTenantAdminInput{
		TenantID: tenantID, Email: email,
		Role: auth.AdminRoleCoOwner, ApplicationIDs: []int64{appID},
	})
	if !errors.Is(err, admin.ErrInviteWouldDemote) {
		t.Fatalf("second invitation error = %v, want ErrInviteWouldDemote", err)
	}

	// The role must be untouched.
	var role string
	if err := f.pool.QueryRow(ctx, `
		SELECT ta.admin_role FROM tenant_admins ta
		JOIN users u ON u.id = ta.user_id
		WHERE ta.tenant_id = $1 AND u.email = $2 AND ta.deleted_at IS NULL
	`, tenantID, email).Scan(&role); err != nil {
		t.Fatalf("load admin_role: %v", err)
	}
	if role != auth.AdminRoleOwner {
		t.Errorf("admin_role = %q, want it left as owner", role)
	}

	// And so must the grant that carries "every application": exactly one row,
	// with application_id NULL. An app-scoped row here would mean the mirror had
	// already narrowed their reach.
	var grantCount, nullScoped int
	if err := f.pool.QueryRow(ctx, `
		SELECT count(*), count(*) FILTER (WHERE g.application_id IS NULL)
		FROM admin_grants g
		JOIN users u ON u.id = g.user_id
		WHERE g.tenant_id = $1 AND u.email = $2 AND g.deleted_at IS NULL
	`, tenantID, email).Scan(&grantCount, &nullScoped); err != nil {
		t.Fatalf("load admin_grants: %v", err)
	}
	if grantCount != 1 || nullScoped != 1 {
		t.Errorf("grants = %d rows (%d NULL-scoped), want exactly 1 NULL-scoped owner grant",
			grantCount, nullScoped)
	}
}

// TestInviteTenantAdmin_CoOwnerToOwnerStillWidens is the other direction, which
// must keep working: widening is the whole point of re-inviting somebody.
func TestInviteTenantAdmin_CoOwnerToOwnerStillWidens(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	tenantID, _ := newAdminTenant(t, f, "promote-ok")
	appID := newTenantApp(t, f, tenantID, "promote-ok-app")

	const email = "coowner@promote-ok.example"
	if _, err := f.svc.InviteTenantAdmin(ctx, admin.InviteTenantAdminInput{
		TenantID: tenantID, Email: email,
		Role: auth.AdminRoleCoOwner, ApplicationIDs: []int64{appID},
	}); err != nil {
		t.Fatalf("InviteTenantAdmin(co_owner): %v", err)
	}

	if _, err := f.svc.InviteTenantAdmin(ctx, admin.InviteTenantAdminInput{
		TenantID: tenantID, Email: email, Role: auth.AdminRoleOwner,
	}); err != nil {
		t.Fatalf("InviteTenantAdmin(promote to owner): %v", err)
	}

	var role string
	if err := f.pool.QueryRow(ctx, `
		SELECT ta.admin_role FROM tenant_admins ta
		JOIN users u ON u.id = ta.user_id
		WHERE ta.tenant_id = $1 AND u.email = $2 AND ta.deleted_at IS NULL
	`, tenantID, email).Scan(&role); err != nil {
		t.Fatalf("load admin_role: %v", err)
	}
	if role != auth.AdminRoleOwner {
		t.Errorf("admin_role = %q, want owner after promotion", role)
	}
}

// ---------------------------------------------------------------------------
// An already-active administrator is not re-invited when their grant widens.
//
// The bug these pin: InviteTenantAdmin sent an invitation unconditionally. For
// somebody who had already accepted and was actively administering, that mail
// gated nothing — upsertTenantAdmin never clears activated_at, so the wider role
// is live the moment it is written. It was also destructive: invite() runs
// "UPDATE user_invitations SET used_at = NOW() WHERE user_id = $1 AND used_at IS
// NULL" first, so promoting an active co-owner in one tenant silently consumed a
// genuine outstanding invitation they held for another, and minted a fresh claim
// token nobody needed.
//
// Re-instatement stays gated because removal soft-deletes the tenant_admins row:
// a re-invite therefore INSERTs a fresh row with activated_at NULL.
// ---------------------------------------------------------------------------

// TestInviteTenantAdmin_ActiveAdminWidenedWithoutReinvite is the regression test.
func TestInviteTenantAdmin_ActiveAdminWidenedWithoutReinvite(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	tenantID, _ := newAdminTenant(t, f, "widen-noinvite")
	appID := newTenantApp(t, f, tenantID, "widen-noinvite-app")

	const email = "coowner@widen-noinvite.example"
	created, err := f.svc.InviteTenantAdmin(ctx, admin.InviteTenantAdminInput{
		TenantID: tenantID, Email: email,
		Role: auth.AdminRoleCoOwner, ApplicationIDs: []int64{appID},
	})
	if err != nil {
		t.Fatalf("InviteTenantAdmin(co_owner): %v", err)
	}
	firstAdminID, err := strconv.ParseInt(created.Admin.ID, 10, 64)
	if err != nil {
		t.Fatalf("parse admin id: %v", err)
	}
	activateAdmin(t, f, firstAdminID)
	f.mail.Reset()

	res, err := f.svc.InviteTenantAdmin(ctx, admin.InviteTenantAdminInput{
		TenantID: tenantID, Email: email, Role: auth.AdminRoleOwner,
	})
	if err != nil {
		t.Fatalf("InviteTenantAdmin(promote): %v", err)
	}

	if res.InviteSent {
		t.Error("InviteSent = true, want false for an already-active administrator")
	}
	if got := len(f.mail.Invitations()); got != 0 {
		t.Errorf("invitation emails sent = %d, want 0", got)
	}

	// The promotion itself must still be immediate and live.
	var role string
	var active bool
	if err := f.pool.QueryRow(ctx, `
		SELECT ta.admin_role, ta.activated_at IS NOT NULL FROM tenant_admins ta
		JOIN users u ON u.id = ta.user_id
		WHERE ta.tenant_id = $1 AND u.email = $2 AND ta.deleted_at IS NULL
	`, tenantID, email).Scan(&role, &active); err != nil {
		t.Fatalf("load admin: %v", err)
	}
	if role != auth.AdminRoleOwner || !active {
		t.Errorf("admin = role %q active %v, want owner and still active", role, active)
	}

	// And the widened reach must be in admin_grants: one NULL-scoped owner row.
	var grants, nullScoped int
	if err := f.pool.QueryRow(ctx, `
		SELECT count(*), count(*) FILTER (WHERE g.application_id IS NULL)
		FROM admin_grants g JOIN users u ON u.id = g.user_id
		WHERE g.tenant_id = $1 AND u.email = $2 AND g.deleted_at IS NULL
	`, tenantID, email).Scan(&grants, &nullScoped); err != nil {
		t.Fatalf("load grants: %v", err)
	}
	if grants != 1 || nullScoped != 1 {
		t.Errorf("grants = %d rows (%d NULL-scoped), want 1 NULL-scoped owner grant", grants, nullScoped)
	}
}

// TestInviteTenantAdmin_WidenKeepsOtherTenantInvitationLive is the destructive
// half: the promotion must not consume an invitation outstanding elsewhere.
func TestInviteTenantAdmin_WidenKeepsOtherTenantInvitationLive(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	tenantA, _ := newAdminTenant(t, f, "widen-keep-a")
	appA := newTenantApp(t, f, tenantA, "widen-keep-a-app")
	tenantB, _ := newAdminTenant(t, f, "widen-keep-b")

	const email = "multi@widen-keep.example"
	createdA, err := f.svc.InviteTenantAdmin(ctx, admin.InviteTenantAdminInput{
		TenantID: tenantA, Email: email,
		Role: auth.AdminRoleCoOwner, ApplicationIDs: []int64{appA},
	})
	if err != nil {
		t.Fatalf("InviteTenantAdmin(tenant A co_owner): %v", err)
	}
	adminAID, err := strconv.ParseInt(createdA.Admin.ID, 10, 64)
	if err != nil {
		t.Fatalf("parse admin id: %v", err)
	}
	activateAdmin(t, f, adminAID)

	// A genuine, unaccepted invitation for tenant B.
	if _, err := f.svc.InviteTenantAdmin(ctx, admin.InviteTenantAdminInput{
		TenantID: tenantB, Email: email, Role: auth.AdminRoleOwner,
	}); err != nil {
		t.Fatalf("InviteTenantAdmin(tenant B owner): %v", err)
	}

	var liveBefore int
	if err := f.pool.QueryRow(ctx, `
		SELECT count(*) FROM user_invitations ui
		JOIN users u ON u.id = ui.user_id
		WHERE u.email = $1 AND ui.used_at IS NULL
	`, email).Scan(&liveBefore); err != nil {
		t.Fatalf("count invitations before: %v", err)
	}
	if liveBefore == 0 {
		t.Fatal("expected an outstanding invitation for tenant B before the promotion")
	}

	// Promote in tenant A, where they are already active.
	if _, err := f.svc.InviteTenantAdmin(ctx, admin.InviteTenantAdminInput{
		TenantID: tenantA, Email: email, Role: auth.AdminRoleOwner,
	}); err != nil {
		t.Fatalf("InviteTenantAdmin(promote in tenant A): %v", err)
	}

	var liveAfter int
	if err := f.pool.QueryRow(ctx, `
		SELECT count(*) FROM user_invitations ui
		JOIN users u ON u.id = ui.user_id
		WHERE u.email = $1 AND ui.used_at IS NULL
	`, email).Scan(&liveAfter); err != nil {
		t.Fatalf("count invitations after: %v", err)
	}
	if liveAfter != liveBefore {
		t.Errorf("live invitations = %d after the promotion, want %d unchanged — the tenant B invitation was consumed",
			liveAfter, liveBefore)
	}
}

// TestInviteTenantAdmin_ReinstatedAdminIsInvitedAgain guards the hole the
// unconditional send existed to close: a removed administrator must not be
// re-instated without their involvement.
func TestInviteTenantAdmin_ReinstatedAdminIsInvitedAgain(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	// The tenant's seeded owner is activated too, so removing the co-owner below
	// is not refused by the last-usable-owner guard — countUsableAdmins requires
	// activated_at, and a tenant whose only owner is still pending has none.
	tenantID, ownerAdminID := newAdminTenant(t, f, "reinstate")
	activateAdmin(t, f, ownerAdminID)
	appID := newTenantApp(t, f, tenantID, "reinstate-app")

	const email = "removed@reinstate.example"
	first, err := f.svc.InviteTenantAdmin(ctx, admin.InviteTenantAdminInput{
		TenantID: tenantID, Email: email,
		Role: auth.AdminRoleCoOwner, ApplicationIDs: []int64{appID},
	})
	if err != nil {
		t.Fatalf("InviteTenantAdmin: %v", err)
	}
	adminID, err := strconv.ParseInt(first.Admin.ID, 10, 64)
	if err != nil {
		t.Fatalf("parse admin id: %v", err)
	}
	activateAdmin(t, f, adminID)

	if err := f.svc.RemoveTenantAdmin(ctx, tenantID, adminID); err != nil {
		t.Fatalf("RemoveTenantAdmin: %v", err)
	}
	f.mail.Reset()

	// Re-inviting must produce a PENDING grant and a real invitation: removal
	// soft-deleted the row, so this INSERTs a fresh one with activated_at NULL.
	res, err := f.svc.InviteTenantAdmin(ctx, admin.InviteTenantAdminInput{
		TenantID: tenantID, Email: email,
		Role: auth.AdminRoleCoOwner, ApplicationIDs: []int64{appID},
	})
	if err != nil {
		t.Fatalf("InviteTenantAdmin(re-instate): %v", err)
	}
	if !res.InviteSent {
		t.Error("InviteSent = false, want true — a re-instated administrator must confirm")
	}
	if got := len(f.mail.Invitations()); got != 1 {
		t.Errorf("invitation emails sent = %d, want 1", got)
	}
	if res.Admin.Status != "pending_invitation" {
		t.Errorf("status = %q, want pending_invitation", res.Admin.Status)
	}
}
