package admin_test

import (
	"context"
	"errors"
	"testing"

	"github.com/engineersmind/emc-auth-server/internal/admin"
	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// The fixture service is built with a nil invitation service, so every call
// here reports invite_error rather than sending mail. That is deliberate: these
// tests are about the ownership model, and a tenant must be created (and an
// administrator recorded) even when mail is unavailable — that is precisely the
// case the break-glass path exists for.

// newAdminTenant creates a tenant through CreateTenant and returns its id plus
// the id of the tenant_admins row seeded for the owner.
func newAdminTenant(t *testing.T, f adminFixture, slug string) (tenantID, adminID int64) {
	t.Helper()
	ctx := context.Background()
	res, err := f.svc.CreateTenant(ctx, admin.CreateTenantInput{
		Name:       slug,
		Slug:       slug,
		OwnerEmail: "owner-" + slug + "@example.com",
	})
	if err != nil {
		t.Fatalf("CreateTenant(%s): %v", slug, err)
	}
	tenantID = parseID(t, res.Tenant.ID)
	if err := f.pool.QueryRow(ctx,
		`SELECT id FROM tenant_admins WHERE tenant_id = $1 AND deleted_at IS NULL`, tenantID,
	).Scan(&adminID); err != nil {
		t.Fatalf("fetch seeded owner admin row: %v", err)
	}
	return tenantID, adminID
}

// newTenantApp creates an application inside a tenant and returns its row id.
func newTenantApp(t *testing.T, f adminFixture, tenantID int64, name string) int64 {
	t.Helper()
	var id int64
	err := f.pool.QueryRow(context.Background(), `
		INSERT INTO oauth_clients (tenant_id, client_id, client_secret_hash, name, redirect_uris)
		VALUES ($1, $2, 'x', $3, ARRAY['https://example.test/cb'])
		RETURNING id
	`, tenantID, name+"-client", name).Scan(&id)
	if err != nil {
		t.Fatalf("create application %s: %v", name, err)
	}
	return id
}

func TestCreateTenant_SeedsOwnerWithoutPassword(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	res, err := f.svc.CreateTenant(ctx, admin.CreateTenantInput{
		Name: "Invited Co", Slug: "invited-co", OwnerEmail: "owner@invited.example",
	})
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	if res.Owner.Status != admin.OwnerStatusPendingInvitation {
		t.Errorf("owner status = %q, want %q", res.Owner.Status, admin.OwnerStatusPendingInvitation)
	}

	tenantID := parseID(t, res.Tenant.ID)
	userID := parseID(t, res.Owner.ID)

	// The account must have no credentials: the invitation link is the only
	// way in, which is what makes following it proof of inbox control.
	var creds int
	if err := f.pool.QueryRow(ctx,
		`SELECT count(*) FROM user_credentials WHERE user_id = $1`, userID,
	).Scan(&creds); err != nil {
		t.Fatalf("count credentials: %v", err)
	}
	if creds != 0 {
		t.Errorf("owner has %d credential rows, want 0 before the invitation is accepted", creds)
	}

	var verified bool
	if err := f.pool.QueryRow(ctx, `SELECT email_verified FROM users WHERE id = $1`, userID).Scan(&verified); err != nil {
		t.Fatalf("read email_verified: %v", err)
	}
	if verified {
		t.Error("owner email is verified before anyone proved control of the inbox")
	}

	// The administration row and the tenant's primary pointer must both exist.
	var adminID, primaryID int64
	var role string
	if err := f.pool.QueryRow(ctx,
		`SELECT id, admin_role FROM tenant_admins WHERE tenant_id = $1 AND deleted_at IS NULL`, tenantID,
	).Scan(&adminID, &role); err != nil {
		t.Fatalf("fetch tenant_admins row: %v", err)
	}
	if role != auth.AdminRoleOwner {
		t.Errorf("admin_role = %q, want %q", role, auth.AdminRoleOwner)
	}
	if err := f.pool.QueryRow(ctx, `SELECT primary_admin_id FROM tenants WHERE id = $1`, tenantID).Scan(&primaryID); err != nil {
		t.Fatalf("fetch primary_admin_id: %v", err)
	}
	if primaryID != adminID {
		t.Errorf("primary_admin_id = %d, want the seeded owner %d", primaryID, adminID)
	}
}

func TestInviteTenantAdmin_CoOwnerGetsOnlyGrantedApplications(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()
	tenantID, _ := newAdminTenant(t, f, "grants-co")
	appA := newTenantApp(t, f, tenantID, "app-a")
	newTenantApp(t, f, tenantID, "app-b")

	res, err := f.svc.InviteTenantAdmin(ctx, admin.InviteTenantAdminInput{
		TenantID:       tenantID,
		Email:          "co@grants.example",
		Role:           auth.AdminRoleCoOwner,
		ApplicationIDs: []int64{appA},
	})
	if err != nil {
		t.Fatalf("InviteTenantAdmin: %v", err)
	}
	if res.Action != "invited" {
		t.Errorf("action = %q, want %q", res.Action, "invited")
	}
	if len(res.Admin.Applications) != 1 {
		t.Fatalf("applications = %v, want exactly the one granted", res.Admin.Applications)
	}
	if res.Admin.Status != "pending_invitation" {
		t.Errorf("status = %q, want pending_invitation", res.Admin.Status)
	}
}

func TestInviteTenantAdmin_OwnerHoldsNoGrants(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()
	tenantID, _ := newAdminTenant(t, f, "owner-grants")
	appA := newTenantApp(t, f, tenantID, "og-app")

	// "Absence means all": granting an owner specific applications is not a
	// narrower owner, it is a contradiction.
	_, err := f.svc.InviteTenantAdmin(ctx, admin.InviteTenantAdminInput{
		TenantID: tenantID, Email: "o2@grants.example",
		Role: auth.AdminRoleOwner, ApplicationIDs: []int64{appA},
	})
	if !errors.Is(err, admin.ErrGrantsForOwner) {
		t.Errorf("error = %v, want ErrGrantsForOwner", err)
	}

	res, err := f.svc.InviteTenantAdmin(ctx, admin.InviteTenantAdminInput{
		TenantID: tenantID, Email: "o2@grants.example", Role: auth.AdminRoleOwner,
	})
	if err != nil {
		t.Fatalf("InviteTenantAdmin(owner): %v", err)
	}
	if len(res.Admin.Applications) != 0 {
		t.Errorf("applications = %v, want empty for an owner", res.Admin.Applications)
	}
}

func TestInviteTenantAdmin_CoOwnerRequiresAtLeastOneApplication(t *testing.T) {
	f := newAdminFixture(t)
	tenantID, _ := newAdminTenant(t, f, "empty-grants")

	// Empty grants fail closed, so this could only create an administrator who
	// can reach nothing.
	_, err := f.svc.InviteTenantAdmin(context.Background(), admin.InviteTenantAdminInput{
		TenantID: tenantID, Email: "nobody@grants.example", Role: auth.AdminRoleCoOwner,
	})
	if !errors.Is(err, admin.ErrGrantsRequired) {
		t.Errorf("error = %v, want ErrGrantsRequired", err)
	}
}

func TestInviteTenantAdmin_RejectsApplicationOfAnotherTenant(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()
	tenantA, _ := newAdminTenant(t, f, "cross-a")
	tenantB, _ := newAdminTenant(t, f, "cross-b")
	appB := newTenantApp(t, f, tenantB, "cross-app-b")

	_, err := f.svc.InviteTenantAdmin(ctx, admin.InviteTenantAdminInput{
		TenantID: tenantA, Email: "x@cross.example",
		Role: auth.AdminRoleCoOwner, ApplicationIDs: []int64{appB},
	})
	if !errors.Is(err, admin.ErrUnknownApplication) {
		t.Errorf("error = %v, want ErrUnknownApplication", err)
	}
}

func TestInviteTenantAdmin_PromotesExistingTenantUserInPlace(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()
	tenantID, _ := newAdminTenant(t, f, "promote")
	appA := newTenantApp(t, f, tenantID, "promote-app")

	u, err := f.svc.CreateUser(ctx, tenantID, nil, "existing@promote.example", "Str0ngPass!", "Ex", "Isting", nil)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	existingID := parseID(t, u.ID)

	res, err := f.svc.InviteTenantAdmin(ctx, admin.InviteTenantAdminInput{
		TenantID: tenantID, Email: "existing@promote.example",
		Role: auth.AdminRoleCoOwner, ApplicationIDs: []int64{appA},
	})
	if err != nil {
		t.Fatalf("InviteTenantAdmin: %v", err)
	}
	if res.Action != "grants_added" {
		t.Errorf("action = %q, want grants_added", res.Action)
	}

	// One identity, not two: a second users row would mean a second password
	// and a split audit trail for one person.
	var n int
	if err := f.pool.QueryRow(ctx, `
		SELECT count(*) FROM users
		WHERE tenant_id = $1 AND email = 'existing@promote.example' AND application_id IS NULL AND deleted_at IS NULL
	`, tenantID).Scan(&n); err != nil {
		t.Fatalf("count users: %v", err)
	}
	if n != 1 {
		t.Errorf("tenant-level rows for the address = %d, want 1", n)
	}
	if parseID(t, res.Admin.ID) == existingID {
		t.Error("admin id should be the tenant_admins row id, not the users id")
	}
}

func TestInviteTenantAdmin_ApplicationUserWithSameEmailDoesNotCollide(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()
	tenantID, _ := newAdminTenant(t, f, "no-collide")
	appA := newTenantApp(t, f, tenantID, "collide-app")

	// The same person as a customer of the application...
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO users (tenant_id, email, application_id, is_active)
		VALUES ($1, 'both@collide.example', $2, true)
	`, tenantID, appA); err != nil {
		t.Fatalf("seed application user: %v", err)
	}

	// ...must not block them from administering the tenant. Different rows,
	// different unique indexes, deliberately independent identities.
	res, err := f.svc.InviteTenantAdmin(ctx, admin.InviteTenantAdminInput{
		TenantID: tenantID, Email: "both@collide.example",
		Role: auth.AdminRoleCoOwner, ApplicationIDs: []int64{appA},
	})
	if err != nil {
		t.Fatalf("InviteTenantAdmin: %v", err)
	}
	if res.Action != "invited" {
		t.Errorf("action = %q, want invited (a fresh tenant-level identity)", res.Action)
	}
}

func TestInviteTenantAdmin_UnchangedInvitationIsRefused(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()
	tenantID, _ := newAdminTenant(t, f, "already")
	appA := newTenantApp(t, f, tenantID, "already-app")

	u, err := f.svc.CreateUser(ctx, tenantID, nil, "dup@already.example", "Str0ngPass!", "D", "Up", nil)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	// Mark verified so the second call is a pure no-op rather than a resend.
	if _, err := f.pool.Exec(ctx, `UPDATE users SET email_verified = true WHERE id = $1`, parseID(t, u.ID)); err != nil {
		t.Fatalf("verify user: %v", err)
	}

	in := admin.InviteTenantAdminInput{
		TenantID: tenantID, Email: "dup@already.example",
		Role: auth.AdminRoleCoOwner, ApplicationIDs: []int64{appA},
	}
	if _, err := f.svc.InviteTenantAdmin(ctx, in); err != nil {
		t.Fatalf("first InviteTenantAdmin: %v", err)
	}
	if _, err := f.svc.InviteTenantAdmin(ctx, in); !errors.Is(err, admin.ErrAlreadyAdmin) {
		t.Errorf("second invite error = %v, want ErrAlreadyAdmin", err)
	}
}

func TestSetTenantAdminGrants_ReplacesAndBumpsTokenVersion(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()
	tenantID, _ := newAdminTenant(t, f, "regrant")
	appA := newTenantApp(t, f, tenantID, "regrant-a")
	appB := newTenantApp(t, f, tenantID, "regrant-b")

	res, err := f.svc.InviteTenantAdmin(ctx, admin.InviteTenantAdminInput{
		TenantID: tenantID, Email: "re@grant.example",
		Role: auth.AdminRoleCoOwner, ApplicationIDs: []int64{appA},
	})
	if err != nil {
		t.Fatalf("InviteTenantAdmin: %v", err)
	}
	adminID := parseID(t, res.Admin.ID)

	var before int
	if err := f.pool.QueryRow(ctx,
		`SELECT token_version FROM users u JOIN tenant_admins ta ON ta.user_id = u.id WHERE ta.id = $1`, adminID,
	).Scan(&before); err != nil {
		t.Fatalf("read token_version: %v", err)
	}

	got, err := f.svc.SetTenantAdminGrants(ctx, tenantID, adminID, []int64{appB})
	if err != nil {
		t.Fatalf("SetTenantAdminGrants: %v", err)
	}
	if len(got.Applications) != 1 {
		t.Fatalf("applications = %v, want exactly the replacement", got.Applications)
	}

	// Revoking a grant must not stay usable until the access token expires.
	var after int
	if err := f.pool.QueryRow(ctx,
		`SELECT token_version FROM users u JOIN tenant_admins ta ON ta.user_id = u.id WHERE ta.id = $1`, adminID,
	).Scan(&after); err != nil {
		t.Fatalf("read token_version: %v", err)
	}
	if after <= before {
		t.Errorf("token_version = %d, want greater than %d so live tokens are invalidated", after, before)
	}

	// Emptying the set is not how administration is withdrawn.
	if _, err := f.svc.SetTenantAdminGrants(ctx, tenantID, adminID, nil); !errors.Is(err, admin.ErrGrantsRequired) {
		t.Errorf("empty grants error = %v, want ErrGrantsRequired", err)
	}
}

func TestRemoveTenantAdmin_LastUsableOwnerIsProtected(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()
	tenantID, ownerAdminID := newAdminTenant(t, f, "last-owner")

	// The seeded owner has not accepted their invitation, so they are not
	// usable — but they are still the only owner, and removing them would leave
	// none at all.
	if err := f.svc.RemoveTenantAdmin(ctx, tenantID, ownerAdminID); !errors.Is(err, admin.ErrLastOwner) {
		t.Fatalf("remove sole owner error = %v, want ErrLastOwner", err)
	}

	// A second owner who has also not accepted changes nothing: counting
	// pending owners would let a tenant end up with two administrators and
	// nobody who can sign in.
	second, err := f.svc.InviteTenantAdmin(ctx, admin.InviteTenantAdminInput{
		TenantID: tenantID, Email: "second@last.example", Role: auth.AdminRoleOwner,
	})
	if err != nil {
		t.Fatalf("InviteTenantAdmin(second owner): %v", err)
	}
	if err := f.svc.RemoveTenantAdmin(ctx, tenantID, ownerAdminID); !errors.Is(err, admin.ErrLastOwner) {
		t.Errorf("remove with only pending owners error = %v, want ErrLastOwner", err)
	}

	// Once the second owner is usable — confirmed AND verified — the first may go.
	// Confirmation is what makes a grant count; verification alone does not,
	// because an unconfirmed grant carries no role and so no authority.
	if _, err := f.pool.Exec(ctx, `
		UPDATE users SET email_verified = true
		WHERE id = (SELECT user_id FROM tenant_admins WHERE id = $1)
	`, parseID(t, second.Admin.ID)); err != nil {
		t.Fatalf("verify second owner: %v", err)
	}
	if err := f.svc.RemoveTenantAdmin(ctx, tenantID, ownerAdminID); !errors.Is(err, admin.ErrLastOwner) {
		t.Errorf("remove with a verified but unconfirmed owner = %v, want ErrLastOwner", err)
	}
	if _, err := f.pool.Exec(ctx,
		`UPDATE tenant_admins SET activated_at = NOW() WHERE id = $1`, parseID(t, second.Admin.ID),
	); err != nil {
		t.Fatalf("confirm second owner: %v", err)
	}
	if err := f.svc.RemoveTenantAdmin(ctx, tenantID, ownerAdminID); err != nil {
		t.Errorf("remove with a usable owner remaining: %v", err)
	}

	// The identity survives the loss of the role — audit history belongs to the
	// person, not to their administrative status.
	var users int
	if err := f.pool.QueryRow(ctx,
		`SELECT count(*) FROM users WHERE tenant_id = $1 AND email = 'owner-last-owner@example.com' AND deleted_at IS NULL`,
		tenantID,
	).Scan(&users); err != nil {
		t.Fatalf("count users: %v", err)
	}
	if users != 1 {
		t.Errorf("user rows after removal = %d, want the account to survive", users)
	}
}

func TestRemoveTenantAdmin_CoOwnerRemovalIsUnrestricted(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()
	tenantID, _ := newAdminTenant(t, f, "free-remove")
	appA := newTenantApp(t, f, tenantID, "free-app")

	res, err := f.svc.InviteTenantAdmin(ctx, admin.InviteTenantAdminInput{
		TenantID: tenantID, Email: "co@free.example",
		Role: auth.AdminRoleCoOwner, ApplicationIDs: []int64{appA},
	})
	if err != nil {
		t.Fatalf("InviteTenantAdmin: %v", err)
	}
	// Zero co-owners is legal — the tenant owner is always the escalation path,
	// so there is nothing to protect here.
	if err := f.svc.RemoveTenantAdmin(ctx, tenantID, parseID(t, res.Admin.ID)); err != nil {
		t.Errorf("RemoveTenantAdmin(co-owner): %v", err)
	}
}

func TestRemoveTenantAdmin_StripsTheAdministrativeRole(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()
	tenantID, _ := newAdminTenant(t, f, "role-leak")
	appA := newTenantApp(t, f, tenantID, "leak-app")

	res, err := f.svc.InviteTenantAdmin(ctx, admin.InviteTenantAdminInput{
		TenantID: tenantID, Email: "leak@acme.example",
		Role: auth.AdminRoleCoOwner, ApplicationIDs: []int64{appA},
	})
	if err != nil {
		t.Fatalf("InviteTenantAdmin: %v", err)
	}
	adminID := parseID(t, res.Admin.ID)

	if err := f.svc.RemoveTenantAdmin(ctx, tenantID, adminID); err != nil {
		t.Fatalf("RemoveTenantAdmin: %v", err)
	}

	// Removal soft-deletes the tenant_admins row, so loadAdminScope stops
	// finding one and the token is issued with no admin_scope. But an absent
	// scope is treated as TENANT-WIDE on tenant-level routes (a token predating
	// the claim must keep working), so leaving the RBAC role attached would let
	// a removed co-owner sign back in with more authority than they had —
	// users:write and friends across the whole tenant.
	var roleName *string
	if err := f.pool.QueryRow(ctx, `
		SELECT r.name FROM users u LEFT JOIN roles r ON r.id = u.role_id
		WHERE u.email = 'leak@acme.example' AND u.tenant_id = $1 AND u.application_id IS NULL
	`, tenantID).Scan(&roleName); err != nil {
		t.Fatalf("read role after removal: %v", err)
	}
	if roleName != nil {
		t.Errorf("removed administrator still holds role %q; they keep every admin permission", *roleName)
	}
}

func TestInviteTenantAdmin_ReAddAfterRemovalRestoresAccess(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()
	tenantID, _ := newAdminTenant(t, f, "re-add")
	appA := newTenantApp(t, f, tenantID, "re-add-app")

	in := admin.InviteTenantAdminInput{
		TenantID: tenantID, Email: "again@acme.example",
		Role: auth.AdminRoleCoOwner, ApplicationIDs: []int64{appA},
	}
	first, err := f.svc.InviteTenantAdmin(ctx, in)
	if err != nil {
		t.Fatalf("first InviteTenantAdmin: %v", err)
	}
	if err := f.svc.RemoveTenantAdmin(ctx, tenantID, parseID(t, first.Admin.ID)); err != nil {
		t.Fatalf("RemoveTenantAdmin: %v", err)
	}

	// Re-adding must work — the soft-deleted row must not collide.
	second, err := f.svc.InviteTenantAdmin(ctx, in)
	if err != nil {
		t.Fatalf("second InviteTenantAdmin: %v", err)
	}
	if second.Admin.Role != auth.AdminRoleCoOwner || len(second.Admin.Applications) != 1 {
		t.Errorf("re-added admin = %+v, want a co-owner with one application", second.Admin)
	}

	// ...but it must NOT hand back any authority. This is the whole point: an
	// operator re-instating a removed administrator cannot make it effective on
	// their own. No role, so no permissions; the grant waits for the recipient
	// to confirm it by email.
	var roleName string
	if err := f.pool.QueryRow(ctx, `
		SELECT COALESCE(r.name, '') FROM users u LEFT JOIN roles r ON r.id = u.role_id
		WHERE u.email = 'again@acme.example' AND u.tenant_id = $1 AND u.application_id IS NULL
	`, tenantID).Scan(&roleName); err != nil {
		t.Fatalf("read role after re-add: %v", err)
	}
	if roleName != "" {
		t.Errorf("re-added administrator already holds role %q before confirming", roleName)
	}

	var activated *string
	if err := f.pool.QueryRow(ctx,
		`SELECT activated_at::text FROM tenant_admins WHERE id = $1`, parseID(t, second.Admin.ID),
	).Scan(&activated); err != nil {
		t.Fatalf("read activated_at: %v", err)
	}
	if activated != nil {
		t.Errorf("activated_at = %q, want NULL until the grant is confirmed", *activated)
	}
	if second.Admin.Status != "pending_invitation" {
		t.Errorf("status = %q, want pending_invitation", second.Admin.Status)
	}
}

func TestInviteTenantAdmin_PromotionGrantsNothingUntilConfirmed(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()
	tenantID, _ := newAdminTenant(t, f, "pending-grant")
	appA := newTenantApp(t, f, tenantID, "pending-app")

	// An existing, fully working tenant user — verified, with a password. This is
	// the case that used to take effect immediately.
	u, err := f.svc.CreateUser(ctx, tenantID, nil, "member@pending.example", "Str0ngPass!", "Mem", "Ber", nil)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	userID := parseID(t, u.ID)
	if _, err := f.pool.Exec(ctx, `UPDATE users SET email_verified = true WHERE id = $1`, userID); err != nil {
		t.Fatalf("verify user: %v", err)
	}
	var roleBefore *int64
	if err := f.pool.QueryRow(ctx, `SELECT role_id FROM users WHERE id = $1`, userID).Scan(&roleBefore); err != nil {
		t.Fatalf("read role before: %v", err)
	}

	res, err := f.svc.InviteTenantAdmin(ctx, admin.InviteTenantAdminInput{
		TenantID: tenantID, Email: "member@pending.example",
		Role: auth.AdminRoleCoOwner, ApplicationIDs: []int64{appA},
	})
	if err != nil {
		t.Fatalf("InviteTenantAdmin: %v", err)
	}

	// Their permissions are untouched — they hold exactly what they held before.
	var roleAfter *int64
	if err := f.pool.QueryRow(ctx, `SELECT role_id FROM users WHERE id = $1`, userID).Scan(&roleAfter); err != nil {
		t.Fatalf("read role after: %v", err)
	}
	if (roleBefore == nil) != (roleAfter == nil) || (roleBefore != nil && *roleBefore != *roleAfter) {
		t.Errorf("role changed on invite: before=%v after=%v; a grant must carry no authority until confirmed", roleBefore, roleAfter)
	}
	if res.Admin.Status != "pending_invitation" {
		t.Errorf("status = %q, want pending_invitation", res.Admin.Status)
	}
}

func TestListTenantAdmins_ReportsRoleGrantsAndPrimary(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()
	tenantID, ownerAdminID := newAdminTenant(t, f, "listing")
	appA := newTenantApp(t, f, tenantID, "listing-app")

	if _, err := f.svc.InviteTenantAdmin(ctx, admin.InviteTenantAdminInput{
		TenantID: tenantID, Email: "co@listing.example",
		Role: auth.AdminRoleCoOwner, ApplicationIDs: []int64{appA},
	}); err != nil {
		t.Fatalf("InviteTenantAdmin: %v", err)
	}

	admins, err := f.svc.ListTenantAdmins(ctx, tenantID)
	if err != nil {
		t.Fatalf("ListTenantAdmins: %v", err)
	}
	if len(admins) != 2 {
		t.Fatalf("administrators = %d, want 2", len(admins))
	}
	for _, a := range admins {
		switch a.Role {
		case auth.AdminRoleOwner:
			if len(a.Applications) != 0 {
				t.Errorf("owner applications = %v, want empty", a.Applications)
			}
			if !a.IsPrimary || parseID(t, a.ID) != ownerAdminID {
				t.Errorf("owner %s: is_primary = %v, want the seeded owner to be primary", a.ID, a.IsPrimary)
			}
		case auth.AdminRoleCoOwner:
			if len(a.Applications) != 1 {
				t.Errorf("co-owner applications = %v, want one", a.Applications)
			}
			if a.IsPrimary {
				t.Error("co-owner must not be the primary administrator")
			}
		default:
			t.Errorf("unexpected role %q", a.Role)
		}
	}
}
