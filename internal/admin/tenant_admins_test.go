package admin_test

import (
	"context"
	"errors"
	"testing"

	"github.com/engineersmind/emc-auth-server/internal/admin"
	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// The fixture wires a real invitation service over a recording mailer, so these
// tests exercise the delivery path rather than stepping around it. They have to:
// CreateTenant and InviteTenantAdmin both refuse outright when no invitation
// service is configured, because the invitation is the only route to a password
// for the account they create, and a 201 for an account nobody can sign in to is
// worse than a failure the operator can act on.

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
	// Consume the invitation the first call sent, so the second is a pure no-op
	// rather than a resend. With one still outstanding the second call is a
	// legitimate resend and is answered as such — covered separately by
	// TestInviteTenantAdmin_ResendIsRateLimitedPerRecipient.
	if _, err := f.pool.Exec(ctx,
		`UPDATE user_invitations SET used_at = NOW() WHERE user_id = $1`, parseID(t, u.ID),
	); err != nil {
		t.Fatalf("consume invitation: %v", err)
	}
	if _, err := f.svc.InviteTenantAdmin(ctx, in); !errors.Is(err, admin.ErrAlreadyAdmin) {
		t.Errorf("second invite error = %v, want ErrAlreadyAdmin", err)
	}
}

// A resend changes nothing but the mail, so the mail is the whole of its effect
// and the only thing worth bounding. Without this an owner can drive unlimited
// invitations at one external address.
func TestInviteTenantAdmin_ResendIsRateLimitedPerRecipient(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()
	tenantID, _ := newAdminTenant(t, f, "resend")
	appA := newTenantApp(t, f, tenantID, "resend-app")

	in := admin.InviteTenantAdminInput{
		TenantID: tenantID, Email: "co@resend.example",
		Role: auth.AdminRoleCoOwner, ApplicationIDs: []int64{appA},
	}
	first, err := f.svc.InviteTenantAdmin(ctx, in)
	if err != nil {
		t.Fatalf("first InviteTenantAdmin: %v", err)
	}
	if !first.InviteSent {
		t.Fatalf("first invite was not sent: %s", first.InviteError)
	}

	// Same input again: nothing to change, invitation still outstanding, so this
	// is a resend — and it lands inside the cooldown.
	if _, err := f.svc.InviteTenantAdmin(ctx, in); !errors.Is(err, admin.ErrInviteCooldown) {
		t.Fatalf("immediate resend error = %v, want ErrInviteCooldown", err)
	}

	// Exactly one invitation was delivered. The refusal must not have sent a
	// second one, and must not have consumed the live token either — the
	// recipient's link has to keep working.
	// Counted per recipient: the fixture's tenant owner was also invited through
	// this mailer, so a bare total would conflate the two.
	if got := invitationsTo(f, "co@resend.example"); got != 1 {
		t.Errorf("invitations delivered to the co-owner = %d, want 1", got)
	}
	var live int
	if err := f.pool.QueryRow(ctx, `
		SELECT count(*) FROM user_invitations
		WHERE user_id = (SELECT user_id FROM tenant_admins WHERE id = $1)
		  AND used_at IS NULL AND expires_at > NOW()
	`, parseID(t, first.Admin.ID)).Scan(&live); err != nil {
		t.Fatalf("count live invitations: %v", err)
	}
	if live != 1 {
		t.Errorf("live invitations after a refused resend = %d, want the original to survive", live)
	}

	// Once the cooldown has passed the resend goes through. Backdating the
	// invitation is how the clock is moved without sleeping through it.
	if _, err := f.pool.Exec(ctx, `
		UPDATE user_invitations SET created_at = NOW() - INTERVAL '10 minutes'
		WHERE user_id = (SELECT user_id FROM tenant_admins WHERE id = $1)
	`, parseID(t, first.Admin.ID)); err != nil {
		t.Fatalf("backdate invitation: %v", err)
	}
	res, err := f.svc.InviteTenantAdmin(ctx, in)
	if err != nil {
		t.Fatalf("resend after the cooldown: %v", err)
	}
	if res.Action != "invitation_resent" {
		t.Errorf("action = %q, want invitation_resent", res.Action)
	}
	if got := invitationsTo(f, "co@resend.example"); got != 2 {
		t.Errorf("invitations delivered to the co-owner = %d, want 2", got)
	}
}

// invitationsTo counts the invitations the fixture's mailer was asked to deliver
// to one address.
func invitationsTo(f adminFixture, email string) int {
	n := 0
	for _, m := range f.mail.Invitations() {
		if m.To == email {
			n++
		}
	}
	return n
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

func TestRemoveTenantAdmin_PendingCoOwnerRemovalIsUnrestricted(t *testing.T) {
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
	// Zero co-owners is legal, and withdrawing a co-owner who never accepted is
	// always legal: they could not sign in, so removing them takes nothing away
	// from the tenant. Refusing this would make a mistyped invitation
	// unretractable precisely when the owner has not accepted either.
	if err := f.svc.RemoveTenantAdmin(ctx, tenantID, parseID(t, res.Admin.ID)); err != nil {
		t.Errorf("RemoveTenantAdmin(pending co-owner): %v", err)
	}
}

// A tenant must never be emptied of administrators who can actually sign in,
// and the owner-only guard does not cover this shape: the sole owner never
// accepted, so the activated co-owner is the only way into the tenant. Removing
// them used to succeed and strand it beyond the reach of every endpoint.
func TestRemoveTenantAdmin_ActivatedCoOwnerIsProtectedWhenNoOwnerIsUsable(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()
	tenantID, _ := newAdminTenant(t, f, "strand")
	appA := newTenantApp(t, f, tenantID, "strand-app")

	res, err := f.svc.InviteTenantAdmin(ctx, admin.InviteTenantAdminInput{
		TenantID: tenantID, Email: "co@strand.example",
		Role: auth.AdminRoleCoOwner, ApplicationIDs: []int64{appA},
	})
	if err != nil {
		t.Fatalf("InviteTenantAdmin: %v", err)
	}
	coAdminID := parseID(t, res.Admin.ID)

	// Make the co-owner usable — accepted and verified — while the seeded owner
	// stays pending. The tenant is now administered by this person alone.
	if _, err := f.pool.Exec(ctx, `
		UPDATE tenant_admins SET activated_at = NOW() WHERE id = $1
	`, coAdminID); err != nil {
		t.Fatalf("activate co-owner: %v", err)
	}
	if _, err := f.pool.Exec(ctx, `
		UPDATE users SET email_verified = true
		WHERE id = (SELECT user_id FROM tenant_admins WHERE id = $1)
	`, coAdminID); err != nil {
		t.Fatalf("verify co-owner: %v", err)
	}

	if err := f.svc.RemoveTenantAdmin(ctx, tenantID, coAdminID); !errors.Is(err, admin.ErrLastOwner) {
		t.Fatalf("remove the only usable administrator = %v, want ErrLastOwner", err)
	}

	// The row must survive the refusal: a guard that rolls back partially would
	// leave the tenant administered by a soft-deleted administrator.
	var live int
	if err := f.pool.QueryRow(ctx,
		`SELECT count(*) FROM tenant_admins WHERE id = $1 AND deleted_at IS NULL`, coAdminID,
	).Scan(&live); err != nil {
		t.Fatalf("count live admin rows: %v", err)
	}
	if live != 1 {
		t.Errorf("live tenant_admins rows after a refused removal = %d, want 1", live)
	}

	// Once an owner can sign in, the co-owner may go: the tenant is no longer
	// depending on them.
	var ownerAdminID int64
	if err := f.pool.QueryRow(ctx, `
		SELECT id FROM tenant_admins
		WHERE tenant_id = $1 AND admin_role = $2 AND deleted_at IS NULL
	`, tenantID, auth.AdminRoleOwner).Scan(&ownerAdminID); err != nil {
		t.Fatalf("fetch owner admin row: %v", err)
	}
	if _, err := f.pool.Exec(ctx, `
		UPDATE tenant_admins SET activated_at = NOW() WHERE id = $1
	`, ownerAdminID); err != nil {
		t.Fatalf("activate owner: %v", err)
	}
	if _, err := f.pool.Exec(ctx, `
		UPDATE users SET email_verified = true
		WHERE id = (SELECT user_id FROM tenant_admins WHERE id = $1)
	`, ownerAdminID); err != nil {
		t.Fatalf("verify owner: %v", err)
	}
	if err := f.svc.RemoveTenantAdmin(ctx, tenantID, coAdminID); err != nil {
		t.Errorf("remove co-owner with a usable owner present: %v", err)
	}
}

// Withdrawing administration must end the sessions that still carry it.
//
// The token_version bump alone does not: nothing in this codebase reads that
// counter at verification time, so it marks the account without invalidating
// anything. Revoking the refresh tokens is what stops the removed administrator
// rotating their way to a fresh access token — indefinitely, since each rotation
// re-mints from the session rather than the original login.
func TestRemoveTenantAdmin_RevokesLiveSessions(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()
	tenantID, _ := newAdminTenant(t, f, "revoke-sess")
	appA := newTenantApp(t, f, tenantID, "revoke-app")

	res, err := f.svc.InviteTenantAdmin(ctx, admin.InviteTenantAdminInput{
		TenantID: tenantID, Email: "co@revoke.example",
		Role: auth.AdminRoleCoOwner, ApplicationIDs: []int64{appA},
	})
	if err != nil {
		t.Fatalf("InviteTenantAdmin: %v", err)
	}
	adminID := parseID(t, res.Admin.ID)

	var userID int64
	if err := f.pool.QueryRow(ctx,
		`SELECT user_id FROM tenant_admins WHERE id = $1`, adminID,
	).Scan(&userID); err != nil {
		t.Fatalf("fetch admin user id: %v", err)
	}
	seedTenantRefreshToken(t, f, tenantID, userID, "live-session-token")

	if err := f.svc.RemoveTenantAdmin(ctx, tenantID, adminID); err != nil {
		t.Fatalf("RemoveTenantAdmin: %v", err)
	}

	var live int
	if err := f.pool.QueryRow(ctx, `
		SELECT count(*) FROM refresh_tokens
		WHERE user_id = $1 AND tenant_id = $2 AND revoked_at IS NULL
	`, userID, tenantID).Scan(&live); err != nil {
		t.Fatalf("count live refresh tokens: %v", err)
	}
	if live != 0 {
		t.Errorf("live refresh tokens after removal = %d, want 0 — the session can still mint admin_scope tokens", live)
	}
}

// Narrowing a co-owner's grants is a revocation and must end their sessions for
// the same reason removal does.
func TestSetTenantAdminGrants_RevokesLiveSessions(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()
	tenantID, _ := newAdminTenant(t, f, "narrow-sess")
	appA := newTenantApp(t, f, tenantID, "narrow-a")
	appB := newTenantApp(t, f, tenantID, "narrow-b")

	res, err := f.svc.InviteTenantAdmin(ctx, admin.InviteTenantAdminInput{
		TenantID: tenantID, Email: "co@narrow.example",
		Role: auth.AdminRoleCoOwner, ApplicationIDs: []int64{appA, appB},
	})
	if err != nil {
		t.Fatalf("InviteTenantAdmin: %v", err)
	}
	adminID := parseID(t, res.Admin.ID)

	var userID int64
	if err := f.pool.QueryRow(ctx,
		`SELECT user_id FROM tenant_admins WHERE id = $1`, adminID,
	).Scan(&userID); err != nil {
		t.Fatalf("fetch admin user id: %v", err)
	}
	seedTenantRefreshToken(t, f, tenantID, userID, "narrow-session-token")

	// Drop appB. The caller's reach shrinks, so what their open session asserts
	// is now wider than what they hold.
	if _, err := f.svc.SetTenantAdminGrants(ctx, tenantID, adminID, []int64{appA}); err != nil {
		t.Fatalf("SetTenantAdminGrants: %v", err)
	}

	var live int
	if err := f.pool.QueryRow(ctx, `
		SELECT count(*) FROM refresh_tokens
		WHERE user_id = $1 AND tenant_id = $2 AND revoked_at IS NULL
	`, userID, tenantID).Scan(&live); err != nil {
		t.Fatalf("count live refresh tokens: %v", err)
	}
	if live != 0 {
		t.Errorf("live refresh tokens after narrowing grants = %d, want 0", live)
	}
}

// A tenant whose owner can never sign in is worse than no tenant at all: no
// endpoint can repair it, because every route that could is guarded by the
// administrator who was never reachable. So nothing may be written at all.
func TestCreateTenant_RefusedWhenInvitationsAreUnavailable(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	// A service with no invitation service wired, over the same pool.
	svc := admin.New(f.pool, nil, testhelper.TestLogger())

	_, err := svc.CreateTenant(ctx, admin.CreateTenantInput{
		Name: "Unreachable Co", Slug: "unreachable-co", OwnerEmail: "owner@unreachable.example",
	})
	if !errors.Is(err, admin.ErrInvitationsUnavailable) {
		t.Fatalf("CreateTenant without invitations = %v, want ErrInvitationsUnavailable", err)
	}

	// Nothing may survive the refusal — not the tenant, and not an orphan owner.
	var tenants, users int
	if err := f.pool.QueryRow(ctx,
		`SELECT count(*) FROM tenants WHERE slug = 'unreachable-co'`,
	).Scan(&tenants); err != nil {
		t.Fatalf("count tenants: %v", err)
	}
	if tenants != 0 {
		t.Errorf("tenant rows = %d, want 0 — a tenant nobody can sign in to was created", tenants)
	}
	if err := f.pool.QueryRow(ctx,
		`SELECT count(*) FROM users WHERE email = 'owner@unreachable.example'`,
	).Scan(&users); err != nil {
		t.Fatalf("count users: %v", err)
	}
	if users != 0 {
		t.Errorf("owner rows = %d, want 0", users)
	}
}

// Same rule for adding an administrator to an existing tenant: refused up front
// rather than recording an inert grant nobody is told about.
func TestInviteTenantAdmin_RefusedWhenInvitationsAreUnavailable(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()
	tenantID, _ := newAdminTenant(t, f, "no-mail")
	appA := newTenantApp(t, f, tenantID, "no-mail-app")

	svc := admin.New(f.pool, nil, testhelper.TestLogger())
	_, err := svc.InviteTenantAdmin(ctx, admin.InviteTenantAdminInput{
		TenantID: tenantID, Email: "co@nomail.example",
		Role: auth.AdminRoleCoOwner, ApplicationIDs: []int64{appA},
	})
	if !errors.Is(err, admin.ErrInvitationsUnavailable) {
		t.Fatalf("InviteTenantAdmin without invitations = %v, want ErrInvitationsUnavailable", err)
	}

	var admins int
	if err := f.pool.QueryRow(ctx,
		`SELECT count(*) FROM users WHERE tenant_id = $1 AND email = 'co@nomail.example'`, tenantID,
	).Scan(&admins); err != nil {
		t.Fatalf("count users: %v", err)
	}
	if admins != 0 {
		t.Errorf("user rows = %d, want 0 — an administrator was recorded who could never be told", admins)
	}
}

// seedTenantRefreshToken inserts a live session for a user so revocation can be
// observed. The token value is opaque here; only its revoked_at matters.
func seedTenantRefreshToken(t *testing.T, f adminFixture, tenantID, userID int64, raw string) {
	t.Helper()
	// session_family_id is NOT NULL and each new session seeds its family from
	// its own primary key, matching migration 00026's backfill.
	if _, err := f.pool.Exec(context.Background(), `
		WITH inserted AS (
		    INSERT INTO refresh_tokens (user_id, tenant_id, token_hash, expires_at, session_family_id)
		    VALUES ($1, $2, $3, NOW() + INTERVAL '30 days', 0)
		    RETURNING id
		)
		UPDATE refresh_tokens r SET session_family_id = r.id
		WHERE r.id = (SELECT id FROM inserted)
	`, userID, tenantID, auth.HashToken(raw)); err != nil {
		t.Fatalf("seed refresh token: %v", err)
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
