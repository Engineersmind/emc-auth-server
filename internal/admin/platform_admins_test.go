package admin_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/engineersmind/emc-auth-server/internal/admin"
	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// activateAdmin does what accepting an invitation does, so a fixture
// administrator counts as usable.
func activateAdmin(t *testing.T, f adminFixture, adminID int64) {
	t.Helper()
	if _, err := f.pool.Exec(context.Background(), `
		UPDATE tenant_admins SET activated_at = NOW() WHERE id = $1
	`, adminID); err != nil {
		t.Fatalf("activate admin %d: %v", adminID, err)
	}
	if _, err := f.pool.Exec(context.Background(), `
		UPDATE users SET email_verified = true
		WHERE id = (SELECT user_id FROM tenant_admins WHERE id = $1)
	`, adminID); err != nil {
		t.Fatalf("verify admin %d: %v", adminID, err)
	}
}

// The directory is the one listing in the system that deliberately crosses
// tenants — a platform admin oversees all of them and cannot open forty tenant
// pages to find the one owner who never accepted.
func TestListPlatformAdministrators_SpansTenants(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	tenantA, ownerA := newAdminTenant(t, f, "dir-a")
	tenantB, ownerB := newAdminTenant(t, f, "dir-b")
	activateAdmin(t, f, ownerA)
	activateAdmin(t, f, ownerB)

	page, err := f.svc.ListPlatformAdministrators(ctx, admin.PlatformAdminFilter{Search: "dir-"})
	if err != nil {
		t.Fatalf("ListPlatformAdministrators: %v", err)
	}
	if page.Total < 2 {
		t.Fatalf("total = %d, want at least the two owners", page.Total)
	}

	seen := map[string]admin.PlatformAdminResult{}
	for _, r := range page.Data {
		seen[r.Email] = r
	}
	for _, want := range []struct {
		email    string
		tenantID int64
	}{
		{"owner-dir-a@example.com", tenantA},
		{"owner-dir-b@example.com", tenantB},
	} {
		got, ok := seen[want.email]
		if !ok {
			t.Fatalf("%s missing from the directory", want.email)
		}
		if got.TenantID != fmt.Sprintf("%d", want.tenantID) {
			t.Errorf("%s tenant = %s, want %d", want.email, got.TenantID, want.tenantID)
		}
		if got.TenantName == "" {
			t.Errorf("%s has no tenant name; the reader has no other context for it", want.email)
		}
		if got.Role != auth.AdminRoleOwner {
			t.Errorf("%s role = %q, want owner", want.email, got.Role)
		}
	}
}

// Status collapses three independent flags, and the order matters: a blocked
// administrator whose grant was never activated reads as blocked, because that
// is the condition an operator must clear first.
func TestListPlatformAdministrators_StatusReflectsTheBlockingCondition(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()
	tenantID, ownerAdminID := newAdminTenant(t, f, "dir-status")

	// Freshly created: granted but never accepted.
	page, err := f.svc.ListPlatformAdministrators(ctx, admin.PlatformAdminFilter{Search: "dir-status"})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(page.Data) != 1 || page.Data[0].Status != "pending_invitation" {
		t.Fatalf("status = %+v, want pending_invitation", page.Data)
	}

	activateAdmin(t, f, ownerAdminID)
	page, _ = f.svc.ListPlatformAdministrators(ctx, admin.PlatformAdminFilter{Search: "dir-status"})
	if page.Data[0].Status != "active" {
		t.Errorf("status = %q, want active after activation", page.Data[0].Status)
	}

	// Blocking wins over everything else.
	if _, err := f.pool.Exec(ctx, `
		UPDATE users SET blocked_at = NOW(), is_active = false
		WHERE id = (SELECT user_id FROM tenant_admins WHERE id = $1)
	`, ownerAdminID); err != nil {
		t.Fatalf("block owner: %v", err)
	}
	page, _ = f.svc.ListPlatformAdministrators(ctx, admin.PlatformAdminFilter{Search: "dir-status"})
	if page.Data[0].Status != "blocked" {
		t.Errorf("status = %q, want blocked", page.Data[0].Status)
	}
	_ = tenantID
}

func TestListPlatformAdministrators_FiltersByRoleAndStatus(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()
	tenantID, ownerAdminID := newAdminTenant(t, f, "dir-filter")
	activateAdmin(t, f, ownerAdminID)
	appID := newTenantApp(t, f, tenantID, "dir-filter-app")

	if _, err := f.svc.InviteTenantAdmin(ctx, admin.InviteTenantAdminInput{
		TenantID: tenantID, Email: "co@dir-filter.example",
		Role: auth.AdminRoleCoOwner, ApplicationIDs: []int64{appID},
	}); err != nil {
		t.Fatalf("InviteTenantAdmin: %v", err)
	}

	owners, err := f.svc.ListPlatformAdministrators(ctx, admin.PlatformAdminFilter{
		Search: "dir-filter", Role: auth.AdminRoleOwner,
	})
	if err != nil {
		t.Fatalf("list owners: %v", err)
	}
	for _, r := range owners.Data {
		if r.Role != auth.AdminRoleOwner {
			t.Errorf("role filter leaked a %s", r.Role)
		}
	}

	pending, err := f.svc.ListPlatformAdministrators(ctx, admin.PlatformAdminFilter{
		Search: "dir-filter", Status: "pending_invitation",
	})
	if err != nil {
		t.Fatalf("list pending: %v", err)
	}
	if len(pending.Data) != 1 || pending.Data[0].Email != "co@dir-filter.example" {
		t.Errorf("pending = %+v, want only the unaccepted co-owner", pending.Data)
	}

	// A co-owner's applications are named, not id'd — the reader is looking at a
	// tenant they may never have opened.
	if len(pending.Data[0].Applications) != 1 || pending.Data[0].Applications[0] != "dir-filter-app" {
		t.Errorf("applications = %v, want the granted application by name", pending.Data[0].Applications)
	}

	// An unknown role is the caller's mistake, not an empty result.
	if _, err := f.svc.ListPlatformAdministrators(ctx, admin.PlatformAdminFilter{Role: "wizard"}); err == nil {
		t.Error("an unknown role was accepted; it would silently return everything")
	}
}

// An owner's empty applications array means "all of them" and a co-owner's means
// "exactly these". The directory must not blur that.
func TestListPlatformAdministrators_OwnerHasNoApplicationList(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()
	tenantID, ownerAdminID := newAdminTenant(t, f, "dir-apps")
	activateAdmin(t, f, ownerAdminID)
	newTenantApp(t, f, tenantID, "dir-apps-app")

	page, err := f.svc.ListPlatformAdministrators(ctx, admin.PlatformAdminFilter{Search: "dir-apps"})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(page.Data) != 1 {
		t.Fatalf("rows = %d, want the single owner", len(page.Data))
	}
	if len(page.Data[0].Applications) != 0 {
		t.Errorf("owner applications = %v, want empty — an owner administers all of them",
			page.Data[0].Applications)
	}
}

func TestListPlatformAdministrators_PaginationTotalMatchesTheFilter(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()
	tenantID, ownerAdminID := newAdminTenant(t, f, "dir-page")
	activateAdmin(t, f, ownerAdminID)
	appID := newTenantApp(t, f, tenantID, "dir-page-app")

	for i := 0; i < 3; i++ {
		if _, err := f.svc.InviteTenantAdmin(ctx, admin.InviteTenantAdminInput{
			TenantID: tenantID, Email: fmt.Sprintf("co%d@dir-page.example", i),
			Role: auth.AdminRoleCoOwner, ApplicationIDs: []int64{appID},
		}); err != nil {
			t.Fatalf("invite %d: %v", i, err)
		}
	}

	page, err := f.svc.ListPlatformAdministrators(ctx, admin.PlatformAdminFilter{
		Search: "dir-page", Limit: 2, Page: 1,
	})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	// The count and the page share one WHERE clause, so the total describes the
	// filtered set rather than the table.
	if page.Total != 4 {
		t.Errorf("total = %d, want 4 (one owner + three co-owners)", page.Total)
	}
	if len(page.Data) != 2 {
		t.Errorf("rows = %d, want the page size", len(page.Data))
	}
	if page.TotalPages != 2 {
		t.Errorf("total_pages = %d, want 2", page.TotalPages)
	}
}

// The two numbers worth acting on: privileged accounts with no second factor,
// and tenants nobody can administer.
func TestPlatformAdminSummary_CountsWhatNeedsAction(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	before, err := f.svc.PlatformAdminSummary(ctx)
	if err != nil {
		t.Fatalf("summary: %v", err)
	}

	_, pendingOwner := newAdminTenant(t, f, "dir-sum-pending")
	_, activeOwner := newAdminTenant(t, f, "dir-sum-active")
	activateAdmin(t, f, activeOwner)
	_ = pendingOwner

	after, err := f.svc.PlatformAdminSummary(ctx)
	if err != nil {
		t.Fatalf("summary: %v", err)
	}
	if after.TotalAdmins != before.TotalAdmins+2 {
		t.Errorf("total = %d, want %d", after.TotalAdmins, before.TotalAdmins+2)
	}
	if after.PendingInvitations != before.PendingInvitations+1 {
		t.Errorf("pending = %d, want %d", after.PendingInvitations, before.PendingInvitations+1)
	}
	// Neither owner has MFA, so both count.
	if after.NoMFA != before.NoMFA+2 {
		t.Errorf("no_mfa = %d, want %d", after.NoMFA, before.NoMFA+2)
	}
	// Only the tenant whose owner never accepted lacks a usable owner.
	if after.TenantsWithoutOwner != before.TenantsWithoutOwner+1 {
		t.Errorf("tenants_without_owner = %d, want %d — an unaccepted owner does not count",
			after.TenantsWithoutOwner, before.TenantsWithoutOwner+1)
	}
}

// Removing an administrator soft-deletes the row; the directory reports who
// administers something now, not who ever did.
func TestListPlatformAdministrators_ExcludesRemovedAdmins(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()
	tenantID, ownerAdminID := newAdminTenant(t, f, "dir-removed")
	activateAdmin(t, f, ownerAdminID)
	appID := newTenantApp(t, f, tenantID, "dir-removed-app")

	res, err := f.svc.InviteTenantAdmin(ctx, admin.InviteTenantAdminInput{
		TenantID: tenantID, Email: "gone@dir-removed.example",
		Role: auth.AdminRoleCoOwner, ApplicationIDs: []int64{appID},
	})
	if err != nil {
		t.Fatalf("invite: %v", err)
	}
	if err := f.svc.RemoveTenantAdmin(ctx, tenantID, parseID(t, res.Admin.ID)); err != nil {
		t.Fatalf("remove: %v", err)
	}

	page, err := f.svc.ListPlatformAdministrators(ctx, admin.PlatformAdminFilter{Search: "dir-removed"})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, r := range page.Data {
		if r.Email == "gone@dir-removed.example" {
			t.Error("a removed administrator is still listed")
		}
	}
}
