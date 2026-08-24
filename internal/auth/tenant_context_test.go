package auth_test

import (
	"errors"
	"testing"

	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// ---------------------------------------------------------------------------
// Tenant context switching and the reachable-tenants listing (plan steps 4, 5).
//
// The properties that matter are negative ones: a tenant the caller does not
// administer must be unreachable even though the tenant id is trivially guessable
// from the request body, and a pending or revoked grant must not open a door.
// ---------------------------------------------------------------------------

// TestReachableTenants_ListsEveryAdministeredTenant covers the listing an owner
// of several tenants sees immediately after login — the requirement that started
// this work.
//
// Note what is NOT involved: no tenant context, no token. The listing is keyed on
// user id alone, which is why all tenants appear before any switch has happened.
func TestReachableTenants_ListsEveryAdministeredTenant(t *testing.T) {
	e := newGrantsEnv(t)
	user := e.seedAdminUser(t, e.tenantA, "reach")

	e.grant(t, user, e.tenantA, auth.AdminRoleOwner, nil)
	e.grant(t, user, e.tenantB, auth.AdminRoleCoOwner, &e.appB1)

	got, err := auth.ListReachableTenants(e.ctx, e.pool, user)
	if err != nil {
		t.Fatalf("ListReachableTenants: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("reachable = %d tenants, want 2 (%+v)", len(got), got)
	}

	byID := map[int64]auth.AdminTenantSummary{}
	for _, s := range got {
		byID[s.TenantID] = s
	}

	a := byID[e.tenantA]
	if a.Role != auth.AdminRoleOwner {
		t.Errorf("tenant A role = %q, want owner", a.Role)
	}
	// An owner's count is the tenant's total applications, and no list is
	// reported — enumerating would imply a fixed set, which absence-means-all
	// exists to avoid.
	if a.AppCount != 2 {
		t.Errorf("tenant A app_count = %d, want 2 (every application in the tenant)", a.AppCount)
	}
	if a.Applications != nil {
		t.Errorf("tenant A applications = %v, want nil for an owner", a.Applications)
	}

	b := byID[e.tenantB]
	if b.Role != auth.AdminRoleCoOwner {
		t.Errorf("tenant B role = %q, want co_owner", b.Role)
	}
	if b.AppCount != 1 || len(b.Applications) != 1 || b.Applications[0] != e.appB1 {
		t.Errorf("tenant B = count %d, apps %v; want count 1, apps [%d]", b.AppCount, b.Applications, e.appB1)
	}
}

// TestReachableTenants_ExcludesPendingAndRevoked: a tenant the caller cannot
// actually enter must not be offered. Listing it produces a dashboard tile that
// 403s when clicked.
func TestReachableTenants_ExcludesPendingAndRevoked(t *testing.T) {
	e := newGrantsEnv(t)
	user := e.seedAdminUser(t, e.tenantA, "pending-list")

	// Pending: granted but never accepted.
	if _, err := e.pool.Exec(e.ctx, `
		INSERT INTO admin_grants (user_id, tenant_id, admin_role, application_id, activated_at)
		VALUES ($1, $2, 'owner', NULL, NULL)
	`, user, e.tenantA); err != nil {
		t.Fatalf("seed pending grant: %v", err)
	}
	// Revoked: activated once, then soft-deleted.
	if _, err := e.pool.Exec(e.ctx, `
		INSERT INTO admin_grants (user_id, tenant_id, admin_role, application_id, activated_at, deleted_at)
		VALUES ($1, $2, 'co_owner', $3, NOW(), NOW())
	`, user, e.tenantB, e.appB1); err != nil {
		t.Fatalf("seed revoked grant: %v", err)
	}

	got, err := auth.ListReachableTenants(e.ctx, e.pool, user)
	if err != nil {
		t.Fatalf("ListReachableTenants: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("reachable = %+v, want empty: a pending grant confers nothing and a revoked one is gone", got)
	}
}

// TestReachableTenants_ManyOwnersOneTenant is the cardinality the old model
// forbade in the other direction — several administrators over the same tenant,
// each seeing it in their own listing.
func TestReachableTenants_ManyOwnersOneTenant(t *testing.T) {
	e := newGrantsEnv(t)
	first := e.seedAdminUser(t, e.tenantA, "co-owner-1")
	second := e.seedAdminUser(t, e.tenantA, "co-owner-2")

	e.grant(t, first, e.tenantA, auth.AdminRoleOwner, nil)
	e.grant(t, second, e.tenantA, auth.AdminRoleOwner, nil)

	for label, user := range map[string]int64{"first": first, "second": second} {
		got, err := auth.ListReachableTenants(e.ctx, e.pool, user)
		if err != nil {
			t.Fatalf("ListReachableTenants(%s): %v", label, err)
		}
		if len(got) != 1 || got[0].TenantID != e.tenantA || got[0].Role != auth.AdminRoleOwner {
			t.Errorf("%s reachable = %+v, want one owner entry for tenant A", label, got)
		}
	}

	// And the tenant really does have two owners.
	var owners int
	if err := e.pool.QueryRow(e.ctx, `
		SELECT COUNT(*) FROM admin_grants
		WHERE tenant_id = $1 AND admin_role = 'owner' AND deleted_at IS NULL
	`, e.tenantA).Scan(&owners); err != nil {
		t.Fatalf("count owners: %v", err)
	}
	if owners != 2 {
		t.Errorf("tenant A owners = %d, want 2", owners)
	}
}

// TestHasAdminGrant_RefusesUnadministeredTenant is the check that stops
// /auth/tenant-context trusting a tenant id from the request body.
//
// The tenant id is a small integer, so a caller can trivially enumerate. The only
// thing standing between them and another tenant is this lookup.
func TestHasAdminGrant_RefusesUnadministeredTenant(t *testing.T) {
	e := newGrantsEnv(t)
	user := e.seedAdminUser(t, e.tenantA, "probe")
	e.grant(t, user, e.tenantA, auth.AdminRoleOwner, nil)

	// The tenant they own: admitted, and reported as owner.
	ok, role, err := auth.HasAdminGrant(e.ctx, e.pool, user, e.tenantA)
	if err != nil {
		t.Fatalf("HasAdminGrant(A): %v", err)
	}
	if !ok || role != auth.AdminRoleOwner {
		t.Errorf("HasAdminGrant(A) = (%t, %q), want (true, owner)", ok, role)
	}

	// A tenant they do not administer at all: refused, even though it exists.
	ok, _, err = auth.HasAdminGrant(e.ctx, e.pool, user, e.tenantB)
	if err != nil {
		t.Fatalf("HasAdminGrant(B): %v", err)
	}
	if ok {
		t.Error("HasAdminGrant(B) = true for a tenant with no grant — tenant-context would admit a probe")
	}

	// A pending grant is not a grant.
	if _, err = e.pool.Exec(e.ctx, `
		INSERT INTO admin_grants (user_id, tenant_id, admin_role, application_id, activated_at)
		VALUES ($1, $2, 'co_owner', $3, NULL)
	`, user, e.tenantB, e.appB1); err != nil {
		t.Fatalf("seed pending grant: %v", err)
	}
	if ok, _, err = auth.HasAdminGrant(e.ctx, e.pool, user, e.tenantB); err != nil {
		t.Fatalf("HasAdminGrant(B, pending): %v", err)
	} else if ok {
		t.Error("HasAdminGrant = true for a PENDING grant — an unaccepted invitation must open no door")
	}
}

// TestDefaultAdminTenant_PrefersOwnedTenant covers the landing tenant at login.
// Landing in the narrower tier when a broader one exists reads to the user as
// missing access.
func TestDefaultAdminTenant_PrefersOwnedTenant(t *testing.T) {
	e := newGrantsEnv(t)
	user := e.seedAdminUser(t, e.tenantB, "landing")

	// Co-owner only: that is where they land.
	e.grant(t, user, e.tenantB, auth.AdminRoleCoOwner, &e.appB1)
	got, err := auth.DefaultAdminTenant(e.ctx, e.pool, user)
	if err != nil {
		t.Fatalf("DefaultAdminTenant (co-owner only): %v", err)
	}
	if got != e.tenantB {
		t.Errorf("default = %d, want tenant B (%d)", got, e.tenantB)
	}

	// Now also an owner elsewhere: the owned tenant wins.
	e.grant(t, user, e.tenantA, auth.AdminRoleOwner, nil)
	got, err = auth.DefaultAdminTenant(e.ctx, e.pool, user)
	if err != nil {
		t.Fatalf("DefaultAdminTenant (mixed): %v", err)
	}
	if got != e.tenantA {
		t.Errorf("default = %d, want the OWNED tenant A (%d)", got, e.tenantA)
	}

	// A user with no grants is not an administrator, reported distinctly so
	// callers can treat it as "ordinary user" rather than as a failure.
	plain := e.seedAdminUser(t, e.tenantA, "not-admin")
	if _, err = auth.DefaultAdminTenant(e.ctx, e.pool, plain); !errors.Is(err, auth.ErrNoAdminReach) {
		t.Errorf("DefaultAdminTenant(non-admin) error = %v, want ErrNoAdminReach", err)
	}
}

// TestReachableTenants_SkipsInactiveTenant: a deactivated tenant must not be
// offered even to an administrator who still holds a live grant in it.
func TestReachableTenants_SkipsInactiveTenant(t *testing.T) {
	e := newGrantsEnv(t)
	user := e.seedAdminUser(t, e.tenantA, "inactive")
	e.grant(t, user, e.tenantA, auth.AdminRoleOwner, nil)
	e.grant(t, user, e.tenantB, auth.AdminRoleOwner, nil)

	if _, err := e.pool.Exec(e.ctx,
		`UPDATE tenants SET is_active = false WHERE id = $1`, e.tenantB); err != nil {
		t.Fatalf("deactivate tenant B: %v", err)
	}

	got, err := auth.ListReachableTenants(e.ctx, e.pool, user)
	if err != nil {
		t.Fatalf("ListReachableTenants: %v", err)
	}
	if len(got) != 1 || got[0].TenantID != e.tenantA {
		t.Errorf("reachable = %+v, want only the active tenant A (%d)", got, e.tenantA)
	}
}
