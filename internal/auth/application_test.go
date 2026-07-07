package auth_test

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/store"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// newApplicationService creates an ApplicationService backed by a real DB and
// returns two independent tenant IDs so tests can assert cross-tenant isolation.
func newApplicationService(t *testing.T) (*auth.ApplicationService, context.Context, int64, int64) {
	t.Helper()
	pool := testhelper.NewTestDB(t)
	testhelper.CleanupTables(t, pool)
	logger := testhelper.TestLogger()

	ctx := context.Background()
	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}

	var tenantA int64
	if err := pool.QueryRow(ctx, `SELECT id FROM tenants WHERE slug = 'emc' AND deleted_at IS NULL`).Scan(&tenantA); err != nil {
		t.Fatalf("fetch seed tenant id: %v", err)
	}

	var tenantB int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenants (name, slug, jwt_secret, is_active)
		VALUES ('Isolation Test Tenant', 'isolation-test', 'test-secret-tenant-b', true)
		RETURNING id
	`).Scan(&tenantB); err != nil {
		t.Fatalf("create second tenant: %v", err)
	}

	svc := auth.NewApplicationService(pool, logger)
	return svc, ctx, tenantA, tenantB
}

func TestApplicationService_CreateReturnsCredentialsOnce(t *testing.T) {
	svc, ctx, tenantA, _ := newApplicationService(t)

	result, err := svc.CreateApplication(ctx, tenantA, "web-frontend", "spa")
	if err != nil {
		t.Fatalf("CreateApplication() error = %v", err)
	}
	if !strings.HasPrefix(result.ClientID, auth.ClientIDPrefix) {
		t.Errorf("ClientID = %q, want prefix %q", result.ClientID, auth.ClientIDPrefix)
	}
	if result.ClientSecret == "" {
		t.Error("ClientSecret is empty — must be returned on creation")
	}

	// The list endpoint must never expose the secret.
	apps, err := svc.ListApplications(ctx, tenantA)
	if err != nil {
		t.Fatalf("ListApplications() error = %v", err)
	}
	if len(apps) != 1 {
		t.Fatalf("ListApplications() returned %d apps, want 1", len(apps))
	}
	if apps[0].ClientID != result.ClientID {
		t.Errorf("listed ClientID = %q, want %q", apps[0].ClientID, result.ClientID)
	}
}

// TestApplicationService_CrossTenantIsolation verifies that an application
// created in tenant A is invisible and immutable from tenant B, even when
// tenant B knows the application's row ID and client_id (issue #56 AC).
func TestApplicationService_CrossTenantIsolation(t *testing.T) {
	svc, ctx, tenantA, tenantB := newApplicationService(t)

	created, err := svc.CreateApplication(ctx, tenantA, "tenant-a-app", "")
	if err != nil {
		t.Fatalf("CreateApplication() error = %v", err)
	}
	appID, err := strconv.ParseInt(created.ID, 10, 64)
	if err != nil {
		t.Fatalf("parse app ID %q: %v", created.ID, err)
	}

	// Tenant B must not see tenant A's application.
	appsB, err := svc.ListApplications(ctx, tenantB)
	if err != nil {
		t.Fatalf("ListApplications(tenantB) error = %v", err)
	}
	if len(appsB) != 0 {
		t.Errorf("tenant B sees %d applications from tenant A, want 0", len(appsB))
	}

	// Tenant B must not be able to deactivate tenant A's application by ID.
	if err := svc.DeactivateApplication(ctx, tenantB, appID); err == nil {
		t.Error("DeactivateApplication() from tenant B succeeded, want error")
	}

	// Tenant B must not be able to validate tenant A's client_id as its own.
	if _, err := svc.ValidateClientID(ctx, tenantB, created.ClientID); err == nil {
		t.Error("ValidateClientID() from tenant B succeeded, want error")
	}

	// The application must still be alive and owned by tenant A.
	appsA, err := svc.ListApplications(ctx, tenantA)
	if err != nil {
		t.Fatalf("ListApplications(tenantA) error = %v", err)
	}
	if len(appsA) != 1 {
		t.Fatalf("tenant A has %d applications, want 1", len(appsA))
	}
}

// TestApplicationService_AuthenticateClientBindsTenant verifies the
// client_credentials grant resolves credentials to their owning tenant and
// rejects wrong or revoked secrets.
func TestApplicationService_AuthenticateClientBindsTenant(t *testing.T) {
	svc, ctx, tenantA, _ := newApplicationService(t)

	created, err := svc.CreateApplication(ctx, tenantA, "m2m-service", "m2m")
	if err != nil {
		t.Fatalf("CreateApplication() error = %v", err)
	}

	gotTenant, gotApp, err := svc.AuthenticateClient(ctx, created.ClientID, created.ClientSecret)
	if err != nil {
		t.Fatalf("AuthenticateClient() error = %v", err)
	}
	if gotTenant != tenantA {
		t.Errorf("AuthenticateClient() tenant = %d, want %d", gotTenant, tenantA)
	}
	if strconv.FormatInt(gotApp, 10) != created.ID {
		t.Errorf("AuthenticateClient() appID = %d, want %s", gotApp, created.ID)
	}

	// Wrong secret must be rejected with the sentinel error.
	if _, _, err := svc.AuthenticateClient(ctx, created.ClientID, "wrong-secret"); err != auth.ErrInvalidClient {
		t.Errorf("AuthenticateClient(wrong secret) error = %v, want ErrInvalidClient", err)
	}

	// A deactivated application's credentials must stop working immediately.
	appID, _ := strconv.ParseInt(created.ID, 10, 64)
	if err := svc.DeactivateApplication(ctx, tenantA, appID); err != nil {
		t.Fatalf("DeactivateApplication() error = %v", err)
	}
	if _, _, err := svc.AuthenticateClient(ctx, created.ClientID, created.ClientSecret); err != auth.ErrInvalidClient {
		t.Errorf("AuthenticateClient(deactivated app) error = %v, want ErrInvalidClient", err)
	}
}

// TestApplicationService_RotateSecret verifies rotation invalidates the old
// secret, keeps the client_id stable, and is tenant-isolated.
func TestApplicationService_RotateSecret(t *testing.T) {
	svc, ctx, tenantA, tenantB := newApplicationService(t)

	created, err := svc.CreateApplication(ctx, tenantA, "rotate-me", "web")
	if err != nil {
		t.Fatalf("CreateApplication() error = %v", err)
	}
	appID, _ := strconv.ParseInt(created.ID, 10, 64)

	// Tenant B must not be able to rotate tenant A's secret.
	if _, err := svc.RotateSecret(ctx, tenantB, appID); err != auth.ErrAppNotFound {
		t.Errorf("RotateSecret() from tenant B error = %v, want ErrAppNotFound", err)
	}

	rotated, err := svc.RotateSecret(ctx, tenantA, appID)
	if err != nil {
		t.Fatalf("RotateSecret() error = %v", err)
	}
	if rotated.ClientID != created.ClientID {
		t.Errorf("RotateSecret() changed client_id: %q → %q", created.ClientID, rotated.ClientID)
	}
	if rotated.ClientSecret == "" || rotated.ClientSecret == created.ClientSecret {
		t.Error("RotateSecret() did not return a fresh secret")
	}

	// Old secret dead, new secret live.
	if _, _, err := svc.AuthenticateClient(ctx, created.ClientID, created.ClientSecret); err != auth.ErrInvalidClient {
		t.Errorf("old secret still authenticates after rotation: err = %v", err)
	}
	if gotTenant, _, err := svc.AuthenticateClient(ctx, created.ClientID, rotated.ClientSecret); err != nil || gotTenant != tenantA {
		t.Errorf("new secret failed to authenticate: tenant = %d, err = %v", gotTenant, err)
	}
}

// TestApplicationService_GetAndUpdate verifies single-app fetch and partial update.
func TestApplicationService_GetAndUpdate(t *testing.T) {
	svc, ctx, tenantA, tenantB := newApplicationService(t)

	created, err := svc.CreateApplication(ctx, tenantA, "get-update-app", "")
	if err != nil {
		t.Fatalf("CreateApplication() error = %v", err)
	}
	if created.AppType != "web" {
		t.Errorf("CreateApplication() default AppType = %q, want \"web\"", created.AppType)
	}
	appID, _ := strconv.ParseInt(created.ID, 10, 64)

	got, err := svc.GetApplication(ctx, tenantA, appID)
	if err != nil {
		t.Fatalf("GetApplication() error = %v", err)
	}
	if !got.IsActive || got.Name != "get-update-app" || got.AppType != "web" {
		t.Errorf("GetApplication() = %+v, want active web app named get-update-app", got)
	}

	// Cross-tenant get must fail.
	if _, err := svc.GetApplication(ctx, tenantB, appID); err != auth.ErrAppNotFound {
		t.Errorf("GetApplication() from tenant B error = %v, want ErrAppNotFound", err)
	}

	// Partial update: change type only, name must survive.
	updated, err := svc.UpdateApplication(ctx, tenantA, appID, "", "m2m")
	if err != nil {
		t.Fatalf("UpdateApplication() error = %v", err)
	}
	if updated.Name != "get-update-app" || updated.AppType != "m2m" {
		t.Errorf("UpdateApplication() = name %q type %q, want get-update-app/m2m", updated.Name, updated.AppType)
	}

	// Invalid type rejected; cross-tenant update rejected.
	if _, err := svc.UpdateApplication(ctx, tenantA, appID, "", "bogus"); err != auth.ErrInvalidAppType {
		t.Errorf("UpdateApplication(bogus type) error = %v, want ErrInvalidAppType", err)
	}
	if _, err := svc.UpdateApplication(ctx, tenantB, appID, "hijacked", ""); err != auth.ErrAppNotFound {
		t.Errorf("UpdateApplication() from tenant B error = %v, want ErrAppNotFound", err)
	}
}

// TestApplicationService_ListPaginated verifies filters, pagination, and that
// deactivated apps appear only under status=inactive.
func TestApplicationService_ListPaginated(t *testing.T) {
	svc, ctx, tenantA, tenantB := newApplicationService(t)

	mkApp := func(name, appType string) int64 {
		t.Helper()
		r, err := svc.CreateApplication(ctx, tenantA, name, appType)
		if err != nil {
			t.Fatalf("CreateApplication(%s) error = %v", name, err)
		}
		id, _ := strconv.ParseInt(r.ID, 10, 64)
		return id
	}
	mkApp("alpha-web", "web")
	mkApp("beta-spa", "spa")
	deadID := mkApp("gamma-m2m", "m2m")
	if err := svc.DeactivateApplication(ctx, tenantA, deadID); err != nil {
		t.Fatalf("DeactivateApplication() error = %v", err)
	}

	// No filters: all 3 (active + inactive).
	page, err := svc.ListApplicationsPaginated(ctx, tenantA, auth.AppFilter{})
	if err != nil {
		t.Fatalf("ListApplicationsPaginated() error = %v", err)
	}
	if page.Total != 3 {
		t.Errorf("Total = %d, want 3", page.Total)
	}

	// status=active → 2; status=inactive → 1.
	active, err := svc.ListApplicationsPaginated(ctx, tenantA, auth.AppFilter{Status: "active"})
	if err != nil {
		t.Fatalf("ListApplicationsPaginated(active) error = %v", err)
	}
	if active.Total != 2 {
		t.Errorf("active Total = %d, want 2", active.Total)
	}
	inactive, err := svc.ListApplicationsPaginated(ctx, tenantA, auth.AppFilter{Status: "inactive"})
	if err != nil {
		t.Fatalf("ListApplicationsPaginated(inactive) error = %v", err)
	}
	if inactive.Total != 1 || inactive.Data[0].Name != "gamma-m2m" || inactive.Data[0].IsActive {
		t.Errorf("inactive page = %+v, want single inactive gamma-m2m", inactive.Data)
	}

	// type filter.
	spas, err := svc.ListApplicationsPaginated(ctx, tenantA, auth.AppFilter{Type: "spa"})
	if err != nil {
		t.Fatalf("ListApplicationsPaginated(type=spa) error = %v", err)
	}
	if spas.Total != 1 || spas.Data[0].Name != "beta-spa" {
		t.Errorf("type=spa page = %+v, want single beta-spa", spas.Data)
	}

	// search filter matches name substring.
	found, err := svc.ListApplicationsPaginated(ctx, tenantA, auth.AppFilter{Search: "alpha"})
	if err != nil {
		t.Fatalf("ListApplicationsPaginated(search) error = %v", err)
	}
	if found.Total != 1 || found.Data[0].Name != "alpha-web" {
		t.Errorf("search=alpha page = %+v, want single alpha-web", found.Data)
	}

	// pagination: limit 2 → 2 pages.
	p1, err := svc.ListApplicationsPaginated(ctx, tenantA, auth.AppFilter{Limit: 2, Page: 1})
	if err != nil {
		t.Fatalf("ListApplicationsPaginated(page 1) error = %v", err)
	}
	if len(p1.Data) != 2 || p1.TotalPages != 2 {
		t.Errorf("page 1: len = %d, total_pages = %d, want 2 and 2", len(p1.Data), p1.TotalPages)
	}
	p2, err := svc.ListApplicationsPaginated(ctx, tenantA, auth.AppFilter{Limit: 2, Page: 2})
	if err != nil {
		t.Fatalf("ListApplicationsPaginated(page 2) error = %v", err)
	}
	if len(p2.Data) != 1 {
		t.Errorf("page 2: len = %d, want 1", len(p2.Data))
	}

	// invalid type filter rejected.
	if _, err := svc.ListApplicationsPaginated(ctx, tenantA, auth.AppFilter{Type: "bogus"}); err != auth.ErrInvalidAppType {
		t.Errorf("ListApplicationsPaginated(type=bogus) error = %v, want ErrInvalidAppType", err)
	}

	// tenant B sees none of tenant A's apps.
	pageB, err := svc.ListApplicationsPaginated(ctx, tenantB, auth.AppFilter{})
	if err != nil {
		t.Fatalf("ListApplicationsPaginated(tenantB) error = %v", err)
	}
	if pageB.Total != 0 {
		t.Errorf("tenant B Total = %d, want 0", pageB.Total)
	}
}
