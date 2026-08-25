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

	result, err := svc.CreateApplication(ctx, tenantA, "web-frontend", "spa", nil)
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

	created, err := svc.CreateApplication(ctx, tenantA, "tenant-a-app", "", nil)
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

	created, err := svc.CreateApplication(ctx, tenantA, "m2m-service", "m2m", nil)
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

	created, err := svc.CreateApplication(ctx, tenantA, "rotate-me", "web", nil)
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

	created, err := svc.CreateApplication(ctx, tenantA, "get-update-app", "", nil)
	if err != nil {
		t.Fatalf("CreateApplication() error = %v", err)
	}
	// Default is m2m, not web: every application here is a backend service using
	// client_credentials. See TestOmittedAppTypeDefaultsToM2M.
	if created.AppType != "m2m" {
		t.Errorf("CreateApplication() default AppType = %q, want \"m2m\"", created.AppType)
	}
	appID, _ := strconv.ParseInt(created.ID, 10, 64)

	got, err := svc.GetApplication(ctx, tenantA, appID)
	if err != nil {
		t.Fatalf("GetApplication() error = %v", err)
	}
	if !got.IsActive || got.Name != "get-update-app" || got.AppType != "m2m" {
		t.Errorf("GetApplication() = %+v, want active m2m app named get-update-app", got)
	}

	// Cross-tenant get must fail.
	if _, err := svc.GetApplication(ctx, tenantB, appID); err != auth.ErrAppNotFound {
		t.Errorf("GetApplication() from tenant B error = %v, want ErrAppNotFound", err)
	}

	// Partial update: change type only, name must survive.
	updated, err := svc.UpdateApplication(ctx, tenantA, appID, "", "m2m", nil)
	if err != nil {
		t.Fatalf("UpdateApplication() error = %v", err)
	}
	if updated.Name != "get-update-app" || updated.AppType != "m2m" {
		t.Errorf("UpdateApplication() = name %q type %q, want get-update-app/m2m", updated.Name, updated.AppType)
	}

	// Invalid type rejected; cross-tenant update rejected.
	if _, err := svc.UpdateApplication(ctx, tenantA, appID, "", "bogus", nil); err != auth.ErrInvalidAppType {
		t.Errorf("UpdateApplication(bogus type) error = %v, want ErrInvalidAppType", err)
	}
	if _, err := svc.UpdateApplication(ctx, tenantB, appID, "hijacked", "", nil); err != auth.ErrAppNotFound {
		t.Errorf("UpdateApplication() from tenant B error = %v, want ErrAppNotFound", err)
	}
}

// TestApplicationService_ListPaginated_OnlyIDs covers the server-side half of
// application-scoped administration (issue #97): a co-owner may list the
// tenant's applications but must see only the ones granted to them.
//
// The distinction that matters is nil versus empty. nil means unrestricted;
// an empty slice means nothing. Collapsing them would show a co-owner whose
// last grant was revoked every application in the tenant.
func TestApplicationService_ListPaginated_OnlyIDs(t *testing.T) {
	svc, ctx, tenantA, _ := newApplicationService(t)

	mk := func(name string) int64 {
		t.Helper()
		r, err := svc.CreateApplication(ctx, tenantA, name, "web", nil)
		if err != nil {
			t.Fatalf("CreateApplication(%s): %v", name, err)
		}
		id, _ := strconv.ParseInt(r.ID, 10, 64)
		return id
	}
	// Measured rather than assumed: the fixture tenant is not guaranteed empty.
	baseline, err := svc.ListApplicationsPaginated(ctx, tenantA, auth.AppFilter{})
	if err != nil {
		t.Fatalf("baseline list: %v", err)
	}

	granted := mk("scoped-granted")
	mk("scoped-other")

	page, err := svc.ListApplicationsPaginated(ctx, tenantA, auth.AppFilter{OnlyIDs: []int64{granted}})
	if err != nil {
		t.Fatalf("ListApplicationsPaginated(OnlyIDs): %v", err)
	}
	// Total is filtered too, so the count reflects what the caller can see
	// rather than the size of the tenant.
	if page.Total != 1 || len(page.Data) != 1 {
		t.Fatalf("Total=%d rows=%d, want exactly the one granted application", page.Total, len(page.Data))
	}
	if page.Data[0].Name != "scoped-granted" {
		t.Errorf("returned %q, want the granted application", page.Data[0].Name)
	}

	empty, err := svc.ListApplicationsPaginated(ctx, tenantA, auth.AppFilter{OnlyIDs: []int64{}})
	if err != nil {
		t.Fatalf("ListApplicationsPaginated(empty OnlyIDs): %v", err)
	}
	if empty.Total != 0 || len(empty.Data) != 0 {
		t.Errorf("Total=%d rows=%d for an empty grant set, want nothing", empty.Total, len(empty.Data))
	}

	unrestricted, err := svc.ListApplicationsPaginated(ctx, tenantA, auth.AppFilter{})
	if err != nil {
		t.Fatalf("ListApplicationsPaginated(nil OnlyIDs): %v", err)
	}
	if unrestricted.Total != baseline.Total+2 {
		t.Errorf("Total = %d for nil OnlyIDs, want %d — nil must not restrict", unrestricted.Total, baseline.Total+2)
	}
}

// TestApplicationService_ListPaginated verifies filters, pagination, and that
// deactivated apps appear only under status=inactive.
func TestApplicationService_ListPaginated(t *testing.T) {
	svc, ctx, tenantA, tenantB := newApplicationService(t)

	mkApp := func(name, appType string) int64 {
		t.Helper()
		r, err := svc.CreateApplication(ctx, tenantA, name, appType, nil)
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

// TestApplicationService_ScopesRoundTrip verifies scopes persist through
// create, surface on get, follow nil-unchanged / empty-clears update semantics,
// and reject malformed scope strings.
func TestApplicationService_ScopesRoundTrip(t *testing.T) {
	svc, ctx, tenantA, _ := newApplicationService(t)

	created, err := svc.CreateApplication(ctx, tenantA, "scoped-app", "m2m", []string{"orders:read", "orders:write"})
	if err != nil {
		t.Fatalf("CreateApplication() error = %v", err)
	}
	if len(created.Scopes) != 2 {
		t.Fatalf("created Scopes = %v, want 2 entries", created.Scopes)
	}
	appID, _ := strconv.ParseInt(created.ID, 10, 64)

	got, err := svc.GetApplication(ctx, tenantA, appID)
	if err != nil {
		t.Fatalf("GetApplication() error = %v", err)
	}
	if len(got.Scopes) != 2 || got.Scopes[0] != "orders:read" || got.Scopes[1] != "orders:write" {
		t.Errorf("GetApplication() Scopes = %v, want [orders:read orders:write]", got.Scopes)
	}

	// nil scopes on update leaves them unchanged.
	updated, err := svc.UpdateApplication(ctx, tenantA, appID, "renamed", "", nil)
	if err != nil {
		t.Fatalf("UpdateApplication(nil scopes) error = %v", err)
	}
	if len(updated.Scopes) != 2 {
		t.Errorf("UpdateApplication(nil scopes) Scopes = %v, want unchanged 2 entries", updated.Scopes)
	}

	// Replacing scopes takes effect.
	updated, err = svc.UpdateApplication(ctx, tenantA, appID, "", "", []string{"reports:read"})
	if err != nil {
		t.Fatalf("UpdateApplication(replace scopes) error = %v", err)
	}
	if len(updated.Scopes) != 1 || updated.Scopes[0] != "reports:read" {
		t.Errorf("UpdateApplication(replace) Scopes = %v, want [reports:read]", updated.Scopes)
	}

	// Empty non-nil slice clears scopes.
	updated, err = svc.UpdateApplication(ctx, tenantA, appID, "", "", []string{})
	if err != nil {
		t.Fatalf("UpdateApplication(clear scopes) error = %v", err)
	}
	if len(updated.Scopes) != 0 {
		t.Errorf("UpdateApplication(clear) Scopes = %v, want empty", updated.Scopes)
	}

	// Malformed scopes are rejected on create and update.
	if _, err := svc.CreateApplication(ctx, tenantA, "bad-scope-app", "", []string{"no-colon"}); err != auth.ErrInvalidScope {
		t.Errorf("CreateApplication(bad scope) error = %v, want ErrInvalidScope", err)
	}
	if _, err := svc.UpdateApplication(ctx, tenantA, appID, "", "", []string{":action-only"}); err != auth.ErrInvalidScope {
		t.Errorf("UpdateApplication(bad scope) error = %v, want ErrInvalidScope", err)
	}
}

// TestAppTypeDerivesGrantTypes pins the rule that app_type decides which OAuth
// grants a client may use.
//
// Before this, every application took the column default
// {authorization_code, refresh_token} whatever its type, so an application
// created as m2m could not perform the client_credentials grant: /oauth/token
// refused it at the GrantTypes check. Nothing surfaced the mismatch until a
// backend service tried to fetch its first token, which is why this is pinned
// here rather than left to the column default.
func TestAppTypeDerivesGrantTypes(t *testing.T) {
	svc, ctx, tenantID, _ := newApplicationService(t)

	cases := []struct {
		appType string
		want    []string
		pkce    bool
	}{
		// client_credentials only, and NOT refresh_token: RFC 6749 §4.4.3 forbids
		// a refresh token in a client_credentials response.
		{"m2m", []string{"client_credentials"}, false},
		{"web", []string{"authorization_code", "refresh_token"}, true},
		{"spa", []string{"authorization_code", "refresh_token"}, true},
		{"native", []string{"authorization_code", "refresh_token"}, true},
	}

	for _, tc := range cases {
		created, err := svc.CreateApplication(ctx, tenantID, "grants-"+tc.appType, tc.appType, nil)
		if err != nil {
			t.Fatalf("create %s: %v", tc.appType, err)
		}
		appID, err := strconv.ParseInt(created.ID, 10, 64)
		if err != nil {
			t.Fatalf("parse id: %v", err)
		}
		got, err := svc.GetApplication(ctx, tenantID, appID)
		if err != nil {
			t.Fatalf("get %s: %v", tc.appType, err)
		}
		if strings.Join(got.GrantTypes, ",") != strings.Join(tc.want, ",") {
			t.Errorf("%s: grant_types = %v, want %v", tc.appType, got.GrantTypes, tc.want)
		}
		if got.RequirePKCE != tc.pkce {
			t.Errorf("%s: require_pkce = %v, want %v", tc.appType, got.RequirePKCE, tc.pkce)
		}
	}
}

// TestOmittedAppTypeDefaultsToM2M pins the default. Every application registered
// in this system is a backend service using client_credentials; defaulting to web
// handed such a service grants it could never exercise, so an omitted app_type
// produced a client that could not get a token at all.
func TestOmittedAppTypeDefaultsToM2M(t *testing.T) {
	svc, ctx, tenantID, _ := newApplicationService(t)

	created, err := svc.CreateApplication(ctx, tenantID, "default-type-app", "", nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.AppType != "m2m" {
		t.Fatalf("app_type = %q, want m2m", created.AppType)
	}
	appID, err := strconv.ParseInt(created.ID, 10, 64)
	if err != nil {
		t.Fatalf("parse id: %v", err)
	}
	got, err := svc.GetApplication(ctx, tenantID, appID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if strings.Join(got.GrantTypes, ",") != "client_credentials" {
		t.Fatalf("grant_types = %v, want [client_credentials]", got.GrantTypes)
	}
}

// TestChangingAppTypeRewritesGrantTypes covers the update path. A row left with
// authorization_code after being switched to m2m describes a client /oauth/token
// will refuse, so the two fields must not be allowed to disagree.
func TestChangingAppTypeRewritesGrantTypes(t *testing.T) {
	svc, ctx, tenantID, _ := newApplicationService(t)

	created, err := svc.CreateApplication(ctx, tenantID, "retype-app", "web", nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	appID, err := strconv.ParseInt(created.ID, 10, 64)
	if err != nil {
		t.Fatalf("parse id: %v", err)
	}

	updated, err := svc.UpdateApplication(ctx, tenantID, appID, "", "m2m", nil)
	if err != nil {
		t.Fatalf("update to m2m: %v", err)
	}
	if strings.Join(updated.GrantTypes, ",") != "client_credentials" {
		t.Fatalf("after switch to m2m: grant_types = %v, want [client_credentials]", updated.GrantTypes)
	}

	// A rename must NOT disturb grant_types — only a type change re-derives them.
	renamed, err := svc.UpdateApplication(ctx, tenantID, appID, "retype-app-renamed", "", nil)
	if err != nil {
		t.Fatalf("rename: %v", err)
	}
	if strings.Join(renamed.GrantTypes, ",") != "client_credentials" {
		t.Fatalf("after rename: grant_types = %v, want unchanged [client_credentials]", renamed.GrantTypes)
	}
}

// TestApplicationDisplayNameFallsBackToName pins the read-side fallback: an
// application with no display_name reports its name there, so a consumer can
// render DisplayName unconditionally without checking which field is set.
func TestApplicationDisplayNameFallsBackToName(t *testing.T) {
	svc, ctx, tenantID, _ := newApplicationService(t)

	created, err := svc.CreateApplication(ctx, tenantID, "fallback-app", "m2m", nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	appID, err := strconv.ParseInt(created.ID, 10, 64)
	if err != nil {
		t.Fatalf("parse id: %v", err)
	}

	got, err := svc.GetApplication(ctx, tenantID, appID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.DisplayName != "fallback-app" {
		t.Errorf("DisplayName = %q, want the name %q as fallback", got.DisplayName, "fallback-app")
	}

	// Setting one takes precedence; a rename must not disturb it.
	updated, err := svc.UpdateApplicationWithOptions(ctx, tenantID, appID, "", "", nil,
		auth.AppUpdate{DisplayName: "Customer Portal"})
	if err != nil {
		t.Fatalf("set display_name: %v", err)
	}
	if updated.DisplayName != "Customer Portal" {
		t.Errorf("DisplayName = %q, want %q", updated.DisplayName, "Customer Portal")
	}

	renamed, err := svc.UpdateApplication(ctx, tenantID, appID, "fallback-app-renamed", "", nil)
	if err != nil {
		t.Fatalf("rename: %v", err)
	}
	if renamed.Name != "fallback-app-renamed" {
		t.Errorf("Name = %q, want renamed", renamed.Name)
	}
	if renamed.DisplayName != "Customer Portal" {
		t.Errorf("DisplayName = %q, want it preserved across a rename", renamed.DisplayName)
	}
}

// TestTypeChangeRederivesRequirePKCE is the update-path half of
// TestAppTypeDerivesGrantTypes.
//
// The update already re-derived grant_types on a type change but left
// require_pkce alone, so a web client converted to m2m kept require_pkce = true
// on a row with no authorization-code flow at all — the same self-contradicting
// row the create path forces false to avoid. The reverse direction was worse:
// m2m converted to spa kept require_pkce = false on a PUBLIC client, where PKCE
// is the only thing binding an authorization code to the client that requested
// it.
//
// web is the one type that keeps the choice, because it is the only confidential
// redirect flow — so an explicit require_pkce must still win there.
func TestTypeChangeRederivesRequirePKCE(t *testing.T) {
	svc, ctx, tenantID, _ := newApplicationService(t)

	newApp := func(t *testing.T, label, appType string) int64 {
		t.Helper()
		created, err := svc.CreateApplication(ctx, tenantID, label, appType, nil)
		if err != nil {
			t.Fatalf("create %s: %v", label, err)
		}
		id, err := strconv.ParseInt(created.ID, 10, 64)
		if err != nil {
			t.Fatalf("parse id: %v", err)
		}
		return id
	}
	pkceOf := func(t *testing.T, appID int64) bool {
		t.Helper()
		got, err := svc.GetApplication(ctx, tenantID, appID)
		if err != nil {
			t.Fatalf("get %d: %v", appID, err)
		}
		return got.RequirePKCE
	}
	yes, no := true, false

	t.Run("web to m2m clears it", func(t *testing.T) {
		appID := newApp(t, "pkce-web-to-m2m", "web")
		if !pkceOf(t, appID) {
			t.Fatalf("precondition: web app should start with require_pkce = true")
		}
		if _, err := svc.UpdateApplication(ctx, tenantID, appID, "", "m2m", nil); err != nil {
			t.Fatalf("update to m2m: %v", err)
		}
		if pkceOf(t, appID) {
			t.Error("require_pkce = true after converting to m2m — m2m has no authorization code to bind")
		}
	})

	t.Run("m2m to spa sets it", func(t *testing.T) {
		appID := newApp(t, "pkce-m2m-to-spa", "m2m")
		if pkceOf(t, appID) {
			t.Fatalf("precondition: m2m app should start with require_pkce = false")
		}
		if _, err := svc.UpdateApplication(ctx, tenantID, appID, "", "spa", nil); err != nil {
			t.Fatalf("update to spa: %v", err)
		}
		if !pkceOf(t, appID) {
			t.Error("require_pkce = false after converting to spa — a public client has nothing else binding the code")
		}
	})

	t.Run("m2m ignores an explicit true", func(t *testing.T) {
		appID := newApp(t, "pkce-m2m-explicit", "web")
		if _, err := svc.UpdateApplicationWithOptions(ctx, tenantID, appID, "", "m2m", nil,
			auth.AppUpdate{RequirePKCE: &yes}); err != nil {
			t.Fatalf("update to m2m with require_pkce=true: %v", err)
		}
		if pkceOf(t, appID) {
			t.Error("require_pkce = true on an m2m client — the type's rule outranks the caller, as on create")
		}
	})

	t.Run("web honours an explicit false", func(t *testing.T) {
		appID := newApp(t, "pkce-web-explicit", "m2m")
		if _, err := svc.UpdateApplicationWithOptions(ctx, tenantID, appID, "", "web", nil,
			auth.AppUpdate{RequirePKCE: &no}); err != nil {
			t.Fatalf("update to web with require_pkce=false: %v", err)
		}
		if pkceOf(t, appID) {
			t.Error("require_pkce = true on web despite an explicit false — web is the one type that keeps the choice")
		}
	})

	t.Run("unchanged type leaves the flag alone", func(t *testing.T) {
		appID := newApp(t, "pkce-untouched", "web")
		if _, err := svc.UpdateApplicationWithOptions(ctx, tenantID, appID, "", "", nil,
			auth.AppUpdate{RequirePKCE: &no}); err != nil {
			t.Fatalf("update require_pkce only: %v", err)
		}
		if pkceOf(t, appID) {
			t.Error("require_pkce = true after an explicit false with no type change — the override must still apply")
		}
		if _, err := svc.UpdateApplication(ctx, tenantID, appID, "renamed", "", nil); err != nil {
			t.Fatalf("rename: %v", err)
		}
		if pkceOf(t, appID) {
			t.Error("a rename re-derived require_pkce — with no type change the flag must be left untouched")
		}
	})
}
