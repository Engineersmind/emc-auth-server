package middleware_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"

	"github.com/engineersmind/emc-auth-server/internal/api/middleware"
	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// runAppScopeMiddleware simulates a request routed through
// /tenants/:tid/applications/:appID/....
func runAppScopeMiddleware(t *testing.T, mw echo.MiddlewareFunc, claims *auth.Claims, tid, appID string) (int, map[string]string) {
	t.Helper()
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/"+tid+"/applications/"+appID+"/users", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("tid", "appID")
	c.SetParamValues(tid, appID)
	if claims != nil {
		c.Set("user", claims)
	}

	handler := mw(func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
	})
	if err := handler(c); err != nil {
		t.Fatalf("middleware returned unexpected error: %v", err)
	}

	body := map[string]string{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response body is not JSON: %v", err)
	}
	return rec.Code, body
}

// adminClaims builds claims for a tenant-1 administrator with the given
// administrative reach.
func adminClaims(scope string, apps []string, perms ...string) *auth.Claims {
	return &auth.Claims{
		UserID:      "1",
		TenantID:    "1",
		Email:       "admin@emc.acme",
		Role:        "owner",
		Permissions: perms,
		AdminScope:  scope,
		AdminApps:   apps,
	}
}

func TestRequireAppScope_OwnerReachesAnyApplication(t *testing.T) {
	// An owner holds no grants at all — their reach is the absence of them —
	// so every application in their tenant must pass, including ids they have
	// never been explicitly associated with.
	mw := middleware.RequireAppScope("appID", "users:read")
	for _, appID := range []string{"7", "99", "1234"} {
		code, body := runAppScopeMiddleware(t, mw, adminClaims(auth.AdminScopeTenant, nil, "users:read"), "1", appID)
		if code != http.StatusOK {
			t.Errorf("app %s: status = %d, want %d (body %v)", appID, code, http.StatusOK, body)
		}
	}
}

func TestRequireAppScope_CoOwnerReachesOnlyGrantedApplications(t *testing.T) {
	mw := middleware.RequireAppScope("appID", "users:read")
	claims := adminClaims(auth.AdminScopeApps, []string{"7", "9"}, "users:read")

	if code, _ := runAppScopeMiddleware(t, mw, claims, "1", "7"); code != http.StatusOK {
		t.Errorf("granted app: status = %d, want %d", code, http.StatusOK)
	}
	// This is the escalation RequireTenantSelfOrAny could not prevent: same
	// tenant, same permission, an application that was never granted.
	code, body := runAppScopeMiddleware(t, mw, claims, "1", "8")
	if code != http.StatusForbidden {
		t.Errorf("ungranted app: status = %d, want %d", code, http.StatusForbidden)
	}
	if body["required"] != "a grant for application 8" {
		t.Errorf(`body["required"] = %q, want the ungranted application named`, body["required"])
	}
}

func TestRequireAppScope_CoOwnerWithNoGrantsReachesNothing(t *testing.T) {
	// Empty grants must mean no access, never all access. A co-owner whose
	// last grant was revoked is the case that matters.
	mw := middleware.RequireAppScope("appID", "users:read")
	code, _ := runAppScopeMiddleware(t, mw, adminClaims(auth.AdminScopeApps, []string{}, "users:read"), "1", "7")
	if code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", code, http.StatusForbidden)
	}
}

func TestRequireAppScope_DeniesAbsentScopeClaim(t *testing.T) {
	// Fail closed: a token minted before admin_scope existed, or by a future
	// code path that forgot to populate it, must not be read as unrestricted.
	mw := middleware.RequireAppScope("appID", "users:read")
	code, body := runAppScopeMiddleware(t, mw, adminClaims("", nil, "users:read"), "1", "7")
	if code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", code, http.StatusForbidden)
	}
	if body["required"] == "" {
		t.Error("denial should explain that re-authentication is needed")
	}
}

func TestRequireAppScope_PlatformAdminReachesAnyTenantAndApplication(t *testing.T) {
	// tenant:manage is cross-tenant and is not a tenant_admins membership, so
	// it carries no admin_scope and must still pass.
	mw := middleware.RequireAppScope("appID", "users:read")
	code, _ := runAppScopeMiddleware(t, mw, adminClaims("", nil, "tenant:manage"), "42", "7")
	if code != http.StatusOK {
		t.Errorf("status = %d, want %d", code, http.StatusOK)
	}
}

func TestRequireAppScope_DeniesOtherTenantEvenWithGrant(t *testing.T) {
	// A grant naming application 7 must not authorise application 7 of some
	// other tenant: the tenant check runs first, and grants are compared only
	// after it passes.
	mw := middleware.RequireAppScope("appID", "users:read")
	code, _ := runAppScopeMiddleware(t, mw, adminClaims(auth.AdminScopeApps, []string{"7"}, "users:read"), "2", "7")
	if code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", code, http.StatusForbidden)
	}
}

func TestRequireAppScope_DeniesMissingPermissionEvenWithGrant(t *testing.T) {
	// Grants narrow reach; they never substitute for the permission itself.
	mw := middleware.RequireAppScope("appID", "users:write")
	code, _ := runAppScopeMiddleware(t, mw, adminClaims(auth.AdminScopeApps, []string{"7"}, "users:read"), "1", "7")
	if code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", code, http.StatusForbidden)
	}
}

func TestRequireAppScope_DeniesNonNumericApplicationID(t *testing.T) {
	mw := middleware.RequireAppScope("appID", "users:read")
	code, _ := runAppScopeMiddleware(t, mw, adminClaims(auth.AdminScopeApps, []string{"7"}, "users:read"), "1", "seven")
	if code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", code, http.StatusForbidden)
	}
}

func TestRequireAppScope_ReadsTheNamedPathParam(t *testing.T) {
	// /applications/:id binds the application to :id, not :appID. Reading the
	// wrong parameter would compare a grant against an empty string (deny
	// everything) or, on a nested route, against a role id.
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/1/applications/7", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("tid", "id")
	c.SetParamValues("1", "7")
	c.Set("user", adminClaims(auth.AdminScopeApps, []string{"7"}, "apps:read"))

	h := middleware.RequireAppScope("id", "apps:read")(func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
	})
	if err := h(c); err != nil {
		t.Fatalf("middleware returned unexpected error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

// Creating an application is reserved to a platform admin and a tenant owner.
// A co-owner administers applications; they do not bring new ones into
// existence, and nothing they were granted implies authority over the tenant's
// shape.
//
// The flat routes are the ones that needed closing: they name no application in
// the path and take their tenant from claims, so apps:write alone let a co-owner
// create, edit or delete ANY application, bypassing the per-application guards
// on the canonical family entirely.
func TestRequireAnyPermission_DeniesCoOwnerOnTenantWideRoutes(t *testing.T) {
	mw := middleware.RequireAnyPermission("apps:write", "admin:access")
	coOwner := adminClaims(auth.AdminScopeApps, []string{"7"}, "apps:write")
	if code, _ := runPermissionMiddleware(t, mw, coOwner); code != http.StatusForbidden {
		t.Errorf("co-owner creating an application: status = %d, want %d", code, http.StatusForbidden)
	}

	// An owner and a platform admin are unaffected, and so is a caller whose
	// token predates the scope claim.
	for name, claims := range map[string]*auth.Claims{
		"owner":          adminClaims(auth.AdminScopeTenant, nil, "apps:write"),
		"platform admin": adminClaims("", nil, "admin:access"),
		"legacy admin":   adminClaims("", nil, "apps:write"),
	} {
		if code, _ := runPermissionMiddleware(t, mw, claims); code != http.StatusOK {
			t.Errorf("%s: status = %d, want %d", name, code, http.StatusOK)
		}
	}
}

func TestRequireAnyPermissionScoped_AllowsCoOwnerOnMonitoring(t *testing.T) {
	// Monitoring is the exception: the handler narrows the events to the
	// caller's own applications, so admitting them here shows them their own
	// data rather than the tenant's.
	mw := middleware.RequireAnyPermissionScoped("audit:read", "admin:access")
	coOwner := adminClaims(auth.AdminScopeApps, []string{"7"}, "audit:read")
	if code, _ := runPermissionMiddleware(t, mw, coOwner); code != http.StatusOK {
		t.Errorf("co-owner reading audit logs: status = %d, want %d", code, http.StatusOK)
	}
	// The permission is still required.
	noPerm := adminClaims(auth.AdminScopeApps, []string{"7"}, "apps:read")
	if code, _ := runPermissionMiddleware(t, mw, noPerm); code != http.StatusForbidden {
		t.Errorf("co-owner without audit:read: status = %d, want %d", code, http.StatusForbidden)
	}
}

// Creating a tenant is reserved to a platform admin. Neither tier of tenant
// administrator holds tenant:manage, so both are refused — this asserts the
// rule rather than leaving it to be inferred from who happens to hold what.
func TestRequirePermission_TenantCreationIsPlatformAdminOnly(t *testing.T) {
	mw := middleware.RequirePermission("tenant:manage")

	for name, claims := range map[string]*auth.Claims{
		"owner":    adminClaims(auth.AdminScopeTenant, nil, "apps:write", "users:write", "admin:access"),
		"co-owner": adminClaims(auth.AdminScopeApps, []string{"7"}, "apps:write", "users:write"),
	} {
		if code, _ := runPermissionMiddleware(t, mw, claims); code != http.StatusForbidden {
			t.Errorf("%s creating a tenant: status = %d, want %d", name, code, http.StatusForbidden)
		}
	}
	if code, _ := runPermissionMiddleware(t, mw, adminClaims("", nil, "tenant:manage")); code != http.StatusOK {
		t.Errorf("platform admin creating a tenant: status = %d, want %d", code, http.StatusOK)
	}
}

func TestRequireTenantSelfOrAny_DeniesCoOwner(t *testing.T) {
	// A co-owner holds the same permission NAMES as an owner, because a
	// permission says what an administrator may do rather than to which
	// application. Without this check they would bypass per-application scoping
	// entirely by calling the tenant-level route instead.
	mw := middleware.RequireTenantSelfOrAny("users:write")
	claims := adminClaims(auth.AdminScopeApps, []string{"7"}, "users:write")
	code, _ := runSelfOrAnyMiddleware(t, mw, claims, "1")
	if code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", code, http.StatusForbidden)
	}
}

func TestRequireTenantSelfScoped_AllowsCoOwnerOnTheCollection(t *testing.T) {
	// The applications LIST is the one tenant-level route a co-owner has to
	// reach — it is how they find the applications they administer. Refusing it
	// left them on "failed to load applications" with no way into their work.
	//
	// Safe only because ListApplications narrows the response to their grants;
	// the guard cannot do that itself.
	mw := middleware.RequireTenantSelfScoped("apps:read")
	claims := adminClaims(auth.AdminScopeApps, []string{"7"}, "apps:read")
	if code, _ := runSelfOrAnyMiddleware(t, mw, claims, "1"); code != http.StatusOK {
		t.Errorf("co-owner on the applications list: status = %d, want %d", code, http.StatusOK)
	}

	// Still bounded by tenant, and still needs the permission.
	if code, _ := runSelfOrAnyMiddleware(t, mw, claims, "2"); code != http.StatusForbidden {
		t.Errorf("co-owner on another tenant: status = %d, want %d", code, http.StatusForbidden)
	}
	noPerm := adminClaims(auth.AdminScopeApps, []string{"7"}, "users:read")
	if code, _ := runSelfOrAnyMiddleware(t, mw, noPerm, "1"); code != http.StatusForbidden {
		t.Errorf("co-owner without apps:read: status = %d, want %d", code, http.StatusForbidden)
	}
}

func TestRequireTenantSelfOrAny_AllowsOwnerAndLegacyAdmin(t *testing.T) {
	mw := middleware.RequireTenantSelfOrAny("users:write")

	if code, _ := runSelfOrAnyMiddleware(t, mw, adminClaims(auth.AdminScopeTenant, nil, "users:write"), "1"); code != http.StatusOK {
		t.Errorf("owner: status = %d, want %d", code, http.StatusOK)
	}
	// An absent claim means an administrator predating tenant_admins, who is
	// tenant-wide by definition and must keep working.
	if code, _ := runSelfOrAnyMiddleware(t, mw, adminClaims("", nil, "users:write"), "1"); code != http.StatusOK {
		t.Errorf("legacy admin: status = %d, want %d", code, http.StatusOK)
	}
}
