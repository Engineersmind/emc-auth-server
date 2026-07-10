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

// runPermissionMiddleware executes mw against a synthetic request. When claims
// is non-nil it is stored under the "user" context key, simulating a request
// that already passed JWTRequired. Returns the HTTP status and response body.
func runPermissionMiddleware(t *testing.T, mw echo.MiddlewareFunc, claims *auth.Claims) (int, map[string]string) {
	t.Helper()
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/applications", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
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

func claimsWith(perms ...string) *auth.Claims {
	return &auth.Claims{
		UserID:      "1",
		TenantID:    "1",
		Email:       "owner@emc.acme",
		Role:        "owner",
		Permissions: perms,
	}
}

func TestRequirePermission_AllowsExactMatch(t *testing.T) {
	mw := middleware.RequirePermission("apps:write")
	code, _ := runPermissionMiddleware(t, mw, claimsWith("users:read", "apps:write"))
	if code != http.StatusOK {
		t.Errorf("status = %d, want %d", code, http.StatusOK)
	}
}

func TestRequirePermission_DeniesMissingPermission(t *testing.T) {
	mw := middleware.RequirePermission("apps:write")
	code, body := runPermissionMiddleware(t, mw, claimsWith("apps:read"))
	if code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", code, http.StatusForbidden)
	}
	if body["required"] != "apps:write" {
		t.Errorf(`body["required"] = %q, want "apps:write"`, body["required"])
	}
}

func TestRequirePermission_DeniesWhenClaimsAbsent(t *testing.T) {
	mw := middleware.RequirePermission("apps:write")
	code, _ := runPermissionMiddleware(t, mw, nil)
	if code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", code, http.StatusForbidden)
	}
}

func TestRequireAnyPermission_AllowsGranularPermission(t *testing.T) {
	// A tenant owner holding the granular permission (but NOT admin:access)
	// must pass — this is the core of issue #56.
	mw := middleware.RequireAnyPermission("apps:write", "admin:access")
	code, _ := runPermissionMiddleware(t, mw, claimsWith("apps:read", "apps:write"))
	if code != http.StatusOK {
		t.Errorf("status = %d, want %d", code, http.StatusOK)
	}
}

func TestRequireAnyPermission_AllowsAdminAccessFallback(t *testing.T) {
	// Super_admin holds only the coarse admin:access permission and must
	// retain access to every tenant-admin route.
	mw := middleware.RequireAnyPermission("apps:write", "admin:access")
	code, _ := runPermissionMiddleware(t, mw, claimsWith("tenant:manage", "admin:access"))
	if code != http.StatusOK {
		t.Errorf("status = %d, want %d", code, http.StatusOK)
	}
}

func TestRequireAnyPermission_DeniesWhenNoListedPermissionHeld(t *testing.T) {
	// apps:read alone must not grant a route guarded by apps:write.
	mw := middleware.RequireAnyPermission("apps:write", "admin:access")
	code, body := runPermissionMiddleware(t, mw, claimsWith("apps:read", "users:read"))
	if code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", code, http.StatusForbidden)
	}
	if body["required"] != "apps:write OR admin:access" {
		t.Errorf(`body["required"] = %q, want "apps:write OR admin:access"`, body["required"])
	}
}

func TestRequireAnyPermission_DeniesEmptyPermissionsClaim(t *testing.T) {
	mw := middleware.RequireAnyPermission("apps:write", "admin:access")
	code, _ := runPermissionMiddleware(t, mw, claimsWith())
	if code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", code, http.StatusForbidden)
	}
}

func TestRequireAnyPermission_DeniesWhenClaimsAbsent(t *testing.T) {
	mw := middleware.RequireAnyPermission("apps:write", "admin:access")
	code, _ := runPermissionMiddleware(t, mw, nil)
	if code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", code, http.StatusForbidden)
	}
}

// runSelfOrAnyMiddleware is runPermissionMiddleware with a :tid path param,
// simulating a request routed through /tenants/:tid/....
func runSelfOrAnyMiddleware(t *testing.T, mw echo.MiddlewareFunc, claims *auth.Claims, tid string) (int, map[string]string) {
	t.Helper()
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/"+tid+"/roles", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("tid")
	c.SetParamValues(tid)
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

func TestRequireTenantSelfOrAny_AllowsOwnTenantWithPermission(t *testing.T) {
	// An owner (tenant 1) with roles:write reaching /tenants/1/... must pass.
	mw := middleware.RequireTenantSelfOrAny("roles:write")
	code, _ := runSelfOrAnyMiddleware(t, mw, claimsWith("roles:read", "roles:write"), "1")
	if code != http.StatusOK {
		t.Errorf("status = %d, want %d", code, http.StatusOK)
	}
}

func TestRequireTenantSelfOrAny_DeniesOtherTenantEvenWithPermission(t *testing.T) {
	// The same owner reaching /tenants/2/... must be denied — the granular
	// permission never grants cross-tenant access.
	mw := middleware.RequireTenantSelfOrAny("roles:write")
	code, _ := runSelfOrAnyMiddleware(t, mw, claimsWith("roles:write"), "2")
	if code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", code, http.StatusForbidden)
	}
}

func TestRequireTenantSelfOrAny_AllowsTenantManageAnyTenant(t *testing.T) {
	// super_admin (tenant:manage) may target any tenant.
	mw := middleware.RequireTenantSelfOrAny("roles:write")
	code, _ := runSelfOrAnyMiddleware(t, mw, claimsWith("tenant:manage", "admin:access"), "42")
	if code != http.StatusOK {
		t.Errorf("status = %d, want %d", code, http.StatusOK)
	}
}

func TestRequireTenantSelfOrAny_DeniesOwnTenantWithoutPermission(t *testing.T) {
	// Matching tenant alone is not enough — the resource permission is required.
	mw := middleware.RequireTenantSelfOrAny("roles:write")
	code, _ := runSelfOrAnyMiddleware(t, mw, claimsWith("roles:read"), "1")
	if code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", code, http.StatusForbidden)
	}
}

func TestRequireTenantSelfOrAny_AllowsAdminAccessFallbackOwnTenant(t *testing.T) {
	// Legacy roles holding only the coarse admin:access permission keep
	// working on their own tenant, mirroring RequireAnyPermission's fallback.
	mw := middleware.RequireTenantSelfOrAny("users:read")
	code, _ := runSelfOrAnyMiddleware(t, mw, claimsWith("admin:access"), "1")
	if code != http.StatusOK {
		t.Errorf("status = %d, want %d", code, http.StatusOK)
	}
}

func TestRequireTenantSelfOrAny_DeniesAdminAccessOtherTenant(t *testing.T) {
	// admin:access must never cross tenants — only tenant:manage does.
	mw := middleware.RequireTenantSelfOrAny("users:read")
	code, _ := runSelfOrAnyMiddleware(t, mw, claimsWith("admin:access"), "2")
	if code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", code, http.StatusForbidden)
	}
}

func TestRequireTenantSelfOrAny_DeniesMalformedTid(t *testing.T) {
	mw := middleware.RequireTenantSelfOrAny("roles:write")
	code, _ := runSelfOrAnyMiddleware(t, mw, claimsWith("roles:write"), "not-a-number")
	if code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", code, http.StatusForbidden)
	}
}

func TestRequireTenantSelfOrAny_DeniesWhenClaimsAbsent(t *testing.T) {
	mw := middleware.RequireTenantSelfOrAny("roles:write")
	code, _ := runSelfOrAnyMiddleware(t, mw, nil, "1")
	if code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", code, http.StatusForbidden)
	}
}
