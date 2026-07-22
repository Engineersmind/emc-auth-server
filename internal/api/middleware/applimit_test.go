package middleware_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/labstack/echo/v4"

	"github.com/engineersmind/emc-auth-server/internal/api/middleware"
	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/store"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// appLimitEnv builds the AppRateLimiter middleware backed by real DB + Redis,
// returning the middleware plus the tenant/app ids used to key limits.
func appLimitEnv(t *testing.T) (echo.MiddlewareFunc, *auth.AppRateLimitService, int64, int64) {
	t.Helper()
	pool := testhelper.NewTestDB(t)
	rdb := testhelper.NewTestRedis(t)
	testhelper.CleanupTables(t, pool)
	logger := testhelper.TestLogger()

	ctx := context.Background()
	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}
	var tenantID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM tenants WHERE slug = 'emc' AND deleted_at IS NULL`).Scan(&tenantID); err != nil {
		t.Fatalf("fetch seed tenant: %v", err)
	}
	app, err := auth.NewApplicationService(pool, logger).CreateApplication(ctx, tenantID, "mw-rl-app", "spa", nil)
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}
	appID, _ := strconv.ParseInt(app.ID, 10, 64)

	svc := auth.NewAppRateLimitService(pool, rdb, logger)
	return middleware.AppRateLimiter(svc, rdb, logger), svc, tenantID, appID
}

// runWithClaims sends one request through the middleware with the given claims
// stored in context (mimicking a prior JWT middleware) and returns the status.
func runWithClaims(mw echo.MiddlewareFunc, claims *auth.Claims) int {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	if claims != nil {
		c.Set("user", claims) // key matches middleware.userContextKey
	}
	handler := mw(func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
	})
	_ = handler(c)
	return rec.Code
}

func TestAppRateLimiter_BlocksOverLimit(t *testing.T) {
	mw, svc, tenantID, appID := appLimitEnv(t)
	if _, err := svc.SetAppLimit(context.Background(), tenantID, appID, 2, 2, ""); err != nil {
		t.Fatalf("SetAppLimit: %v", err)
	}
	claims := &auth.Claims{TenantID: strconv.FormatInt(tenantID, 10), AppID: strconv.FormatInt(appID, 10)}

	// Burst of 2: first two allowed, third blocked.
	if code := runWithClaims(mw, claims); code != http.StatusOK {
		t.Errorf("request 1 = %d, want 200", code)
	}
	if code := runWithClaims(mw, claims); code != http.StatusOK {
		t.Errorf("request 2 = %d, want 200", code)
	}
	if code := runWithClaims(mw, claims); code != http.StatusTooManyRequests {
		t.Errorf("request 3 = %d, want 429", code)
	}
}

func TestAppRateLimiter_SkipsWithoutAppContext(t *testing.T) {
	mw, _, tenantID, _ := appLimitEnv(t)

	// No claims at all → passed through (unauthenticated path reaching here).
	if code := runWithClaims(mw, nil); code != http.StatusOK {
		t.Errorf("no claims = %d, want 200 (skip)", code)
	}
	// First-party token with empty app_id → not per-app limited even under load.
	claims := &auth.Claims{TenantID: strconv.FormatInt(tenantID, 10), AppID: ""}
	for i := 0; i < 5; i++ {
		if code := runWithClaims(mw, claims); code != http.StatusOK {
			t.Fatalf("empty app_id request %d = %d, want 200 (no per-app limit)", i+1, code)
		}
	}
}

func TestAppRateLimiter_PerAppIsolation(t *testing.T) {
	mw, svc, tenantID, appID := appLimitEnv(t)
	if _, err := svc.SetAppLimit(context.Background(), tenantID, appID, 1, 1, ""); err != nil {
		t.Fatalf("SetAppLimit: %v", err)
	}
	limited := &auth.Claims{TenantID: strconv.FormatInt(tenantID, 10), AppID: strconv.FormatInt(appID, 10)}

	// Exhaust the limited app's bucket.
	_ = runWithClaims(mw, limited)
	if code := runWithClaims(mw, limited); code != http.StatusTooManyRequests {
		t.Fatalf("limited app second request = %d, want 429", code)
	}

	// A different app id (no config → default 60/min) is unaffected.
	other := &auth.Claims{TenantID: strconv.FormatInt(tenantID, 10), AppID: strconv.FormatInt(appID+1, 10)}
	if code := runWithClaims(mw, other); code != http.StatusOK {
		t.Errorf("other app = %d, want 200 (isolated bucket)", code)
	}
}
