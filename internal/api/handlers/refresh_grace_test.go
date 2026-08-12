package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"

	mw "github.com/engineersmind/emc-auth-server/internal/api/middleware"
	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/store"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// grace409Fixture registers a tenant-level user and returns the handler (wired
// with a real service + Redis), the user's refresh token, and its session
// family id. It then holds the per-family rotation lock in Redis so the next
// RefreshWithLock call is forced down the grace-window path — the branch the
// handler maps to HTTP 409 (`concurrent_refresh`).
//
// This is the previously-untested middle branch flagged in the #83 review: the
// happy path (200) and the replay path (401) were covered, but not the
// concurrent-rotation 409 that the explicit refresh endpoints now return.
func grace409Fixture(t *testing.T) (*AuthHandler, string) {
	return grace409FixtureScoped(t, false)
}

// grace409FixtureScoped builds the grace-window fixture for either identity
// shape. appScoped=true registers the user through an application's
// client_id/client_secret so the resulting tokens carry an app_id claim — the
// identity that, since issue #108, takes a different 200 branch in Refresh. A
// grace hit must still be a 409 with no token pair for it, because the new
// branch sits strictly after the grace return. This states that as a fact
// rather than leaving it as an assumption.
func grace409FixtureScoped(t *testing.T, appScoped bool) (*AuthHandler, string) {
	t.Helper()

	pool := testhelper.NewTestDB(t)
	rdb := testhelper.NewTestRedis(t)
	logger := testhelper.TestLogger()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}
	t.Cleanup(func() { testhelper.CleanupTables(t, pool) })

	jwtSvc, err := auth.NewJWTService(pool, "https://auth.emc.local")
	if err != nil {
		t.Fatalf("NewJWTService: %v", err)
	}
	appSvc := auth.NewApplicationService(pool, logger)
	svc := auth.NewAuthService(pool, jwtSvc, logger).WithApplications(appSvc)

	in := auth.RegisterInput{
		TenantSlug: "emc",
		Email:      fmt.Sprintf("grace-409-%d@test.example.com", time.Now().UnixNano()),
		Password:   "Password123!",
		FirstName:  "Grace",
		LastName:   "Hit",
	}
	if appScoped {
		var tenantID int64
		if err := pool.QueryRow(ctx,
			`SELECT id FROM tenants WHERE slug = 'emc' AND deleted_at IS NULL`,
		).Scan(&tenantID); err != nil {
			t.Fatalf("fetch seed tenant id: %v", err)
		}
		app, err := appSvc.CreateApplication(ctx, tenantID, fmt.Sprintf("grace-409-app-%d", time.Now().UnixNano()), "web", nil)
		if err != nil {
			t.Fatalf("CreateApplication() error = %v", err)
		}
		in.TenantSlug = ""
		in.ClientID = app.ClientID
		in.ClientSecret = app.ClientSecret
	}

	reg, err := svc.Register(ctx, in)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	// Look up the session family so we can pre-hold its rotation lock.
	var familyID int64
	if err := pool.QueryRow(ctx,
		`SELECT session_family_id FROM refresh_tokens WHERE token_hash = $1`,
		auth.HashToken(reg.RefreshToken),
	).Scan(&familyID); err != nil {
		t.Fatalf("lookup session family: %v", err)
	}

	// Simulate a concurrent request that already holds the family lock. The
	// handler's SetNX will fail, sending it into the grace-window branch where
	// the still-valid token issued moments ago yields a GraceResult → 409.
	lockKey := fmt.Sprintf("renewal:lock:family:%d", familyID)
	ok, err := rdb.SetNX(ctx, lockKey, "1", 5*time.Second).Result()
	if err != nil {
		t.Fatalf("pre-hold rotation lock: %v", err)
	}
	if !ok {
		t.Fatal("could not acquire rotation lock for test setup")
	}

	// audit + resetSvc are nil: the grace branch returns before any audit call.
	h := NewAuthHandler(svc, nil, nil, logger).
		WithRedis(rdb).
		WithCookieConfig(mw.CookieConfig{})

	return h, reg.RefreshToken
}

// assertConcurrentRefresh409 checks the handler wrote a 409 carrying the
// documented concurrent_refresh code and no token pair.
func assertConcurrentRefresh409(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 (body: %s)", rec.Code, rec.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v (raw: %s)", err, rec.Body.String())
	}
	if body["code"] != "concurrent_refresh" {
		t.Errorf("code = %q, want %q", body["code"], "concurrent_refresh")
	}
	if body["access_token"] != "" || body["refresh_token"] != "" {
		t.Errorf("409 response unexpectedly carried a token pair: %v", body)
	}
}

// TestRefresh_ConcurrentRotationReturns409 exercises the body-based
// POST /api/v1/auth/refresh grace-hit branch: a concurrent caller must get a
// 409 concurrent_refresh with no token pair (the sibling request's response
// carries the fresh tokens).
func TestRefresh_ConcurrentRotationReturns409(t *testing.T) {
	h, refreshToken := grace409Fixture(t)

	e := echo.New()
	body := fmt.Sprintf(`{"refresh_token":%q}`, refreshToken)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", strings.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if err := h.Refresh(c); err != nil {
		t.Fatalf("Refresh() returned error: %v", err)
	}
	assertConcurrentRefresh409(t, rec)
}

// TestRefresh_AppScopedConcurrentRotationReturns409 is the same grace hit for an
// application-scoped identity. Since issue #108 those callers get the token pair
// in the 200 body; a grace hit must not become a token response, because there
// is no fresh pair to hand back — the sibling request holds it. The new branch
// is placed after the grace return, and this pins it there.
func TestRefresh_AppScopedConcurrentRotationReturns409(t *testing.T) {
	h, refreshToken := grace409FixtureScoped(t, true)

	e := echo.New()
	body := fmt.Sprintf(`{"refresh_token":%q}`, refreshToken)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", strings.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if err := h.Refresh(c); err != nil {
		t.Fatalf("Refresh() returned error: %v", err)
	}
	assertConcurrentRefresh409(t, rec)
}

// TestSessionRefresh_ConcurrentRotationReturns409 exercises the same grace-hit
// branch on the cookie-based POST /api/v1/auth/session/refresh endpoint.
func TestSessionRefresh_ConcurrentRotationReturns409(t *testing.T) {
	h, refreshToken := grace409Fixture(t)

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/session/refresh", nil)
	req.AddCookie(&http.Cookie{Name: mw.RefreshTokenCookie, Value: refreshToken})
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if err := h.SessionRefresh(c); err != nil {
		t.Fatalf("SessionRefresh() returned error: %v", err)
	}
	assertConcurrentRefresh409(t, rec)
}
