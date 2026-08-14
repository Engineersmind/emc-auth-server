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
	svc := auth.NewAuthService(pool, jwtSvc, logger)

	email := fmt.Sprintf("grace-409-%d@test.example.com", time.Now().UnixNano())
	if _, err := svc.Register(ctx, auth.RegisterInput{
		TenantSlug: "emc",
		Email:      email,
		Password:   "Password123!",
		FirstName:  "Grace",
		LastName:   "Hit",
	}); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	// A separate sign-in, because registration no longer issues tokens — creating an
	// account and starting a session are separate acts now.
	res, err := svc.Login(ctx, auth.LoginInput{Email: email, Password: "Password123!"})
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	reg := res.Token

	// Look up the session so we can pre-hold its rotation lock.
	var sessionID int64
	if err := pool.QueryRow(ctx,
		`SELECT session_id FROM refresh_tokens WHERE token_hash = $1`,
		auth.HashToken(reg.RefreshToken),
	).Scan(&sessionID); err != nil {
		t.Fatalf("lookup session: %v", err)
	}

	// Simulate a concurrent request that already holds the session's rotation lock.
	// The handler's SetNX will fail, sending it into the grace-window branch where
	// the still-valid token issued moments ago yields a GraceResult → 409.
	//
	// The key must match the one RefreshWithLock builds. If it drifts, this test does
	// not fail cleanly: the lock is simply not held, the handler rotates normally, and
	// the 409 assertion fails somewhere further along — which is exactly what happened
	// when the key was renamed from "family" to "session".
	lockKey := fmt.Sprintf("renewal:lock:session:%d", sessionID)
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
