package middleware_test

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/engineersmind/emc-auth-server/internal/api/middleware"
	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// makeRequest creates a synthetic echo.Context with the given remote address and
// a JSON body carrying the given email, runs it through the provided middleware,
// and returns the HTTP status code. LoginRateLimiter keys its per-account bucket
// on the email in the body since Login no longer takes a tenant slug/header.
func makeRequest(t *testing.T, mw echo.MiddlewareFunc, remoteAddr, email string) int {
	t.Helper()
	e := echo.New()
	var body *strings.Reader
	if email != "" {
		body = strings.NewReader(`{"email":"` + email + `","password":"x"}`)
	} else {
		body = strings.NewReader(`{}`)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", body)
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = remoteAddr + ":12345"
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	// Handler that always returns 200 (simulates a successful login handler).
	handler := mw(func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
	})
	_ = handler(c)
	return rec.Code
}

// TestLoginRateLimiter_BlocksAfterFiveAttempts verifies that the 6th request
// from the same IP within a 1-minute window is blocked with HTTP 429.
// This directly verifies AUTH-07 per-IP brute-force protection.
func TestLoginRateLimiter_BlocksAfterFiveAttempts(t *testing.T) {
	// Reset the global rate limiter stores before this test so that running
	// with -count=N or after other tests does not carry over consumed token
	// buckets (CR-01: package-level singleton store isolation).
	middleware.ResetStoresForTest()

	cfg := middleware.DefaultRateLimitConfig() // PerIPRate: 5
	mw := middleware.LoginRateLimiter(cfg)

	// Use a unique IP per test invocation derived from nanosecond timestamp to
	// isolate bucket state even if ResetStoresForTest is not called between runs.
	// TEST-NET-1 (192.0.2.0/24) is reserved for documentation — safe for tests.
	ip := fmt.Sprintf("192.0.2.%d", (time.Now().UnixNano()%200)+10)

	// First 5 requests must pass (HTTP 200).
	for i := 0; i < 5; i++ {
		status := makeRequest(t, mw, ip, "emc")
		if status != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d", i+1, status)
		}
	}

	// 6th request from the same IP must be blocked (HTTP 429).
	status := makeRequest(t, mw, ip, "emc")
	if status != http.StatusTooManyRequests {
		t.Fatalf("6th request: expected 429 Too Many Requests, got %d", status)
	}
}

// TestLoginRateLimiter_PerTenantLimit verifies that a per-tenant rate limit is
// enforced independently of the per-IP limit. Different IPs hitting the same
// tenant fill the tenant bucket and are blocked once the tenant limit is exceeded.
func TestLoginRateLimiter_PerTenantLimit(t *testing.T) {
	// Reset global stores for isolation across test runs (CR-01).
	middleware.ResetStoresForTest()

	cfg := middleware.RateLimitConfig{
		PerIPRate:     1000, // effectively unlimited per IP
		PerTenantRate: 3,
	}
	mw := middleware.LoginRateLimiter(cfg)

	// Unique tenant slug per test run to prevent cross-test bucket pollution.
	tenant := "sec-test-tenant-" + strconv.Itoa(time.Now().Nanosecond())

	// Send 3 requests from different IPs but the same tenant — all must pass.
	// Use TEST-NET-2 (198.51.100.0/24) to avoid clashing with the IP range used
	// in BlocksAfterFiveAttempts (which uses 192.0.2.0/24).
	for i := 0; i < 3; i++ {
		ip := fmt.Sprintf("198.51.100.%d", 50+i) // distinct IPs so IP limit doesn't apply
		status := makeRequest(t, mw, ip, tenant)
		if status != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d", i+1, status)
		}
	}

	// 4th request from yet another IP but the same tenant — must be blocked.
	status := makeRequest(t, mw, "198.51.100.54", tenant)
	if status != http.StatusTooManyRequests {
		t.Fatalf("4th tenant request: expected 429 Too Many Requests, got %d", status)
	}
}

// TestLoginRateLimiter_DifferentIPsNotBlocked verifies that distinct IPs have
// independent per-IP buckets — filling one IP's bucket does not block another IP.
func TestLoginRateLimiter_DifferentIPsNotBlocked(t *testing.T) {
	// Reset global stores for isolation across test runs (CR-01).
	middleware.ResetStoresForTest()

	cfg := middleware.RateLimitConfig{
		PerIPRate:     2,
		PerTenantRate: 1000, // effectively unlimited per tenant
	}
	mw := middleware.LoginRateLimiter(cfg)

	// Use TEST-NET-3 (203.0.113.0/24) with a timestamp-derived suffix so these
	// IPs are unique per test invocation and cannot collide with other tests.
	// This handles both parallel runs and -count=N re-runs without bucket bleed.
	suffix := int(time.Now().UnixNano() % 100)
	ip1 := fmt.Sprintf("203.0.113.%d", suffix+1)
	ip2 := fmt.Sprintf("203.0.113.%d", suffix+2)

	status1 := makeRequest(t, mw, ip1, "tenant-a")
	status2 := makeRequest(t, mw, ip2, "tenant-a")

	if status1 != http.StatusOK {
		t.Errorf("%s first request: expected 200, got %d", ip1, status1)
	}
	if status2 != http.StatusOK {
		t.Errorf("%s first request: expected 200, got %d", ip2, status2)
	}
}

// tokenRequest runs a synthetic client_credentials request through the given
// middleware and returns the status code. Credentials are header-only: a
// non-empty clientID synthesizes an Authorization: Basic header, or pass an
// explicit basicHeader; with neither, the request is anonymous (per-IP only).
func tokenRequest(t *testing.T, mw echo.MiddlewareFunc, remoteAddr, clientID, basicHeader string) int {
	t.Helper()
	e := echo.New()
	body := strings.NewReader(`{"grant_type":"client_credentials"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/token", body)
	req.Header.Set("Content-Type", "application/json")
	if basicHeader == "" && clientID != "" {
		basicHeader = "Basic " + base64.StdEncoding.EncodeToString([]byte(clientID+":secret"))
	}
	if basicHeader != "" {
		req.Header.Set("Authorization", basicHeader)
	}
	req.RemoteAddr = remoteAddr + ":12345"
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	handler := mw(func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
	})
	_ = handler(c)
	return rec.Code
}

// TestTokenRateLimiter_IsolatesClients verifies that exhausting one client_id's
// bucket does not throttle a different client_id — the cross-tenant collision
// the email-keyed login limiter would have caused on this endpoint.
func TestTokenRateLimiter_IsolatesClients(t *testing.T) {
	middleware.ResetStoresForTest()

	// High per-IP allowance so only the per-client bucket is exercised.
	cfg := middleware.RateLimitConfig{PerIPRate: 1000, PerTenantRate: 3}
	mw := middleware.TokenRateLimiter(cfg)
	ip := fmt.Sprintf("192.0.2.%d", (time.Now().UnixNano()%200)+10)

	for i := 1; i <= 3; i++ {
		if code := tokenRequest(t, mw, ip, "app_client_A", ""); code != http.StatusOK {
			t.Fatalf("client A request %d = %d, want 200", i, code)
		}
	}
	if code := tokenRequest(t, mw, ip, "app_client_A", ""); code != http.StatusTooManyRequests {
		t.Errorf("client A request 4 = %d, want 429", code)
	}
	// A different client from the same IP must NOT be throttled.
	if code := tokenRequest(t, mw, ip, "app_client_B", ""); code != http.StatusOK {
		t.Errorf("client B request after A throttled = %d, want 200", code)
	}
}

// TestTokenRateLimiter_KeysBasicAuthHeader verifies the per-client bucket also
// keys on a client_id delivered via the Authorization Basic header.
func TestTokenRateLimiter_KeysBasicAuthHeader(t *testing.T) {
	middleware.ResetStoresForTest()

	cfg := middleware.RateLimitConfig{PerIPRate: 1000, PerTenantRate: 2}
	mw := middleware.TokenRateLimiter(cfg)
	ip := fmt.Sprintf("192.0.2.%d", (time.Now().UnixNano()%200)+10)

	// base64("app_basic_client:secret")
	header := "Basic " + base64.StdEncoding.EncodeToString([]byte("app_basic_client:secret"))
	for i := 1; i <= 2; i++ {
		if code := tokenRequest(t, mw, ip, "", header); code != http.StatusOK {
			t.Fatalf("basic-auth request %d = %d, want 200", i, code)
		}
	}
	if code := tokenRequest(t, mw, ip, "", header); code != http.StatusTooManyRequests {
		t.Errorf("basic-auth request 3 = %d, want 429", code)
	}
}

// TestTokenRateLimiter_NoClientIDFallsBackToIPOnly verifies that requests with
// no determinable client_id are limited per-IP only — never via a shared bucket.
func TestTokenRateLimiter_NoClientIDFallsBackToIPOnly(t *testing.T) {
	middleware.ResetStoresForTest()

	cfg := middleware.RateLimitConfig{PerIPRate: 2, PerTenantRate: 1000}
	mw := middleware.TokenRateLimiter(cfg)

	ipA := fmt.Sprintf("192.0.2.%d", (time.Now().UnixNano()%100)+10)
	ipB := fmt.Sprintf("192.0.2.%d", (time.Now().UnixNano()%100)+120)

	for i := 1; i <= 2; i++ {
		if code := tokenRequest(t, mw, ipA, "", ""); code != http.StatusOK {
			t.Fatalf("ipA request %d = %d, want 200", i, code)
		}
	}
	if code := tokenRequest(t, mw, ipA, "", ""); code != http.StatusTooManyRequests {
		t.Errorf("ipA request 3 = %d, want 429", code)
	}
	// A different IP with an equally anonymous request must not be affected —
	// proves there is no shared "unknown client" bucket.
	if code := tokenRequest(t, mw, ipB, "", ""); code != http.StatusOK {
		t.Errorf("ipB request after ipA throttled = %d, want 200", code)
	}
}

// TestTokenRateLimiter_ReadsClientAuthHeader covers a limiter that was mounted
// but inert.
//
// GET /auth/apps/me carries the user's Bearer token in Authorization and the
// application's credentials in X-Client-Authorization. The client_id lookup only
// consulted Authorization, so on that route it always came back empty and every
// per-application bucket was skipped — the route looked rate limited and was not.
//
// Each request uses a distinct IP so the per-IP bucket cannot be what trips;
// only the shared client_id bucket can produce the 429.
func TestTokenRateLimiter_ReadsClientAuthHeader(t *testing.T) {
	middleware.ResetStoresForTest()

	cfg := middleware.DefaultRateLimitConfig() // PerTenantRate: 10 per client_id
	mw := middleware.TokenRateLimiter(cfg)
	creds := "Basic " + base64.StdEncoding.EncodeToString([]byte("app_scoped_client:secret"))

	call := func(n int) int {
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/apps/me", nil)
		req.Header.Set("Authorization", "Bearer some.user.jwt")
		req.Header.Set(middleware.ClientAuthHeader, creds)
		// A fresh IP every call: TEST-NET-1 is reserved for documentation.
		req.RemoteAddr = fmt.Sprintf("192.0.2.%d:12345", n)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		handler := mw(func(c echo.Context) error {
			return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
		})
		_ = handler(c)
		return rec.Code
	}

	for i := 1; i <= cfg.PerTenantRate; i++ {
		if code := call(i); code != http.StatusOK {
			t.Fatalf("call %d = %d, want 200 (inside the client budget)", i, code)
		}
	}
	if code := call(cfg.PerTenantRate + 1); code != http.StatusTooManyRequests {
		t.Errorf("call %d = %d, want 429 — the client_id in %s was never read, so the bucket never filled",
			cfg.PerTenantRate+1, code, middleware.ClientAuthHeader)
	}
}

// runRotation drives one request through the signing-key rotation limiter,
// carrying the JWT claims the limiter buckets on.
func runRotation(t *testing.T, mw echo.MiddlewareFunc, tenantID string) int {
	t.Helper()
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/signing-keys/complete", nil)
	req.RemoteAddr = "192.0.2.7:12345"
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set("user", &auth.Claims{TenantID: tenantID, Role: "tenant_admin"})

	handler := mw(func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
	})
	_ = handler(c)
	return rec.Code
}

// TestSigningKeyRotationRateLimiter_BoundsRotationsPerTenant covers the PR #98
// review flag: rotation was authorised but unthrottled.
//
// The risk is not request volume. Completing a rotation retires the outgoing
// key, and a retired key leaves the published set once its grace window elapses,
// so cycling prepare→complete walks a tenant through key generations faster than
// its issued tokens expire — every token signed by a key pushed past the window
// stops verifying. The bucket is sized to let one honest two-step rotation
// through and then hold.
func TestSigningKeyRotationRateLimiter_BoundsRotationsPerTenant(t *testing.T) {
	middleware.ResetStoresForTest()
	mw := middleware.SigningKeyRotationRateLimiter()

	// One honest rotation is prepare + complete, so both must pass.
	for i := 1; i <= 2; i++ {
		if code := runRotation(t, mw, "4242"); code != http.StatusOK {
			t.Fatalf("rotation call %d = %d, want 200 — an honest rotation must not be throttled", i, code)
		}
	}
	if code := runRotation(t, mw, "4242"); code != http.StatusTooManyRequests {
		t.Errorf("third rotation call = %d, want 429", code)
	}

	// The bucket is per tenant: one tenant exhausting it must not throttle another.
	if code := runRotation(t, mw, "9999"); code != http.StatusOK {
		t.Errorf("other tenant = %d, want 200 — the bucket leaked across tenants", code)
	}
}

// passkeyBeginRequest drives one POST through PasskeyBeginRateLimiter and
// returns the status.
func passkeyBeginRequest(t *testing.T, mw echo.MiddlewareFunc, remoteAddr string) int {
	t.Helper()
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/passkey/login/begin",
		strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = remoteAddr + ":12345"
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	handler := mw(func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
	})
	_ = handler(c)
	return rec.Code
}

// TestPasskeyBeginRateLimiter_SurvivesPageViewTraffic is the regression test for
// the defect this limiter exists to fix.
//
// /passkey/login/begin is hit once per login-page VIEW by every visitor, passkey
// or not, because conditional-mediation autofill needs the challenge before the
// user interacts with the page. It previously shared TokenRateLimiter's 5/min,
// and measured five successes followed by 429 — locking out any shared egress
// address (a corporate NAT, a mobile carrier, an application backend proxying
// its users) after five page loads, silently: the console just stops offering
// the passkey button.
//
// Twenty requests is well beyond the old ceiling and still an unremarkable
// number of page views for one office.
func TestPasskeyBeginRateLimiter_SurvivesPageViewTraffic(t *testing.T) {
	middleware.ResetStoresForTest()
	mw := middleware.PasskeyBeginRateLimiter()

	for i := 1; i <= 20; i++ {
		if got := passkeyBeginRequest(t, mw, "203.0.113.10"); got != http.StatusOK {
			t.Fatalf("request %d returned %d, want 200 — a shared address is being "+
				"locked out of passkeys by ordinary page-view traffic", i, got)
		}
	}
}

// TestPasskeyBeginRateLimiter_StillClampsAbuse confirms the limit is a real
// clamp and not effectively disabled: a client scripting challenge generation
// past the configured rate is still refused.
func TestPasskeyBeginRateLimiter_StillClampsAbuse(t *testing.T) {
	middleware.ResetStoresForTest()
	mw := middleware.PasskeyBeginRateLimiter()

	// Drain the bucket.
	for i := 0; i < middleware.PasskeyBeginPerIPRate; i++ {
		if got := passkeyBeginRequest(t, mw, "203.0.113.11"); got != http.StatusOK {
			t.Fatalf("request %d of the allowance returned %d, want 200", i+1, got)
		}
	}
	if got := passkeyBeginRequest(t, mw, "203.0.113.11"); got != http.StatusTooManyRequests {
		t.Fatalf("request past the allowance returned %d, want 429 — the limit is "+
			"not clamping abuse", got)
	}
}

// TestPasskeyBeginRateLimiter_IsolatesIPs confirms one address exhausting its
// bucket cannot deny the endpoint to anyone else.
func TestPasskeyBeginRateLimiter_IsolatesIPs(t *testing.T) {
	middleware.ResetStoresForTest()
	mw := middleware.PasskeyBeginRateLimiter()

	for i := 0; i < middleware.PasskeyBeginPerIPRate; i++ {
		_ = passkeyBeginRequest(t, mw, "203.0.113.12")
	}
	if got := passkeyBeginRequest(t, mw, "203.0.113.12"); got != http.StatusTooManyRequests {
		t.Fatalf("exhausted IP returned %d, want 429", got)
	}
	if got := passkeyBeginRequest(t, mw, "203.0.113.13"); got != http.StatusOK {
		t.Fatalf("a different IP returned %d, want 200 — buckets are not isolated", got)
	}
}

// TestPasskeyBeginPerIPRate_ExceedsLoginRate pins the relationship the fix is
// about: the challenge endpoint must be allowed materially more traffic than a
// login attempt, because it is not one. Equalising them silently reintroduces
// the lockout.
func TestPasskeyBeginPerIPRate_ExceedsLoginRate(t *testing.T) {
	loginRate := middleware.DefaultRateLimitConfig().PerIPRate
	if middleware.PasskeyBeginPerIPRate <= loginRate*10 {
		t.Fatalf("PasskeyBeginPerIPRate is %d against a login rate of %d — the "+
			"challenge endpoint tracks page views, not sign-ins, and needs a "+
			"materially higher allowance", middleware.PasskeyBeginPerIPRate, loginRate)
	}
}
