package middleware_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/engineersmind/emc-auth-server/internal/api/middleware"
)

// makeRequest creates a synthetic echo.Context with the given remote address and
// X-Tenant-Slug header, runs it through the provided middleware, and returns the
// HTTP status code.
func makeRequest(t *testing.T, mw echo.MiddlewareFunc, remoteAddr, tenantSlug string) int {
	t.Helper()
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	req.RemoteAddr = remoteAddr + ":12345"
	if tenantSlug != "" {
		req.Header.Set("X-Tenant-Slug", tenantSlug)
	}
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
