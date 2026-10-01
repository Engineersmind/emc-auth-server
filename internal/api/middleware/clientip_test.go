package middleware_test

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"

	"github.com/engineersmind/emc-auth-server/internal/api/middleware"
)

// newEchoBehindProxy mirrors production (GHSA-3rxg-g9v9-4gh8): nginx reaches
// the container through Docker port forwarding, so the app sees it as the
// emc-auth-net gateway, and only that network is a trusted proxy.
//
// The existing limiter tests use a bare echo.New(), which runs Echo's legacy
// leftmost-X-Forwarded-For fallback — exactly why none of them caught this.
func newEchoBehindProxy(t *testing.T) *echo.Echo {
	t.Helper()
	_, dockerNet, err := net.ParseCIDR("172.18.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	e := echo.New()
	e.IPExtractor = middleware.ClientIPExtractor([]*net.IPNet{dockerNet})
	return e
}

func TestClientIPExtractor(t *testing.T) {
	e := newEchoBehindProxy(t)
	cases := []struct{ name, remote, xff, want string }{
		{"spoofed entry left of the real hop is ignored", "172.18.0.1:5000", "1.1.1.1, 198.51.100.7", "198.51.100.7"},
		{"nginx overwriting the header", "172.18.0.1:5000", "198.51.100.7", "198.51.100.7"},
		{"untrusted direct peer: header ignored", "198.51.100.5:5000", "1.1.1.1", "198.51.100.5"},
		{"other private ranges are not trusted", "10.0.0.5:5000", "1.1.1.1", "10.0.0.5"},
		{"garbage entry falls back to the peer", "172.18.0.1:5000", "unknown", "172.18.0.1"},
		{"no header", "198.51.100.5:5000", "", "198.51.100.5"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tc.remote
			if tc.xff != "" {
				req.Header.Set("X-Forwarded-For", tc.xff)
			}
			if got := e.NewContext(req, httptest.NewRecorder()).RealIP(); got != tc.want {
				t.Fatalf("RealIP() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestLoginRateLimiter_RotatingXFFBehindProxy is the advisory's PoC: one
// attacker rotating X-Forwarded-For must still hit the per-IP limit. Distinct
// emails keep the per-account bucket out of the way, so only the per-IP bucket
// can produce the 429s.
func TestLoginRateLimiter_RotatingXFFBehindProxy(t *testing.T) {
	middleware.ResetStoresForTest()
	mw := middleware.LoginRateLimiter(middleware.DefaultRateLimitConfig()) // PerIPRate: 5
	e := newEchoBehindProxy(t)
	h := mw(func(c echo.Context) error { return c.NoContent(http.StatusOK) })

	blocked := 0
	for i := 0; i < 20; i++ {
		body := strings.NewReader(fmt.Sprintf(`{"email":"spray%d@example.com","password":"x"}`, i))
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", body)
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "172.18.0.1:5000"
		req.Header.Set("X-Forwarded-For", fmt.Sprintf("10.9.0.%d, 203.0.113.9", i))
		rec := httptest.NewRecorder()
		_ = h(e.NewContext(req, rec))
		if rec.Code == http.StatusTooManyRequests {
			blocked++
		}
	}
	if blocked != 15 {
		t.Fatalf("blocked %d of 20, want 15 (limit 5/min for one real client IP)", blocked)
	}
}
