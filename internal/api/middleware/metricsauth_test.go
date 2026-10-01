package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
)

// GHSA-4r4c-348x-w452 (L-02): the bearer gate must be constant-time and return
// 404 (not 401) so an unauthenticated caller cannot even learn the endpoint
// exists.

func metricsRequest(t *testing.T, mw echo.MiddlewareFunc, authHeader string) *httptest.ResponseRecorder {
	t.Helper()
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	if authHeader != "" {
		req.Header.Set(echo.HeaderAuthorization, authHeader)
	}
	rec := httptest.NewRecorder()
	mw(func(c echo.Context) error { return c.NoContent(http.StatusOK) })(e.NewContext(req, rec))
	return rec
}

func TestMetricsAuth_ValidTokenPasses(t *testing.T) {
	rec := metricsRequest(t, MetricsAuth("secret-token"), "Bearer secret-token")
	if rec.Code != http.StatusOK {
		t.Errorf("valid token: status = %d, want 200", rec.Code)
	}
}

func TestMetricsAuth_InvalidToken404s(t *testing.T) {
	for _, header := range []string{"", "Bearer wrong", "Bearer secret-tok", "Bearer secret-tokenX"} {
		rec := metricsRequest(t, MetricsAuth("secret-token"), header)
		if rec.Code != http.StatusNotFound {
			t.Errorf("header %q: status = %d, want 404 (no existence leak)", header, rec.Code)
		}
	}
}

// Empty token still passes through the middleware itself — but that branch is
// unreachable in production/staging now that RegisterRoutes skips registering
// the endpoint entirely when METRICS_TOKEN is unset there.
func TestMetricsAuth_EmptyTokenPasses(t *testing.T) {
	rec := metricsRequest(t, MetricsAuth(""), "")
	if rec.Code != http.StatusOK {
		t.Errorf("empty token (dev-only branch): status = %d, want 200", rec.Code)
	}
}
