package middleware

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
)

// MetricsAuth gates the Prometheus scrape endpoint behind a bearer token.
// An empty token disables the check entirely — that permissive branch is only
// reachable in development/test, where RegisterRoutes still registers the
// endpoint without a token. In production/staging the route is not registered
// unless METRICS_TOKEN is set, so this middleware's empty-token pass-through
// cannot be reached there (GHSA-4r4c-348x-w452, L-02).
//
// This is defence in depth, not the primary control. The network-level
// restriction is easy to omit — a catch-all `location /` in nginx publishes
// /metrics along with the API — and the registry exposes tenant identifiers,
// login and token volumes, MFA lockout counts, risk-signal counts, and the
// internal route table. For an auth server that is reconnaissance material, so
// a proxy misconfiguration should not be enough on its own to leak it.
//
// Prometheus sends the token via `authorization` in its scrape config:
//
//	scrape_configs:
//	  - job_name: emc-auth-server
//	    authorization:
//	      credentials: <METRICS_TOKEN>
func MetricsAuth(token string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		if token == "" {
			return next
		}
		want := []byte(token)
		return func(c echo.Context) error {
			got := strings.TrimPrefix(c.Request().Header.Get(echo.HeaderAuthorization), "Bearer ")
			// Constant-time compare: the token is a fixed shared secret, so a
			// length-or-prefix-dependent comparison would leak it to a caller
			// able to time repeated scrapes.
			if subtle.ConstantTimeCompare([]byte(got), want) != 1 {
				// 404 rather than 401: an unauthenticated caller learns nothing
				// about whether a metrics endpoint exists here at all.
				return c.NoContent(http.StatusNotFound)
			}
			return next(c)
		}
	}
}
