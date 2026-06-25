package middleware

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/labstack/echo/v4"
)

// SessionCSRF protects session-mutating cookie endpoints from CSRF attacks.
//
// With SameSite=None (staging/production), browsers attach cookies to all
// cross-site requests, including form POSTs from attacker-controlled pages.
// The attacker cannot read the response (CORS blocks that), but rotation still
// occurs — revoking the victim's in-flight token.
//
// Protection: reject requests whose Origin header is present and whose host
// does not match the trusted domain at a label boundary.  Same-origin and
// Bearer-only clients (no Origin header) pass through unchanged.
//
// Security properties:
//
//   - Label-boundary check: "evil-engineersmind.com" does NOT match trusted
//     domain "engineersmind.com" because HasSuffix(".engineersmind.com") fails.
//
//   - Fail-closed on missing domain: if COOKIE_DOMAIN is not set in production
//     (cfg.Secure=true, cfg.Domain=""), all cross-origin requests are rejected
//     rather than silently accepted.
//
// Apply only to state-mutating session endpoints:
//   - POST /auth/session (login)
//   - POST /auth/session/refresh
//   - POST /auth/session/logout
func SessionCSRF(cfg CookieConfig) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// In development, SameSite=Lax already prevents cross-site requests;
			// skip the Origin check to avoid breaking localhost setups.
			if !cfg.Secure {
				return next(c)
			}

			origin := c.Request().Header.Get("Origin")
			if origin == "" {
				// No Origin header — non-browser client or same-origin request.
				return next(c)
			}

			// cfg.Domain is e.g. ".engineersmind.com"; strip the leading dot to get
			// the bare hostname used for comparison.
			trusted := strings.TrimPrefix(cfg.Domain, ".")

			// Fail-closed: if ENV=production but COOKIE_DOMAIN is not configured,
			// reject all cross-origin requests rather than accepting every origin.
			if trusted == "" {
				return c.JSON(http.StatusForbidden, map[string]string{
					"error": "CSRF check misconfigured: COOKIE_DOMAIN must be set in production",
					"code":  "csrf_misconfigured",
				})
			}

			// Parse the Origin header to extract the hostname.
			// Malformed or opaque origins (e.g. "null") are treated as untrusted.
			u, parseErr := url.Parse(origin)
			if parseErr != nil || u.Host == "" {
				return c.JSON(http.StatusForbidden, map[string]string{
					"error": "cross-origin request not allowed on session endpoints",
					"code":  "csrf_check_failed",
				})
			}

			// u.Hostname() strips any port suffix so "app.engineersmind.com:443"
			// is treated the same as "app.engineersmind.com".
			host := u.Hostname()

			// Label-boundary match: exact equality OR subdomain with a "." separator.
			// This prevents "evil-engineersmind.com" from matching "engineersmind.com".
			if host != trusted && !strings.HasSuffix(host, "."+trusted) {
				return c.JSON(http.StatusForbidden, map[string]string{
					"error": "cross-origin request not allowed on session endpoints",
					"code":  "csrf_check_failed",
				})
			}

			return next(c)
		}
	}
}
