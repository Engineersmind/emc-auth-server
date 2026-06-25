package middleware

import (
	"net/http"
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
// Protection: reject requests whose Origin header is present and does not end
// with the configured trusted domain.  Same-origin and Bearer-only clients
// (no Origin header) pass through unchanged.
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

			// Accept origins that end with the configured cookie domain.
			// cfg.Domain is set to e.g. ".engineersmind.com"; strip the leading dot
			// when matching so both "https://app.engineersmind.com" and
			// "https://engineersmind.com" are accepted.
			trusted := strings.TrimPrefix(cfg.Domain, ".")
			if trusted != "" && !strings.HasSuffix(origin, trusted) {
				return c.JSON(http.StatusForbidden, map[string]string{
					"error": "cross-origin request not allowed on session endpoints",
					"code":  "csrf_check_failed",
				})
			}

			return next(c)
		}
	}
}
