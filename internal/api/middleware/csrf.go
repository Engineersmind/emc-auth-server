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
			if err := checkTrustedOrigin(c, cfg); err != nil {
				return err
			}
			return next(c)
		}
	}
}

// CookieCSRF protects every state-mutating API route from cross-site requests
// made with the browser's session cookies.
//
// Scope is deliberately narrow — it engages only when ALL of these hold:
//
//   - SameSite=None is in effect (staging/production). Development uses Lax,
//     which the browser already refuses to attach to cross-site requests.
//   - The request mutates state (POST/PUT/PATCH/DELETE). Safe methods are left
//     alone; CORS prevents the attacker from reading any response.
//   - An auth cookie is present. Without one there is no ambient credential to
//     abuse, so public endpoints (/auth/login, /auth/register) and pure Bearer
//     clients — a tenant's own application calling from its own domain, whose
//     credential a third-party page cannot forge — stay reachable from any
//     origin the CORS policy permits.
//
// Note that the cookie, not the absence of an Authorization header, is the
// trigger. Exempting any request that merely *carries* a bearer header would be
// bypassable: a cross-site page can get an Authorization header past preflight
// (TenantCORS reflects the requested headers when a preflight announces
// X-Tenant-Slug, since a browser never sends a custom header's value during
// preflight), then send a garbage bearer alongside the victim's cookies. That
// only fails today because JWTRequired happens to reject an invalid bearer
// rather than falling back to the cookie — too fragile a thing to rest a CSRF
// defence on. When both are present we enforce.
//
// Under those conditions the request is cookie-authenticated and forgeable, so
// the Origin must match the trusted cookie domain at a label boundary.
func CookieCSRF(cfg CookieConfig) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if !cfg.Secure || !isMutating(c.Request().Method) {
				return next(c)
			}
			if !hasAuthCookie(c) {
				return next(c)
			}
			if err := checkTrustedOrigin(c, cfg); err != nil {
				return err
			}
			return next(c)
		}
	}
}

// isMutating reports whether the method can change server state.
func isMutating(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

// hasAuthCookie reports whether the request carries either session cookie.
func hasAuthCookie(c echo.Context) bool {
	for _, name := range []string{AccessTokenCookie, RefreshTokenCookie} {
		if cookie, err := c.Cookie(name); err == nil && cookie.Value != "" {
			return true
		}
	}
	return false
}

// checkTrustedOrigin returns a 403 response error when the request's Origin is
// not the trusted cookie domain. A missing Origin passes: that means a
// non-browser client or a same-origin request, neither of which is forgeable.
func checkTrustedOrigin(c echo.Context, cfg CookieConfig) error {
	origin := c.Request().Header.Get("Origin")
	if origin == "" {
		return nil
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
		return csrfRejected(c)
	}

	// u.Hostname() strips any port suffix so "app.engineersmind.com:443"
	// is treated the same as "app.engineersmind.com".
	host := u.Hostname()

	// Label-boundary match: exact equality OR subdomain with a "." separator.
	// This prevents "evil-engineersmind.com" from matching "engineersmind.com".
	if host != trusted && !strings.HasSuffix(host, "."+trusted) {
		return csrfRejected(c)
	}

	return nil
}

func csrfRejected(c echo.Context) error {
	return c.JSON(http.StatusForbidden, map[string]string{
		"error": "cross-origin request not allowed with session cookies",
		"code":  "csrf_check_failed",
	})
}
