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
// Protection: the Origin must exactly match the trusted-origins list
// (GLOBAL_CORS_ORIGINS via CookieConfig.TrustedOrigins). GHSA-jv2c-x735-vff7
// (L-04) removed the two looser behaviours: blanket trust of every subdomain
// of the cookie domain — any attacker-controlled subdomain could CSRF — and
// allowing requests with no Origin at all. Browsers always send Origin on
// POSTs; a missing Origin on a cookie-authenticated write is a curl client or
// an attack, and cookie sessions are browser-facing by definition.
//
// Security properties:
//
//   - Exact origin match: "evil-engineersmind.com" and unlisted subdomains are
//     rejected — only origins in GLOBAL_CORS_ORIGINS pass.
//
//   - Fail-closed on misconfiguration: secure cookies with an empty trusted
//     list rejects every request rather than silently accepting them.
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
			if rejection, blocked := checkTrustedOrigin(c, cfg); blocked {
				return rejection
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
			if rejection, blocked := checkTrustedOrigin(c, cfg); blocked {
				return rejection
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
//
// Either cookie counts, deliberately: the presence of one means a
// browser-managed session is in use, and a cross-site request carrying only the
// refresh cookie can still rotate the family — obtaining a fresh access token
// and revoking the victim's in-flight one. Do not narrow this to the access
// cookie alone.
func hasAuthCookie(c echo.Context) bool {
	for _, name := range []string{AccessTokenCookie, RefreshTokenCookie} {
		if cookie, err := c.Cookie(name); err == nil && cookie.Value != "" {
			return true
		}
	}
	return false
}

// checkTrustedOrigin reports whether the request must be blocked, and returns
// the error from writing the 403 response when it is.
//
// blocked is returned separately because echo's c.JSON returns nil on success:
// a single error return would read as "allowed" immediately after the 403 body
// was written, and the caller would go on to invoke the handler anyway. Any
// future rejection site must return (…, true).
//
// GHSA-jv2c-x735-vff7 (L-04) tightened both directions of this check:
//
//   - A missing Origin is now rejected. Browsers send Origin on every mutating
//     request (fetch AND form posts), so absence on a cookie-authenticated
//     write means a non-browser client or a stripped-header attack — the
//     endpoints this guards exist for browser sessions.
//   - Subdomain suffix-matching is gone in favour of an exact allowlist
//     (cfg.TrustedOrigins, fed by GLOBAL_CORS_ORIGINS). Trusting every
//     subdomain of the cookie domain let any attacker-controlled or
//     abandoned subdomain CSRF the session endpoints.
func checkTrustedOrigin(c echo.Context, cfg CookieConfig) (rejection error, blocked bool) {
	origin := c.Request().Header.Get("Origin")
	if origin == "" {
		return csrfRejected(c), true
	}

	// Deliberately GLOBAL_CORS_ORIGINS only — per-tenant cors_origins rows are
	// NOT consulted here. CORS is a read-protection (which origins may read
	// responses); CSRF is a write-protection (which origins may drive the
	// browser's ambient credential). The session cookies this guards are set
	// by the portal, which lives at the global origin — tenant SPAs carry
	// Bearer tokens, whose security does not depend on this list at all.
	// Widening the allowlist to every tenant's cors_origins would let any
	// tenant-controlled origin CSRF the admin session: a cross-tenant
	// privilege escalation.
	if len(cfg.TrustedOrigins) == 0 {
		return c.JSON(http.StatusForbidden, map[string]string{
			"error": "CSRF check misconfigured: GLOBAL_CORS_ORIGINS must be set in production",
			"code":  "csrf_misconfigured",
		}), true
	}

	// Exact match on the full origin (scheme + host + port). Opaque origins
	// like "null" and every subdomain not explicitly listed are rejected.
	// Trailing slashes are stripped in config parsing (getEnvList); strip here
	// too so a stray configured slash cannot silently break legitimate calls.
	for _, trusted := range cfg.TrustedOrigins {
		if origin == strings.TrimSuffix(trusted, "/") {
			return nil, false
		}
	}
	return csrfRejected(c), true
}

func csrfRejected(c echo.Context) error {
	return c.JSON(http.StatusForbidden, map[string]string{
		"error": "cross-origin request not allowed with session cookies",
		"code":  "csrf_check_failed",
	})
}
