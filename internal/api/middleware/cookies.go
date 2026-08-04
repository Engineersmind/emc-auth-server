package middleware

import (
	"net/http"

	"github.com/labstack/echo/v4"

	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// CookieConfig controls the security attributes of auth cookies.
// Build it with BuildCookieConfig — do not set fields manually.
type CookieConfig struct {
	Domain   string
	Secure   bool
	SameSite http.SameSite
}

// BuildCookieConfig derives cookie settings from the runtime environment:
//
//	development — HTTP, frontend on localhost.
//	              SameSite=Lax, Secure=false, no Domain.
//
//	staging / production — HTTPS, frontend on a different domain.
//	                        SameSite=None (required for cross-domain AJAX), Secure=true.
func BuildCookieConfig(env, domain string) CookieConfig {
	switch env {
	case "staging", "production":
		return CookieConfig{
			Domain:   domain,
			Secure:   true,
			SameSite: http.SameSiteNoneMode,
		}
	default:
		return CookieConfig{
			Domain:   "",
			Secure:   false,
			SameSite: http.SameSiteLaxMode,
		}
	}
}

// Cookie Path scopes. The two credentials are deliberately scoped differently:
//
//	AccessCookiePath  — every API route, because a browser session must
//	                    authenticate the management endpoints (/api/v1/tenants,
//	                    /api/v1/applications, …), not just /api/v1/auth.
//	RefreshCookiePath — only the auth endpoints that consume it, so the 30-day
//	                    credential is not attached to ordinary API traffic.
const (
	AccessCookiePath  = "/api/v1"
	RefreshCookiePath = "/api/v1/auth"
)

// BuildAuthCookies constructs the access and refresh token cookie objects.
// The caller is responsible for writing them to the response.
func BuildAuthCookies(accessToken, refreshToken string, cfg CookieConfig) []*http.Cookie {
	access := &http.Cookie{
		Name:     AccessTokenCookie,
		Value:    accessToken,
		HttpOnly: true,
		Secure:   cfg.Secure,
		SameSite: cfg.SameSite,
		Domain:   cfg.Domain,
		Path:     AccessCookiePath,
		MaxAge:   int(auth.AccessTokenTTL.Seconds()),
	}
	refresh := &http.Cookie{
		Name:     RefreshTokenCookie,
		Value:    refreshToken,
		HttpOnly: true,
		Secure:   cfg.Secure,
		SameSite: cfg.SameSite,
		Domain:   cfg.Domain,
		Path:     RefreshCookiePath,
		MaxAge:   int(auth.RefreshTokenTTL.Seconds()),
	}
	return []*http.Cookie{access, refresh}
}

// ClearAuthCookies expires both auth cookies immediately on the response.
// Domain, Path, Secure, and SameSite must match what was set in BuildAuthCookies;
// RFC 6265 §5.2.3 treats a missing Domain as a different entry than an explicit one,
// and a deletion whose Path differs leaves the original cookie in place.
func ClearAuthCookies(c echo.Context, cfg CookieConfig) {
	http.SetCookie(c.Response().Writer, &http.Cookie{
		Name:     AccessTokenCookie,
		Value:    "",
		HttpOnly: true,
		Secure:   cfg.Secure,
		SameSite: cfg.SameSite,
		Domain:   cfg.Domain,
		Path:     AccessCookiePath,
		MaxAge:   -1,
	})
	http.SetCookie(c.Response().Writer, &http.Cookie{
		Name:     RefreshTokenCookie,
		Value:    "",
		HttpOnly: true,
		Secure:   cfg.Secure,
		SameSite: cfg.SameSite,
		Domain:   cfg.Domain,
		Path:     RefreshCookiePath,
		MaxAge:   -1,
	})
}
