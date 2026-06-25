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

// BuildAuthCookies constructs the access and refresh token cookie objects.
// The caller is responsible for writing them to the response.
//
// The refresh cookie is scoped to /api/v1/auth so browsers only transmit
// the 30-day credential to the auth endpoints that actually need it.
func BuildAuthCookies(accessToken, refreshToken string, cfg CookieConfig) []*http.Cookie {
	access := &http.Cookie{
		Name:     AccessTokenCookie,
		Value:    accessToken,
		HttpOnly: true,
		Secure:   cfg.Secure,
		SameSite: cfg.SameSite,
		Domain:   cfg.Domain,
		Path:     "/api/v1",
		MaxAge:   int(auth.AccessTokenTTL.Seconds()),
	}
	refresh := &http.Cookie{
		Name:     RefreshTokenCookie,
		Value:    refreshToken,
		HttpOnly: true,
		Secure:   cfg.Secure,
		SameSite: cfg.SameSite,
		Domain:   cfg.Domain,
		Path:     "/api/v1",
		MaxAge:   int(auth.RefreshTokenTTL.Seconds()),
	}
	return []*http.Cookie{access, refresh}
}

// ClearAuthCookies expires both auth cookies immediately on the response.
// Domain, Secure, and SameSite must match what was set in BuildAuthCookies;
// RFC 6265 §5.2.3 treats a missing Domain as a different entry than an explicit one.
func ClearAuthCookies(c echo.Context, cfg CookieConfig) {
	http.SetCookie(c.Response().Writer, &http.Cookie{
		Name:     AccessTokenCookie,
		Value:    "",
		HttpOnly: true,
		Secure:   cfg.Secure,
		SameSite: cfg.SameSite,
		Domain:   cfg.Domain,
		Path:     "/api/v1",
		MaxAge:   -1,
	})
	http.SetCookie(c.Response().Writer, &http.Cookie{
		Name:     RefreshTokenCookie,
		Value:    "",
		HttpOnly: true,
		Secure:   cfg.Secure,
		SameSite: cfg.SameSite,
		Domain:   cfg.Domain,
		Path:     "/api/v1",
		MaxAge:   -1,
	})
}
