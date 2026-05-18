package middleware

import (
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"

	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// userContextKey is the echo context key under which *auth.Claims is stored.
// All handlers and downstream middleware read claims via c.Get(userContextKey).
const userContextKey = "user"

// Cookie names used for browser-session authentication (see auth/session handlers).
const (
	AccessTokenCookie  = "emc_access_token"
	RefreshTokenCookie = "emc_refresh_token"
)

// JWTRequired returns an Echo middleware that:
//  1. Reads the Authorization header (must be "Bearer <token>"); falls back to
//     the emc_access_token HttpOnly cookie for browser-session clients.
//  2. Verifies the JWT signature + expiry using the per-tenant secret (fetched from DB).
//  3. Stores the validated *auth.Claims in the echo context under key "user".
//  4. Returns HTTP 401 if no valid token is found in either location.
//
// Performance note (NFR-01): Verify() does one DB round-trip to fetch the tenant secret.
// With pgxpool (MaxConns=25) and the p99 < 2ms DB query target, this adds ≤2ms latency.
func JWTRequired(jwtSvc *auth.JWTService) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			tokenString, found := bearerToken(c)
			if !found {
				// Fall back to HttpOnly cookie set by /auth/session endpoints.
				if cookie, err := c.Cookie(AccessTokenCookie); err == nil && cookie.Value != "" {
					tokenString = cookie.Value
					found = true
				}
			}

			if !found || tokenString == "" {
				return c.JSON(http.StatusUnauthorized, map[string]string{"error": "authorization required"})
			}

			claims, err := jwtSvc.Verify(c.Request().Context(), tokenString)
			if err != nil {
				return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid or expired token"})
			}

			// Store claims for downstream handlers.
			c.Set(userContextKey, claims)
			return next(c)
		}
	}
}

// bearerToken extracts the token string from "Authorization: Bearer <token>".
// Returns ("", false) if the header is absent or malformed.
func bearerToken(c echo.Context) (string, bool) {
	header := c.Request().Header.Get("Authorization")
	if header == "" {
		return "", false
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", false
	}
	token := strings.TrimSpace(parts[1])
	return token, token != ""
}
