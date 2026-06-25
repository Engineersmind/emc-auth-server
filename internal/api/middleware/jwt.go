package middleware

import (
	"errors"
	"net/http"
	"strings"

	gojwt "github.com/golang-jwt/jwt/v5"
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
				return c.JSON(http.StatusUnauthorized, map[string]string{
					"error": "authorization required",
					"code":  "token_missing",
				})
			}

			claims, err := jwtSvc.Verify(c.Request().Context(), tokenString)
			if err != nil {
				// Distinguish expired tokens from invalid ones.
				// Clients should refresh on token_expired; redirect to login on token_invalid.
				if errors.Is(err, gojwt.ErrTokenExpired) {
					return c.JSON(http.StatusUnauthorized, map[string]string{
						"error": "access token expired",
						"code":  "token_expired",
					})
				}
				return c.JSON(http.StatusUnauthorized, map[string]string{
					"error": "invalid token",
					"code":  "token_invalid",
				})
			}

			// Store claims for downstream handlers.
			c.Set(userContextKey, claims)
			return next(c)
		}
	}
}

// bearerToken extracts the token string from "Authorization: Bearer <token>".
// Also accepts a raw JWT (no scheme prefix) to support Swagger UI's apiKey flow.
// Returns ("", false) if the header is absent or malformed.
func bearerToken(c echo.Context) (string, bool) {
	header := c.Request().Header.Get("Authorization")
	if header == "" {
		return "", false
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
		token := strings.TrimSpace(parts[1])
		return token, token != ""
	}
	// Raw JWT (no scheme) — Swagger UI apiKey sends the value as-is.
	if len(parts) == 1 && strings.HasPrefix(parts[0], "eyJ") {
		return parts[0], true
	}
	return "", false
}
