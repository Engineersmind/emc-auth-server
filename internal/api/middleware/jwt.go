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

// JWTRequired returns an Echo middleware that:
//  1. Reads the Authorization header (must be "Bearer <token>").
//  2. Verifies the JWT signature + expiry using the per-tenant secret (fetched from DB).
//  3. Stores the validated *auth.Claims in the echo context under key "user".
//  4. Returns HTTP 401 if the header is absent, malformed, expired, or signature invalid.
//
// Performance note (NFR-01): Verify() does one DB round-trip to fetch the tenant secret.
// With pgxpool (MaxConns=25) and the p99 < 2ms DB query target, this adds ≤2ms latency.
func JWTRequired(jwtSvc *auth.JWTService) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			header := c.Request().Header.Get("Authorization")
			if header == "" {
				return c.JSON(http.StatusUnauthorized, map[string]string{"error": "authorization header required"})
			}

			parts := strings.SplitN(header, " ", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
				return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid authorization header format"})
			}

			tokenString := strings.TrimSpace(parts[1])
			if tokenString == "" {
				return c.JSON(http.StatusUnauthorized, map[string]string{"error": "token is empty"})
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
