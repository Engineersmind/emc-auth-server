package middleware

import (
	"net/http"

	"github.com/labstack/echo/v4"

	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// RequirePermission returns an Echo middleware factory that checks whether the
// authenticated user's JWT contains the specified permission string.
//
// Must be used AFTER JWTRequired in the middleware chain — it reads *auth.Claims
// from the context key "user" set by JWTRequired.
//
// Returns HTTP 403 if:
//   - The "user" context value is absent or not *auth.Claims (JWTRequired was skipped).
//   - The Claims.Permissions slice does not contain the required permission.
//
// Usage in routes:
//
//	adminGroup.POST("/tenants", handler, mw.JWTRequired(jwtSvc), mw.RequirePermission("tenant:write"))
func RequirePermission(permission string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			claims, ok := c.Get(userContextKey).(*auth.Claims)
			if !ok || claims == nil {
				return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
			}

			for _, p := range claims.Permissions {
				if p == permission {
					return next(c)
				}
			}

			return c.JSON(http.StatusForbidden, map[string]string{
				"error":      "forbidden",
				"required":   permission,
				"has_access": "false",
			})
		}
	}
}
