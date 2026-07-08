package middleware

import (
	"net/http"
	"strings"

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

// RequireAnyPermission returns an Echo middleware that grants access when the
// authenticated user's JWT contains AT LEAST ONE of the given permission
// strings. Used to guard tenant-admin routes with a granular permission
// (e.g. "apps:write") while still honouring the coarse "admin:access"
// permission held by the super_admin role.
//
// Must be used AFTER JWTRequired, same as RequirePermission.
func RequireAnyPermission(permissions ...string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			claims, ok := c.Get(userContextKey).(*auth.Claims)
			if !ok || claims == nil {
				return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
			}

			for _, held := range claims.Permissions {
				for _, required := range permissions {
					if held == required {
						return next(c)
					}
				}
			}

			return c.JSON(http.StatusForbidden, map[string]string{
				"error":      "forbidden",
				"required":   strings.Join(permissions, " OR "),
				"has_access": "false",
			})
		}
	}
}
