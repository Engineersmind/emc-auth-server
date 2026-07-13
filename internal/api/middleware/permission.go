package middleware

import (
	"net/http"
	"strconv"
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

// RequireTenantSelfOrAny guards the canonical /tenants/:tid/... resource
// routes so ONE URL family serves both personas:
//
//   - super_admin: holds "tenant:manage" — any :tid is allowed (cross-tenant
//     administration, unchanged from the old tenantMgmt blanket guard).
//   - tenant admin (e.g. the seeded "owner" role): :tid must equal the
//     tenant_id in their own JWT claims AND they must hold at least one of
//     the given resource permissions (e.g. "roles:write") — or the coarse
//     "admin:access" fallback, mirroring RequireAnyPermission on the flat
//     routes so legacy roles that only hold admin:access keep working.
//
// The decision is always made against JWT claims — the path :tid is only
// compared to them, never trusted on its own — so tenant isolation holds:
// admin:access and granular permissions never grant access to another tenant.
// Must be used AFTER JWTRequired, same as RequirePermission.
func RequireTenantSelfOrAny(permissions ...string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			claims, ok := c.Get(userContextKey).(*auth.Claims)
			if !ok || claims == nil {
				return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
			}

			has := func(perm string) bool {
				for _, held := range claims.Permissions {
					if held == perm {
						return true
					}
				}
				return false
			}

			if has("tenant:manage") {
				return next(c)
			}

			// Same-tenant caller: compare numerically so "007" == "7" cannot
			// slip through as a mismatch (or vice versa).
			tid, err := strconv.ParseInt(c.Param("tid"), 10, 64)
			if err == nil {
				if own, ownErr := strconv.ParseInt(claims.TenantID, 10, 64); ownErr == nil && own == tid {
					if has("admin:access") {
						return next(c)
					}
					for _, perm := range permissions {
						if has(perm) {
							return next(c)
						}
					}
				}
			}

			return c.JSON(http.StatusForbidden, map[string]string{
				"error":      "forbidden",
				"required":   "tenant:manage OR own tenant with " + strings.Join(permissions, " OR ") + " OR admin:access",
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
