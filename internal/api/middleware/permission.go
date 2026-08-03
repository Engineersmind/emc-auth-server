package middleware

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/labstack/echo/v4"

	"github.com/engineersmind/emc-auth-server/internal/audit"
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

			return denyAudited(c, claims, permission)
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
	return tenantSelfOrAny(false, permissions)
}

// RequireTenantSelfScoped is RequireTenantSelfOrAny for a tenant-level
// COLLECTION route that an application-scoped administrator legitimately
// reaches — today, listing the tenant's applications.
//
// A co-owner has to be able to see the applications they administer, and the
// list lives at the tenant level. Refusing them here (as RequireTenantSelfOrAny
// does) leaves them staring at "failed to load applications" with no way into
// their own work.
//
// USE ONLY where the handler narrows the response to the caller's granted
// applications. The guard cannot do that itself — it does not know what the
// handler is about to return — so on any route without that filtering this
// would hand an app-scoped admin the whole tenant.
func RequireTenantSelfScoped(permissions ...string) echo.MiddlewareFunc {
	return tenantSelfOrAny(true, permissions)
}

func tenantSelfOrAny(allowAppScoped bool, permissions []string) echo.MiddlewareFunc {
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

			// A co-owner's authority stops at the applications they were
			// granted, so they have none over tenant-level resources — the
			// tenant's own roles, its permission catalog, its tenant-level user
			// pool. They hold the same permission names as an owner (a
			// permission says what an administrator may do, not which
			// application they may do it to), so without this check the
			// per-application scoping would be trivially bypassed by calling the
			// tenant-level route instead of the per-application one.
			//
			// Only an explicit AdminScopeApps is refused. An absent claim means
			// a caller who predates tenant_admins — an owner or a legacy tenant
			// admin, both tenant-wide — and must keep working.
			if claims.AdminScope == auth.AdminScopeApps && !allowAppScoped {
				return denyAudited(c, claims,
					"tenant-wide administration; this account administers specific applications only")
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

			return denyAudited(c, claims,
				"tenant:manage OR own tenant with "+strings.Join(permissions, " OR ")+" OR admin:access")
		}
	}
}

// RequireAppScope guards per-application admin routes (/tenants/:tid/apps/:aid/...).
//
// It layers an application-scope check on top of everything
// RequireTenantSelfOrAny does. That guard compares only :tid against the
// caller's claims, which was sufficient while every tenant administrator
// administered every application in their tenant. Once co-owners exist that is
// no longer true: a co-owner holding apps:write would otherwise pass the tenant
// check and act on applications they were never granted.
//
// Decision order:
//
//  1. tenant:manage (super_admin) — cross-tenant platform tier, allowed for any
//     :tid and any :aid, unchanged from the existing guards.
//  2. :tid must equal the tenant in the caller's own claims.
//  3. The caller must hold one of the given resource permissions, or the coarse
//     admin:access, mirroring RequireTenantSelfOrAny so legacy roles keep working.
//  4. The caller's admin scope must cover :aid — tenant-wide, or :aid present in
//     their granted application list.
//
// Step 4 fails closed on an absent admin_scope claim. See AdminScopeTenant in
// internal/auth for why the zero value is not treated as unrestricted, and for
// the short self-healing window that costs at deploy time.
//
// appParam names the path parameter holding the application row id, because the
// route table is not consistent about it: nested routes use ":appID" while the
// application resource itself uses ":id". It is passed explicitly rather than
// guessed, since guessing wrong on a route like
// /applications/:appID/roles/:id would silently scope the check to a role id.
//
// As everywhere else here, the decision is made against claims; the path
// parameters are only ever compared to them, never trusted alone.
func RequireAppScope(appParam string, permissions ...string) echo.MiddlewareFunc {
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

			deny := func(reason string) error { return denyAudited(c, claims, reason) }

			// Same-tenant caller, compared numerically so "007" == "7" cannot
			// read as a mismatch (or vice versa).
			tid, err := strconv.ParseInt(c.Param("tid"), 10, 64)
			if err != nil {
				return deny("valid tenant id in path")
			}
			own, err := strconv.ParseInt(claims.TenantID, 10, 64)
			if err != nil || own != tid {
				return deny("tenant:manage OR own tenant")
			}

			permitted := has("admin:access")
			for _, perm := range permissions {
				if permitted {
					break
				}
				permitted = has(perm)
			}
			if !permitted {
				return deny(strings.Join(permissions, " OR ") + " OR admin:access")
			}

			switch claims.AdminScope {
			case auth.AdminScopeTenant:
				return next(c)
			case auth.AdminScopeApps:
				// Compare as strings: both sides originate as decimal row ids
				// with no leading zeros — claims.AdminApps from
				// strconv.FormatInt, the path from the router — so a numeric
				// parse would buy nothing. Reject a non-numeric :aid anyway so a
				// malformed path can never be answered by a downstream handler.
				aid := c.Param(appParam)
				if _, err := strconv.ParseInt(aid, 10, 64); err != nil {
					return deny("valid application id in path")
				}
				for _, granted := range claims.AdminApps {
					if granted == aid {
						return next(c)
					}
				}
				return deny("a grant for application " + aid)
			default:
				return deny("an administrative scope claim (re-authenticate to obtain one)")
			}
		}
	}
}

// denyAudited records a refused privileged request and returns the 403.
//
// A refusal is the only trace a probe leaves: the handler never runs, so nothing
// downstream logs anything. Until this existed, a co-owner walking every
// application in the tenant looking for one they could reach was invisible.
//
// Staged rather than logged directly so it picks up the response status and body
// through AuditCapture, and so this package needs no audit logger threaded
// through ~100 route registrations. When capture is inactive the event is
// dropped rather than the request failing — an audit gap must never become a
// broken response.
func denyAudited(c echo.Context, claims *auth.Claims, required string) error {
	if claims != nil {
		tenantID, err := strconv.ParseInt(claims.TenantID, 10, 64)
		e := audit.Event{
			ActorEmail:   claims.Email,
			Action:       audit.ActionAdminAccessDenied,
			ResourceType: "route",
			ResourceID:   c.Request().Method + " " + c.Path(),
			Status:       audit.StatusFailure,
			IPAddress:    c.RealIP(),
			UserAgent:    c.Request().UserAgent(),
			Metadata: map[string]any{
				"required":    required,
				"admin_scope": claims.AdminScope,
			},
		}
		if err == nil {
			e.TenantID = &tenantID
		}
		// The id, not just the address: it is what the notifier matches the
		// actor's tier on, and it survives an email change that the address
		// would not.
		if uid, uidErr := strconv.ParseInt(claims.UserID, 10, 64); uidErr == nil {
			e.UserID = &uid
		}
		StageAuditEvent(c, e)
	}
	return c.JSON(http.StatusForbidden, map[string]string{
		"error":      "forbidden",
		"required":   required,
		"has_access": "false",
	})
}

// RequireAnyPermission returns an Echo middleware that grants access when the
// authenticated user's JWT contains AT LEAST ONE of the given permission
// strings. Used to guard the FLAT tenant-admin routes (/applications,
// /users, /roles, …) with a granular permission (e.g. "apps:write") while still
// honouring the coarse "admin:access" permission held by the super_admin role.
//
// These routes take their tenant from the caller's own claims and name no
// application in the path, so they act on the tenant as a whole. An application-
// scoped administrator is therefore refused: both tiers hold the same permission
// NAMES, so apps:write alone would have let a co-owner create, edit or delete
// ANY application in the tenant through these aliases — the per-application
// guards on the canonical /tenants/:tid/... family are bypassed entirely here.
//
// Routes whose HANDLER narrows the result to the caller's applications (the
// monitoring endpoints) use RequireAnyPermissionScoped instead.
//
// Must be used AFTER JWTRequired, same as RequirePermission.
func RequireAnyPermission(permissions ...string) echo.MiddlewareFunc {
	return anyPermission(false, permissions)
}

// RequireAnyPermissionScoped is RequireAnyPermission for a flat route that an
// application-scoped administrator may legitimately call because the handler
// restricts what comes back — today the audit and stats endpoints, where a
// co-owner sees events for their own applications and nothing else.
//
// USE ONLY with a handler that applies that restriction. Without one this hands
// an app-scoped caller the whole tenant.
func RequireAnyPermissionScoped(permissions ...string) echo.MiddlewareFunc {
	return anyPermission(true, permissions)
}

func anyPermission(allowAppScoped bool, permissions []string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			claims, ok := c.Get(userContextKey).(*auth.Claims)
			if !ok || claims == nil {
				return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
			}

			if claims.AdminScope == auth.AdminScopeApps && !allowAppScoped {
				return denyAudited(c, claims,
					"tenant-wide administration; this account administers specific applications only")
			}

			for _, held := range claims.Permissions {
				for _, required := range permissions {
					if held == required {
						return next(c)
					}
				}
			}

			return denyAudited(c, claims, strings.Join(permissions, " OR "))
		}
	}
}
