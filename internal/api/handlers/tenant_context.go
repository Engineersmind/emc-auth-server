package handlers

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/labstack/echo/v4"

	"github.com/engineersmind/emc-auth-server/internal/audit"
	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// ---------------------------------------------------------------------------
// Multi-tenant administrator endpoints (plan steps 4 and 5).
//
// Two questions, deliberately answered by two endpoints:
//
//	GET  /api/v1/admin/my-tenants     which tenants may I reach?
//	POST /api/v1/auth/tenant-context  mint me a token for one of them
//
// The first never consults the caller's current tenant — it queries admin_grants
// by user id — so an owner of five tenants sees all five immediately after login,
// before any switching has happened. The second exists because claims.TenantID is
// a scalar and the tenant-scoped guards compare the path :tid against it.
//
// The second is NOT re-authentication: the caller presents the access token they
// already hold. Named "tenant-context" rather than "switch-tenant" because that is
// what it changes — the identity was already proven at login.
// ---------------------------------------------------------------------------

// TenantContextRequest is the body for POST /api/v1/auth/tenant-context.
type TenantContextRequest struct {
	TenantID string `json:"tenant_id"`
}

// ReachableTenantResponse is one tenant in the my-tenants listing.
//
// Applications is populated only for a co-owner. An owner's is deliberately
// absent: they administer every application in the tenant, present and future, so
// a list would imply a fixed set. AppCount still reports a number either way, so
// read Applications together with Role.
type ReachableTenantResponse struct {
	TenantID string `json:"tenant_id"`
	Name     string `json:"name"`
	Slug     string `json:"slug"`
	// Role is "owner", "co_owner", or "platform_admin".
	Role         string   `json:"role"`
	AppCount     int      `json:"app_count"`
	IsPrimary    bool     `json:"is_primary,omitempty"`
	Applications []string `json:"applications,omitempty"`
	// Can carries the capability flags the UI must branch on instead of comparing
	// role names. Server-derived so a button and the route guarding it share one
	// source of truth.
	Can ReachableTenantCapabilities `json:"can"`
}

// ReachableTenantCapabilities is what the caller may do in one tenant.
type ReachableTenantCapabilities struct {
	CreateApplication bool `json:"create_application"`
	ManageUsers       bool `json:"manage_users"`
	ManageRoles       bool `json:"manage_roles"`
	ManageAdmins      bool `json:"manage_admins"`
}

// MyTenantsResponse is the my-tenants payload.
type MyTenantsResponse struct {
	// CanCreateTenant is server-supplied rather than inferred by the client from a
	// role name. Only a platform administrator may create tenants — asserted in
	// middleware and covered by TestRequirePermission_TenantCreationIsPlatformAdminOnly.
	CanCreateTenant bool                      `json:"can_create_tenant"`
	Tenants         []ReachableTenantResponse `json:"tenants"`
	Total           int                       `json:"total"`
}

// MyTenants lists every tenant the caller may administer.
//
// @Summary      List tenants the caller administers
// @Description  Returns every tenant the authenticated administrator may reach, with per-tenant capability flags. A platform admin (tenant:manage) gets every tenant, paginated; an owner gets the tenants they own; a co-owner gets the tenants where they hold at least one application grant. An owner's applications array is absent because they administer every application present and future — read it together with role.
// @Tags         admin
// @Produce      json
// @Success      200  {object}  MyTenantsResponse
// @Failure      401  {object}  map[string]string
// @Security     BearerAuth
// @Router       /admin/my-tenants [get]
func (h *AuthHandler) MyTenants(c echo.Context) error {
	claims, ok := c.Get("user").(*auth.Claims)
	if !ok || claims == nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	userID, err := strconv.ParseInt(claims.UserID, 10, 64)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}

	platformAdmin := claimsHavePermission(claims, "tenant:manage")

	// A platform administrator holds no grants at all, so their reach cannot be
	// derived from them — see migration 00062 on why the platform tier is a
	// permission rather than a membership.
	if platformAdmin {
		limit, _ := strconv.Atoi(c.QueryParam("limit"))
		offset, _ := strconv.Atoi(c.QueryParam("offset"))
		tenants, total, lerr := h.svc.AllTenantsForPlatformAdmin(c.Request().Context(), limit, offset)
		if lerr != nil {
			h.logger.Error().Err(lerr).Msg("my-tenants: list all tenants failed")
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to list tenants"})
		}
		return c.JSON(http.StatusOK, MyTenantsResponse{
			CanCreateTenant: true,
			Tenants:         toReachableResponses(tenants, true),
			Total:           total,
		})
	}

	tenants, err := h.svc.ReachableTenants(c.Request().Context(), userID)
	if err != nil {
		h.logger.Error().Err(err).Int64("user_id", userID).Msg("my-tenants: list reachable tenants failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to list tenants"})
	}
	return c.JSON(http.StatusOK, MyTenantsResponse{
		// Neither administrator tier may create a tenant. Not inferred from the
		// role here: the middleware owns that rule and this flag mirrors it.
		CanCreateTenant: false,
		Tenants:         toReachableResponses(tenants, false),
		Total:           len(tenants),
	})
}

// toReachableResponses maps service rows to the wire shape, deriving capability
// flags from the tier.
//
// Computed here, once, rather than in the client: a co-owner's authority stops at
// the applications they hold, so they may not create applications, manage the
// tenant's user pool, or change who administers it — the same rule tenantSelfOrAny
// enforces by refusing AdminScopeApps on tenant-level routes.
func toReachableResponses(in []auth.AdminTenantSummary, platformAdmin bool) []ReachableTenantResponse {
	out := make([]ReachableTenantResponse, 0, len(in))
	for _, t := range in {
		r := ReachableTenantResponse{
			TenantID:  strconv.FormatInt(t.TenantID, 10),
			Name:      t.Name,
			Slug:      t.Slug,
			Role:      t.Role,
			AppCount:  t.AppCount,
			IsPrimary: t.IsPrimary,
		}
		for _, appID := range t.Applications {
			r.Applications = append(r.Applications, strconv.FormatInt(appID, 10))
		}
		switch {
		case platformAdmin, t.Role == auth.AdminRoleOwner:
			// Tenant-wide authority. Creating a TENANT is still refused, which is
			// the CanCreateTenant flag on the envelope, not a per-tenant one.
			r.Can = ReachableTenantCapabilities{
				CreateApplication: true,
				ManageUsers:       true,
				ManageRoles:       true,
				ManageAdmins:      true,
			}
		default:
			// co_owner: application-scoped only. Every tenant-level capability is
			// false, matching the guard that refuses them tenant-level routes.
			r.Can = ReachableTenantCapabilities{}
		}
		out = append(out, r)
	}
	return out
}

// TenantContext mints an access token for another tenant the caller administers.
//
// @Summary      Change the active tenant
// @Description  Re-mints the caller's session for another tenant they already administer. NOT re-authentication — the current session authenticates the request, and no password or second factor is involved. Required because an access token names exactly one tenant, so acting in another needs a token for it. The requested tenant is verified against the caller's grants and never trusted from the body. The new token pair is delivered as HttpOnly cookies (emc_access_token / emc_refresh_token) and is deliberately NOT returned in the response body, so it stays unreadable by JavaScript.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request  body      TenantContextRequest  true  "Target tenant"
// @Success      200      {object}  map[string]any
// @Failure      400      {object}  map[string]string
// @Failure      403      {object}  map[string]string
// @Security     BearerAuth
// @Router       /auth/tenant-context [post]
func (h *AuthHandler) TenantContext(c echo.Context) error {
	claims, ok := c.Get("user").(*auth.Claims)
	if !ok || claims == nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	userID, err := strconv.ParseInt(claims.UserID, 10, 64)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	currentTenant, err := strconv.ParseInt(claims.TenantID, 10, 64)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}

	var req TenantContextRequest
	if bindErr := c.Bind(&req); bindErr != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}
	targetTenant, err := strconv.ParseInt(req.TenantID, 10, 64)
	if err != nil || targetTenant <= 0 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "tenant_id must be a numeric tenant id"})
	}

	platformAdmin := claimsHavePermission(claims, "tenant:manage")

	result, err := h.svc.SwitchTenantContextForClaims(
		c.Request().Context(), userID, currentTenant, targetTenant, platformAdmin, claims.SessionID,
	)
	switch {
	case errors.Is(err, auth.ErrSameTenant):
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "already in the requested tenant"})
	case errors.Is(err, auth.ErrNoGrantInTenant):
		// Audited: a caller probing tenant ids they do not administer is exactly
		// what this log is for. The response is deliberately identical for "no
		// grant" and "no such tenant", so probing is not cheaper than not probing.
		h.auditEvent(c, audit.Event{
			Action:       audit.ActionAdminGrantDenied,
			ResourceType: "tenant",
			ResourceID:   req.TenantID,
			Status:       audit.StatusFailure,
			IPAddress:    c.RealIP(),
			UserAgent:    c.Request().UserAgent(),
			Metadata:     map[string]any{"reason": "no administrative grant in the requested tenant"},
		})
		return c.JSON(http.StatusForbidden, map[string]string{"error": "no access to the requested tenant"})
	case errors.Is(err, auth.ErrSwitchAccountUnusable):
		return c.JSON(http.StatusForbidden, map[string]string{"error": "account is blocked or inactive"})
	case err != nil:
		h.logger.Error().Err(err).
			Int64("user_id", userID).Int64("target_tenant", targetTenant).
			Msg("tenant-context: switch failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to change tenant"})
	}

	setAuthCookies(c, result.AccessToken, result.RefreshToken, h.cookieCfg)

	// The only record that one identity acted across a tenant boundary.
	// Reconstructing a multi-tenant administrator's session is impossible without
	// it, so both ends of the move are recorded.
	h.auditEvent(c, audit.Event{
		Action:       audit.ActionAdminTenantSwitched,
		ResourceType: "tenant",
		ResourceID:   req.TenantID,
		Status:       audit.StatusSuccess,
		IPAddress:    c.RealIP(),
		UserAgent:    c.Request().UserAgent(),
		Metadata: map[string]any{
			"from_tenant": claims.TenantID,
			"to_tenant":   req.TenantID,
		},
	})

	// The token pair is deliberately NOT in the body.
	//
	// setAuthCookies above already delivered it as HttpOnly cookies, which is the
	// whole point of the portal's auth model: the credential is never readable by
	// JavaScript, so an XSS cannot exfiltrate it. Echoing the same tokens in the
	// response body would hand them straight back to any script on the page and
	// undo that, while adding nothing — the browser attaches the cookies to the
	// next request either way.
	//
	// Same shape as POST /auth/refresh's first-party response, which withholds
	// the pair for exactly this reason. Only the non-credential facts are
	// returned: what the caller needs to update its own UI.
	return c.JSON(http.StatusOK, map[string]any{
		"message":    "tenant context changed",
		"tenant_id":  req.TenantID,
		"expires_in": result.ExpiresIn,
		"expires_at": result.ExpiresAt,
	})
}

// claimsHavePermission reports whether the claims carry a permission.
//
// Deliberately not shared with the middleware's identically-shaped closure: a
// handler using this is making a presentation decision (which flags to report),
// not an authorization one, and the two must not share a code path where a change
// for one silently alters the other.
func claimsHavePermission(claims *auth.Claims, permission string) bool {
	for _, p := range claims.Permissions {
		if p == permission {
			return true
		}
	}
	return false
}
