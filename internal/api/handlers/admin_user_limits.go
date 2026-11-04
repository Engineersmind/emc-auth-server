package handlers

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/labstack/echo/v4"

	"github.com/engineersmind/emc-auth-server/internal/audit"
	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// WithUserLimits attaches the per-user limit overrides and the server defaults
// they replace (middleware.AppUserLimits.ByKey), and the per-IP limit server
// IPs skip, which the server-trust routes report.
func (h *AdminHandler) WithUserLimits(svc *auth.AppUserLimitService, defaults map[string]int, perIPLimit int) *AdminHandler {
	h.userLimitSvc = svc
	h.userLimitDefaults = defaults
	h.perIPLimit = perIPLimit
	return h
}

// UserLimitView is one per-user limit as the admin API reports it.
type UserLimitView struct {
	auth.UserLimitDef
	// Default is the server-wide value, per minute.
	Default int `json:"default"`
	// Override is the application's own value, or null when it uses the default.
	Override *int `json:"override"`
	// Effective is what the limiter enforces for this application.
	Effective int `json:"effective"`
}

// AppUserLimits is the response of the per-user limit routes.
type AppUserLimits struct {
	ApplicationID int64           `json:"application_id"`
	TenantID      int64           `json:"tenant_id"`
	Limits        []UserLimitView `json:"limits"`
}

// UserLimitsRequest is the body of PUT .../user-limits. Overrides REPLACES the
// application's overrides: a key that is absent returns to the server default,
// and {} clears them all.
type UserLimitsRequest struct {
	Overrides *map[string]int `json:"overrides"`
}

func (h *AdminHandler) userLimitsView(tenantID, appID int64, overrides map[string]int) AppUserLimits {
	out := AppUserLimits{ApplicationID: appID, TenantID: tenantID, Limits: make([]UserLimitView, 0, len(auth.UserLimitDefs))}
	for _, def := range auth.UserLimitDefs {
		v := UserLimitView{UserLimitDef: def, Default: h.userLimitDefaults[def.Key]}
		v.Effective = v.Default
		if o, ok := overrides[def.Key]; ok {
			o := o
			v.Override = &o
			v.Effective = o
		}
		out.Limits = append(out.Limits, v)
	}
	return out
}

// GetUserLimits handles GET /api/v1/applications/:appID/user-limits and its
// tenant-scoped mirror.
//
// @Summary      Get an application's per-user rate limits
// @Description  Lists every per-user limit on the application end-user routes (sign in, password reset, magic link, OTP, ...) with the server default, the application's override if any, the effective value, and the highest override accepted. Requires apps:read.
// @Tags         admin-rate-limits
// @Produce      json
// @Security     BearerAuth
// @Param        appID  path      string  true   "Application ID"
// @Param        tid    path      string  false  "Tenant ID (super_admin cross-tenant mirror)"
// @Success      200    {object}  AppUserLimits
// @Failure      404    {object}  map[string]string  "Application not found"
// @Router       /api/v1/applications/{appID}/user-limits [get]
// @Router       /api/v1/tenants/{tid}/applications/{appID}/user-limits [get]
func (h *AdminHandler) GetUserLimits(c echo.Context) error {
	if h.userLimitSvc == nil {
		return c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "per-user limits are not configured"})
	}
	tenantID, _, err := h.tenantFromClaimsOrPath(c)
	if err != nil {
		return c.JSON(http.StatusForbidden, APIError{Error: "forbidden", Message: err.Error()})
	}
	appID, ok := h.applicationOwnedByTenant(c, tenantID)
	if !ok {
		return nil
	}

	overrides, err := h.userLimitSvc.GetUserLimits(c.Request().Context(), tenantID, appID)
	if err != nil {
		if errors.Is(err, auth.ErrAppNotFound) {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "application not found"})
		}
		h.logger.Error().Err(err).Msg("admin: get user limits failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to get user limits"})
	}
	return c.JSON(http.StatusOK, h.userLimitsView(tenantID, appID, overrides))
}

// SetUserLimits handles PUT /api/v1/applications/:appID/user-limits and its
// tenant-scoped mirror.
//
// @Summary      Set an application's per-user rate limits
// @Description  Replaces the application's per-user limit overrides. Each value is requests per minute, between 1 and that limit's max; a limit left out returns to the server default, and {"overrides": {}} clears them all. Changes apply on this instance immediately and on others within 30 seconds. Requires apps:write.
// @Tags         admin-rate-limits
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        appID  path      string             true   "Application ID"
// @Param        tid    path      string             false  "Tenant ID (super_admin cross-tenant mirror)"
// @Param        body   body      UserLimitsRequest  true   "Overrides"
// @Success      200    {object}  AppUserLimits
// @Failure      400    {object}  map[string]string  "Unknown limit or value out of range"
// @Failure      404    {object}  map[string]string  "Application not found"
// @Router       /api/v1/applications/{appID}/user-limits [put]
// @Router       /api/v1/tenants/{tid}/applications/{appID}/user-limits [put]
func (h *AdminHandler) SetUserLimits(c echo.Context) error {
	if h.userLimitSvc == nil {
		return c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "per-user limits are not configured"})
	}
	tenantID, claims, err := h.tenantFromClaimsOrPath(c)
	if err != nil {
		return c.JSON(http.StatusForbidden, APIError{Error: "forbidden", Message: err.Error()})
	}
	appID, ok := h.applicationOwnedByTenant(c, tenantID)
	if !ok {
		return nil
	}

	var req UserLimitsRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}
	if req.Overrides == nil {
		// Explicit, so a malformed body cannot silently reset every limit.
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": `send "overrides": an object of limit key to requests per minute ({} returns all to the defaults)`,
		})
	}

	overrides, err := h.userLimitSvc.SetUserLimits(c.Request().Context(), tenantID, appID, *req.Overrides)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrInvalidUserLimit):
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		case errors.Is(err, auth.ErrAppNotFound):
			return c.JSON(http.StatusNotFound, map[string]string{"error": "application not found"})
		}
		h.logger.Error().Err(err).Msg("admin: set user limits failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to set user limits"})
	}

	// The resulting overrides, not the request.
	h.auditAdminTenantMeta(c, claims, &tenantID, audit.ActionAdminAppUserLimitsUpdated,
		"application", strconv.FormatInt(appID, 10), &appID, map[string]any{
			"overrides": overrides,
		})
	return c.JSON(http.StatusOK, h.userLimitsView(tenantID, appID, overrides))
}
