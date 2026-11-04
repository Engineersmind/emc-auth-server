package handlers

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/labstack/echo/v4"

	"github.com/engineersmind/emc-auth-server/internal/audit"
	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// WithServerTrust attaches the AppTrustService behind the server-trust routes.
func (h *AdminHandler) WithServerTrust(svc *auth.AppTrustService) *AdminHandler {
	h.trustSvc = svc
	return h
}

// ServerTrustRequest is the body of PUT .../server-trust. Both fields are
// optional; an omitted field keeps its current value, so changing the flag
// cannot clear the address list by accident. Send "server_ips": [] to clear it.
type ServerTrustRequest struct {
	// TrustForwardedIP lets the application report its end user's address in
	// X-EMC-Forwarded-For.
	TrustForwardedIP *bool `json:"trust_forwarded_ip"`
	// ServerIPs replaces the application's registered egress addresses. Each
	// entry is an address or CIDR range (IPv4 /24 or narrower, IPv6 /48 or
	// narrower), at most 50.
	ServerIPs *[]auth.AppServerIPInput `json:"server_ips"`
}

// GetServerTrust handles GET /api/v1/applications/:appID/server-trust and its
// tenant-scoped mirror.
//
// @Summary      Get an application's server-to-server settings
// @Description  Returns the application's registered server IPs and whether it may forward its end users' IP in X-EMC-Forwarded-For. Requires apps:read.
// @Tags         admin-rate-limits
// @Produce      json
// @Security     BearerAuth
// @Param        appID  path      string  true   "Application ID"
// @Param        tid    path      string  false  "Tenant ID (super_admin cross-tenant mirror)"
// @Success      200    {object}  auth.AppServerTrust
// @Failure      404    {object}  map[string]string  "Application not found"
// @Router       /api/v1/applications/{appID}/server-trust [get]
// @Router       /api/v1/tenants/{tid}/applications/{appID}/server-trust [get]
func (h *AdminHandler) GetServerTrust(c echo.Context) error {
	if h.trustSvc == nil {
		return c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "server trust is not configured"})
	}
	tenantID, _, err := h.tenantFromClaimsOrPath(c)
	if err != nil {
		return c.JSON(http.StatusForbidden, APIError{Error: "forbidden", Message: err.Error()})
	}
	appID, ok := h.applicationOwnedByTenant(c, tenantID)
	if !ok {
		return nil
	}

	trust, err := h.trustSvc.GetServerTrust(c.Request().Context(), tenantID, appID)
	if err != nil {
		if errors.Is(err, auth.ErrAppNotFound) {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "application not found"})
		}
		h.logger.Error().Err(err).Msg("admin: get server trust failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to get server trust"})
	}
	trust.PerIPLimit = h.perIPLimit
	return c.JSON(http.StatusOK, trust)
}

// SuggestServerIPs handles GET /api/v1/applications/:appID/server-trust/suggestions
// and its tenant-scoped mirror.
//
// @Summary      Suggest an application's server addresses
// @Description  Lists the addresses that served several different users of the application recently (from the audit log, administrator actions excluded) — likely the application backend's outbound addresses — and whether each is already registered. Suggestions only; nothing is registered until the server IPs are saved. Requires apps:read.
// @Tags         admin-rate-limits
// @Produce      json
// @Security     BearerAuth
// @Param        appID  path      string  true   "Application ID"
// @Param        tid    path      string  false  "Tenant ID (super_admin cross-tenant mirror)"
// @Success      200    {object}  auth.ServerIPSuggestions
// @Failure      404    {object}  map[string]string  "Application not found"
// @Router       /api/v1/applications/{appID}/server-trust/suggestions [get]
// @Router       /api/v1/tenants/{tid}/applications/{appID}/server-trust/suggestions [get]
func (h *AdminHandler) SuggestServerIPs(c echo.Context) error {
	if h.trustSvc == nil {
		return c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "server trust is not configured"})
	}
	tenantID, _, err := h.tenantFromClaimsOrPath(c)
	if err != nil {
		return c.JSON(http.StatusForbidden, APIError{Error: "forbidden", Message: err.Error()})
	}
	appID, ok := h.applicationOwnedByTenant(c, tenantID)
	if !ok {
		return nil
	}

	out, err := h.trustSvc.SuggestServerIPs(c.Request().Context(), tenantID, appID)
	if err != nil {
		if errors.Is(err, auth.ErrAppNotFound) {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "application not found"})
		}
		h.logger.Error().Err(err).Msg("admin: suggest server ips failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to suggest server addresses"})
	}
	return c.JSON(http.StatusOK, out)
}

// SetServerTrust handles PUT /api/v1/applications/:appID/server-trust and its
// tenant-scoped mirror.
//
// @Summary      Set an application's server-to-server settings
// @Description  Registers the application backend's egress IPs (requests from them skip the per-IP flood guard; the application quota and per-user limits still apply) and turns forwarding of the end user's IP on or off. A forwarded IP is believed only when the client secret verifies and the request comes from one of the registered server IPs, so forwarding needs at least one. Omitted fields are left unchanged. Changes apply on this instance immediately and on others within 30 seconds. Requires apps:write.
// @Tags         admin-rate-limits
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        appID  path      string              true   "Application ID"
// @Param        tid    path      string              false  "Tenant ID (super_admin cross-tenant mirror)"
// @Param        body   body      ServerTrustRequest  true   "Settings to change"
// @Success      200    {object}  auth.AppServerTrust
// @Failure      400    {object}  map[string]string  "Invalid address or range"
// @Failure      404    {object}  map[string]string  "Application not found"
// @Router       /api/v1/applications/{appID}/server-trust [put]
// @Router       /api/v1/tenants/{tid}/applications/{appID}/server-trust [put]
func (h *AdminHandler) SetServerTrust(c echo.Context) error {
	if h.trustSvc == nil {
		return c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "server trust is not configured"})
	}
	tenantID, claims, err := h.tenantFromClaimsOrPath(c)
	if err != nil {
		return c.JSON(http.StatusForbidden, APIError{Error: "forbidden", Message: err.Error()})
	}
	appID, ok := h.applicationOwnedByTenant(c, tenantID)
	if !ok {
		return nil
	}

	var req ServerTrustRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}
	if req.TrustForwardedIP == nil && req.ServerIPs == nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "nothing to change: send trust_forwarded_ip, server_ips, or both",
		})
	}

	trust, err := h.trustSvc.SetServerTrust(c.Request().Context(), tenantID, appID, req.TrustForwardedIP, req.ServerIPs)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrInvalidServerIP):
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		case errors.Is(err, auth.ErrAppNotFound):
			return c.JSON(http.StatusNotFound, map[string]string{"error": "application not found"})
		}
		h.logger.Error().Err(err).Msg("admin: set server trust failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to set server trust"})
	}

	// The resulting state, not the request: an auditor wants to know what the
	// application now trusts, including entries this request left untouched.
	cidrs := make([]string, 0, len(trust.ServerIPs))
	for _, ip := range trust.ServerIPs {
		cidrs = append(cidrs, ip.CIDR)
	}
	h.auditAdminTenantMeta(c, claims, &tenantID, audit.ActionAdminAppServerTrustUpdated,
		"application", strconv.FormatInt(appID, 10), &appID, map[string]any{
			"trust_forwarded_ip": trust.TrustForwardedIP,
			"server_ips":         cidrs,
		})
	trust.PerIPLimit = h.perIPLimit
	return c.JSON(http.StatusOK, trust)
}
