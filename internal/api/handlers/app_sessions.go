package handlers

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/labstack/echo/v4"

	"github.com/engineersmind/emc-auth-server/internal/admin"
	"github.com/engineersmind/emc-auth-server/internal/audit"
)

// ---------------------------------------------------------------------------
// Admin action: revoke every session of one application (#196, #189 backlog)
// ---------------------------------------------------------------------------

// RevokeApplicationSessionsResponse is the body of POST .../sessions/revoke.
type RevokeApplicationSessionsResponse struct {
	ApplicationID string `json:"application_id"`
	// Revoked is how many live sessions this call ended.
	Revoked int `json:"revoked"`
	// Failed is how many sessions could not be revoked (logged server-side).
	// Non-zero is worth a retry; the call is idempotent.
	Failed int `json:"failed"`
}

// RevokeApplicationSessions handles POST /api/v1/applications/:appID/sessions/revoke
// and POST /api/v1/tenants/:tid/applications/:appID/sessions/revoke.
//
// @Summary      Revoke every session of an application
// @Description  Ends every live session bound to this application inside the tenant — its own users and tenant-level users who signed in through it. Each session's refresh tokens are revoked and its outstanding access tokens are denied immediately, so every user must sign in again and meets the application's CURRENT MFA policy. MFA policy changes never revoke sessions by themselves; this is the manual action to apply a tightened policy now. Idempotent: a second call revokes nothing more. Audited as admin.application_sessions_revoked with the count.
// @Tags         admin-applications
// @Produce      json
// @Security     BearerAuth
// @Param        appID  path      string  true  "Application ID"
// @Success      200    {object}  RevokeApplicationSessionsResponse
// @Failure      403    {object}  map[string]string
// @Failure      404    {object}  map[string]string  "Application not found"
// @Failure      503    {object}  APIError           "service_unavailable"
// @Router       /api/v1/applications/{appID}/sessions/revoke [post]
// @Router       /api/v1/tenants/{tid}/applications/{appID}/sessions/revoke [post]
func (h *AdminHandler) RevokeApplicationSessions(c echo.Context) error {
	tenantID, claims, err := h.tenantFromClaimsOrPath(c)
	if err != nil {
		return c.JSON(http.StatusForbidden, APIError{Error: "forbidden", Message: err.Error()})
	}
	appID, ok := h.applicationOwnedByTenant(c, tenantID)
	if !ok {
		return nil
	}

	res, err := h.svc.RevokeApplicationSessions(c.Request().Context(), tenantID, appID)
	if err != nil {
		if errors.Is(err, admin.ErrSessionRevokeUnavailable) {
			return fail(c, http.StatusServiceUnavailable, "service_unavailable")
		}
		h.logger.Error().Err(err).Int64("application_id", appID).Msg("admin: revoke application sessions failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to revoke application sessions"})
	}

	// Audited even when nothing was revoked: the action itself — an
	// administrator signing out a whole application — is the event. Filed under
	// the tenant acted on, as for the other application MFA actions.
	appIDStr := strconv.FormatInt(appID, 10)
	h.auditAdminTenantMeta(c, claims, &tenantID, audit.ActionAdminAppSessionsRevoked, "application", appIDStr, &appID,
		map[string]any{"application_id": appIDStr, "revoked": res.Revoked, "failed": res.Failed})

	return c.JSON(http.StatusOK, RevokeApplicationSessionsResponse{ApplicationID: appIDStr, Revoked: res.Revoked, Failed: res.Failed})
}
