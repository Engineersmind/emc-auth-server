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
// Passkey administration — issue #112.
//
// Two things an operator needs and a user cannot do for themselves:
//
//  1. Decide whether passkeys are permitted at all, at the tenant or the
//     application scope, and under which relying party. Without this the feature
//     is only switchable by hand-written SQL, which is not a feature.
//
//  2. See and revoke a user's credentials. A support agent taking a call about a
//     lost laptop has no other way to end the factor that laptop holds.
//
// Both are mounted under the existing admin group, so they inherit its
// permission guards rather than inventing new ones.
// ---------------------------------------------------------------------------

// UpdatePasskeyPolicyRequest is the body for PUT .../passkey-policy.
//
// Every field is a pointer: omitted means "leave this as it is". That matters
// more here than in most bodies, because a console that round-trips a partially
// filled form would otherwise clear the RP ID a tenant depends on as a side
// effect of toggling a switch.
type UpdatePasskeyPolicyRequest struct {
	AllowPasskeys           *bool `json:"allow_passkeys"`
	AllowPasswordless       *bool `json:"allow_passwordless"`
	RequireUserVerification *bool `json:"require_user_verification"`
	// RPID, RPDisplayName and Origins accept "" / [] as a deliberate
	// clear-to-inherit, which is why they are pointers rather than plain values:
	// there has to be a way to say "go back to the server's relying party".
	RPID                  *string   `json:"rp_id"`
	RPDisplayName         *string   `json:"rp_display_name"`
	Origins               *[]string `json:"origins"`
	MaxCredentialsPerUser *int      `json:"max_credentials_per_user"`
}

func (r UpdatePasskeyPolicyRequest) toUpdate() auth.PasskeyPolicyUpdate {
	return auth.PasskeyPolicyUpdate{
		AllowPasskeys:           r.AllowPasskeys,
		AllowPasswordless:       r.AllowPasswordless,
		RequireUserVerification: r.RequireUserVerification,
		RPID:                    r.RPID,
		RPDisplayName:           r.RPDisplayName,
		Origins:                 r.Origins,
		MaxCredentialsPerUser:   r.MaxCredentialsPerUser,
	}
}

// passkeyPolicySvc returns the policy resolver, or writes 501 and reports false.
//
// 501 rather than 500: a deployment with no WEBAUTHN_RP_ID has not built this
// feature in, and there is nothing the caller or their tenant can change to make
// the request work. Telling them "not implemented" is the honest answer.
func (h *AdminHandler) passkeyPolicySvc(c echo.Context) (*auth.PasskeyPolicyService, bool) {
	if h.webauthnSvc == nil {
		_ = c.JSON(http.StatusNotImplemented, map[string]string{
			"error": "passkeys are not configured on this server",
			"code":  "not_configured",
		})
		return nil, false
	}
	return h.webauthnSvc.Policy(), true
}

// GetTenantPasskeyPolicy handles GET /api/v1/passkey-policy and
// GET /api/v1/tenants/:tid/passkey-policy.
//
// @Summary      Get tenant passkey policy
// @Description  Returns the tenant's own passkey policy row (or exists=false when it inherits) plus the effective policy after inheritance from the platform default and server configuration.
// @Tags         admin-passkeys
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  auth.PasskeyPolicyRecord
// @Failure      403  {object}  map[string]string
// @Failure      501  {object}  map[string]string  "passkeys not configured on this server"
// @Router       /api/v1/passkey-policy [get]
func (h *AdminHandler) GetTenantPasskeyPolicy(c echo.Context) error {
	svc, ok := h.passkeyPolicySvc(c)
	if !ok {
		return nil
	}
	tenantID, _, err := h.tenantFromClaimsOrPath(c)
	if err != nil {
		return c.JSON(http.StatusForbidden, map[string]string{"error": err.Error()})
	}

	rec, err := svc.GetPolicyRecord(c.Request().Context(), &tenantID, nil)
	if err != nil {
		return h.passkeyPolicyError(c, "get tenant passkey policy", err)
	}
	return c.JSON(http.StatusOK, rec)
}

// UpdateTenantPasskeyPolicy handles PUT /api/v1/passkey-policy and
// PUT /api/v1/tenants/:tid/passkey-policy.
//
// @Summary      Set tenant passkey policy
// @Description  Creates or updates the tenant's passkey policy. Omitted fields keep their stored value; sending rp_id as "" reverts to the server's relying party. Origins are normalised and must be full origins including scheme and port.
// @Tags         admin-passkeys
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body  body      UpdatePasskeyPolicyRequest  true  "Policy fields to change"
// @Success      200   {object}  auth.PasskeyPolicyRecord
// @Failure      400   {object}  map[string]string
// @Failure      403   {object}  map[string]string
// @Router       /api/v1/passkey-policy [put]
func (h *AdminHandler) UpdateTenantPasskeyPolicy(c echo.Context) error {
	svc, ok := h.passkeyPolicySvc(c)
	if !ok {
		return nil
	}
	tenantID, _, err := h.tenantFromClaimsOrPath(c)
	if err != nil {
		return c.JSON(http.StatusForbidden, map[string]string{"error": err.Error()})
	}

	var req UpdatePasskeyPolicyRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}

	rec, err := svc.SetPolicy(c.Request().Context(), &tenantID, nil, req.toUpdate())
	if err != nil {
		return h.passkeyPolicyError(c, "set tenant passkey policy", err)
	}

	h.auditPasskeyPolicy(c, tenantID, nil, rec)
	return c.JSON(http.StatusOK, rec)
}

// GetApplicationPasskeyPolicy handles GET .../applications/:appID/passkey-policy.
//
// @Summary      Get application passkey policy
// @Description  Returns the application's own policy row (or exists=false when it inherits from the tenant) plus the effective policy.
// @Tags         admin-passkeys
// @Produce      json
// @Security     BearerAuth
// @Param        appID  path      string  true  "Application ID"
// @Success      200    {object}  auth.PasskeyPolicyRecord
// @Failure      404    {object}  map[string]string
// @Router       /api/v1/applications/{appID}/passkey-policy [get]
func (h *AdminHandler) GetApplicationPasskeyPolicy(c echo.Context) error {
	svc, ok := h.passkeyPolicySvc(c)
	if !ok {
		return nil
	}
	tenantID, appID, ok := h.passkeyAppScope(c)
	if !ok {
		return nil
	}

	rec, err := svc.GetPolicyRecord(c.Request().Context(), &tenantID, &appID)
	if err != nil {
		return h.passkeyPolicyError(c, "get application passkey policy", err)
	}
	return c.JSON(http.StatusOK, rec)
}

// UpdateApplicationPasskeyPolicy handles PUT .../applications/:appID/passkey-policy.
//
// @Summary      Set application passkey policy
// @Description  Creates or updates the application's passkey policy, overriding the tenant's. This is where a tenant sets the relying-party ID for an application served from its own domain.
// @Tags         admin-passkeys
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        appID  path      string                      true  "Application ID"
// @Param        body   body      UpdatePasskeyPolicyRequest  true  "Policy fields to change"
// @Success      200    {object}  auth.PasskeyPolicyRecord
// @Failure      400    {object}  map[string]string
// @Failure      404    {object}  map[string]string
// @Router       /api/v1/applications/{appID}/passkey-policy [put]
func (h *AdminHandler) UpdateApplicationPasskeyPolicy(c echo.Context) error {
	svc, ok := h.passkeyPolicySvc(c)
	if !ok {
		return nil
	}
	tenantID, appID, ok := h.passkeyAppScope(c)
	if !ok {
		return nil
	}

	var req UpdatePasskeyPolicyRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}

	rec, err := svc.SetPolicy(c.Request().Context(), &tenantID, &appID, req.toUpdate())
	if err != nil {
		return h.passkeyPolicyError(c, "set application passkey policy", err)
	}

	h.auditPasskeyPolicy(c, tenantID, &appID, rec)
	return c.JSON(http.StatusOK, rec)
}

// DeleteApplicationPasskeyPolicy handles DELETE .../applications/:appID/passkey-policy.
//
// @Summary      Clear application passkey policy
// @Description  Removes the application's override so it inherits the tenant's policy again. 404 when there was no override to remove.
// @Tags         admin-passkeys
// @Produce      json
// @Security     BearerAuth
// @Param        appID  path  string  true  "Application ID"
// @Success      204    "cleared"
// @Failure      404    {object}  map[string]string
// @Router       /api/v1/applications/{appID}/passkey-policy [delete]
func (h *AdminHandler) DeleteApplicationPasskeyPolicy(c echo.Context) error {
	svc, ok := h.passkeyPolicySvc(c)
	if !ok {
		return nil
	}
	tenantID, appID, ok := h.passkeyAppScope(c)
	if !ok {
		return nil
	}

	removed, err := svc.DeletePolicy(c.Request().Context(), &tenantID, &appID)
	if err != nil {
		return h.passkeyPolicyError(c, "clear application passkey policy", err)
	}
	if !removed {
		// Reported rather than treated as an idempotent success: an operator who
		// expected an override to exist has learned something useful, and the
		// effective policy they were trying to change lives at another scope.
		return c.JSON(http.StatusNotFound, map[string]string{
			"error": "this application has no passkey policy override",
		})
	}

	rec, err := svc.GetPolicyRecord(c.Request().Context(), &tenantID, &appID)
	if err == nil {
		h.auditPasskeyPolicy(c, tenantID, &appID, rec)
	}
	return c.NoContent(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// A user's credentials, seen by an operator
// ---------------------------------------------------------------------------

// ListUserPasskeys handles GET .../users/:uid/passkeys.
//
// @Summary      List a user's passkeys
// @Description  Support view of one user's registered passkeys. Carries no key material — a public key is useless to a client and a credential id is only meaningful inside a ceremony.
// @Tags         admin-passkeys
// @Produce      json
// @Security     BearerAuth
// @Param        uid  path      string  true  "User ID"
// @Success      200  {array}   auth.StoredCredential
// @Failure      404  {object}  map[string]string  "user not found in this scope"
// @Router       /api/v1/users/{uid}/passkeys [get]
func (h *AdminHandler) ListUserPasskeys(c echo.Context) error {
	if h.webauthnSvc == nil {
		return c.JSON(http.StatusNotImplemented, map[string]string{
			"error": "passkeys are not configured on this server", "code": "not_configured"})
	}
	tenantID, appScope, userID, ok := h.passkeyUserScope(c)
	if !ok {
		return nil
	}

	creds, err := h.webauthnSvc.AdminListCredentials(c.Request().Context(), tenantID, appScope, userID)
	if err != nil {
		return h.passkeyPolicyError(c, "list user passkeys", err)
	}
	return c.JSON(http.StatusOK, creds)
}

// RevokeUserPasskey handles DELETE .../users/:uid/passkeys/:pid.
//
// @Summary      Remove a user's passkey
// @Description  Deactivates one of a user's passkeys on their behalf — the lost-device case. Unlike the user's own delete, this is not blocked when the passkey is their last sign-in method: leaving a factor live on a stolen device is worse than needing a password reset.
// @Tags         admin-passkeys
// @Produce      json
// @Security     BearerAuth
// @Param        uid  path      string  true  "User ID"
// @Param        pid  path      string  true  "Passkey ID"
// @Success      204  "removed"
// @Failure      404  {object}  map[string]string
// @Router       /api/v1/users/{uid}/passkeys/{pid} [delete]
func (h *AdminHandler) RevokeUserPasskey(c echo.Context) error {
	if h.webauthnSvc == nil {
		return c.JSON(http.StatusNotImplemented, map[string]string{
			"error": "passkeys are not configured on this server", "code": "not_configured"})
	}
	tenantID, appScope, userID, ok := h.passkeyUserScope(c)
	if !ok {
		return nil
	}

	pid := c.Param("pid")
	if err := h.webauthnSvc.AdminRevokeCredential(c.Request().Context(), tenantID, appScope, userID, pid); err != nil {
		return h.passkeyPolicyError(c, "revoke user passkey", err)
	}

	claims, _ := c.Get("user").(*auth.Claims)
	actor := ""
	if claims != nil {
		actor = claims.Email
	}
	h.auditEvent(c, audit.Event{
		TenantID:      &tenantID,
		UserID:        &userID,
		ApplicationID: appScope,
		ActorEmail:    actor,
		Action:        audit.ActionAuthPasskeyRemoved,
		ResourceType:  "passkey",
		ResourceID:    pid,
		Metadata:      map[string]any{"by_admin": true},
	})
	return c.NoContent(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// Scope helpers and errors
// ---------------------------------------------------------------------------

// passkeyAppScope resolves the tenant and verifies the path's application
// belongs to it.
func (h *AdminHandler) passkeyAppScope(c echo.Context) (tenantID, appID int64, ok bool) {
	tenantID, _, err := h.tenantFromClaimsOrPath(c)
	if err != nil {
		_ = c.JSON(http.StatusForbidden, map[string]string{"error": err.Error()})
		return 0, 0, false
	}
	appID, ok = h.applicationOwnedByTenant(c, tenantID)
	if !ok {
		return 0, 0, false
	}
	return tenantID, appID, true
}

// passkeyUserScope resolves the tenant, the optional application scope, and the
// target user id from the path.
//
// The application scope is nil on the tenant-level routes and set on the
// application-level ones, which is what makes an application administrator
// unable to reach a user outside their own application's isolated user base.
func (h *AdminHandler) passkeyUserScope(c echo.Context) (tenantID int64, appScope *int64, userID int64, ok bool) {
	tenantID, _, err := h.tenantFromClaimsOrPath(c)
	if err != nil {
		_ = c.JSON(http.StatusForbidden, map[string]string{"error": err.Error()})
		return 0, nil, 0, false
	}

	if c.Param("appID") != "" {
		appID, appOK := h.applicationOwnedByTenant(c, tenantID)
		if !appOK {
			return 0, nil, 0, false
		}
		appScope = &appID
	}

	raw := c.Param("uid")
	if raw == "" {
		raw = c.Param("id")
	}
	userID, err = strconv.ParseInt(raw, 10, 64)
	if err != nil {
		_ = c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid user id"})
		return 0, nil, 0, false
	}
	return tenantID, appScope, userID, true
}

// passkeyPolicyError maps service errors onto admin responses.
func (h *AdminHandler) passkeyPolicyError(c echo.Context, op string, err error) error {
	switch {
	case errors.Is(err, auth.ErrInvalidPasskeyPolicy):
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	case errors.Is(err, auth.ErrUserNotFound):
		return c.JSON(http.StatusNotFound, map[string]string{"error": "user not found"})
	case errors.Is(err, auth.ErrCredentialNotFound):
		return c.JSON(http.StatusNotFound, map[string]string{"error": "passkey not found"})
	case errors.Is(err, auth.ErrPasskeysNotAllowed):
		// Reaches here only when the platform-default row is missing, which is a
		// deployment fault rather than a caller fault — resolution cannot answer
		// at all without it.
		h.logger.Error().Err(err).Msg("admin: " + op + " failed — platform passkey policy row missing")
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "passkey policy is not initialised on this server"})
	default:
		h.logger.Error().Err(err).Msg("admin: " + op + " failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "operation failed"})
	}
}

// auditPasskeyPolicy records a policy change.
//
// The effective values go in the metadata rather than just the row's own fields:
// "allow_passkeys was set to true" is not the interesting fact if the RP ID
// still resolves from somewhere else, and an auditor reading this later needs to
// know what the change actually meant at the time it was made.
func (h *AdminHandler) auditPasskeyPolicy(c echo.Context, tenantID int64, appID *int64, rec *auth.PasskeyPolicyRecord) {
	claims, _ := c.Get("user").(*auth.Claims)
	actor := ""
	if claims != nil {
		actor = claims.Email
	}
	resourceID := strconv.FormatInt(tenantID, 10)
	if appID != nil {
		resourceID = strconv.FormatInt(*appID, 10)
	}
	h.auditEvent(c, audit.Event{
		TenantID:      &tenantID,
		ApplicationID: appID,
		ActorEmail:    actor,
		Action:        audit.ActionAdminPasskeyPolicyUpdated,
		ResourceType:  "passkey_policy",
		ResourceID:    resourceID,
		Metadata: map[string]any{
			"scope":                    rec.Scope,
			"exists":                   rec.Exists,
			"effective_allow_passkeys": rec.Effective.AllowPasskeys,
			"effective_passwordless":   rec.Effective.AllowPasswordless,
			"effective_require_uv":     rec.Effective.RequireUserVerification,
			"effective_rp_id":          rec.Effective.RPID,
			"effective_origins":        rec.Effective.Origins,
			"effective_policy_source":  rec.Effective.Source,
			"max_credentials_per_user": rec.Effective.MaxCredentialsPerUser,
		},
	})
}
