package handlers

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/labstack/echo/v4"

	"github.com/engineersmind/emc-auth-server/internal/admin"
	"github.com/engineersmind/emc-auth-server/internal/audit"
	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// ---------------------------------------------------------------------------
// Mandatory administrator MFA (migration 00094)
//
// Three surfaces:
//
//   - /auth/session/mfa/*  — the console's cookie-only completion of an
//     MFA-gated sign-in: authenticator or email code, and forced enrollment.
//     Tokens land in HttpOnly cookies and never in a response body, matching
//     /auth/session.
//     Deliberately not captcha-gated: the per-challenge attempt cap and the
//     OTP rate limiter bound guessing, and MFA is the stronger control.
//   - /auth/me/mfa         — the caller's own MFA state, for the settings page.
//   - admin-mfa-policy     — which methods satisfy the requirement, per tenant
//     and for the platform. MFA itself cannot be turned off.
// ---------------------------------------------------------------------------

// sessionLoggedIn is the body of every cookie-session success: no tokens.
func sessionLoggedIn(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]string{
		"message":    "logged in",
		"expires_in": accessTokenExpiresIn,
	})
}

// adminMFAPolicyError maps the administrator-policy refusals shared by the
// self-service factor endpoints.
func adminMFAPolicyError(c echo.Context, h *AuthHandler, userID string, err error) error {
	switch {
	case errors.Is(err, auth.ErrAdminMFAMethodNotAllowed):
		return fail(c, http.StatusForbidden, "mfa_method_not_allowed")
	case errors.Is(err, auth.ErrMFARequiredByPolicy):
		return fail(c, http.StatusConflict, "mfa_required_by_policy")
	}
	h.logger.Error().Err(err).Str("user_id", userID).Msg("admin MFA policy check failed")
	return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to check MFA policy"})
}

// sessionMFAFailure maps a failed cookie-session MFA step onto a response and
// an audit row. session may be nil when the token did not resolve.
func (h *AuthHandler) sessionMFAFailure(c echo.Context, session *auth.OTPSession, method, phase string, err error) error {
	event := audit.Event{
		Action:       audit.ActionAuthMFAChallengeFailed,
		AuthMethod:   method,
		ResourceType: "user",
		IPAddress:    c.RealIP(),
		UserAgent:    c.Request().UserAgent(),
		Metadata:     map[string]any{"phase": phase, "flow": "session"},
	}
	if errors.Is(err, auth.ErrTooManyOTPAttempts) {
		event.Action = audit.ActionAuthMFALockedOut
	}
	if session != nil {
		event.TenantID, event.UserID, event.ActorEmail = &session.TenantID, &session.UserID, session.Email
	}
	h.auditFailure(c, event, err)

	switch {
	case errors.Is(err, auth.ErrCookieSessionNotAvailable):
		return errCookieSessionForApps(c)
	case errors.Is(err, auth.ErrTooManyOTPAttempts):
		return c.JSON(http.StatusTooManyRequests, map[string]string{"error": err.Error()})
	case errors.Is(err, auth.ErrAdminMFAMethodNotAllowed), errors.Is(err, auth.ErrMFAMethodNotAllowed):
		return fail(c, http.StatusForbidden, "mfa_method_not_allowed")
	case containsMsg(err, "invalid or expired"):
		return fail(c, http.StatusUnauthorized, "mfa_session_expired")
	case containsMsg(err, "invalid TOTP"), containsMsg(err, "invalid backup"), containsMsg(err, "invalid code"):
		return fail(c, http.StatusUnauthorized, "mfa_code_invalid")
	case containsMsg(err, "not configured"):
		return fail(c, http.StatusNotImplemented, "mfa_unavailable")
	}
	h.logger.Error().Err(err).Str("phase", phase).Msg("session MFA step failed")
	return fail(c, http.StatusInternalServerError, "login_failed")
}

// auditSessionMFALogin records the completed sign-in.
func (h *AuthHandler) auditSessionMFALogin(c echo.Context, session *auth.OTPSession, method string, extra map[string]any) {
	meta := map[string]any{"flow": "session"}
	for k, v := range extra {
		meta[k] = v
	}
	h.auditEvent(c, audit.Event{
		TenantID:     &session.TenantID,
		UserID:       &session.UserID,
		ActorEmail:   session.Email,
		Action:       audit.ActionAuthLogin,
		AuthMethod:   method,
		ResourceType: "user",
		IPAddress:    c.RealIP(),
		UserAgent:    c.Request().UserAgent(),
		Metadata:     meta,
	})
}

// SessionMFAVerifyRequest is the body of POST /auth/session/mfa/verify.
type SessionMFAVerifyRequest struct {
	OTPSessionToken string `json:"otp_session_token"`
	Code            string `json:"code"`
}

// SessionMFAVerify handles POST /api/v1/auth/session/mfa/verify.
//
// @Summary      Complete a console sign-in with a code
// @Description  Completes the MFA challenge returned by POST /auth/session with an authenticator code, a backup code, or the emailed code. The session is set in HttpOnly cookies; no tokens are returned.
// @Tags         auth-session
// @Accept       json
// @Produce      json
// @Param        body  body      SessionMFAVerifyRequest  true  "Challenge token and code"
// @Success      200   {object}  map[string]string
// @Failure      401   {object}  APIError  "mfa_code_invalid or mfa_session_expired"
// @Failure      429   {object}  map[string]string
// @Router       /api/v1/auth/session/mfa/verify [post]
func (h *AuthHandler) SessionMFAVerify(c echo.Context) error {
	var req SessionMFAVerifyRequest
	if err := c.Bind(&req); err != nil || req.OTPSessionToken == "" || req.Code == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "otp_session_token and code are required"})
	}
	ctx := c.Request().Context()

	result, err := h.svc.LoginOTPForCookieSession(ctx, auth.LoginOTPInput{
		OTPSessionToken: req.OTPSessionToken,
		Code:            req.Code,
	})
	if err != nil {
		return h.sessionMFAFailure(c, nil, audit.AuthMethodMFA, "challenge", err)
	}
	tid, uid, _ := claimsFromToken(result.AccessToken)
	h.auditEvent(c, audit.Event{
		TenantID:     tid,
		UserID:       uid,
		Action:       audit.ActionAuthLogin,
		AuthMethod:   audit.AuthMethodMFA,
		ResourceType: "user",
		IPAddress:    c.RealIP(),
		UserAgent:    c.Request().UserAgent(),
		Metadata:     map[string]any{"flow": "session", "transaction_id": transactionID(req.OTPSessionToken)},
	})
	setAuthCookies(c, result.AccessToken, result.RefreshToken, h.cookieCfg)
	return sessionLoggedIn(c)
}

// SessionMFAActivateRequest is the body of POST /auth/session/mfa/enroll/activate.
type SessionMFAActivateRequest struct {
	EnrollmentToken string `json:"enrollment_token"`
	Code            string `json:"code"`
}

// SessionMFAEnrollActivate handles POST /api/v1/auth/session/mfa/enroll/activate.
//
// Completes a forced enrollment started with POST /auth/login/mfa/enroll (TOTP)
// or /auth/login/mfa/email (email), and signs the console in.
//
// @Summary      Finish MFA setup during a console sign-in
// @Tags         auth-session
// @Accept       json
// @Produce      json
// @Param        body  body      SessionMFAActivateRequest  true  "Enrollment token and first code"
// @Success      200   {object}  map[string]string
// @Router       /api/v1/auth/session/mfa/enroll/activate [post]
func (h *AuthHandler) SessionMFAEnrollActivate(c echo.Context) error {
	var req SessionMFAActivateRequest
	if err := c.Bind(&req); err != nil || req.EnrollmentToken == "" || req.Code == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "enrollment_token and code are required"})
	}
	result, session, err := h.svc.ActivatePendingForCookieSession(c.Request().Context(), req.EnrollmentToken, req.Code)
	if err != nil {
		return h.sessionMFAFailure(c, session, audit.AuthMethodMFA, "enrollment", err)
	}
	h.auditEvent(c, audit.Event{
		TenantID:     &session.TenantID,
		UserID:       &session.UserID,
		ActorEmail:   session.Email,
		Action:       audit.ActionAuthMFAActivated,
		AuthMethod:   audit.AuthMethodMFA,
		ResourceType: "user",
		IPAddress:    c.RealIP(),
		UserAgent:    c.Request().UserAgent(),
		Metadata:     map[string]any{"flow": "session", "phase": "enrollment"},
	})
	h.auditSessionMFALogin(c, session, audit.AuthMethodMFA, nil)
	setAuthCookies(c, result.AccessToken, result.RefreshToken, h.cookieCfg)
	return sessionLoggedIn(c)
}

// MyMFA handles GET /api/v1/auth/me/mfa.
//
// @Summary      My MFA status
// @Description  Every MFA method with whether it is allowed for the caller, available on this server, and enrolled. mfa_required is true for administrators, for whom MFA is mandatory.
// @Tags         AUTH
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  auth.MFAStatus
// @Router       /api/v1/auth/me/mfa [get]
func (h *AuthHandler) MyMFA(c echo.Context) error {
	claims, userID, tenantID, ok := mfaClaimIDs(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	status, err := h.svc.MyMFAStatus(c.Request().Context(), userID, tenantID, claims.Permissions)
	if err != nil {
		h.logger.Error().Err(err).Str("user_id", claims.UserID).Msg("MFA status failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to load MFA status"})
	}
	return c.JSON(http.StatusOK, status)
}

// ---------------------------------------------------------------------------
// Administrator MFA policy — tenant and platform
// ---------------------------------------------------------------------------

func (h *AdminHandler) adminMFAPolicyWriteError(c echo.Context, err error) error {
	if errors.Is(err, admin.ErrInvalidAdminMFAPolicy) {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	if errors.Is(err, admin.ErrNotFound) {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "no policy set for this tenant"})
	}
	h.logger.Error().Err(err).Msg("admin: administrator MFA policy write failed")
	return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to save administrator MFA policy"})
}

// GetAdminMFAPolicy handles GET /api/v1/tenants/:tid/admin-mfa-policy.
//
// @Summary      Get the administrator MFA policy
// @Description  Which methods satisfy mandatory MFA for this tenant's administrators, and whether the tenant inherits the platform policy.
// @Tags         admin-security
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  admin.AdminMFAPolicyView
// @Router       /api/v1/tenants/{tid}/admin-mfa-policy [get]
func (h *AdminHandler) GetAdminMFAPolicy(c echo.Context) error {
	tenantID, _, err := h.tenantFromClaimsOrPath(c)
	if err != nil {
		return c.JSON(http.StatusForbidden, map[string]string{"error": err.Error()})
	}
	return h.getAdminMFAPolicy(c, tenantID)
}

// UpdateAdminMFAPolicy handles PUT /api/v1/tenants/:tid/admin-mfa-policy.
//
// @Summary      Set the administrator MFA policy
// @Description  Sets which methods (passkey, totp, email) satisfy mandatory MFA for this tenant's administrators. At least one method is required; MFA itself cannot be turned off.
// @Tags         admin-security
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body  body      admin.AdminMFAPolicyInput  true  "Allowed methods"
// @Success      200   {object}  admin.AdminMFAPolicyView
// @Failure      400   {object}  map[string]string
// @Router       /api/v1/tenants/{tid}/admin-mfa-policy [put]
func (h *AdminHandler) UpdateAdminMFAPolicy(c echo.Context) error {
	tenantID, claims, err := h.tenantFromClaimsOrPath(c)
	if err != nil {
		return c.JSON(http.StatusForbidden, map[string]string{"error": err.Error()})
	}
	return h.setAdminMFAPolicy(c, claims, tenantID)
}

// DeleteAdminMFAPolicy handles DELETE /api/v1/tenants/:tid/admin-mfa-policy.
//
// @Summary      Reset the administrator MFA policy
// @Description  Removes the tenant's own policy so it inherits the platform policy.
// @Tags         admin-security
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /api/v1/tenants/{tid}/admin-mfa-policy [delete]
func (h *AdminHandler) DeleteAdminMFAPolicy(c echo.Context) error {
	tenantID, claims, err := h.tenantFromClaimsOrPath(c)
	if err != nil {
		return c.JSON(http.StatusForbidden, map[string]string{"error": err.Error()})
	}
	if err := h.svc.DeleteAdminMFAPolicy(c.Request().Context(), tenantID); err != nil {
		return h.adminMFAPolicyWriteError(c, err)
	}
	h.auditAdminTenantMeta(c, claims, &tenantID, audit.ActionAdminAdminMFAPolicyReset, "admin_mfa_policy",
		strconv.FormatInt(tenantID, 10), nil, nil)
	return c.JSON(http.StatusOK, map[string]string{"message": "administrator MFA policy now inherits the platform policy"})
}

// GetPlatformAdminMFAPolicy handles GET /api/v1/platform/admin-mfa-policy.
//
// @Summary      Get the platform administrator MFA policy
// @Description  Governs platform administrators and every tenant without its own policy.
// @Tags         admin-security
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  admin.AdminMFAPolicyView
// @Router       /api/v1/platform/admin-mfa-policy [get]
func (h *AdminHandler) GetPlatformAdminMFAPolicy(c echo.Context) error {
	return h.getAdminMFAPolicy(c, 0)
}

// UpdatePlatformAdminMFAPolicy handles PUT /api/v1/platform/admin-mfa-policy.
//
// @Summary      Set the platform administrator MFA policy
// @Tags         admin-security
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body  body      admin.AdminMFAPolicyInput  true  "Allowed methods"
// @Success      200   {object}  admin.AdminMFAPolicyView
// @Router       /api/v1/platform/admin-mfa-policy [put]
func (h *AdminHandler) UpdatePlatformAdminMFAPolicy(c echo.Context) error {
	claims, ok := claimsFromCtx(c)
	if !ok {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
	}
	return h.setAdminMFAPolicy(c, claims, 0)
}

func (h *AdminHandler) getAdminMFAPolicy(c echo.Context, tenantID int64) error {
	policy, err := h.svc.GetAdminMFAPolicy(c.Request().Context(), tenantID)
	if err != nil {
		h.logger.Error().Err(err).Msg("admin: get administrator MFA policy failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to load administrator MFA policy"})
	}
	return c.JSON(http.StatusOK, policy)
}

func (h *AdminHandler) setAdminMFAPolicy(c echo.Context, claims *auth.Claims, tenantID int64) error {
	var in admin.AdminMFAPolicyInput
	if err := c.Bind(&in); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}
	policy, err := h.svc.SetAdminMFAPolicy(c.Request().Context(), tenantID, actorUserID(claims), in)
	if err != nil {
		return h.adminMFAPolicyWriteError(c, err)
	}
	// Attributed to the tenant the policy governs; the platform policy has no
	// tenant, so it is filed under the actor's own.
	var tid *int64
	if tenantID != 0 {
		tid = &tenantID
	} else if own, err := tenantIDFromClaims(claims); err == nil {
		tid = &own
	}
	h.auditAdminTenantMeta(c, claims, tid, audit.ActionAdminAdminMFAPolicySet, "admin_mfa_policy",
		strconv.FormatInt(tenantID, 10), nil, map[string]any{
			"scope":           policy.Scope,
			"allowed_methods": policy.AllowedMethods,
		})
	return c.JSON(http.StatusOK, policy)
}

// ---------------------------------------------------------------------------
// Administrator MFA reset — the recovery path for a lost factor
// ---------------------------------------------------------------------------

// ResetAdministratorMFA handles DELETE /api/v1/tenants/:tid/admins/:adminID/mfa.
//
// Removes every factor the administrator has (TOTP and backup codes, email
// MFA, passkeys) and signs them out everywhere; their next sign-in enrolls
// again. Nobody may reset their own MFA — that would let a stolen session
// replace the factor it was missing. Co-owners never reach this route: it is
// tenant-level, and the route guard refuses application-scoped callers.
//
// @Summary      Reset an administrator's MFA
// @Tags         admin-tenant-admins
// @Produce      json
// @Security     BearerAuth
// @Param        tid          path  int  true  "Tenant ID"
// @Param        adminID      path  int  true  "Administrator ID"
// @Success      200  {object}  map[string]string
// @Failure      403  {object}  APIError  "mfa_reset_forbidden"
// @Failure      404  {object}  map[string]string
// @Router       /api/v1/tenants/{tid}/admins/{adminID}/mfa [delete]
func (h *AdminHandler) ResetAdministratorMFA(c echo.Context) error {
	tenantID, claims, err := h.tenantFromClaimsOrPath(c)
	if err != nil {
		return c.JSON(http.StatusForbidden, map[string]string{"error": err.Error()})
	}
	adminID, err := strconv.ParseInt(c.Param("adminID"), 10, 64)
	if err != nil || adminID <= 0 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid administrator id"})
	}
	if h.totpSvc == nil {
		return fail(c, http.StatusNotImplemented, "mfa_unavailable")
	}

	ctx := c.Request().Context()
	targetID, homeTenant, err := h.svc.AdministratorForReset(ctx, tenantID, adminID)
	if err != nil {
		if errors.Is(err, admin.ErrNotFound) {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "administrator not found"})
		}
		h.logger.Error().Err(err).Msg("admin: resolve administrator for MFA reset failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to reset MFA"})
	}
	if actor := actorUserID(claims); actor != nil && *actor == targetID {
		return fail(c, http.StatusForbidden, "mfa_reset_forbidden")
	}

	if err := h.totpSvc.ResetUserMFA(ctx, homeTenant, nil, targetID); err != nil {
		if errors.Is(err, auth.ErrUserNotFound) {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "administrator not found"})
		}
		h.logger.Error().Err(err).Msg("admin: reset administrator MFA failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to reset MFA"})
	}
	// A lost device usually still holds a session. Ending them all is what makes
	// the reset a recovery rather than a new factor next to a live compromise.
	revoked, err := h.svc.RevokeAllUserSessions(ctx, homeTenant, nil, targetID)
	if err != nil {
		h.logger.Error().Err(err).Int64("user_id", targetID).
			Msg("admin: administrator MFA was reset but sessions could not be revoked")
	}

	h.auditAdminTenantMeta(c, claims, &tenantID, audit.ActionAdminUserMFAReset, "user",
		strconv.FormatInt(targetID, 10), nil, map[string]any{
			"administrator":    true,
			"sessions_revoked": revoked,
		})
	return c.JSON(http.StatusOK, map[string]string{
		"message": "MFA reset — the administrator has been signed out and will set up MFA at their next sign-in",
	})
}
