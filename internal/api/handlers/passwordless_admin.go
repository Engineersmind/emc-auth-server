package handlers

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/labstack/echo/v4"

	"github.com/engineersmind/emc-auth-server/internal/audit"
	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// ---------------------------------------------------------------------------
// Admin: passwordless policy and user recovery (issue #203, plan section 7.3).
//
// Routes (every GET returns the stored row, the effective values and where each
// came from):
//
//	GET|PUT|DELETE  /tenants/:tid/passwordless-policy
//	GET|PUT|DELETE  /tenants/:tid/applications/:appID/passwordless-policy
//	GET|PUT         /platform/passwordless-policy             defaults and ceilings
//	POST            .../applications/:appID/passwordless-policy/impact
//	GET             .../passwordless-policy/history
//	POST            .../passwordless-policy/history/:hid/restore
//	GET             .../applications/:appID/passwordless/stats?window=24h|7d|30d
//	GET             .../applications/:appID/users/:uid/auth-methods
//	POST            .../applications/:appID/users/:uid/verify-email
//	POST            .../applications/:appID/users/:uid/clear-passwordless-throttle
//	PUT             .../applications/:appID/users/:uid/email
//
// A test email of the sign-in code needs no route of its own: the existing
// email-settings/test route accepts template_type "passwordless_code", marks the
// message as a test and never creates a challenge for any account.
// ---------------------------------------------------------------------------

// PasswordlessAdminDeps are the services the passwordless admin routes use.
type PasswordlessAdminDeps struct {
	Policy      *auth.PasswordlessPolicyService
	Admin       *auth.PasswordlessAdminService
	Auth        *auth.AuthService
	EmailChange *auth.EmailChangeService
	// ServerEnabled is the deployment switch (PASSWORDLESS_ENABLED). The routes
	// work either way, so an administrator can prepare a policy before the
	// switch is turned on; the console uses this to show the cards read-only.
	ServerEnabled bool
}

// WithPasswordlessAdmin attaches the passwordless admin services. Without them
// the routes answer 503.
func (h *AdminHandler) WithPasswordlessAdmin(d PasswordlessAdminDeps) *AdminHandler {
	h.pwless = &d
	return h
}

// pwlessCtx is what every passwordless admin handler needs resolved.
type pwlessCtx struct {
	tenantID int64
	appID    *int64
	claims   *auth.Claims
	scope    auth.PasswordlessScope
}

func (h *AdminHandler) pwlessRequest(c echo.Context) (*pwlessCtx, bool) {
	if h.pwless == nil || h.pwless.Policy == nil {
		_ = c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "passwordless administration is not configured"})
		return nil, false
	}
	tenantID, claims, err := h.tenantFromClaimsOrPath(c)
	if err != nil {
		_ = c.JSON(http.StatusForbidden, map[string]string{"error": err.Error()})
		return nil, false
	}
	appID, ok := h.optionalAppScope(c, tenantID)
	if !ok {
		return nil, false
	}
	return &pwlessCtx{tenantID: tenantID, appID: appID, claims: claims,
		scope: auth.PasswordlessScope{TenantID: &tenantID, ApplicationID: appID}}, true
}

// tenantWide reports whether the caller administers the whole tenant: a platform
// operator or a tenant owner, not an application-scoped administrator.
func tenantWide(claims *auth.Claims) bool {
	return claims != nil && (hasPermission(claims, "tenant:manage") || claims.AdminScope == auth.AdminScopeTenant)
}

// pwlessErr writes the response for a recognised policy error and reports whether it
// did. The two-value return matters: echo's c.JSON returns nil on success, so a
// single error return could not tell "handled" from "not mine".
func pwlessErr(c echo.Context, err error) (bool, error) {
	switch {
	case errors.Is(err, auth.ErrPasswordlessVersionConflict):
		return true, c.JSON(http.StatusConflict, map[string]string{"error": "version_conflict", "message": err.Error()})
	case errors.Is(err, auth.ErrPasswordlessNoFirstFactor):
		return true, c.JSON(http.StatusUnprocessableEntity, map[string]string{"error": "no_first_factor", "message": err.Error()})
	case errors.Is(err, auth.ErrPasswordlessMFAConflict):
		return true, c.JSON(http.StatusUnprocessableEntity, map[string]string{"error": "passwordless_mfa_conflict", "message": err.Error()})
	case errors.Is(err, auth.ErrPasswordlessTemplateDisabled):
		return true, c.JSON(http.StatusUnprocessableEntity, map[string]string{"error": "template_disabled", "message": err.Error()})
	case errors.Is(err, auth.ErrPasswordlessCeiling):
		return true, c.JSON(http.StatusUnprocessableEntity, map[string]string{"error": "exceeds_platform_limit", "message": err.Error()})
	case errors.Is(err, auth.ErrPasswordlessInvalid):
		return true, c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid_policy", "message": err.Error()})
	case errors.Is(err, auth.ErrPasswordlessNoPasswordUsers):
		return true, c.JSON(http.StatusConflict, map[string]string{"error": "users_without_password", "message": err.Error()})
	case errors.Is(err, auth.ErrPasswordlessPolicyNotFound):
		return true, c.JSON(http.StatusNotFound, map[string]string{"error": "not_found", "message": err.Error()})
	}
	return false, nil
}

func actorID(claims *auth.Claims) *int64 {
	if claims == nil {
		return nil
	}
	if id, err := strconv.ParseInt(claims.UserID, 10, 64); err == nil {
		return &id
	}
	return nil
}

// PasswordlessPolicyResponse is the GET body: the view plus the server switch.
type PasswordlessPolicyResponse struct {
	*auth.PasswordlessPolicyView
	ServerEnabled bool `json:"server_enabled"`
}

// GetPasswordlessPolicy handles GET on the passwordless-policy routes.
//
// @Summary      Get the passwordless sign-in policy
// @Description  Returns the overrides stored at this scope (null when none), the effective values after inheritance, which level supplied each value, and the resulting mode (password_only, both, passwordless_only). server_enabled reports whether PASSWORDLESS_ENABLED is on for this deployment.
// @Tags         admin-security
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  PasswordlessPolicyResponse
// @Router       /api/v1/tenants/{tid}/applications/{appID}/passwordless-policy [get]
func (h *AdminHandler) GetPasswordlessPolicy(c echo.Context) error {
	p, ok := h.pwlessRequest(c)
	if !ok {
		return nil
	}
	view, err := h.pwless.Policy.View(c.Request().Context(), p.scope)
	if err != nil {
		h.logger.Error().Err(err).Msg("admin: get passwordless policy failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to load the passwordless policy"})
	}
	return c.JSON(http.StatusOK, PasswordlessPolicyResponse{view, h.pwless.ServerEnabled})
}

// PutPasswordlessPolicyRequest is the PUT body. Policy replaces the overrides at
// the scope: a field set to null inherits. Version is the version last read (0
// when the scope has no row).
type PutPasswordlessPolicyRequest struct {
	Policy  auth.PasswordlessPolicyRow `json:"policy"`
	Version int                        `json:"version"`
	// OverrideNoPasswordUsers confirms a switch to password only while active
	// users have no stored password.
	OverrideNoPasswordUsers bool `json:"override_no_password_users"`
}

// PutPasswordlessPolicy handles PUT on the passwordless-policy routes.
//
// @Summary      Set the passwordless sign-in policy
// @Description  Replaces the overrides at this scope. Checked against the resolved policy: at least one first factor must remain, email codes cannot be enabled where required MFA allows only email, values may not exceed platform limits, and the sign-in-code template must be enabled. Optimistic concurrency: send the version you read; a mismatch is 409. Enabling sign-up, closing the password flow and editing tenant defaults need a tenant owner. Switching to password only while active users have no password needs override_no_password_users.
// @Tags         admin-security
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body  body      PutPasswordlessPolicyRequest  true  "Overrides"
// @Success      200   {object}  PasswordlessPolicyResponse
// @Failure      409   {object}  map[string]string
// @Failure      422   {object}  map[string]string
// @Router       /api/v1/tenants/{tid}/applications/{appID}/passwordless-policy [put]
func (h *AdminHandler) PutPasswordlessPolicy(c echo.Context) error {
	p, ok := h.pwlessRequest(c)
	if !ok {
		return nil
	}
	var req PutPasswordlessPolicyRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}
	ctx := c.Request().Context()

	// Tenant defaults change every application that does not override them.
	if p.appID == nil && !tenantWide(p.claims) {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "tenant_owner_required",
			"message": "Only a tenant owner can change the authentication defaults for the whole tenant."})
	}

	// Opening sign-up or closing the password flow reshapes who can get in, so an
	// application-scoped administrator needs the tenant owner to do it.
	before, err := h.pwless.Policy.View(ctx, p.scope)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to load the passwordless policy"})
	}
	if p.appID != nil && !tenantWide(p.claims) {
		after, vErr := h.pwless.Policy.Validate(ctx, p.scope, &req.Policy)
		if vErr == nil &&
			((after.SignupEnabled && !before.Effective.SignupEnabled) || (!after.PasswordEnabled && before.Effective.PasswordEnabled)) {
			return c.JSON(http.StatusForbidden, map[string]string{"error": "tenant_owner_required",
				"message": "Only a tenant owner can turn on sign-up by code or close the password flow."})
		}
	}
	if handled, resp := h.pwlessSwitchGuard(c, p.scope, &req.Policy, req.OverrideNoPasswordUsers); handled {
		return resp
	}

	saved, err := h.pwless.Policy.Put(ctx, p.scope, auth.PasswordlessWriteInput{
		Row: req.Policy, Version: req.Version, Actor: actorID(p.claims),
	})
	if err != nil {
		if errors.Is(err, auth.ErrPasswordlessVersionConflict) {
			// Show the other administrator's change instead of overwriting it.
			cur, _ := h.pwless.Policy.View(ctx, p.scope)
			return c.JSON(http.StatusConflict, map[string]any{
				"error": "version_conflict", "message": err.Error(), "current": cur,
			})
		}
		if handled, resp := pwlessErr(c, err); handled {
			return resp
		}
		h.logger.Error().Err(err).Msg("admin: put passwordless policy failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to save the passwordless policy"})
	}
	h.auditPasswordlessChange(c, p, "set", saved)
	view, _ := h.pwless.Policy.View(ctx, p.scope)
	return c.JSON(http.StatusOK, PasswordlessPolicyResponse{view, h.pwless.ServerEnabled})
}

// pwlessSwitchGuard refuses a change (PUT, DELETE with in == nil, restore) that
// would leave an application password only while active users have no password,
// unless the administrator confirmed it. It covers every application the write
// reaches, so tenant and platform defaults are guarded like an application's own.
func (h *AdminHandler) pwlessSwitchGuard(c echo.Context, sc auth.PasswordlessScope, in *auth.PasswordlessPolicyRow, override bool) (bool, error) {
	if h.pwless.Admin == nil {
		return false, nil
	}
	err := h.pwless.Admin.SwitchGuardScope(c.Request().Context(), sc, in, override)
	if err == nil {
		return false, nil
	}
	if handled, resp := pwlessErr(c, err); handled {
		return true, resp
	}
	h.logger.Error().Err(err).Msg("admin: passwordless switch guard failed")
	return true, c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to check the effect of this change"})
}

func (h *AdminHandler) auditPasswordlessChange(c echo.Context, p *pwlessCtx, how string, saved *auth.PasswordlessPolicyRow) {
	meta := map[string]any{"how": how, "scope": p.scope.Level()}
	if saved != nil {
		meta["version"] = saved.Version
		meta["email_otp_enabled"] = saved.EmailOTPEnabled
		meta["signup_enabled"] = saved.SignupEnabled
		meta["password_enabled"] = saved.PasswordEnabled
	}
	h.auditAdminAppMeta(c, p.claims, audit.ActionAdminPasswordlessPolicyChanged, "passwordless_policy",
		strconv.FormatInt(p.tenantID, 10), p.appID, meta)
}

// DeletePasswordlessPolicy handles DELETE on the passwordless-policy routes.
//
// @Summary      Reset the passwordless sign-in policy
// @Description  Removes this scope's overrides so it inherits again. Refused when the inherited result would leave no first factor.
// @Tags         admin-security
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  map[string]string
// @Router       /api/v1/tenants/{tid}/applications/{appID}/passwordless-policy [delete]
func (h *AdminHandler) DeletePasswordlessPolicy(c echo.Context) error {
	p, ok := h.pwlessRequest(c)
	if !ok {
		return nil
	}
	if p.appID == nil && !tenantWide(p.claims) {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "tenant_owner_required"})
	}
	var body struct {
		OverrideNoPasswordUsers bool `json:"override_no_password_users"`
	}
	_ = c.Bind(&body)
	ctx := c.Request().Context()
	// Deleting an override is a write whose result the parent chooses, so apply
	// the checks PUT applies to the inherited result.
	if p.appID != nil && !tenantWide(p.claims) {
		before, after, err := h.pwless.Policy.ProjectApp(ctx, p.scope, nil, p.tenantID, *p.appID)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to load the passwordless policy"})
		}
		if (after.SignupEnabled && !before.SignupEnabled) || (!after.PasswordEnabled && before.PasswordEnabled) {
			return c.JSON(http.StatusForbidden, map[string]string{"error": "tenant_owner_required",
				"message": "Resetting to the inherited policy would turn on sign-up by code or close the password flow, which needs a tenant owner."})
		}
	}
	if handled, resp := h.pwlessSwitchGuard(c, p.scope, nil, body.OverrideNoPasswordUsers); handled {
		return resp
	}
	if err := h.pwless.Policy.Delete(ctx, p.scope, actorID(p.claims)); err != nil {
		if handled, resp := pwlessErr(c, err); handled {
			return resp
		}
		h.logger.Error().Err(err).Msg("admin: delete passwordless policy failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to reset the passwordless policy"})
	}
	h.auditPasswordlessChange(c, p, "reset", nil)
	return c.JSON(http.StatusOK, map[string]string{"message": "passwordless policy reset to inherited"})
}

// GetPlatformPasswordlessPolicy handles GET /api/v1/platform/passwordless-policy.
//
// @Summary      Get the platform passwordless defaults and ceilings
// @Description  Platform values are defaults for every tenant and ceilings no tenant or application may exceed. Requires tenant:manage.
// @Tags         admin-security
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  PasswordlessPolicyResponse
// @Router       /api/v1/platform/passwordless-policy [get]
func (h *AdminHandler) GetPlatformPasswordlessPolicy(c echo.Context) error {
	if h.pwless == nil || h.pwless.Policy == nil {
		return c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "passwordless administration is not configured"})
	}
	view, err := h.pwless.Policy.View(c.Request().Context(), auth.PasswordlessScope{})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to load the passwordless policy"})
	}
	return c.JSON(http.StatusOK, PasswordlessPolicyResponse{view, h.pwless.ServerEnabled})
}

// PutPlatformPasswordlessPolicy handles PUT /api/v1/platform/passwordless-policy.
//
// @Summary      Set the platform passwordless defaults and ceilings
// @Description  Requires tenant:manage. Same body and checks as the tenant route.
// @Tags         admin-security
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body  body      PutPasswordlessPolicyRequest  true  "Overrides"
// @Success      200   {object}  PasswordlessPolicyResponse
// @Router       /api/v1/platform/passwordless-policy [put]
func (h *AdminHandler) PutPlatformPasswordlessPolicy(c echo.Context) error {
	if h.pwless == nil || h.pwless.Policy == nil {
		return c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "passwordless administration is not configured"})
	}
	claims, _ := claimsFromCtx(c)
	var req PutPasswordlessPolicyRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}
	sc := auth.PasswordlessScope{}
	if handled, resp := h.pwlessSwitchGuard(c, sc, &req.Policy, req.OverrideNoPasswordUsers); handled {
		return resp
	}
	saved, err := h.pwless.Policy.Put(c.Request().Context(), sc, auth.PasswordlessWriteInput{
		Row: req.Policy, Version: req.Version, Actor: actorID(claims),
	})
	if err != nil {
		if handled, resp := pwlessErr(c, err); handled {
			return resp
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to save the passwordless policy"})
	}
	h.auditAdminAppMeta(c, claims, audit.ActionAdminPasswordlessPolicyChanged, "passwordless_policy", "platform", nil,
		map[string]any{"how": "set", "scope": "platform", "version": saved.Version})
	view, _ := h.pwless.Policy.View(c.Request().Context(), sc)
	return c.JSON(http.StatusOK, PasswordlessPolicyResponse{view, h.pwless.ServerEnabled})
}

// PasswordlessImpactRequest is the body of the impact dry run.
type PasswordlessImpactRequest struct {
	Policy auth.PasswordlessPolicyRow `json:"policy"`
}

// PasswordlessImpact handles POST .../passwordless-policy/impact.
//
// @Summary      Preview what a policy change would do
// @Description  Dry run, writes nothing. Reports the mode before and after, active users with and without a stored password, users whose address is unverified, password sign-ins in the last 7 and 30 days, users who would be asked to enrol an authenticator app, whether self-registration remains possible, and warnings. risky means the console should ask for the application name to be typed; requires_override means the change would strand users without a password.
// @Tags         admin-security
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body  body      PasswordlessImpactRequest  true  "Proposed overrides"
// @Success      200   {object}  auth.PasswordlessImpact
// @Router       /api/v1/tenants/{tid}/applications/{appID}/passwordless-policy/impact [post]
func (h *AdminHandler) PasswordlessImpact(c echo.Context) error {
	p, ok := h.pwlessRequest(c)
	if !ok {
		return nil
	}
	if p.appID == nil || h.pwless.Admin == nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "impact_requires_application",
			"message": "The impact preview is computed per application."})
	}
	var req PasswordlessImpactRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}
	im, err := h.pwless.Admin.Impact(c.Request().Context(), p.tenantID, *p.appID, req.Policy)
	if err != nil {
		if handled, resp := pwlessErr(c, err); handled {
			return resp
		}
		h.logger.Error().Err(err).Msg("admin: passwordless impact failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to compute the impact"})
	}
	return c.JSON(http.StatusOK, im)
}

// PasswordlessHistory handles GET .../passwordless-policy/history.
//
// @Summary      Passwordless policy history
// @Description  Append-only list of changes at this scope, newest first, with the field-level before and after of each.
// @Tags         admin-security
// @Produce      json
// @Security     BearerAuth
// @Success      200  {array}  auth.PasswordlessHistoryEntry
// @Router       /api/v1/tenants/{tid}/applications/{appID}/passwordless-policy/history [get]
func (h *AdminHandler) PasswordlessHistory(c echo.Context) error {
	p, ok := h.pwlessRequest(c)
	if !ok {
		return nil
	}
	limit, _ := strconv.Atoi(c.QueryParam("limit"))
	entries, err := h.pwless.Policy.History(c.Request().Context(), p.scope, limit)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to load the history"})
	}
	return c.JSON(http.StatusOK, entries)
}

// PasswordlessRestore handles POST .../passwordless-policy/history/:hid/restore.
//
// @Summary      Restore an earlier passwordless policy version
// @Description  Writes a NEW version from the old snapshot; history is never rewritten. Send the current version as version. Restoring is checked and permissioned exactly like a PUT.
// @Tags         admin-security
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  PasswordlessPolicyResponse
// @Router       /api/v1/tenants/{tid}/applications/{appID}/passwordless-policy/history/{hid}/restore [post]
func (h *AdminHandler) PasswordlessRestore(c echo.Context) error {
	p, ok := h.pwlessRequest(c)
	if !ok {
		return nil
	}
	if p.appID == nil && !tenantWide(p.claims) {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "tenant_owner_required"})
	}
	hid, err := strconv.ParseInt(c.Param("hid"), 10, 64)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid history id"})
	}
	var body struct {
		Version                 int  `json:"version"`
		OverrideNoPasswordUsers bool `json:"override_no_password_users"`
	}
	_ = c.Bind(&body)
	// A restore is a write: an application administrator may not use it to open
	// sign-up or close the password flow.
	if p.appID != nil && !tenantWide(p.claims) {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "tenant_owner_required",
			"message": "Restoring an earlier version can reopen sign-up or close the password flow, so it needs a tenant owner."})
	}
	snap, err := h.pwless.Policy.Snapshot(c.Request().Context(), p.scope, hid)
	if err != nil {
		if handled, resp := pwlessErr(c, err); handled {
			return resp
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to restore the policy"})
	}
	if handled, resp := h.pwlessSwitchGuard(c, p.scope, snap, body.OverrideNoPasswordUsers); handled {
		return resp
	}
	saved, err := h.pwless.Policy.Restore(c.Request().Context(), p.scope, hid, body.Version, actorID(p.claims))
	if err != nil {
		if handled, resp := pwlessErr(c, err); handled {
			return resp
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to restore the policy"})
	}
	h.auditPasswordlessChange(c, p, "restore", saved)
	view, _ := h.pwless.Policy.View(c.Request().Context(), p.scope)
	return c.JSON(http.StatusOK, PasswordlessPolicyResponse{view, h.pwless.ServerEnabled})
}

// PasswordlessStats handles GET .../passwordless/stats.
//
// @Summary      Passwordless usage statistics
// @Description  Counts over 24h, 7d or 30d from the audit log: codes requested and throttled, sign-ins by code, failed verifications and the success rate, accounts created and secured, and password requests refused because the flow is closed.
// @Tags         admin-security
// @Produce      json
// @Security     BearerAuth
// @Param        window  query  string  false  "24h, 7d or 30d (default 24h)"
// @Success      200  {object}  auth.PasswordlessStats
// @Router       /api/v1/tenants/{tid}/applications/{appID}/passwordless/stats [get]
func (h *AdminHandler) PasswordlessStats(c echo.Context) error {
	p, ok := h.pwlessRequest(c)
	if !ok {
		return nil
	}
	if p.appID == nil || h.pwless.Admin == nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "stats_require_application"})
	}
	st, err := h.pwless.Admin.Stats(c.Request().Context(), p.tenantID, *p.appID, c.QueryParam("window"))
	if err != nil {
		h.logger.Error().Err(err).Msg("admin: passwordless stats failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to load the statistics"})
	}
	return c.JSON(http.StatusOK, st)
}

// pwlessUser resolves tenant, application and user id for the per-user routes.
func (h *AdminHandler) pwlessUser(c echo.Context) (*pwlessCtx, int64, bool) {
	p, ok := h.pwlessRequest(c)
	if !ok {
		return nil, 0, false
	}
	if h.pwless.Admin == nil {
		_ = c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "passwordless administration is not configured"})
		return nil, 0, false
	}
	uid, err := strconv.ParseInt(c.Param("uid"), 10, 64)
	if err != nil {
		_ = c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid user id"})
		return nil, 0, false
	}
	if p.appID == nil {
		// A tenant-level route: the user names its own application.
		app, aErr := h.pwless.Admin.UserApplication(c.Request().Context(), p.tenantID, uid)
		if aErr != nil {
			_ = c.JSON(http.StatusNotFound, map[string]string{"error": "not_found"})
			return nil, 0, false
		}
		p.appID = &app
		p.scope.ApplicationID = &app
	}
	return p, uid, true
}

// UserAuthMethods handles GET .../users/:uid/auth-methods.
//
// @Summary      A user's sign-in methods
// @Description  Password, email code, passkeys, social providers and MFA factors, each with when it was added and last used.
// @Tags         admin-users
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  auth.PasswordlessUserMethods
// @Router       /api/v1/tenants/{tid}/applications/{appID}/users/{uid}/auth-methods [get]
func (h *AdminHandler) UserAuthMethods(c echo.Context) error {
	p, uid, ok := h.pwlessUser(c)
	if !ok {
		return nil
	}
	res, err := h.pwless.Admin.UserAuthMethods(c.Request().Context(), p.tenantID, *p.appID, uid)
	if err != nil {
		if handled, resp := pwlessErr(c, err); handled {
			return resp
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to load the sign-in methods"})
	}
	return c.JSON(http.StatusOK, res)
}

// VerifyUserEmail handles POST .../users/:uid/verify-email.
//
// @Summary      Mark a user's email address as verified
// @Tags         admin-users
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  map[string]any
// @Router       /api/v1/tenants/{tid}/applications/{appID}/users/{uid}/verify-email [post]
func (h *AdminHandler) VerifyUserEmail(c echo.Context) error {
	p, uid, ok := h.pwlessUser(c)
	if !ok {
		return nil
	}
	changed, err := h.pwless.Admin.MarkEmailVerified(c.Request().Context(), p.tenantID, *p.appID, uid)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to verify the address"})
	}
	h.auditAdminAppMeta(c, p.claims, audit.ActionAdminUserEmailVerified, "user", strconv.FormatInt(uid, 10), p.appID,
		map[string]any{"changed": changed})
	return c.JSON(http.StatusOK, map[string]any{"email_verified": true, "changed": changed})
}

// ClearPasswordlessThrottle handles POST .../users/:uid/clear-passwordless-throttle.
//
// @Summary      Lift a user's passwordless verify block
// @Description  Clears the 15-minute block that follows too many failed code attempts for the address, and its failure count.
// @Tags         admin-users
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  map[string]string
// @Router       /api/v1/tenants/{tid}/applications/{appID}/users/{uid}/clear-passwordless-throttle [post]
func (h *AdminHandler) ClearPasswordlessThrottle(c echo.Context) error {
	p, uid, ok := h.pwlessUser(c)
	if !ok {
		return nil
	}
	email, err := h.pwless.Admin.UserEmail(c.Request().Context(), p.tenantID, *p.appID, uid)
	if err != nil {
		_, resp := pwlessErr(c, err)
		return resp
	}
	if h.pwless.Auth == nil {
		return c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "passwordless is not configured"})
	}
	if err := h.pwless.Auth.ClearPasswordlessThrottle(c.Request().Context(), *p.appID, email); err != nil {
		return c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "the throttle could not be cleared"})
	}
	h.auditAdminAppMeta(c, p.claims, audit.ActionAdminPasswordlessThrottleCleared, "user", strconv.FormatInt(uid, 10), p.appID, nil)
	return c.JSON(http.StatusOK, map[string]string{"message": "throttle cleared"})
}

// ChangeUserEmailRequest is the body of the admin-assisted email change.
type ChangeUserEmailRequest struct {
	Email  string `json:"email"`
	Reason string `json:"reason"`
}

// ChangeUserEmail handles PUT .../users/:uid/email.
//
// @Summary      Change a user's email on their behalf (lost-mailbox recovery)
// @Description  Requires a reason. Marks the new address verified, revokes every session of the user and tells the previous address what happened. Audited with the reason.
// @Tags         admin-users
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body  body      ChangeUserEmailRequest  true  "New address and reason"
// @Success      200   {object}  map[string]string
// @Failure      409   {object}  map[string]string  "The address is taken"
// @Router       /api/v1/tenants/{tid}/applications/{appID}/users/{uid}/email [put]
func (h *AdminHandler) ChangeUserEmail(c echo.Context) error {
	p, uid, ok := h.pwlessUser(c)
	if !ok {
		return nil
	}
	if h.pwless.EmailChange == nil {
		return c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "email change is not configured"})
	}
	var req ChangeUserEmailRequest
	if err := c.Bind(&req); err != nil || strings.TrimSpace(req.Email) == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "email is required"})
	}
	if len(strings.TrimSpace(req.Reason)) < 8 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "reason_required",
			"message": "Say why the address is being changed (at least 8 characters). It is recorded in the audit log."})
	}
	res, err := h.pwless.EmailChange.AdminChange(c.Request().Context(), p.tenantID, p.appID, uid, req.Email)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrEmailTaken):
			return c.JSON(http.StatusConflict, map[string]string{"error": "email_taken"})
		case errors.Is(err, auth.ErrInvalidEmailChange):
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid_email"})
		}
		h.logger.Error().Err(err).Msg("admin: change user email failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to change the address"})
	}
	h.auditAdminAppMeta(c, p.claims, audit.ActionAdminUserEmailChanged, "user", strconv.FormatInt(uid, 10), p.appID,
		map[string]any{"reason": strings.TrimSpace(req.Reason), "old_email_domain": emailDomainOf(res.OldEmail), "new_email_domain": emailDomainOf(res.NewEmail)})
	return c.JSON(http.StatusOK, map[string]string{"message": "email changed; the user's sessions were revoked"})
}

func emailDomainOf(email string) string {
	if i := strings.LastIndexByte(email, '@'); i >= 0 {
		return email[i+1:]
	}
	return ""
}
