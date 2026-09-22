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
// Admin: CAPTCHA policy (issue #145)
// ---------------------------------------------------------------------------

// GetCaptchaPolicy handles GET on the captcha-policy routes.
//
// @Summary      Get the CAPTCHA policy
// @Description  Returns the captcha settings in force for the tenant or application, and whether they are inherited. `inherited: true` means no row exists at this scope — editing creates one, and DELETE reverts to inheriting again.
// @Tags         admin-security
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  admin.CaptchaPolicyView
// @Router       /api/v1/captcha-policy [get]
func (h *AdminHandler) GetCaptchaPolicy(c echo.Context) error {
	tenantID, _, err := h.tenantFromClaimsOrPath(c)
	if err != nil {
		return c.JSON(http.StatusForbidden, map[string]string{"error": err.Error()})
	}
	appScope, ok := h.optionalAppScope(c, tenantID)
	if !ok {
		return nil
	}

	policy, err := h.svc.GetCaptchaPolicy(c.Request().Context(), tenantID, appScope)
	if err != nil {
		h.logger.Error().Err(err).Msg("admin: get captcha policy failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to load captcha policy"})
	}
	return c.JSON(http.StatusOK, policy)
}

// UpdateCaptchaPolicy handles PUT on the captcha-policy routes.
//
// @Summary      Update the CAPTCHA policy
// @Description  Turns captchas on or off for this scope and sets how they behave. Omitted fields are left unchanged — send only what changed, because a full-form PUT on an inheriting scope converts every inherited value into an explicit override and stops tracking the parent.
// @Tags         admin-security
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body  body      admin.CaptchaPolicyInput  true  "Policy fields to change"
// @Success      200   {object}  admin.CaptchaPolicyView
// @Failure      400   {object}  map[string]string
// @Router       /api/v1/captcha-policy [put]
func (h *AdminHandler) UpdateCaptchaPolicy(c echo.Context) error {
	tenantID, claims, err := h.tenantFromClaimsOrPath(c)
	if err != nil {
		return c.JSON(http.StatusForbidden, map[string]string{"error": err.Error()})
	}
	appScope, ok := h.optionalAppScope(c, tenantID)
	if !ok {
		return nil
	}

	var in admin.CaptchaPolicyInput
	if err := c.Bind(&in); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}

	policy, err := h.svc.SetCaptchaPolicy(c.Request().Context(), tenantID, appScope, in)
	if err != nil {
		// The bound-check errors name the offending field and are safe to return:
		// they describe the caller's own input, not server state.
		if errors.Is(err, admin.ErrInvalidCaptchaPolicy) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		h.logger.Error().Err(err).Msg("admin: update captcha policy failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to update captcha policy"})
	}

	// Audit the resulting values, not the request body: a partial update's effect
	// is not visible from the fields the caller happened to send, and "what is
	// the policy now" is the question asked afterwards.
	//
	// enabled leads the metadata because turning a captcha on changes what every
	// user of the application has to do to sign in — it is the line somebody
	// scanning the audit feed after a spike in support tickets is looking for.
	h.auditAdminAppMeta(c, claims, audit.ActionAdminCaptchaPolicySet, "captcha_policy",
		strconv.FormatInt(tenantID, 10), appScope, map[string]any{
			"enabled":                    policy.Enabled,
			"mode":                       policy.Mode,
			"protected_flows":            policy.ProtectedFlows,
			"trigger_after_failures":     policy.TriggerAfterFailures,
			"failure_window_seconds":     policy.FailureWindowSeconds,
			"code_length":                policy.CodeLength,
			"case_sensitive":             policy.CaseSensitive,
			"ttl_seconds":                policy.TTLSeconds,
			"max_attempts_per_challenge": policy.MaxAttemptsPerChallenge,
			"noise_level":                policy.NoiseLevel,
		})
	return c.JSON(http.StatusOK, policy)
}

// DeleteCaptchaPolicy handles DELETE on the captcha-policy routes, so the scope
// inherits from the broader one again.
//
// This is NOT the same as setting enabled=false, and the console renders the two
// as adjacent controls. Off is a decision this scope owns; reverting to
// inherited means this scope follows whatever the tenant or platform decides
// next.
//
// @Summary      Reset the CAPTCHA policy
// @Description  Removes this scope's captcha override so it inherits from the tenant or platform default. Distinct from setting enabled=false, which is an explicit decision recorded at this scope.
// @Tags         admin-security
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /api/v1/captcha-policy [delete]
func (h *AdminHandler) DeleteCaptchaPolicy(c echo.Context) error {
	tenantID, claims, err := h.tenantFromClaimsOrPath(c)
	if err != nil {
		return c.JSON(http.StatusForbidden, map[string]string{"error": err.Error()})
	}
	appScope, ok := h.optionalAppScope(c, tenantID)
	if !ok {
		return nil
	}

	if err := h.svc.DeleteCaptchaPolicy(c.Request().Context(), tenantID, appScope); err != nil {
		if errors.Is(err, admin.ErrNotFound) {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "no policy set at this scope"})
		}
		h.logger.Error().Err(err).Msg("admin: delete captcha policy failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to reset captcha policy"})
	}
	h.auditAdminApp(c, claims, audit.ActionAdminCaptchaPolicyReset, "captcha_policy",
		strconv.FormatInt(tenantID, 10), appScope)
	return c.JSON(http.StatusOK, map[string]string{"message": "captcha policy reset to inherited"})
}

// ---------------------------------------------------------------------------
// Platform-scope captcha policy (super_admin only)
//
// WHY THIS EXISTS AND THE TENANT ROUTES ARE NOT ENOUGH
//
// /auth/login, /auth/session and /auth/login/otp resolve policy at PLATFORM
// scope, because none of them knows a tenant before authenticating - the tenant
// is discovered by looking the email up across tenants. The tenant-scoped routes
// above write a row with tenant_id SET, which those three flows never read.
//
// Without these routes the three first-party flows would be unreachable: the
// policy governing them could not be written through the API at all. That was a
// real gap, and it was found by running the feature rather than by reading it.
//
// Guarded by tenant:manage, so only a platform operator can change what the
// shared sign-in surface does. A tenant administrator must not be able to put a
// captcha in front of every other tenant's console login.
// ---------------------------------------------------------------------------

// GetPlatformCaptchaPolicy handles GET /api/v1/platform/captcha-policy.
//
// @Summary      Get the platform CAPTCHA policy
// @Description  The policy governing the tenant-less sign-in flows (/auth/login, /auth/session, /auth/login/otp), which cannot resolve a tenant before authenticating. Requires tenant:manage.
// @Tags         admin-security
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  admin.CaptchaPolicyView
// @Router       /api/v1/platform/captcha-policy [get]
func (h *AdminHandler) GetPlatformCaptchaPolicy(c echo.Context) error {
	// Tenant 0 with a nil application matches only the platform-default row,
	// which is exactly what the first-party flows resolve.
	policy, err := h.svc.GetCaptchaPolicy(c.Request().Context(), 0, nil)
	if err != nil {
		h.logger.Error().Err(err).Msg("admin: get platform captcha policy failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to load captcha policy"})
	}
	return c.JSON(http.StatusOK, policy)
}

// UpdatePlatformCaptchaPolicy handles PUT /api/v1/platform/captcha-policy.
//
// @Summary      Update the platform CAPTCHA policy
// @Description  Sets the policy for the tenant-less sign-in flows. This affects EVERY tenant's console sign-in, so it requires tenant:manage. Omitted fields are left unchanged.
// @Tags         admin-security
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body  body      admin.CaptchaPolicyInput  true  "Policy fields to change"
// @Success      200   {object}  admin.CaptchaPolicyView
// @Failure      400   {object}  map[string]string
// @Router       /api/v1/platform/captcha-policy [put]
func (h *AdminHandler) UpdatePlatformCaptchaPolicy(c echo.Context) error {
	claims, _ := claimsFromCtx(c)

	var in admin.CaptchaPolicyInput
	if err := c.Bind(&in); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}

	policy, err := h.svc.SetPlatformCaptchaPolicy(c.Request().Context(), in)
	if err != nil {
		if errors.Is(err, admin.ErrInvalidCaptchaPolicy) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		h.logger.Error().Err(err).Msg("admin: update platform captcha policy failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to update captcha policy"})
	}

	h.auditAdminAppMeta(c, claims, audit.ActionAdminCaptchaPolicySet, "captcha_policy",
		"platform", nil, map[string]any{
			"scope":                  "platform",
			"enabled":                policy.Enabled,
			"mode":                   policy.Mode,
			"protected_flows":        policy.ProtectedFlows,
			"trigger_after_failures": policy.TriggerAfterFailures,
			"noise_level":            policy.NoiseLevel,
		})
	return c.JSON(http.StatusOK, policy)
}
