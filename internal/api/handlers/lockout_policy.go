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
// Admin: account-lockout policy (issue #72)
// ---------------------------------------------------------------------------

// GetLockoutPolicy handles GET on the lockout-policy routes.
//
// @Summary      Get the account lockout policy
// @Description  Returns the lockout thresholds in force for the tenant or application, and whether they are inherited. A null hard_lock_duration_seconds means a hard lock lasts until an administrator lifts it.
// @Tags         admin-security
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  admin.LockoutPolicyView
// @Router       /api/v1/lockout-policy [get]
func (h *AdminHandler) GetLockoutPolicy(c echo.Context) error {
	tenantID, _, err := h.tenantFromClaimsOrPath(c)
	if err != nil {
		return c.JSON(http.StatusForbidden, map[string]string{"error": err.Error()})
	}
	appScope, ok := h.optionalAppScope(c, tenantID)
	if !ok {
		return nil
	}

	policy, err := h.svc.GetLockoutPolicy(c.Request().Context(), tenantID, appScope)
	if err != nil {
		h.logger.Error().Err(err).Msg("admin: get lockout policy failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to load lockout policy"})
	}
	return c.JSON(http.StatusOK, policy)
}

// UpdateLockoutPolicy handles PUT on the lockout-policy routes.
//
// @Summary      Update the account lockout policy
// @Description  Sets the warn/soft-lock/hard-lock thresholds, their durations, the failure window, and the tenant spike-alert threshold. Omitted fields are left unchanged. Send hard_lock_permanent=true to make hard locks last until an administrator lifts them.
// @Tags         admin-security
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body  body      admin.LockoutPolicyInput  true  "Policy fields to change"
// @Success      200   {object}  admin.LockoutPolicyView
// @Failure      400   {object}  map[string]string
// @Router       /api/v1/lockout-policy [put]
func (h *AdminHandler) UpdateLockoutPolicy(c echo.Context) error {
	tenantID, claims, err := h.tenantFromClaimsOrPath(c)
	if err != nil {
		return c.JSON(http.StatusForbidden, map[string]string{"error": err.Error()})
	}
	appScope, ok := h.optionalAppScope(c, tenantID)
	if !ok {
		return nil
	}

	var in admin.LockoutPolicyInput
	if err := c.Bind(&in); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}

	policy, err := h.svc.SetLockoutPolicy(c.Request().Context(), tenantID, appScope, in)
	if err != nil {
		// The bound-check errors name the offending field and are safe to return:
		// they describe the caller's own input, not server state.
		if errors.Is(err, admin.ErrInvalidLockoutPolicy) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		h.logger.Error().Err(err).Msg("admin: update lockout policy failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to update lockout policy"})
	}

	// Audit the resulting values, not the request body: a partial update's effect is
	// not visible from the fields the caller happened to send, and "what is the
	// policy now" is the question asked afterwards.
	//
	// hard_lock_permanent is recorded as its own boolean rather than left implicit
	// in a null duration. Making locks permanent is the change most worth being able
	// to find later, and a reader scanning the audit feed should not have to infer it
	// from an absent field.
	meta := map[string]any{
		"notify_user_threshold":      policy.NotifyUserThreshold,
		"soft_lock_threshold":        policy.SoftLockThreshold,
		"soft_lock_duration_seconds": policy.SoftLockDurationSeconds,
		"hard_lock_threshold":        policy.HardLockThreshold,
		"failure_window_seconds":     policy.FailureWindowSeconds,
		"tenant_spike_threshold":     policy.TenantSpikeThreshold,
		"hard_lock_permanent":        policy.HardLockDurationSeconds == nil,
	}
	if policy.HardLockDurationSeconds != nil {
		meta["hard_lock_duration_seconds"] = *policy.HardLockDurationSeconds
	}
	h.auditAdminAppMeta(c, claims, audit.ActionAdminLockoutPolicySet, "lockout_policy",
		strconv.FormatInt(tenantID, 10), appScope, meta)
	return c.JSON(http.StatusOK, policy)
}

// DeleteLockoutPolicy handles DELETE on the lockout-policy routes, so the scope
// inherits from the broader one again.
//
// @Summary      Reset the account lockout policy
// @Description  Removes this scope's lockout override so it inherits from the tenant or platform default.
// @Tags         admin-security
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /api/v1/lockout-policy [delete]
func (h *AdminHandler) DeleteLockoutPolicy(c echo.Context) error {
	tenantID, claims, err := h.tenantFromClaimsOrPath(c)
	if err != nil {
		return c.JSON(http.StatusForbidden, map[string]string{"error": err.Error()})
	}
	appScope, ok := h.optionalAppScope(c, tenantID)
	if !ok {
		return nil
	}

	if err := h.svc.DeleteLockoutPolicy(c.Request().Context(), tenantID, appScope); err != nil {
		if errors.Is(err, admin.ErrNotFound) {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "no policy set at this scope"})
		}
		h.logger.Error().Err(err).Msg("admin: delete lockout policy failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to reset lockout policy"})
	}
	h.auditAdminApp(c, claims, audit.ActionAdminLockoutPolicyReset, "lockout_policy",
		strconv.FormatInt(tenantID, 10), appScope)
	return c.JSON(http.StatusOK, map[string]string{"message": "lockout policy reset to inherited"})
}
