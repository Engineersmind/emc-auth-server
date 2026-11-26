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
// Application MFA role rules (#195, stage 2 of #189)
// ---------------------------------------------------------------------------

// MFARoleRulesResponse is the body of GET and PUT .../mfa/role-rules.
type MFARoleRulesResponse struct {
	ApplicationID string             `json:"application_id"`
	Rules         []auth.MFARoleRule `json:"rules"`
}

// UpdateMFARoleRulesRequest is the body of PUT .../mfa/role-rules. RoleIDs is
// the WHOLE new list: roles not in it lose their rule, [] clears every rule.
// Each id must be a live role of this application.
type UpdateMFARoleRulesRequest struct {
	RoleIDs []string `json:"role_ids"`
}

// GetApplicationMFARoleRules handles GET /api/v1/applications/:appID/mfa/role-rules
// and GET /api/v1/tenants/:tid/applications/:appID/mfa/role-rules.
//
// @Summary      List application MFA role rules
// @Description  Returns the roles whose holders must use MFA on this application, as if its mode were 'required'. Rules apply only while the application's MFA switch (mfa_enabled) is on and its mode is not 'disabled'. They cover password, magic-link and email-code sign-ins, and social / unverified-passkey sign-ins only when federated_mfa is 'enforce'.
// @Tags         admin-applications
// @Produce      json
// @Security     BearerAuth
// @Param        appID  path      string  true  "Application ID"
// @Success      200    {object}  MFARoleRulesResponse
// @Failure      403    {object}  map[string]string
// @Failure      404    {object}  map[string]string  "Application not found"
// @Router       /api/v1/applications/{appID}/mfa/role-rules [get]
// @Router       /api/v1/tenants/{tid}/applications/{appID}/mfa/role-rules [get]
func (h *AdminHandler) GetApplicationMFARoleRules(c echo.Context) error {
	tenantID, _, err := h.tenantFromClaimsOrPath(c)
	if err != nil {
		return c.JSON(http.StatusForbidden, APIError{Error: "forbidden", Message: err.Error()})
	}
	appID, ok := h.applicationOwnedByTenant(c, tenantID)
	if !ok {
		return nil
	}
	rules, err := h.totpSvc.ListAppMFARoleRules(c.Request().Context(), tenantID, appID)
	if err != nil {
		h.logger.Error().Err(err).Msg("admin: list MFA role rules failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to list MFA role rules"})
	}
	return c.JSON(http.StatusOK, MFARoleRulesResponse{ApplicationID: strconv.FormatInt(appID, 10), Rules: rules})
}

// UpdateApplicationMFARoleRules handles PUT /api/v1/applications/:appID/mfa/role-rules
// and PUT /api/v1/tenants/:tid/applications/:appID/mfa/role-rules.
//
// @Summary      Replace application MFA role rules
// @Description  Replaces the application's whole MFA role-rule list in one transaction. A user holding any listed role (as primary role or any additional grant, read from the database at each login) is treated as 'required': challenged if enrolled, forced to enrol in an allowed method otherwise, and unable to remove their last factor. Only the application's own live roles are accepted (400 mfa_role_rule_invalid_role). A non-empty list is refused while the MFA switch is off or the mode is 'disabled' (409 mfa_role_rules_inactive), and while email is the only allowed MFA method and passwordless email-code sign-in is on for the application (409 mfa_role_rules_passwordless_conflict: covered users could no longer sign in by email code); an empty list (clear) is always accepted. At most 100 roles (400 mfa_role_rules_too_many). A role listed by a rule cannot be deleted until the rule is removed. A real change is audited as admin.mfa_role_rules_set with the old and new lists. Applies at each user's NEXT login.
// @Tags         admin-applications
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        appID  path      string                     true  "Application ID"
// @Param        body   body      UpdateMFARoleRulesRequest  true  "The complete new list of role ids"
// @Success      200    {object}  MFARoleRulesResponse
// @Failure      400    {object}  APIError  "invalid body | mfa_role_rule_invalid_role | mfa_role_rules_too_many"
// @Failure      403    {object}  map[string]string
// @Failure      404    {object}  map[string]string  "Application not found"
// @Failure      409    {object}  APIError  "mfa_role_rules_inactive | mfa_role_rules_passwordless_conflict"
// @Router       /api/v1/applications/{appID}/mfa/role-rules [put]
// @Router       /api/v1/tenants/{tid}/applications/{appID}/mfa/role-rules [put]
func (h *AdminHandler) UpdateApplicationMFARoleRules(c echo.Context) error {
	tenantID, claims, err := h.tenantFromClaimsOrPath(c)
	if err != nil {
		return c.JSON(http.StatusForbidden, APIError{Error: "forbidden", Message: err.Error()})
	}
	appID, ok := h.applicationOwnedByTenant(c, tenantID)
	if !ok {
		return nil
	}

	var req UpdateMFARoleRulesRequest
	if err := c.Bind(&req); err != nil || req.RoleIDs == nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "role_ids is required (send [] to clear every rule)"})
	}
	roleIDs := make([]int64, 0, len(req.RoleIDs))
	for _, raw := range req.RoleIDs {
		id, perr := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
		if perr != nil || id <= 0 {
			return fail(c, http.StatusBadRequest, "mfa_role_rule_invalid_role")
		}
		roleIDs = append(roleIDs, id)
	}

	// Service tokens carry the public client_id in UserID — record no creator
	// rather than a garbage id (same convention as UpdateApplicationMFA).
	var createdBy *int64
	if claims != nil {
		if uid, perr := strconv.ParseInt(claims.UserID, 10, 64); perr == nil {
			createdBy = &uid
		}
	}

	res, err := h.totpSvc.SetAppMFARoleRules(c.Request().Context(), tenantID, appID, roleIDs, createdBy)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrMFARoleRulesInactive):
			return fail(c, http.StatusConflict, "mfa_role_rules_inactive")
		case errors.Is(err, auth.ErrMFARoleRulesPasswordlessConflict):
			return fail(c, http.StatusConflict, "mfa_role_rules_passwordless_conflict")
		case errors.Is(err, auth.ErrMFARoleRuleInvalidRole):
			return fail(c, http.StatusBadRequest, "mfa_role_rule_invalid_role")
		case errors.Is(err, auth.ErrTooManyMFARoleRules):
			return fail(c, http.StatusBadRequest, "mfa_role_rules_too_many")
		case errors.Is(err, auth.ErrAppNotFound):
			return c.JSON(http.StatusNotFound, map[string]string{"error": err.Error()})
		}
		h.logger.Error().Err(err).Msg("admin: set MFA role rules failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to set MFA role rules"})
	}

	// Only a real change is audited, like the MFA switch: re-sending the
	// current list is a no-op. Filed under the tenant acted on.
	if res.Changed() {
		appIDStr := strconv.FormatInt(appID, 10)
		h.auditAdminTenantMeta(c, claims, &tenantID, audit.ActionAdminMFARoleRulesSet, "application", appIDStr, &appID,
			map[string]any{
				"old_role_ids":   auth.RoleIDs(res.Old),
				"new_role_ids":   auth.RoleIDs(res.New),
				"old_role_names": roleNames(res.Old),
				"new_role_names": roleNames(res.New),
			})
	}
	return c.JSON(http.StatusOK, MFARoleRulesResponse{ApplicationID: strconv.FormatInt(appID, 10), Rules: res.New})
}

func roleNames(rules []auth.MFARoleRule) []string {
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		out = append(out, r.RoleName)
	}
	return out
}
