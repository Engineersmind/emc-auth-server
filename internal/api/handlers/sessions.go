package handlers

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/labstack/echo/v4"

	"github.com/engineersmind/emc-auth-server/internal/admin"
	"github.com/engineersmind/emc-auth-server/internal/audit"
	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// SessionLister is the subset of the admin service the end-user session routes
// need. Declared as an interface at the point of use so the account handlers do
// not depend on the whole admin surface — and so a test can supply a stub without
// standing up admin.Service.
type SessionLister interface {
	ListUserSessions(ctx context.Context, tenantID int64, applicationID *int64, userID int64, currentFamilyID string) ([]admin.UserSession, error)
	RevokeUserSession(ctx context.Context, tenantID int64, applicationID *int64, userID, familyID int64, reason string) error
}

// WithSessionLister wires the session queries behind the /me/sessions routes.
func (h *AuthHandler) WithSessionLister(svc SessionLister) *AuthHandler {
	h.adminSvc = svc
	return h
}

// ---------------------------------------------------------------------------
// End-user session self-service
//
// Every mainstream IdP lets a user see their own signed-in devices and end the
// ones they do not recognise, and SOC 2 user-access-control evidence expects it.
// Until now this server exposed session listing to administrators only, so a user
// who suspected their account was compromised had to ask an operator.
//
// These handlers deliberately reuse the admin service methods with the caller's
// own ids forced from their token rather than taken from the path. There is no
// user-supplied identifier to get wrong, so no route here can be turned into a
// read of somebody else's sessions by editing a URL.
// ---------------------------------------------------------------------------

// ListMySessions handles GET /api/v1/me/sessions.
//
// @Summary      List your own active sessions
// @Description  Returns the caller's active sessions with device, IP, and last-activity, marking the session the request came from.
// @Tags         account
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  map[string]any
// @Failure      401  {object}  map[string]string
// @Router       /api/v1/me/sessions [get]
func (h *AuthHandler) ListMySessions(c echo.Context) error {
	subject, err := selfSubject(c)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "authentication required"})
	}
	if h.adminSvc == nil {
		return c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "session listing unavailable"})
	}

	sessions, err := h.adminSvc.ListUserSessions(c.Request().Context(),
		subject.tenantID, nil, subject.userID, subject.sessionID)
	if err != nil {
		h.logger.Error().Err(err).Msg("account: list own sessions failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to list sessions"})
	}
	return c.JSON(http.StatusOK, map[string]any{"sessions": sessions})
}

// RevokeMySession handles DELETE /api/v1/me/sessions/:familyID.
//
// @Summary      Sign out one of your own sessions
// @Description  Ends a single session belonging to the caller. Use the logout endpoint to end the current session.
// @Tags         account
// @Produce      json
// @Security     BearerAuth
// @Param        familyID  path      string  true  "Session ID"
// @Success      200       {object}  map[string]string
// @Failure      404       {object}  map[string]string
// @Router       /api/v1/me/sessions/{familyID} [delete]
func (h *AuthHandler) RevokeMySession(c echo.Context) error {
	subject, err := selfSubject(c)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "authentication required"})
	}
	if h.adminSvc == nil {
		return c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "session management unavailable"})
	}
	familyID, err := strconv.ParseInt(c.Param("familyID"), 10, 64)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid session id"})
	}

	// Refuse to revoke the caller's own session here.
	//
	// It would work — and then the response the client is waiting on would be
	// authenticated by a session that no longer exists, the cookies would still be
	// set, and the next request would fail with a bare 401 the UI has no context
	// for. Logout is the operation that ends the current session, and it also
	// clears the cookies, which this endpoint has no business doing.
	if subject.sessionID != "" && strconv.FormatInt(familyID, 10) == subject.sessionID {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "use logout to end the session you are signed in with",
			"code":  "cannot_revoke_current_session",
		})
	}

	err = h.adminSvc.RevokeUserSession(c.Request().Context(),
		subject.tenantID, nil, subject.userID, familyID, auth.RevokeReasonUserRevoked)
	if err != nil {
		if errors.Is(err, admin.ErrNotFound) {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "session not found"})
		}
		h.logger.Error().Err(err).Msg("account: revoke own session failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to revoke session"})
	}

	h.auditEvent(c, audit.Event{
		TenantID:     &subject.tenantID,
		UserID:       &subject.userID,
		ActorEmail:   subject.email,
		Action:       audit.ActionSessionEndedUser,
		AuthMethod:   audit.AuthMethodRefreshToken,
		ResourceType: "session",
		ResourceID:   strconv.FormatInt(familyID, 10),
		IPAddress:    c.RealIP(),
		UserAgent:    c.Request().UserAgent(),
		Metadata:     map[string]any{"scope": "single"},
	})
	return c.JSON(http.StatusOK, map[string]string{"message": "session revoked"})
}

// RevokeMyOtherSessions handles DELETE /api/v1/me/sessions.
//
// Ends every session EXCEPT the caller's own — the "sign out everywhere else"
// action a user reaches for after a suspected compromise. Keeping the current
// session alive is what makes it usable: the alternative logs the user out of the
// page they are using to secure their account, and they then have to sign in again
// on a device they have just been told may be compromised.
//
// @Summary      Sign out your other sessions
// @Description  Ends every session except the one this request came from.
// @Tags         account
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  map[string]any
// @Router       /api/v1/me/sessions [delete]
func (h *AuthHandler) RevokeMyOtherSessions(c echo.Context) error {
	subject, err := selfSubject(c)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "authentication required"})
	}

	revoked, err := h.svc.RevokeOtherSessions(c.Request().Context(),
		subject.userID, subject.tenantID, subject.sessionID)
	if err != nil {
		h.logger.Error().Err(err).Msg("account: revoke other sessions failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to revoke sessions"})
	}

	h.auditEvent(c, audit.Event{
		TenantID:     &subject.tenantID,
		UserID:       &subject.userID,
		ActorEmail:   subject.email,
		Action:       audit.ActionSessionEndedUser,
		AuthMethod:   audit.AuthMethodRefreshToken,
		ResourceType: "session",
		IPAddress:    c.RealIP(),
		UserAgent:    c.Request().UserAgent(),
		Metadata:     map[string]any{"scope": "others", "revoked": revoked},
	})
	return c.JSON(http.StatusOK, map[string]any{"message": "other sessions revoked", "revoked": revoked})
}

// selfSubject is the caller's own identity, resolved entirely from their verified
// token. Nothing here comes from the request path or body — that is what makes the
// /me routes structurally incapable of addressing another account.
type selfSubjectIDs struct {
	userID    int64
	tenantID  int64
	email     string
	sessionID string
}

// selfSubject extracts the caller's ids from their claims.
//
// Rejects a token whose user_id is not a users.id — a client-credentials or agent
// token carries a client id there. Such a caller has no sessions and no account, so
// letting the parse fall through would either produce an empty list (confusing) or,
// worse, address user id 0.
func selfSubject(c echo.Context) (selfSubjectIDs, error) {
	claims, ok := claimsFromCtx(c)
	if !ok {
		return selfSubjectIDs{}, errors.New("no claims")
	}
	userID, err := strconv.ParseInt(claims.UserID, 10, 64)
	if err != nil {
		return selfSubjectIDs{}, errors.New("not a user token")
	}
	tenantID, err := strconv.ParseInt(claims.TenantID, 10, 64)
	if err != nil {
		return selfSubjectIDs{}, errors.New("no tenant")
	}
	return selfSubjectIDs{
		userID:    userID,
		tenantID:  tenantID,
		email:     claims.Email,
		sessionID: claims.SessionID,
	}, nil
}

// ---------------------------------------------------------------------------
// Admin: session policy
// ---------------------------------------------------------------------------

// GetSessionPolicy handles GET on the session-policy routes.
//
// @Summary      Get the session lifetime policy
// @Description  Returns the session policy in force for the tenant or application, and whether it is inherited. Requires apps:write (apps:read to view).
// @Tags         admin-sessions
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  admin.SessionPolicyView
// @Router       /api/v1/session-policy [get]
func (h *AdminHandler) GetSessionPolicy(c echo.Context) error {
	tenantID, _, err := h.tenantFromClaimsOrPath(c)
	if err != nil {
		return c.JSON(http.StatusForbidden, map[string]string{"error": err.Error()})
	}
	appScope, ok := h.optionalAppScope(c, tenantID)
	if !ok {
		return nil
	}

	policy, err := h.svc.GetSessionPolicy(c.Request().Context(), tenantID, appScope)
	if err != nil {
		h.logger.Error().Err(err).Msg("admin: get session policy failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to load session policy"})
	}
	return c.JSON(http.StatusOK, policy)
}

// UpdateSessionPolicy handles PUT on the session-policy routes.
//
// @Summary      Update the session lifetime policy
// @Description  Sets idle/absolute session lifetimes, the concurrent-session cap, and whether "remember me" is allowed. Omitted fields are left unchanged. Requires apps:write (apps:read to view).
// @Tags         admin-sessions
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body  body      admin.SessionPolicyInput  true  "Policy fields to change"
// @Success      200   {object}  admin.SessionPolicyView
// @Failure      400   {object}  map[string]string
// @Router       /api/v1/session-policy [put]
func (h *AdminHandler) UpdateSessionPolicy(c echo.Context) error {
	tenantID, claims, err := h.tenantFromClaimsOrPath(c)
	if err != nil {
		return c.JSON(http.StatusForbidden, map[string]string{"error": err.Error()})
	}
	appScope, ok := h.optionalAppScope(c, tenantID)
	if !ok {
		return nil
	}

	var in admin.SessionPolicyInput
	if err := c.Bind(&in); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}

	policy, err := h.svc.SetSessionPolicy(c.Request().Context(), tenantID, appScope, in)
	if err != nil {
		// The bound-check errors name the offending field and are safe to return:
		// they describe the caller's own input, not server state.
		if errors.Is(err, admin.ErrInvalidSessionPolicy) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		h.logger.Error().Err(err).Msg("admin: update session policy failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to update session policy"})
	}

	// Audit the resulting values, not the request body: a partial update's effect
	// is not visible from the fields the caller happened to send, and "what is the
	// policy now" is the question asked afterwards.
	h.auditAdminAppMeta(c, claims, audit.ActionAdminSessionPolicySet, "session_policy",
		strconv.FormatInt(tenantID, 10), appScope, map[string]any{
			"idle_ttl_seconds":                policy.IdleTTLSeconds,
			"non_persistent_idle_ttl_seconds": policy.NonPersistentIdleTTLSeconds,
			"absolute_ttl_seconds":            policy.AbsoluteTTLSeconds,
			"max_concurrent_sessions":         policy.MaxConcurrentSessions,
			"allow_persistent":                policy.AllowPersistent,
		})
	return c.JSON(http.StatusOK, policy)
}

// DeleteSessionPolicy handles DELETE on the session-policy routes, so the scope
// inherits from the broader one again.
//
// @Summary      Reset the session lifetime policy
// @Description  Removes this scope's policy override so it inherits from the tenant or platform default. Requires apps:write (apps:read to view).
// @Tags         admin-sessions
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /api/v1/session-policy [delete]
func (h *AdminHandler) DeleteSessionPolicy(c echo.Context) error {
	tenantID, claims, err := h.tenantFromClaimsOrPath(c)
	if err != nil {
		return c.JSON(http.StatusForbidden, map[string]string{"error": err.Error()})
	}
	appScope, ok := h.optionalAppScope(c, tenantID)
	if !ok {
		return nil
	}

	if err := h.svc.DeleteSessionPolicy(c.Request().Context(), tenantID, appScope); err != nil {
		if errors.Is(err, admin.ErrNotFound) {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "no policy set at this scope"})
		}
		h.logger.Error().Err(err).Msg("admin: delete session policy failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to reset session policy"})
	}
	h.auditAdminApp(c, claims, audit.ActionAdminSessionPolicyReset, "session_policy",
		strconv.FormatInt(tenantID, 10), appScope)
	return c.JSON(http.StatusOK, map[string]string{"message": "session policy reset to inherited"})
}
