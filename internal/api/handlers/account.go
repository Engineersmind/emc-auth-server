package handlers

import (
	"errors"
	"net/http"

	"github.com/labstack/echo/v4"

	"github.com/engineersmind/emc-auth-server/internal/audit"
	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// ---------------------------------------------------------------------------
// Endpoints behind the invitation, email-change, and account-unblock emails.
// Each is the landing point for a link in one of the transactional templates.
// ---------------------------------------------------------------------------

// WithInvitations attaches an InvitationService for the accept-invitation endpoint.
func (h *AuthHandler) WithInvitations(invSvc *auth.InvitationService) *AuthHandler {
	h.invSvc = invSvc
	return h
}

// WithEmailChange attaches an EmailChangeService for the email-change endpoints.
func (h *AuthHandler) WithEmailChange(chgSvc *auth.EmailChangeService) *AuthHandler {
	h.chgSvc = chgSvc
	return h
}

// WithAccountBlocking attaches an AccountBlockService for the unblock endpoint.
func (h *AuthHandler) WithAccountBlocking(blockSvc *auth.AccountBlockService) *AuthHandler {
	h.blockSvc = blockSvc
	return h
}

// notifyRiskySignIn raises a suspicious-activity alert for a sign-in that has
// just succeeded, when the risk assessor considers it unusual for this user. A
// no-op unless account blocking and a risk assessor are both wired.
func (h *AuthHandler) notifyRiskySignIn(c echo.Context, tenantID, userID, appID *int64, email string) {
	if h.blockSvc == nil || tenantID == nil || userID == nil {
		return
	}
	h.blockSvc.NotifyIfRisky(c.Request().Context(), *tenantID, appID, *userID, email, c.RealIP(), c.Request().UserAgent())
}

// AcceptInvitationRequest is the body for POST /api/v1/auth/accept-invitation.
//
// For an account with no password yet, Password is required and CurrentPassword
// is meaningless. For an account that already has one — see PreviewInvitation —
// the recipient chooses: supply CurrentPassword to keep it, or Password to
// replace it. Supplying neither is refused, so activating an administrative
// grant always takes more than possession of the emailed link.
type AcceptInvitationRequest struct {
	Token           string `json:"token" validate:"required"`
	Password        string `json:"password"`
	CurrentPassword string `json:"current_password"`
}

// PreviewInvitation handles GET /api/v1/auth/invitation.
//
// @Summary      Inspect an invitation link
// @Description  Returns what a live invitation token is for, WITHOUT consuming it, so the landing page can ask for a password only when there is one to set. requires_password is false for an account that already has credentials — an existing user being made an administrator, or an administrator being re-instated — and for those the link only confirms the grant. grants_admin reports that accepting will activate a pending administrative grant.
// @Tags         AUTH
// @Produce      json
// @Param        token  query     string  true  "Invitation token from the email"
// @Success      200    {object}  auth.InvitationPreview
// @Failure      400    {object}  map[string]string
// @Router       /api/v1/auth/invitation [get]
func (h *AuthHandler) PreviewInvitation(c echo.Context) error {
	if h.invSvc == nil {
		return c.JSON(http.StatusNotImplemented, map[string]string{"error": "invitations are not configured"})
	}
	token := c.QueryParam("token")
	if token == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "token is required"})
	}
	preview, err := h.invSvc.Preview(c.Request().Context(), token)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidInvitation) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid or expired invitation link"})
		}
		h.logger.Error().Err(err).Msg("auth: preview invitation failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not read that invitation"})
	}
	return c.JSON(http.StatusOK, preview)
}

// AcceptInvitation handles POST /api/v1/auth/accept-invitation — the user sets
// their password using the token from the invitation email. Single-use.
//
// The GET route with the same path exists only so the emailed link opens
// somewhere sensible; it does not consume the token.
//
// @Summary      Accept an invitation
// @Description  Sets the password for an invited account using the token from the invitation email, and marks the address verified. Single-use.
// @Tags         AUTH
// @Accept       json
// @Produce      json
// @Param        body  body      AcceptInvitationRequest  true  "Invitation token and chosen password"
// @Success      200   {object}  map[string]string
// @Failure      400   {object}  map[string]string
// @Failure      403   {object}  map[string]string
// @Router       /api/v1/auth/accept-invitation [post]
func (h *AuthHandler) AcceptInvitation(c echo.Context) error {
	if h.invSvc == nil {
		return c.JSON(http.StatusNotImplemented, map[string]string{"error": "invitations are not configured"})
	}
	var req AcceptInvitationRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}
	// The token may also arrive as a query parameter, so the emailed link can be
	// posted from a form that carries it in the URL.
	if req.Token == "" {
		req.Token = c.QueryParam("token")
	}
	// Password is deliberately not required here: the service decides, since only
	// it knows whether the account already has credentials. An empty password for
	// an account that has none comes back as ErrWeakPassword below.
	if req.Token == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "token is required"})
	}

	target, err := h.invSvc.Accept(c.Request().Context(), req.Token, auth.AcceptOptions{
		NewPassword:     req.Password,
		CurrentPassword: req.CurrentPassword,
	})
	if err != nil {
		if errors.Is(err, auth.ErrInvalidInvitation) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid or expired invitation link"})
		}
		if errors.Is(err, auth.ErrInvitationBlocked) {
			// The link is valid; the account state is what forbids acceptance.
			return c.JSON(http.StatusForbidden, map[string]string{"error": "this account has been blocked — contact your administrator"})
		}
		if errors.Is(err, auth.ErrCurrentPasswordMismatch) {
			// 401, not 400: the link is fine, the credential is not. A 400 here
			// would read as "expired link" and send the recipient looking for a
			// new email that nobody needs to send.
			return c.JSON(http.StatusUnauthorized, map[string]string{
				"error": "that is not your current password",
				"code":  "current_password_mismatch",
			})
		}
		if errors.Is(err, auth.ErrWeakPassword) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		h.logger.Error().Err(err).Msg("auth: accept invitation failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to accept invitation"})
	}

	h.auditEvent(c, audit.Event{
		TenantID:     &target.TenantID,
		UserID:       &target.UserID,
		ActorEmail:   target.Email,
		Action:       audit.ActionAuthInvitationAccepted,
		ResourceType: "user",
		IPAddress:    c.RealIP(),
		UserAgent:    c.Request().UserAgent(),
	})
	return c.JSON(http.StatusOK, map[string]string{"message": "invitation accepted — you can now sign in"})
}

// ChangeEmailRequest is the body for POST /api/v1/auth/change-email.
type ChangeEmailRequest struct {
	NewEmail string `json:"new_email" validate:"required,email"`
}

// ChangeEmail handles POST /api/v1/auth/change-email for the authenticated user.
// It emails a confirmation link to the NEW address; the account's email only
// moves once that link is followed.
//
// @Summary      Request an email change
// @Description  Sends a confirmation link to the new address. The account email changes only after the link is followed. Requires a valid access token.
// @Tags         AUTH
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body  body      ChangeEmailRequest  true  "New email address"
// @Success      202   {object}  map[string]string
// @Failure      400   {object}  map[string]string
// @Failure      409   {object}  map[string]string
// @Router       /api/v1/auth/change-email [post]
func (h *AuthHandler) ChangeEmail(c echo.Context) error {
	if h.chgSvc == nil {
		return c.JSON(http.StatusNotImplemented, map[string]string{"error": "email change is not configured"})
	}
	claims, userID, tenantID, ok := mfaClaimIDs(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}

	var req ChangeEmailRequest
	if err := c.Bind(&req); err != nil || req.NewEmail == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "new_email is required"})
	}

	if err := h.chgSvc.Request(c.Request().Context(), tenantID, userID, req.NewEmail); err != nil {
		switch {
		case errors.Is(err, auth.ErrEmailTaken):
			// The address is genuinely unavailable, and the requester is
			// authenticated, so this is not an enumeration vector worth hiding —
			// they could learn the same thing by trying to register it.
			return c.JSON(http.StatusConflict, map[string]string{"error": "that email address is already in use"})
		case errors.Is(err, auth.ErrSameEmail):
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "that is already your email address"})
		}
		h.logger.Error().Err(err).Str("user_id", claims.UserID).Msg("auth: email change request failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to start email change"})
	}

	h.auditEvent(c, audit.Event{
		TenantID:     &tenantID,
		UserID:       &userID,
		ActorEmail:   claims.Email,
		Action:       audit.ActionAuthEmailChangeReq,
		ResourceType: "user",
		IPAddress:    c.RealIP(),
		UserAgent:    c.Request().UserAgent(),
	})
	return c.JSON(http.StatusAccepted, map[string]string{"message": "confirmation link sent to the new address"})
}

// ConfirmEmailChange handles GET /api/v1/auth/confirm-email-change?token=... —
// the link sent to the new address. Single-use.
//
// @Summary      Confirm an email change
// @Description  Applies a pending email change using the token sent to the new address, and marks it verified. Single-use.
// @Tags         AUTH
// @Produce      json
// @Param        token  query     string  true  "Email change token"
// @Success      200    {object}  map[string]string
// @Failure      400    {object}  map[string]string
// @Failure      409    {object}  map[string]string
// @Router       /api/v1/auth/confirm-email-change [get]
func (h *AuthHandler) ConfirmEmailChange(c echo.Context) error {
	if h.chgSvc == nil {
		return c.JSON(http.StatusNotImplemented, map[string]string{"error": "email change is not configured"})
	}
	token := c.QueryParam("token")
	if token == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "token is required"})
	}

	res, err := h.chgSvc.Confirm(c.Request().Context(), token)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrInvalidEmailChange):
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid or expired confirmation link"})
		case errors.Is(err, auth.ErrEmailTaken):
			return c.JSON(http.StatusConflict, map[string]string{"error": "that email address has since been taken"})
		}
		h.logger.Error().Err(err).Msg("auth: confirm email change failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to confirm email change"})
	}

	h.auditEvent(c, audit.Event{
		TenantID:     &res.TenantID,
		UserID:       &res.UserID,
		ActorEmail:   res.NewEmail,
		Action:       audit.ActionAuthEmailChanged,
		ResourceType: "user",
		IPAddress:    c.RealIP(),
		UserAgent:    c.Request().UserAgent(),
		Metadata:     map[string]any{"previous_email": res.OldEmail},
	})
	return c.JSON(http.StatusOK, map[string]string{"message": "email address updated", "email": res.NewEmail})
}

// UnblockAccount handles GET /api/v1/auth/unblock-account?token=... — the link
// in the blocked-account email after an automatic lockout. Single-use.
//
// Only an automatic (failed-attempt) lockout can be lifted here; an
// administrator's block never issues one of these tokens.
//
// @Summary      Unblock an account
// @Description  Lifts an automatic failed-attempt lockout using the token from the blocked-account email. Single-use. Admin blocks cannot be lifted this way.
// @Tags         AUTH
// @Produce      json
// @Param        token  query     string  true  "Unblock token"
// @Success      200    {object}  map[string]string
// @Failure      400    {object}  map[string]string
// @Router       /api/v1/auth/unblock-account [get]
func (h *AuthHandler) UnblockAccount(c echo.Context) error {
	if h.blockSvc == nil {
		return c.JSON(http.StatusNotImplemented, map[string]string{"error": "account lockout is not configured"})
	}
	token := c.QueryParam("token")
	if token == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "token is required"})
	}

	if err := h.blockSvc.Unblock(c.Request().Context(), token); err != nil {
		if errors.Is(err, auth.ErrInvalidUnblockToken) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid or expired unblock link"})
		}
		h.logger.Error().Err(err).Msg("auth: unblock account failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to unblock account"})
	}
	return c.JSON(http.StatusOK, map[string]string{"message": "account unblocked — you can now sign in"})
}
