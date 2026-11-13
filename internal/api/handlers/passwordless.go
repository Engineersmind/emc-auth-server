package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/labstack/echo/v4"

	"github.com/engineersmind/emc-auth-server/internal/audit"
	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// ---------------------------------------------------------------------------
// Passwordless sign-in and sign-up by emailed code (issue #203,
// docs/plans/passwordless-email-otp.md). Three application-authenticated routes
// that share the credential channel and limiter chain of /apps/login.
//
// The routes answer 404 while PASSWORDLESS_ENABLED is false, so deploying the
// feature changes nothing until it is switched on.
// ---------------------------------------------------------------------------

// WithPasswordless records whether the deployment-level switch is on.
func (h *AuthHandler) WithPasswordless(enabled bool) *AuthHandler {
	h.passwordlessEnabled = enabled
	return h
}

// PasswordlessStartRequest is the JSON body for POST /api/v1/auth/apps/passwordless/start.
type PasswordlessStartRequest struct {
	Email      string `json:"email"`
	FirstName  string `json:"first_name"`
	LastName   string `json:"last_name"`
	Persistent bool   `json:"persistent"`

	// CaptchaID and CaptchaAnswer carry a solved challenge. Optional, and ignored
	// unless the scope's captcha policy protects the "passwordless" flow.
	CaptchaID     string `json:"captcha_id"`
	CaptchaAnswer string `json:"captcha_answer"`
}

// PasswordlessResendRequest is the JSON body for POST /api/v1/auth/apps/passwordless/resend.
type PasswordlessResendRequest struct {
	ChallengeID string `json:"challenge_id"`
}

// PasswordlessVerifyRequest is the JSON body for POST /api/v1/auth/apps/passwordless/verify.
type PasswordlessVerifyRequest struct {
	ChallengeID  string   `json:"challenge_id"`
	Code         string   `json:"code"`
	Organization string   `json:"organization"`
	Roles        []string `json:"roles"`
}

func emailAuditMeta(email string) map[string]any {
	domain := ""
	if i := strings.LastIndexByte(email, '@'); i >= 0 {
		domain = strings.ToLower(email[i+1:])
	}
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(email))))
	// An address hash and its domain, never the address: the audit row must not
	// become a list of who asked for codes (plan T15).
	return map[string]any{"email_hash": hex.EncodeToString(sum[:8]), "email_domain": domain}
}

// passwordlessError maps a service error to a response. ok is false for an error
// it does not recognise.
func (h *AuthHandler) passwordlessError(c echo.Context, err error) (handled bool, resp error) {
	var cool *auth.PasswordlessCooldownError
	switch {
	case errors.Is(err, auth.ErrInvalidClient):
		return true, c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid client credentials"})
	case errors.Is(err, auth.ErrPasswordlessDisabled):
		return true, fail(c, http.StatusForbidden, "passwordless_disabled")
	case errors.Is(err, auth.ErrPasswordlessInvalidEmail):
		return true, fail(c, http.StatusBadRequest, "invalid_email")
	case errors.Is(err, auth.ErrPasswordlessInvalidCode):
		return true, fail(c, http.StatusBadRequest, "invalid_or_expired_code")
	case errors.As(err, &cool):
		c.Response().Header().Set("Retry-After", strconv.Itoa(int(cool.RetryAfter.Seconds())+1))
		return true, fail(c, http.StatusTooManyRequests, "resend_cooldown")
	case errors.Is(err, auth.ErrPasswordlessTooManyResends):
		return true, fail(c, http.StatusTooManyRequests, "too_many_resends")
	case errors.Is(err, auth.ErrPasswordlessUnavailable):
		return true, fail(c, http.StatusServiceUnavailable, "passwordless_unavailable")
	}
	return false, nil
}

// PasswordlessStart handles POST /api/v1/auth/apps/passwordless/start.
//
// @Summary      Request a sign-in or sign-up code
// @Description  Emails a 6-digit one-time code for the address, or, for an address that must not receive one (unknown with sign-up off, blocked, domain refused, throttled), stores a decoy and sends nothing. The response is identical in every case, so it cannot be used to find out which addresses are registered. Sending is asynchronous.
// @Tags         AUTH
// @Accept       json
// @Produce      json
// @Param        Authorization  header  string                    true  "Basic base64(client_id:client_secret)"
// @Param        body           body    PasswordlessStartRequest  true  "Address and optional profile hints"
// @Success      200  {object}  auth.PasswordlessStartResult
// @Failure      400  {object}  APIError  "invalid_email"
// @Failure      403  {object}  APIError  "passwordless_disabled"
// @Failure      404  {object}  APIError  "not_found, the feature is not enabled on this server"
// @Failure      428  {object}  APIError  "captcha_required"
// @Failure      429  {object}  map[string]string  "Rate limited"
// @Router       /api/v1/auth/apps/passwordless/start [post]
func (h *AuthHandler) PasswordlessStart(c echo.Context) error {
	if !h.passwordlessEnabled {
		return fail(c, http.StatusNotFound, "not_found")
	}
	var req PasswordlessStartRequest
	if err := c.Bind(&req); err != nil || strings.TrimSpace(req.Email) == "" {
		return fail(c, http.StatusBadRequest, "invalid_email")
	}
	clientID, clientSecret, errResp := appCredentialsFromRequest(c)
	if errResp != nil {
		return c.JSON(http.StatusBadRequest, errResp)
	}

	scope := h.appCaptchaScopeFor(c, clientID)
	if handled, capErr := h.captchaCheck(c, scope, auth.CaptchaFlowPasswordless, req.CaptchaID, req.CaptchaAnswer); handled {
		return capErr
	}

	res, meta, err := h.svc.PasswordlessStart(c.Request().Context(), auth.PasswordlessStartInput{
		ClientID: clientID, ClientSecret: clientSecret,
		Email: req.Email, FirstName: clip(req.FirstName, 100), LastName: clip(req.LastName, 100),
		Persistent: req.Persistent, IP: clientIP(c), UserAgent: c.Request().UserAgent(),
	})
	if err != nil {
		if handled, resp := h.passwordlessError(c, err); handled {
			return resp
		}
		h.logger.Error().Err(err).Msg("passwordless start failed")
		return fail(c, http.StatusInternalServerError, "login_failed")
	}

	action := audit.ActionAuthPasswordlessStarted
	if meta.Outcome == "throttled" {
		action = audit.ActionAuthPasswordlessThrottled
	}
	ev := audit.Event{
		TenantID: &meta.TenantID, ApplicationID: &meta.AppRowID,
		Action: action, AuthMethod: audit.AuthMethodEmailOTP, ResourceType: "user",
		IPAddress: clientIP(c), UserAgent: c.Request().UserAgent(),
		HTTPStatus: http.StatusOK, Metadata: emailAuditMeta(req.Email),
	}
	ev.Metadata["outcome"] = meta.Outcome
	h.auditEvent(c, ev)

	return c.JSON(http.StatusOK, res)
}

// PasswordlessResend handles POST /api/v1/auth/apps/passwordless/resend.
//
// @Summary      Send a fresh code for an open challenge
// @Description  Rotates the code on the same challenge: the previous code stops working. Subject to a cooldown and a resend budget set by the application's policy. Failed attempts are not reset, so resending cannot multiply guesses.
// @Tags         AUTH
// @Accept       json
// @Produce      json
// @Param        Authorization  header  string                     true  "Basic base64(client_id:client_secret)"
// @Param        body           body    PasswordlessResendRequest  true  "Challenge"
// @Success      200  {object}  auth.PasswordlessResendResult
// @Failure      400  {object}  APIError  "invalid_or_expired_code"
// @Failure      429  {object}  APIError  "resend_cooldown or too_many_resends"
// @Router       /api/v1/auth/apps/passwordless/resend [post]
func (h *AuthHandler) PasswordlessResend(c echo.Context) error {
	if !h.passwordlessEnabled {
		return fail(c, http.StatusNotFound, "not_found")
	}
	var req PasswordlessResendRequest
	if err := c.Bind(&req); err != nil || req.ChallengeID == "" {
		return fail(c, http.StatusBadRequest, "invalid_or_expired_code")
	}
	clientID, clientSecret, errResp := appCredentialsFromRequest(c)
	if errResp != nil {
		return c.JSON(http.StatusBadRequest, errResp)
	}
	res, err := h.svc.PasswordlessResend(c.Request().Context(), clientID, clientSecret, req.ChallengeID)
	if err != nil {
		if handled, resp := h.passwordlessError(c, err); handled {
			return resp
		}
		h.logger.Error().Err(err).Msg("passwordless resend failed")
		return fail(c, http.StatusInternalServerError, "login_failed")
	}
	ev := audit.Event{
		Action: audit.ActionAuthPasswordlessResent, AuthMethod: audit.AuthMethodEmailOTP,
		ResourceType: "user", IPAddress: clientIP(c), UserAgent: c.Request().UserAgent(), HTTPStatus: http.StatusOK,
	}
	attachAppContext(c.Request().Context(), &ev, h.appSvc, clientID)
	h.auditEvent(c, ev)
	return c.JSON(http.StatusOK, res)
}

// PasswordlessVerify handles POST /api/v1/auth/apps/passwordless/verify.
//
// @Summary      Verify a code to sign in or sign up
// @Description  Proves the code, then signs the user in, or creates the account (when the application allows sign-up) and signs in. The application's MFA policy still applies, and the email method is not offered as a second factor after an emailed first factor: the response is a token pair, an OTP challenge (requires_otp), a forced-enrollment challenge (403 mfa_enrollment_required) or 409 organization_selection_required. Every refusal is the single error invalid_or_expired_code.
// @Tags         AUTH
// @Accept       json
// @Produce      json
// @Param        Authorization  header  string                     true  "Basic base64(client_id:client_secret)"
// @Param        body           body    PasswordlessVerifyRequest  true  "Challenge and code"
// @Success      200  {object}  auth.AuthResult
// @Failure      400  {object}  APIError  "invalid_or_expired_code"
// @Failure      403  {object}  APIError  "MFA enrollment required"
// @Failure      409  {object}  APIError  "organization_selection_required"
// @Param        X-EMC-Forwarded-For  header  string  false  "End user's IP. Used only when the application trusts forwarded IPs and the client secret is valid; see /docs/reference/rate-limits"
// @Failure      429  {object}  map[string]string  "Rate limited. The limiter field says which limit (user, app or ip); wait Retry-After seconds"
// @Router       /api/v1/auth/apps/passwordless/verify [post]
func (h *AuthHandler) PasswordlessVerify(c echo.Context) error {
	if !h.passwordlessEnabled {
		return fail(c, http.StatusNotFound, "not_found")
	}
	var req PasswordlessVerifyRequest
	if err := c.Bind(&req); err != nil || req.ChallengeID == "" || req.Code == "" {
		return fail(c, http.StatusBadRequest, "invalid_or_expired_code")
	}
	clientID, clientSecret, errResp := appCredentialsFromRequest(c)
	if errResp != nil {
		return c.JSON(http.StatusBadRequest, errResp)
	}

	result, meta, err := h.svc.PasswordlessVerify(c.Request().Context(), auth.PasswordlessVerifyInput{
		ClientID: clientID, ClientSecret: clientSecret,
		ChallengeID: req.ChallengeID, Code: req.Code,
		Organization: req.Organization, Roles: req.Roles,
		IP: clientIP(c), UserAgent: c.Request().UserAgent(),
	})
	if err != nil {
		if handled, resp := h.organizationOutcome(c, err, audit.AuthMethodEmailOTP, clientID, ""); handled {
			return resp
		}
		ev := audit.Event{
			Action: audit.ActionAuthLoginFailed, AuthMethod: audit.AuthMethodEmailOTP,
			ResourceType: "user", IPAddress: clientIP(c), UserAgent: c.Request().UserAgent(),
		}
		if meta != nil && meta.Email != "" {
			ev.Metadata = emailAuditMeta(meta.Email)
		}
		attachAppContext(c.Request().Context(), &ev, h.appSvc, clientID)
		h.auditFailure(c, ev, err)
		if handled, resp := h.passwordlessError(c, err); handled {
			return resp
		}
		h.logger.Error().Err(err).Msg("passwordless verify failed")
		return fail(c, http.StatusInternalServerError, "login_failed")
	}

	if result.OTPChallenge != nil {
		return c.JSON(http.StatusOK, result.OTPChallenge)
	}
	if result.MFAEnrollment != nil {
		return c.JSON(http.StatusForbidden, result.MFAEnrollment)
	}

	tid, uid, appID := claimsFromToken(result.Token.AccessToken)
	ev := audit.Event{
		TenantID: tid, UserID: uid, ApplicationID: appID,
		Action: audit.ActionAuthLogin, AuthMethod: audit.AuthMethodEmailOTP, ResourceType: "user",
		IPAddress: clientIP(c), UserAgent: c.Request().UserAgent(),
		Metadata: map[string]any{"created": meta != nil && meta.Created},
	}
	h.auditEvent(c, ev)
	if meta != nil {
		h.notifyRiskySignIn(c, tid, uid, appID, meta.Email)
	}

	setAuthCookies(c, result.Token.AccessToken, result.Token.RefreshToken, h.cookieCfg)
	return c.JSON(http.StatusOK, result.Token)
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n]
	}
	return s
}
