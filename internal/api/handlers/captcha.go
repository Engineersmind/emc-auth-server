package handlers

import (
	"errors"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog"

	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// ---------------------------------------------------------------------------
// Public CAPTCHA endpoint (issue #145).
//
// One route. There is deliberately no verify endpoint and no requirement
// endpoint:
//
//   - Verification happens inline on the protected flow, so there is no second
//     round trip and no new short-lived token type for anything to validate.
//
//   - A "does this email need a captcha?" endpoint is an account-enumeration
//     oracle and would break non-negotiable #6. The protected endpoint answers
//     428 captcha_required instead, and the client fetches a challenge and
//     retries — the same shape Auth0 uses, for the same reason.
// ---------------------------------------------------------------------------

// CaptchaHandler serves challenge issuance.
type CaptchaHandler struct {
	svc    *auth.CaptchaService
	authz  *auth.AuthorizationServer
	logger zerolog.Logger
}

// NewCaptchaHandler constructs a CaptchaHandler. A nil service makes every route
// answer 404 captcha_disabled, which is what a deployment with CAPTCHA_ENABLED
// unset should look like from outside.
func NewCaptchaHandler(svc *auth.CaptchaService, authz *auth.AuthorizationServer, logger zerolog.Logger) *CaptchaHandler {
	return &CaptchaHandler{svc: svc, authz: authz, logger: logger}
}

// CaptchaChallengeRequest is the body of POST /api/v1/captcha/challenge.
type CaptchaChallengeRequest struct {
	// ClientID names the application the challenge is for.
	//
	// OPTIONAL, and which way you send it must match the flow you will spend the
	// challenge on — the challenge is bound to this value, so a mismatch is
	// refused however correct the answer is:
	//
	//   OMIT it for the first-party flows — /auth/login, /auth/session,
	//   /auth/login/otp and the tenant-level /auth/register. None of those knows
	//   a tenant or an application before authenticating, so they verify against
	//   the platform policy with no client binding.
	//
	//   SEND it for the application-authenticated flows — /auth/apps/login,
	//   /auth/apps/register and /auth/forgot-password — which authenticate a
	//   client first and verify against that application's policy.
	ClientID string `json:"client_id"`
	// Purpose is the flow the challenge will be spent on — "login", "session",
	// "login_otp", "register" or "forgot_password". Bound into the challenge, so
	// one minted for the cheap register path cannot be used on login.
	Purpose string `json:"purpose" validate:"required"`
	// PreviousChallengeID, when set, is burned before the new one is issued.
	//
	// This is what makes the "I can't read it" button safe. Without it a caller
	// could accumulate outstanding challenges and work through them at leisure,
	// which is precisely the position a solver farm wants to be in.
	PreviousChallengeID string `json:"previous_challenge_id"`
}

// IssueChallenge handles POST /api/v1/captcha/challenge.
//
// @Summary      Get a CAPTCHA challenge
// @Description  Issues a single-use image challenge. OMIT client_id for the first-party flows (login, session, login_otp, tenant-level register); SEND it for the application-authenticated flows (apps/login, apps/register, forgot_password). The challenge is bound to whichever you chose, so a mismatch is refused however correct the answer is. The image is returned inline as a PNG data URI. Answer it by sending `captcha_id` and `captcha_answer` on the protected request. Returns 404 when the application has no captcha policy enabled.
// @Tags         AUTH
// @Accept       json
// @Produce      json
// @Param        body  body      CaptchaChallengeRequest  true  "Application and flow"
// @Success      200   {object}  auth.CaptchaChallenge
// @Failure      400   {object}  map[string]string
// @Failure      404   {object}  map[string]string
// @Router       /api/v1/captcha/challenge [post]
func (h *CaptchaHandler) IssueChallenge(c echo.Context) error {
	if h.svc == nil || !h.svc.Enabled() {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "captcha_disabled"})
	}

	var req CaptchaChallengeRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}
	if req.Purpose == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "purpose is required"})
	}
	if !auth.IsValidCaptchaFlow(req.Purpose) {
		// Naming the valid set is safe — it is a fixed, documented vocabulary,
		// not server state — and a client that typo'd a purpose would otherwise
		// see an empty 404 and conclude captchas are off.
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "purpose must be one of login, session, login_otp, register, forgot_password",
		})
	}

	// Scope resolution, and it must produce exactly what the flow being protected
	// will present at verify time — otherwise the binding check refuses a
	// correct answer and the user is stuck in a loop they cannot escape.
	var (
		tenantID int64
		appID    *int64
		clientID string
	)
	if req.ClientID != "" {
		// The tenant comes OUT of the client lookup and is authoritative from
		// then on — it is never read from the request body. Same rule as the
		// authorize endpoint, and the same reason: this route is
		// unauthenticated, so anything the caller says about which tenant they
		// belong to is a claim, not a fact.
		client, err := h.authz.LookupClient(c.Request().Context(), req.ClientID)
		if err != nil {
			if errors.Is(err, auth.ErrClientNotFound) {
				// Same response as a disabled policy. An unauthenticated caller
				// must not be able to tell a client_id that does not exist from
				// one whose tenant has captchas switched off — that would turn
				// this endpoint into a client_id enumeration oracle.
				return c.JSON(http.StatusNotFound, map[string]string{"error": "captcha_disabled"})
			}
			h.logger.Error().Err(err).Msg("captcha: client lookup failed")
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to issue challenge"})
		}
		rowID := client.RowID
		tenantID, appID, clientID = client.TenantID, &rowID, client.ClientID
	}
	// With no client_id: tenant 0, no application, no client binding — which is
	// precisely the scope the first-party flows check against.

	challenge, err := h.svc.Issue(
		c.Request().Context(),
		tenantID,
		appID,
		clientID,
		auth.CaptchaFlow(req.Purpose),
		req.PreviousChallengeID,
	)
	if err != nil {
		if errors.Is(err, auth.ErrCaptchaDisabled) {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "captcha_disabled"})
		}
		h.logger.Error().Err(err).Msg("captcha: issue failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to issue challenge"})
	}

	// No-store, and not only out of habit: the response body contains the image
	// for a single-use challenge, and a cached copy served to a second request
	// would be a challenge whose answer has already been spent.
	c.Response().Header().Set("Cache-Control", "no-store")
	return c.JSON(http.StatusOK, challenge)
}
