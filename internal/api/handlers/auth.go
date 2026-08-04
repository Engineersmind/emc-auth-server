package handlers

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"

	mw "github.com/engineersmind/emc-auth-server/internal/api/middleware"
	"github.com/engineersmind/emc-auth-server/internal/audit"
	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/metrics"
)

// AuthHandler holds HTTP handlers for auth endpoints.
type AuthHandler struct {
	svc       *auth.AuthService
	resetSvc  *auth.ResetService
	verifSvc  *auth.VerificationService // nil when email verification not configured
	totpSvc   *auth.TOTPService         // nil when TOTP not configured
	emailSvc  *auth.EmailMFAService     // nil when email MFA not configured
	apiKeySvc *auth.APIKeyService
	appSvc    *auth.ApplicationService  // nil until WithApplications is called
	invSvc    *auth.InvitationService   // nil when invitations are not configured
	chgSvc    *auth.EmailChangeService  // nil when email change is not configured
	blockSvc  *auth.AccountBlockService // nil when account lockout is not configured
	jwtSvc    *auth.JWTService
	audit     *audit.Logger
	logger    zerolog.Logger
	cookieCfg mw.CookieConfig
	redisCli  *redis.Client // per-family refresh lock; nil degrades to lock-free replay detection
}

// NewAuthHandler creates an AuthHandler.
func NewAuthHandler(svc *auth.AuthService, resetSvc *auth.ResetService, auditLog *audit.Logger, logger zerolog.Logger) *AuthHandler {
	return &AuthHandler{svc: svc, resetSvc: resetSvc, audit: auditLog, logger: logger}
}

// WithTOTP attaches a TOTPService to the handler.
func (h *AuthHandler) WithTOTP(totpSvc *auth.TOTPService) *AuthHandler {
	h.totpSvc = totpSvc
	return h
}

// WithEmailMFA attaches an EmailMFAService to the handler.
func (h *AuthHandler) WithEmailMFA(emailSvc *auth.EmailMFAService) *AuthHandler {
	h.emailSvc = emailSvc
	return h
}

// WithVerification attaches a VerificationService for the email-verification
// endpoints (verify + resend).
func (h *AuthHandler) WithVerification(verifSvc *auth.VerificationService) *AuthHandler {
	h.verifSvc = verifSvc
	return h
}

// VerifyEmail handles GET /api/v1/auth/verify-email?token=... — the link
// emailed on registration. Marks the address verified and triggers a welcome
// email. Single-use; a reused or expired token returns 400.
//
// @Summary      Verify email address
// @Description  Confirms ownership of an email address via the token from the verification link. Single-use.
// @Tags         AUTH
// @Produce      json
// @Param        token  query     string  true  "Verification token"
// @Success      200    {object}  map[string]string
// @Failure      400    {object}  map[string]string
// @Router       /api/v1/auth/verify-email [get]
func (h *AuthHandler) VerifyEmail(c echo.Context) error {
	if h.verifSvc == nil {
		return c.JSON(http.StatusNotImplemented, map[string]string{"error": "email verification is not configured"})
	}
	token := c.QueryParam("token")
	if token == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "token is required"})
	}
	if err := h.verifSvc.VerifyEmail(c.Request().Context(), token); err != nil {
		if errors.Is(err, auth.ErrInvalidVerificationToken) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid or expired verification link"})
		}
		h.logger.Error().Err(err).Msg("auth: verify email failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to verify email"})
	}
	return c.JSON(http.StatusOK, map[string]string{"message": "email verified"})
}

// ResendVerificationRequest is the body for POST /api/v1/auth/resend-verification.
type ResendVerificationRequest struct {
	Email string `json:"email" validate:"required,email"`
}

// ResendVerification handles POST /api/v1/auth/resend-verification. The tenant
// comes from the X-Tenant-Slug header. Enumeration-safe: always 200.
//
// @Summary      Resend verification email
// @Description  Re-sends the email-verification link for an unverified tenant-level user. Always returns 200 to prevent account enumeration.
// @Tags         AUTH
// @Accept       json
// @Produce      json
// @Param        X-Tenant-Slug  header    string                     true  "Tenant slug"
// @Param        body           body      ResendVerificationRequest  true  "Email to resend to"
// @Success      200            {object}  map[string]string
// @Router       /api/v1/auth/resend-verification [post]
func (h *AuthHandler) ResendVerification(c echo.Context) error {
	if h.verifSvc == nil {
		return c.JSON(http.StatusNotImplemented, map[string]string{"error": "email verification is not configured"})
	}
	tenantSlug := c.Request().Header.Get("X-Tenant-Slug")
	var req ResendVerificationRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}
	if tenantSlug == "" || req.Email == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "tenant slug and email are required"})
	}
	if err := h.verifSvc.ResendVerification(c.Request().Context(), tenantSlug, req.Email); err != nil {
		h.logger.Error().Err(err).Msg("auth: resend verification failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to process request"})
	}
	return c.JSON(http.StatusOK, map[string]string{"message": "if the account exists and is unverified, a verification email has been sent"})
}

// WithAPIKeys attaches an APIKeyService to the handler.
func (h *AuthHandler) WithAPIKeys(apiKeySvc *auth.APIKeyService) *AuthHandler {
	h.apiKeySvc = apiKeySvc
	return h
}

// WithCookieConfig sets the cookie security policy for this handler.
func (h *AuthHandler) WithCookieConfig(cfg mw.CookieConfig) *AuthHandler {
	h.cookieCfg = cfg
	return h
}

// WithApplications attaches the ApplicationService so Register, Login, and Token
// handlers can validate X-Client-ID and issue client_credentials tokens.
func (h *AuthHandler) WithApplications(appSvc *auth.ApplicationService) *AuthHandler {
	h.appSvc = appSvc
	return h
}

// WithJWT attaches a JWTService to the handler (needed for management token endpoint).
func (h *AuthHandler) WithJWT(jwtSvc *auth.JWTService) *AuthHandler {
	h.jwtSvc = jwtSvc
	return h
}

// WithRedis attaches the Redis client used by the explicit refresh endpoints to
// acquire the per-family rotation lock (see AuthService.RefreshWithLock). When
// nil, refresh still detects replay but cannot serialize concurrent rotations.
func (h *AuthHandler) WithRedis(redisCli *redis.Client) *AuthHandler {
	h.redisCli = redisCli
	return h
}

// clientIDFromCtx extracts the optional X-Client-ID header value.
func clientIDFromCtx(c echo.Context) string {
	return c.Request().Header.Get("X-Client-ID")
}

// MyActivity handles GET /api/v1/auth/my-activity.
//
// @Summary      My activity log
// @Description  Returns the authenticated user's own recent audit log entries.
// @Tags         AUTH
// @Produce      json
// @Security     BearerAuth
// @Param        page   query     int  false  "Page number (default 1)"
// @Param        limit  query     int  false  "Rows per page (default 20, max 100)"
// @Success      200    {object}  audit.LogsPage
// @Failure      401    {object}  map[string]string
// @Router       /api/v1/auth/my-activity [get]
func (h *AuthHandler) MyActivity(c echo.Context) error {
	claims, ok := c.Get("user").(*auth.Claims)
	if !ok || claims == nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	tenantID, err := strconv.ParseInt(claims.TenantID, 10, 64)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid tenant"})
	}
	page := 1
	if p, err := strconv.Atoi(c.QueryParam("page")); err == nil && p > 0 {
		page = p
	}
	result, err := h.audit.Query(c.Request().Context(), audit.QueryParams{
		TenantID: &tenantID,
		UserID:   claims.UserID,
		Page:     page,
		Limit:    50,
	})
	if err != nil {
		h.logger.Error().Err(err).Msg("auth: my-activity query failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to query activity"})
	}
	return c.JSON(http.StatusOK, result)
}

// RegisterRequest is the JSON body for POST /api/v1/auth/register.
// This is the first-party, tenant-level flow — see AppRegisterRequest /
// POST /api/v1/auth/apps/register for the application-authenticated flow.
type RegisterRequest struct {
	Email     string `json:"email"     validate:"required,email"`
	Password  string `json:"password"  validate:"required,min=8"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

// LoginRequest is the JSON body for POST /api/v1/auth/login.
// This is the first-party, tenant-level flow — see AppLoginRequest /
// POST /api/v1/auth/apps/login for the application-authenticated flow.
type LoginRequest struct {
	Email    string `json:"email"    validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

// tenantSlugFromCtx extracts the X-Tenant-Slug header.
// Returns the slug and whether it was explicitly provided.
// For login/session endpoints the slug is optional — defaults to "emc".
func tenantSlugFromCtx(c echo.Context) (string, bool) {
	slug := c.Request().Header.Get("X-Tenant-Slug")
	return slug, slug != ""
}

// Register handles POST /api/v1/auth/register.
//
// @Summary      Register a new user
// @Description  Creates a user account in the specified tenant and returns a token pair.
// @Tags         AUTH
// @Accept       json
// @Produce      json
// @Param        X-Tenant-Slug  header    string          true  "Tenant slug (e.g. emc)"
// @Param        body           body      RegisterRequest true  "Registration payload"
// @Success      201            {object}  auth.AuthResult
// @Failure      400            {object}  map[string]string
// @Failure      404            {object}  map[string]string  "Tenant not found"
// @Failure      409            {object}  map[string]string  "Email already registered"
// @Router       /api/v1/auth/register [post]
func (h *AuthHandler) Register(c echo.Context) error {
	slug, ok := tenantSlugFromCtx(c)
	if !ok {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "X-Tenant-Slug header is required — for application-authenticated registration use POST /api/v1/auth/apps/register"})
	}

	var req RegisterRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}
	if req.Email == "" || req.Password == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "email and password are required"})
	}
	if len(req.Password) < 8 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "password must be at least 8 characters"})
	}

	result, err := h.svc.Register(c.Request().Context(), auth.RegisterInput{
		TenantSlug: slug,
		ClientID:   clientIDFromCtx(c), // legacy X-Client-ID tagging only — no secret, no auth
		Email:      req.Email,
		Password:   req.Password,
		FirstName:  req.FirstName,
		LastName:   req.LastName,
	})
	if err != nil {
		h.logger.Error().Err(err).Str("email", req.Email).Msg("register failed")
		if containsMsg(err, "tenant not found") {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "tenant not found"})
		}
		if containsMsg(err, "duplicate") || containsMsg(err, "unique") {
			return c.JSON(http.StatusConflict, map[string]string{"error": "email already registered"})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "registration failed"})
	}

	tid, uid, appID := claimsFromToken(result.AccessToken)
	h.auditEvent(c, audit.Event{
		TenantID:      tid,
		UserID:        uid,
		ApplicationID: appID,
		ActorEmail:    req.Email,
		Action:        audit.ActionAuthRegister,
		AuthMethod:    audit.AuthMethodPassword,
		ResourceType:  "user",
		IPAddress:     c.RealIP(),
		UserAgent:     c.Request().UserAgent(),
	})

	setAuthCookies(c, result.AccessToken, result.RefreshToken, h.cookieCfg)
	return c.JSON(http.StatusCreated, result)
}

// Login handles POST /api/v1/auth/login.
//
// @Summary      Login
// @Description  Authenticates an existing user by email and password only. The tenant is resolved automatically from which account the password matches — no tenant slug or header is required.
// @Tags         AUTH
// @Accept       json
// @Produce      json
// @Param        body  body      LoginRequest  true  "Login credentials"
// @Success      200   {object}  auth.AuthResult
// @Failure      400   {object}  map[string]string
// @Failure      401   {object}  map[string]string  "Invalid credentials"
// @Router       /api/v1/auth/login [post]
func (h *AuthHandler) Login(c echo.Context) error {
	var req LoginRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}
	if req.Email == "" || req.Password == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "email and password are required"})
	}

	result, err := h.svc.Login(c.Request().Context(), auth.LoginInput{
		ClientID: clientIDFromCtx(c), // legacy X-Client-ID tagging only — no secret, no auth
		Email:    req.Email,
		Password: req.Password,
	})
	if err != nil {
		h.logger.Warn().Err(err).Str("email", req.Email).Msg("login failed")
		h.auditFailure(c, audit.Event{
			ActorEmail:   req.Email,
			Action:       audit.ActionAuthLoginFailed,
			AuthMethod:   audit.AuthMethodPassword,
			ResourceType: "user",
			IPAddress:    c.RealIP(),
			UserAgent:    c.Request().UserAgent(),
		}, err)
		if containsMsg(err, "invalid credentials") {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "login failed"})
	}

	if result.OTPChallenge != nil {
		return c.JSON(http.StatusOK, result.OTPChallenge)
	}
	if result.MFAEnrollment != nil {
		return c.JSON(http.StatusForbidden, result.MFAEnrollment)
	}

	tid, uid, appID := claimsFromToken(result.Token.AccessToken)
	h.auditEvent(c, audit.Event{
		TenantID:      tid,
		UserID:        uid,
		ApplicationID: appID,
		ActorEmail:    req.Email,
		Action:        audit.ActionAuthLogin,
		AuthMethod:    audit.AuthMethodPassword,
		ResourceType:  "user",
		IPAddress:     c.RealIP(),
		UserAgent:     c.Request().UserAgent(),
	})

	h.notifyRiskySignIn(c, tid, uid, appID, req.Email)

	setAuthCookies(c, result.Token.AccessToken, result.Token.RefreshToken, h.cookieCfg)
	return c.JSON(http.StatusOK, result.Token)
}

// ---------------------------------------------------------------------------
// Application-authenticated end-user register/login (Auth0-style integration)
// ---------------------------------------------------------------------------

// AppRegisterRequest is the JSON body for POST /api/v1/auth/apps/register.
// The calling application is authenticated via the Authorization: Basic
// header (RFC 6749 §2.3.1) — never in the body. The tenant and the isolated
// user base are both derived from the authenticated application.
type AppRegisterRequest struct {
	Email     string `json:"email"     validate:"required,email"`
	Password  string `json:"password"  validate:"required,min=8"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

// AppLoginRequest is the JSON body for POST /api/v1/auth/apps/login.
// See AppRegisterRequest for the application-authentication contract.
type AppLoginRequest struct {
	Email    string `json:"email"    validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

// appCredentialsFromRequest resolves and requires the calling application's
// credentials from the Authorization: Basic header — the only credential
// channel these endpoints accept. AppRegisterRequest/AppLoginRequest have no
// client_id/client_secret fields, so anything sent in the body is simply
// unread, not rejected — there is nothing to strip.
func appCredentialsFromRequest(c echo.Context) (clientID, clientSecret string, errResp map[string]string) {
	id, secret, ok, err := clientCredentialsFromBasicAuth(c)
	if err != nil {
		return "", "", map[string]string{"error": err.Error()}
	}
	if !ok {
		return "", "", map[string]string{"error": "Authorization: Basic base64(client_id:client_secret) header is required"}
	}
	return id, secret, nil
}

// AppRegister handles POST /api/v1/auth/apps/register.
//
// @Summary      Register an end user via application credentials
// @Description  Creates a user account owned by the authenticated application — the same email may hold independent accounts in different applications. Application credentials via Authorization: Basic header only; no tenant slug needed.
// @Tags         AUTH
// @Accept       json
// @Produce      json
// @Param        Authorization  header  string              true  "Basic base64(client_id:client_secret)"
// @Param        body           body    AppRegisterRequest  true  "Registration payload"
// @Success      201  {object}  auth.AuthResult
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string  "Invalid application credentials"
// @Failure      409  {object}  map[string]string  "Email already registered in this application"
// @Router       /api/v1/auth/apps/register [post]
func (h *AuthHandler) AppRegister(c echo.Context) error {
	var req AppRegisterRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}
	if req.Email == "" || req.Password == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "email and password are required"})
	}
	if len(req.Password) < 8 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "password must be at least 8 characters"})
	}

	clientID, clientSecret, errResp := appCredentialsFromRequest(c)
	if errResp != nil {
		return c.JSON(http.StatusBadRequest, errResp)
	}

	result, err := h.svc.Register(c.Request().Context(), auth.RegisterInput{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Email:        req.Email,
		Password:     req.Password,
		FirstName:    req.FirstName,
		LastName:     req.LastName,
	})
	if err != nil {
		h.logger.Error().Err(err).Str("email", req.Email).Msg("app register failed")
		if errors.Is(err, auth.ErrInvalidClient) {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid client credentials"})
		}
		if containsMsg(err, "duplicate") || containsMsg(err, "unique") {
			return c.JSON(http.StatusConflict, map[string]string{"error": "email already registered in this application"})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "registration failed"})
	}

	tid, uid, appID := claimsFromToken(result.AccessToken)
	h.auditEvent(c, audit.Event{
		TenantID:      tid,
		UserID:        uid,
		ApplicationID: appID,
		ActorEmail:    req.Email,
		Action:        audit.ActionAuthRegister,
		AuthMethod:    audit.AuthMethodPassword,
		ResourceType:  "user",
		IPAddress:     c.RealIP(),
		UserAgent:     c.Request().UserAgent(),
	})

	setAuthCookies(c, result.AccessToken, result.RefreshToken, h.cookieCfg)
	return c.JSON(http.StatusCreated, result)
}

// AppLogin handles POST /api/v1/auth/apps/login.
//
// @Summary      Login an end user via application credentials
// @Description  Authenticates a user that belongs to the authenticated application's own user base — invisible to POST /auth/login and to every other application. Application credentials via Authorization: Basic header only.
// @Tags         AUTH
// @Accept       json
// @Produce      json
// @Param        Authorization  header  string           true  "Basic base64(client_id:client_secret)"
// @Param        body           body    AppLoginRequest  true  "Login credentials"
// @Success      200  {object}  auth.AuthResult
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string  "Invalid application or user credentials"
// @Router       /api/v1/auth/apps/login [post]
func (h *AuthHandler) AppLogin(c echo.Context) error {
	var req AppLoginRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}
	if req.Email == "" || req.Password == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "email and password are required"})
	}

	clientID, clientSecret, errResp := appCredentialsFromRequest(c)
	if errResp != nil {
		return c.JSON(http.StatusBadRequest, errResp)
	}

	result, err := h.svc.Login(c.Request().Context(), auth.LoginInput{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Email:        req.Email,
		Password:     req.Password,
	})
	if err != nil {
		h.logger.Warn().Err(err).Str("email", req.Email).Msg("app login failed")
		ev := audit.Event{
			ActorEmail:   req.Email,
			Action:       audit.ActionAuthLoginFailed,
			AuthMethod:   audit.AuthMethodPassword,
			ResourceType: "user",
			IPAddress:    c.RealIP(),
			UserAgent:    c.Request().UserAgent(),
		}
		attachAppContext(c.Request().Context(), &ev, h.appSvc, clientID)
		h.auditFailure(c, ev, err)
		if errors.Is(err, auth.ErrInvalidClient) {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid client credentials"})
		}
		if containsMsg(err, "invalid credentials") {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "login failed"})
	}

	if result.OTPChallenge != nil {
		return c.JSON(http.StatusOK, result.OTPChallenge)
	}
	if result.MFAEnrollment != nil {
		// The application's MFA policy is 'required' and this user has no
		// active enrollment: no tokens yet — the client takes the enrollment
		// token through /auth/login/mfa/enroll + /auth/login/mfa/activate.
		return c.JSON(http.StatusForbidden, result.MFAEnrollment)
	}

	tid, uid, appID := claimsFromToken(result.Token.AccessToken)
	h.auditEvent(c, audit.Event{
		TenantID:      tid,
		UserID:        uid,
		ApplicationID: appID,
		ActorEmail:    req.Email,
		Action:        audit.ActionAuthLogin,
		AuthMethod:    audit.AuthMethodPassword,
		ResourceType:  "user",
		IPAddress:     c.RealIP(),
		UserAgent:     c.Request().UserAgent(),
	})

	h.notifyRiskySignIn(c, tid, uid, appID, req.Email)

	setAuthCookies(c, result.Token.AccessToken, result.Token.RefreshToken, h.cookieCfg)
	return c.JSON(http.StatusOK, result.Token)
}

// MagicLinkRequest is the JSON body for POST /api/v1/auth/apps/login/magic.
type MagicLinkRequest struct {
	Email string `json:"email"`
}

// AppMagicLink handles POST /api/v1/auth/apps/login/magic — requests a
// passwordless sign-in link for an end user of the authenticated application.
//
// @Summary      Request a magic sign-in link
// @Description  Emails a single-use, 15-minute sign-in link to the account address if it exists in the application's user base. Always returns success for unknown emails (no account enumeration). Requires magic-link sign-in to be enabled on the application's auth policy.
// @Tags         AUTH
// @Accept       json
// @Produce      json
// @Param        Authorization  header  string            true  "Basic base64(client_id:client_secret)"
// @Param        body           body    MagicLinkRequest  true  "Account email"
// @Success      200  {object}  map[string]string
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string  "Invalid application credentials"
// @Failure      403  {object}  map[string]string  "Magic link not enabled for this application"
// @Router       /api/v1/auth/apps/login/magic [post]
func (h *AuthHandler) AppMagicLink(c echo.Context) error {
	var req MagicLinkRequest
	if err := c.Bind(&req); err != nil || req.Email == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "email is required"})
	}

	clientID, clientSecret, errResp := appCredentialsFromRequest(c)
	if errResp != nil {
		return c.JSON(http.StatusBadRequest, errResp)
	}

	err := h.svc.RequestMagicLink(c.Request().Context(), clientID, clientSecret, req.Email)
	if err != nil {
		h.logger.Warn().Err(err).Msg("magic link request failed")
		if errors.Is(err, auth.ErrInvalidClient) {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid client credentials"})
		}
		if errors.Is(err, auth.ErrMagicLinkDisabled) || errors.Is(err, auth.ErrMagicLinkNotConfigured) {
			return c.JSON(http.StatusForbidden, map[string]string{"error": err.Error()})
		}
		if containsMsg(err, "not configured on this server") {
			return c.JSON(http.StatusNotImplemented, map[string]string{"error": "magic link not configured on this server"})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not send sign-in link"})
	}

	h.auditEvent(c, audit.Event{
		ActorEmail:   req.Email,
		Action:       audit.ActionAuthMagicLinkRequested,
		AuthMethod:   audit.AuthMethodMagicLink,
		ResourceType: "user",
		IPAddress:    c.RealIP(),
		UserAgent:    c.Request().UserAgent(),
	})

	return c.JSON(http.StatusOK, map[string]string{"message": "if an account exists for this email, a sign-in link has been sent"})
}

// MagicLinkVerifyRequest is the JSON body for POST /api/v1/auth/apps/login/magic/verify.
type MagicLinkVerifyRequest struct {
	Token string `json:"token"`
}

// AppMagicLinkVerify handles POST /api/v1/auth/apps/login/magic/verify —
// consumes a magic-link token and completes the login.
//
// @Summary      Verify a magic sign-in link
// @Description  Consumes the single-use token from the emailed link. The application's MFA policy still applies: the response is a token pair, an OTP challenge (requires_otp), or a forced-enrollment challenge (403 mfa_enrollment_required) — exactly like a password login.
// @Tags         AUTH
// @Accept       json
// @Produce      json
// @Param        Authorization  header  string                  true  "Basic base64(client_id:client_secret)"
// @Param        body           body    MagicLinkVerifyRequest  true  "Token from the emailed link"
// @Success      200  {object}  auth.AuthResult
// @Failure      401  {object}  map[string]string  "Invalid application credentials or invalid/expired link"
// @Failure      403  {object}  map[string]string  "MFA enrollment required"
// @Router       /api/v1/auth/apps/login/magic/verify [post]
func (h *AuthHandler) AppMagicLinkVerify(c echo.Context) error {
	var req MagicLinkVerifyRequest
	if err := c.Bind(&req); err != nil || req.Token == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "token is required"})
	}

	clientID, clientSecret, errResp := appCredentialsFromRequest(c)
	if errResp != nil {
		return c.JSON(http.StatusBadRequest, errResp)
	}

	result, err := h.svc.VerifyMagicLink(c.Request().Context(), clientID, clientSecret, req.Token)
	if err != nil {
		h.logger.Warn().Err(err).Msg("magic link verify failed")
		ev := audit.Event{
			Action:       audit.ActionAuthLoginFailed,
			AuthMethod:   audit.AuthMethodMagicLink,
			ResourceType: "user",
			IPAddress:    c.RealIP(),
			UserAgent:    c.Request().UserAgent(),
		}
		attachAppContext(c.Request().Context(), &ev, h.appSvc, clientID)
		h.auditFailure(c, ev, err)
		if errors.Is(err, auth.ErrInvalidClient) {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid client credentials"})
		}
		if errors.Is(err, auth.ErrInvalidMagicLink) {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": err.Error()})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "sign-in failed"})
	}

	if result.OTPChallenge != nil {
		return c.JSON(http.StatusOK, result.OTPChallenge)
	}
	if result.MFAEnrollment != nil {
		return c.JSON(http.StatusForbidden, result.MFAEnrollment)
	}

	tid, uid, appID := claimsFromToken(result.Token.AccessToken)
	h.auditEvent(c, audit.Event{
		TenantID:      tid,
		UserID:        uid,
		ApplicationID: appID,
		Action:        audit.ActionAuthLogin,
		AuthMethod:    audit.AuthMethodMagicLink,
		ResourceType:  "user",
		IPAddress:     c.RealIP(),
		UserAgent:     c.Request().UserAgent(),
	})

	setAuthCookies(c, result.Token.AccessToken, result.Token.RefreshToken, h.cookieCfg)
	return c.JSON(http.StatusOK, result.Token)
}

// LoginOTPRequest is the JSON body for POST /api/v1/auth/login/otp.
type LoginOTPRequest struct {
	OTPSessionToken string `json:"otp_session_token"`
	Code            string `json:"code"`
}

// LoginOTP handles POST /api/v1/auth/login/otp — completes a TOTP-gated login.
//
// @Summary      Complete TOTP login
// @Description  Submit the TOTP code (or backup code) to complete a two-step login. The session allows 5 incorrect codes before it is invalidated. Returns the full token pair (and sets auth cookies for browser clients).
// @Tags         AUTH
// @Accept       json
// @Produce      json
// @Param        body  body      LoginOTPRequest  true  "OTP session token + TOTP code"
// @Success      200   {object}  auth.AuthResult
// @Failure      400   {object}  map[string]string
// @Failure      401   {object}  map[string]string
// @Failure      429   {object}  map[string]string  "Attempt budget exhausted — restart login"
// @Router       /api/v1/auth/login/otp [post]
func (h *AuthHandler) LoginOTP(c echo.Context) error {
	var req LoginOTPRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}
	if req.OTPSessionToken == "" || req.Code == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "otp_session_token and code are required"})
	}

	result, err := h.svc.LoginOTP(c.Request().Context(), auth.LoginOTPInput{
		OTPSessionToken: req.OTPSessionToken,
		Code:            req.Code,
	})
	if err != nil {
		h.logger.Warn().Err(err).Msg("login OTP failed")
		action := audit.ActionAuthMFAChallengeFailed
		metrics.MFAChallenges.WithLabelValues("mfa", "failure").Inc()
		if errors.Is(err, auth.ErrTooManyOTPAttempts) {
			action = audit.ActionAuthMFALockedOut
			metrics.MFALockouts.Inc()
		}
		h.auditFailure(c, audit.Event{
			Action:       action,
			AuthMethod:   audit.AuthMethodMFA,
			ResourceType: "user",
			IPAddress:    c.RealIP(),
			UserAgent:    c.Request().UserAgent(),
			Metadata:     map[string]any{"transaction_id": transactionID(req.OTPSessionToken)},
		}, err)
		if errors.Is(err, auth.ErrTooManyOTPAttempts) {
			return c.JSON(http.StatusTooManyRequests, map[string]string{"error": err.Error()})
		}
		if containsMsg(err, "invalid TOTP") || containsMsg(err, "invalid or expired") || containsMsg(err, "invalid backup") {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid or expired OTP code"})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "OTP login failed"})
	}

	metrics.MFAChallenges.WithLabelValues("mfa", "success").Inc()
	tid, uid, appID := claimsFromToken(result.AccessToken)
	h.auditEvent(c, audit.Event{
		TenantID:      tid,
		UserID:        uid,
		ApplicationID: appID,
		Action:        audit.ActionAuthLogin,
		AuthMethod:    audit.AuthMethodMFA,
		ResourceType:  "user",
		IPAddress:     c.RealIP(),
		UserAgent:     c.Request().UserAgent(),
		Metadata:      map[string]any{"transaction_id": transactionID(req.OTPSessionToken)},
	})

	setAuthCookies(c, result.AccessToken, result.RefreshToken, h.cookieCfg)
	// The full token pair is returned in the body (not just cookies) so
	// application-integrated (non-browser) clients can complete the app-login
	// MFA flow; cookies are still set for browser/SPA clients.
	return c.JSON(http.StatusOK, result)
}

// MFAEnrollRequest is the JSON body for POST /api/v1/auth/login/mfa/enroll.
type MFAEnrollRequest struct {
	EnrollmentToken string `json:"enrollment_token"`
}

// MFAEnrollPending handles POST /api/v1/auth/login/mfa/enroll — forced MFA
// enrollment for applications whose MFA mode is 'required'.
//
// @Summary      Begin forced MFA enrollment
// @Description  Exchanges the enrollment token returned by a login against a 'required'-MFA application for a TOTP secret (otpauth:// URI + backup codes). The token authorizes only this call and /auth/login/mfa/activate; no JWT is issued until activation completes.
// @Tags         AUTH
// @Accept       json
// @Produce      json
// @Param        body  body      MFAEnrollRequest  true  "Enrollment token from the login response"
// @Success      200   {object}  auth.EnrollResult
// @Failure      400   {object}  map[string]string
// @Failure      401   {object}  map[string]string  "Invalid or expired enrollment token"
// @Router       /api/v1/auth/login/mfa/enroll [post]
func (h *AuthHandler) MFAEnrollPending(c echo.Context) error {
	var req MFAEnrollRequest
	if err := c.Bind(&req); err != nil || req.EnrollmentToken == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "enrollment_token is required"})
	}

	result, session, err := h.svc.EnrollPending(c.Request().Context(), req.EnrollmentToken)
	if err != nil {
		h.logger.Warn().Err(err).Msg("pending MFA enroll failed")
		if containsMsg(err, "not configured") {
			return c.JSON(http.StatusNotImplemented, map[string]string{"error": "TOTP not configured on this server"})
		}
		if containsMsg(err, "invalid or expired") {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid or expired enrollment token"})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "MFA enrollment failed"})
	}

	h.auditEvent(c, audit.Event{
		TenantID:      &session.TenantID,
		UserID:        &session.UserID,
		ApplicationID: appIDFromClaim(session.AppID),
		ActorEmail:    session.Email,
		Action:        audit.ActionAuthMFAEnrolled,
		AuthMethod:    audit.AuthMethodTOTP,
		ResourceType:  "user",
		IPAddress:     c.RealIP(),
		UserAgent:     c.Request().UserAgent(),
	})

	return c.JSON(http.StatusOK, result)
}

// MFAActivateRequest is the JSON body for POST /api/v1/auth/login/mfa/activate.
type MFAActivateRequest struct {
	EnrollmentToken string `json:"enrollment_token"`
	Code            string `json:"code"`
}

// MFAActivatePending handles POST /api/v1/auth/login/mfa/activate — verifies
// the first TOTP code of a forced enrollment and completes the pending login.
//
// @Summary      Activate forced MFA enrollment and complete login
// @Description  Verifies the first TOTP code for a pending enrollment, marks MFA active, and completes the login in the same step — the response carries the token pair. 5 incorrect codes invalidate the enrollment session.
// @Tags         AUTH
// @Accept       json
// @Produce      json
// @Param        body  body      MFAActivateRequest  true  "Enrollment token + first TOTP code"
// @Success      200   {object}  auth.AuthResult
// @Failure      400   {object}  map[string]string
// @Failure      401   {object}  map[string]string  "Invalid code or expired enrollment token"
// @Failure      429   {object}  map[string]string  "Attempt budget exhausted — restart login"
// @Router       /api/v1/auth/login/mfa/activate [post]
func (h *AuthHandler) MFAActivatePending(c echo.Context) error {
	var req MFAActivateRequest
	if err := c.Bind(&req); err != nil || req.EnrollmentToken == "" || req.Code == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "enrollment_token and code are required"})
	}

	result, session, err := h.svc.ActivatePending(c.Request().Context(), req.EnrollmentToken, req.Code)
	if err != nil {
		h.logger.Warn().Err(err).Msg("pending MFA activate failed")
		event := audit.Event{
			Action:       audit.ActionAuthMFAChallengeFailed,
			AuthMethod:   audit.AuthMethodTOTP,
			ResourceType: "user",
			IPAddress:    c.RealIP(),
			UserAgent:    c.Request().UserAgent(),
			Metadata:     map[string]any{"phase": "enrollment"},
		}
		if session != nil {
			event.TenantID, event.UserID, event.ActorEmail = &session.TenantID, &session.UserID, session.Email
			event.ApplicationID = appIDFromClaim(session.AppID)
		}
		h.auditFailure(c, event, err)

		if errors.Is(err, auth.ErrTooManyOTPAttempts) {
			return c.JSON(http.StatusTooManyRequests, map[string]string{"error": err.Error()})
		}
		if containsMsg(err, "not configured") {
			return c.JSON(http.StatusNotImplemented, map[string]string{"error": "TOTP not configured on this server"})
		}
		if containsMsg(err, "invalid TOTP") || containsMsg(err, "invalid or expired") {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid code or expired enrollment token"})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "MFA activation failed"})
	}

	h.auditEvent(c, audit.Event{
		TenantID:      &session.TenantID,
		UserID:        &session.UserID,
		ApplicationID: appIDFromClaim(session.AppID),
		ActorEmail:    session.Email,
		Action:        audit.ActionAuthMFAActivated,
		AuthMethod:    audit.AuthMethodTOTP,
		ResourceType:  "user",
		IPAddress:     c.RealIP(),
		UserAgent:     c.Request().UserAgent(),
	})
	h.auditEvent(c, audit.Event{
		TenantID:      &session.TenantID,
		UserID:        &session.UserID,
		ApplicationID: appIDFromClaim(session.AppID),
		ActorEmail:    session.Email,
		Action:        audit.ActionAuthLogin,
		AuthMethod:    audit.AuthMethodTOTP,
		ResourceType:  "user",
		IPAddress:     c.RealIP(),
		UserAgent:     c.Request().UserAgent(),
	})

	setAuthCookies(c, result.AccessToken, result.RefreshToken, h.cookieCfg)
	return c.JSON(http.StatusOK, result)
}

// Me handles GET /api/v1/auth/me.
//
// @Summary      Get current user profile
// @Description  Returns the authenticated user's profile decoded from the JWT.
// @Tags         AUTH
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  auth.MeResult
// @Failure      401  {object}  map[string]string
// @Router       /api/v1/auth/me [get]
func (h *AuthHandler) Me(c echo.Context) error {
	claims, ok := c.Get("user").(*auth.Claims)
	if !ok || claims == nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	return c.JSON(http.StatusOK, h.svc.Me(claims))
}

// appClientAuthHeader carries the calling application's credentials on endpoints
// that ALSO require a user Bearer token.
//
// Why a second header rather than Authorization: one header cannot hold two
// credentials, and Bearer has to stay in Authorization because that is where
// every HTTP client, proxy, and JWT library expects it. The value format is
// identical to the Authorization: Basic used by every other /apps/* route
// (base64(client_id:client_secret)) and is parsed by the same code, so this adds
// a header name, not a third credential scheme.
//
// Aliased from the middleware package rather than redeclared: the per-application
// rate limiters read the same header to find the client_id, and a limiter reading
// a different header than this parser is a limiter that does nothing.
const appClientAuthHeader = mw.ClientAuthHeader

// AppMe handles GET /api/v1/auth/apps/me (issue #96).
//
// The app-scoped counterpart to Me. It answers a question Me structurally
// cannot: "was this token issued for the application that is asking?"
//
// Me is gated only on signature, tenant, expiry, and audience. It carries no
// client credential, so the server has nothing to compare the token's app_id
// claim against — it cannot know who is asking. Me also legitimately serves
// admin and browser sessions, which have an empty app_id by design, so it cannot
// be tightened without breaking the admin console. Hence a separate endpoint;
// Me is left untouched.
//
// Before this, enforcement lived in each consumer's own middleware as an opt-in
// local check (`decodeJwt(token).app_id === MY_APP_ID`). That is the kind of
// control a new consumer silently omits, that cannot be audited centrally, and
// that we could not assert was in place — because it wasn't, on our side.
//
// Token verification is inherited from the jwtRenew middleware this route is
// mounted behind — the same middleware Me uses — so signature, algorithm,
// issuer, expiry, and tenant are already enforced by the time this runs.
// #84's audience machinery (VerifyForAudience / AudienceAPI) does not exist
// in this codebase yet, so this handler cannot lean on it; the Role=="service"
// check below is the interim substitute for rejecting non-user tokens until
// that lands. This handler adds two things: the non-user-token check and the
// app boundary.
//
// Every rejection returns the same generic 401. Following #84's no-oracle
// philosophy, a caller must not be able to distinguish "wrong application" from
// "bad client secret" from "expired token" — otherwise the endpoint becomes a
// probe for which application a token belongs to. The jwtRenew middleware this
// route is mounted behind is wrapped in NormalizeAppScopeUnauthorized (see
// routes.go) so that an expired-token rejection there ALSO comes back as the
// same generic token_invalid, not jwtRenew's usual token_expired.
//
// @Summary      Current user, scoped to the calling application
// @Description  Same payload as GET /auth/me, but additionally proves the token was issued FOR the calling application. Requires a user Bearer token in Authorization AND the application's credentials in X-Client-Authorization. Rejects app-scoped tokens belonging to a different application in the same tenant, and rejects first-party tokens (empty app_id).
// @Tags         AUTH
// @Security     BearerAuth
// @Produce      json
// @Param        Authorization          header  string  true  "Bearer <app-scoped end-user access token>"
// @Param        X-Client-Authorization  header  string  true  "Basic base64(client_id:client_secret)"
// @Success      200  {object}  auth.MeResult
// @Failure      401  {object}  map[string]string  "token_invalid — generic for every rejection reason"
// @Router       /api/v1/auth/apps/me [get]
func (h *AuthHandler) AppMe(c echo.Context) error {
	claims, ok := c.Get("user").(*auth.Claims)
	if !ok || claims == nil {
		return h.rejectAppScope(c, "unauthenticated", "missing_claims")
	}

	// Fail closed on non-user tokens. #84's audience machinery does not exist
	// yet (m2m/service tokens are signed with the SAME audience literal as
	// user login tokens — see IssueServiceToken), so audience alone cannot
	// distinguish them. Role can: "service" is the one fixed, reserved value
	// IssueServiceToken assigns machine clients, and no real user role is
	// ever named "service". Without this check, an m2m token minted for an
	// application (which DOES carry that application's real app_id) would
	// pass every check below and return a live user's payload shape for a
	// caller that is not a user at all.
	// Email is checked alongside Role as the general form of the same rule: this
	// endpoint answers "who is the signed-in person", so a token carrying no user
	// identity has no answer regardless of what its role happens to say. Every
	// path that mints a *Claims for a real person sets an email (registration
	// requires one; API-key tokens use name@apikey), so an empty one here means a
	// machine identity or a malformed token.
	//
	// Deliberately placed BEFORE client authentication: this token can never
	// succeed, so there is no reason to spend a DB round-trip authenticating the
	// caller first. The metric label is "unauthenticated" because at this point
	// that is simply true — the client has not been checked yet.
	if claims.Role == "service" || claims.Email == "" {
		return h.rejectAppScope(c, "unauthenticated", "not_a_user_token")
	}

	if h.appSvc == nil {
		// Misconfiguration, not a caller error — but fail closed rather than
		// serving an endpoint whose entire purpose is a check we cannot perform.
		h.logger.Error().Msg("apps/me: application service not configured — cannot enforce app scope")
		return h.rejectAppScope(c, "unauthenticated", "appsvc_unconfigured")
	}

	clientID, clientSecret, present, err := clientCredentialsFromHeader(c, appClientAuthHeader)
	if err != nil || !present {
		return h.rejectAppScope(c, "unauthenticated", "client_credentials_missing")
	}

	// Server-authoritative: the application is resolved from its own credentials
	// against oauth_clients, never from anything the caller asserts about itself.
	appTenantID, appRowID, err := h.appSvc.AuthenticateClient(c.Request().Context(), clientID, clientSecret)
	if err != nil {
		// clientID is deliberately NOT used as a metric label here — see
		// rejectAppScope. An unauthenticated value is attacker-chosen.
		return h.rejectAppScope(c, "unauthenticated", "client_auth_failed")
	}

	// From here the client is authenticated, so clientID is a known, bounded value
	// and safe to use as a label.

	// Fail closed on an empty app_id. This is the important one: first-party
	// admin and browser tokens carry an empty app_id by design, and they have no
	// business on an app-scoped endpoint. Treating empty as "matches anything"
	// would make this endpoint worse than useless — it would look enforced.
	if claims.AppID == "" {
		return h.rejectAppScope(c, clientID, "empty_app_id")
	}

	if claims.AppID != strconv.FormatInt(appRowID, 10) {
		// The core case: a token minted for application A presented by
		// application B in the same tenant.
		return h.rejectAppScope(c, clientID, "app_mismatch")
	}

	// Defence in depth. If the app matched, the tenant necessarily matches too —
	// an application belongs to exactly one tenant. Checking anyway means a future
	// bug that lets app ids collide across tenants cannot silently become a
	// cross-tenant hole.
	if claims.TenantID != strconv.FormatInt(appTenantID, 10) {
		h.logger.Error().
			Str("token_tenant", claims.TenantID).
			Int64("app_tenant", appTenantID).
			Msg("apps/me: app matched but tenant did not — invariant violated")
		return h.rejectAppScope(c, clientID, "tenant_mismatch")
	}

	return c.JSON(http.StatusOK, h.svc.Me(claims))
}

// rejectAppScope returns the single generic 401 used for every app-scope failure,
// recording the real reason where only operators can see it.
//
// clientLabel must be an AUTHENTICATED client_id, or the literal
// "unauthenticated". Prometheus labels are unbounded-cardinality by nature, so
// putting an attacker-supplied client_id in one lets anyone inflate the metric
// series count at will — a denial of service against our own monitoring. Bounding
// it to real applications plus one sentinel keeps cardinality at
// (number of applications + 1).
func (h *AuthHandler) rejectAppScope(c echo.Context, clientLabel, reason string) error {
	metrics.AppScopeRejections.WithLabelValues(clientLabel, reason).Inc()

	// Fire-and-forget: an audit failure must never change the auth outcome.
	if h.audit != nil {
		h.audit.Log(c.Request().Context(), audit.Event{
			Action:       "auth.app_scope_rejected",
			ResourceType: "application",
			ResourceID:   clientLabel,
			Status:       audit.StatusFailure,
			HTTPStatus:   http.StatusUnauthorized,
			IPAddress:    c.RealIP(),
			UserAgent:    c.Request().UserAgent(),
			Metadata:     map[string]any{"reason": reason},
		})
	}

	// Level by what the reason actually indicates, not by the fact that a request
	// was refused. Most rejections here are ordinary bad-request traffic — a
	// client that forgot a header, a caller whose session lapsed — and logging
	// those at Warn buries the ones that matter under volume an unauthenticated
	// caller controls. Warn stays for the reasons that describe a token being
	// used somewhere it was not issued for; Prometheus counts every reason
	// regardless, so nothing stops being observable.
	event := h.logger.Warn()
	switch reason {
	case "client_credentials_missing", "missing_claims", "not_a_user_token", "client_auth_failed":
		event = h.logger.Debug()
	}
	event.
		Str("client_id", clientLabel).
		Str("reason", reason).
		Msg("apps/me: app scope rejected")

	return c.JSON(http.StatusUnauthorized, map[string]string{
		"error": "invalid token",
		"code":  "token_invalid",
	})
}

// RefreshRequest is the JSON body for POST /api/v1/auth/refresh.
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// LogoutRequest is the JSON body for POST /api/v1/auth/logout.
type LogoutRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// Refresh handles POST /api/v1/auth/refresh (AUTH-03).
//
// @Summary      Refresh token rotation
// @Description  Issues a new access + refresh token pair and immediately invalidates the old refresh token.
// @Description  Body-based (mobile/API) clients must handle two additional responses that the cookie flow absorbs transparently:
// @Description  409 (`concurrent_refresh`) means a sibling request already rotated this token family within the grace window — this response carries NO token pair; the client should use the in-flight sibling's response rather than treating 409 as an error.
// @Description  503 means the session store (Redis) is temporarily unavailable — the client should retry.
// @Tags         AUTH
// @Accept       json
// @Produce      json
// @Param        body  body      RefreshRequest  true  "Refresh token"
// @Success      200   {object}  auth.AuthResult
// @Failure      400   {object}  map[string]string
// @Failure      401   {object}  map[string]string
// @Failure      409   {object}  map[string]string  "concurrent_refresh — sibling request already rotated the family; no token pair returned"
// @Failure      503   {object}  map[string]string  "session store unavailable — retry"
// @Router       /api/v1/auth/refresh [post]
func (h *AuthHandler) Refresh(c echo.Context) error {
	var req RefreshRequest
	_ = c.Bind(&req) // body is optional — cookie is the fallback

	// Accept refresh token from cookie when the body doesn't supply one.
	if req.RefreshToken == "" {
		if cookie, err := c.Cookie(mw.RefreshTokenCookie); err == nil && cookie.Value != "" {
			req.RefreshToken = cookie.Value
		}
	}
	if req.RefreshToken == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "refresh token missing"})
	}

	result, grace, err := h.svc.RefreshWithLock(c.Request().Context(), req.RefreshToken, h.redisCli)
	if err != nil {
		h.logger.Warn().Err(err).Msg("refresh failed")
		action := audit.ActionAuthTokenRefreshFailed
		if errors.Is(err, auth.ErrTokenReplay) {
			action = audit.ActionAuthReplayDetected
		}
		ev := audit.Event{
			Action:       action,
			AuthMethod:   audit.AuthMethodRefreshToken,
			ResourceType: "session",
			IPAddress:    c.RealIP(),
			UserAgent:    c.Request().UserAgent(),
		}
		attachTokenOwner(c.Request().Context(), &ev, h.svc, req.RefreshToken)
		h.auditFailure(c, ev, err)
		if errors.Is(err, auth.ErrTokenReplay) {
			clearAuthCookies(c, h.cookieCfg)
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "session terminated — security event detected"})
		}
		if errors.Is(err, auth.ErrInvalidRefreshToken) {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid or expired refresh token"})
		}
		if errors.Is(err, auth.ErrServiceUnavailable) {
			return c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "service temporarily unavailable — please retry"})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "token refresh failed"})
	}

	// A concurrent request already rotated this token family within the grace
	// window. There is no fresh token pair to hand back to this caller — the
	// sibling request's response carries the new tokens. Signal the collision
	// so the client uses that pair rather than treating this as an error.
	if grace != nil {
		return c.JSON(http.StatusConflict, map[string]string{
			"error": "refresh already completed by a concurrent request",
			"code":  "concurrent_refresh",
		})
	}

	tid, uid, appID := claimsFromToken(result.AccessToken)
	h.auditEvent(c, audit.Event{
		TenantID:      tid,
		UserID:        uid,
		ApplicationID: appID,
		Action:        audit.ActionAuthTokenRefresh,
		AuthMethod:    audit.AuthMethodRefreshToken,
		ResourceType:  "session",
		IPAddress:     c.RealIP(),
		UserAgent:     c.Request().UserAgent(),
	})

	setAuthCookies(c, result.AccessToken, result.RefreshToken, h.cookieCfg)
	return c.JSON(http.StatusOK, map[string]interface{}{
		"message":    "session refreshed",
		"expires_in": result.ExpiresIn,
		"expires_at": result.ExpiresAt,
	})
}

// Logout handles POST /api/v1/auth/logout (AUTH-04).
//
// @Summary      Logout
// @Description  Revokes the supplied refresh token. Idempotent — calling twice is safe.
// @Tags         AUTH
// @Accept       json
// @Produce      json
// @Param        body  body      LogoutRequest  true  "Refresh token to revoke"
// @Success      200   {object}  map[string]string
// @Failure      400   {object}  map[string]string
// @Router       /api/v1/auth/logout [post]
func (h *AuthHandler) Logout(c echo.Context) error {
	var req LogoutRequest
	_ = c.Bind(&req) // body is optional — cookie is the fallback

	// Accept refresh token from cookie when the body doesn't supply one.
	if req.RefreshToken == "" {
		if cookie, err := c.Cookie(mw.RefreshTokenCookie); err == nil && cookie.Value != "" {
			req.RefreshToken = cookie.Value
		}
	}

	if req.RefreshToken == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "refresh_token is required"})
	}

	if err := h.svc.Logout(c.Request().Context(), req.RefreshToken); err != nil {
		h.logger.Error().Err(err).Msg("logout failed")
	}

	clearAuthCookies(c, h.cookieCfg)

	ev := audit.Event{
		Action:       audit.ActionAuthLogout,
		AuthMethod:   audit.AuthMethodRefreshToken,
		ResourceType: "session",
		IPAddress:    c.RealIP(),
		UserAgent:    c.Request().UserAgent(),
	}
	// Attribute the logout to the token's owner (resolves even though it was just
	// revoked); an unknown token leaves it anonymous.
	attachTokenOwner(c.Request().Context(), &ev, h.svc, req.RefreshToken)
	h.auditEvent(c, ev)

	return c.JSON(http.StatusOK, map[string]string{"message": "logged out"})
}

// ForgotPasswordRequest is the JSON body for POST /api/v1/auth/forgot-password.
type ForgotPasswordRequest struct {
	Email string `json:"email"`
}

// ForgotPassword handles POST /api/v1/auth/forgot-password (RESET-01, RESET-03).
//
// @Summary      Request password reset
// @Description  Sends a reset link to the email address for the authenticated application's user. The application authenticates with Authorization: Basic base64(client_id:client_secret) — this identifies both the tenant and application, scoping the reset to that app's account. ALWAYS returns 200 for a valid client regardless of whether the email is registered (prevents email enumeration).
// @Tags         AUTH
// @Accept       json
// @Produce      json
// @Param        Authorization  header    string                 true  "Basic base64(client_id:client_secret)"
// @Param        body           body      ForgotPasswordRequest  true  "Email address"
// @Success      200            {object}  map[string]string
// @Failure      401            {object}  map[string]string  "Invalid client credentials"
// @Router       /api/v1/auth/forgot-password [post]
func (h *AuthHandler) ForgotPassword(c echo.Context) error {
	genericOK := map[string]string{
		"message": "if that email address is registered, a password reset link has been sent",
	}

	// Authenticate the requesting application via client_id/client_secret. This
	// identifies the tenant + application, scoping the reset to that app's user.
	id, secret, ok, err := clientCredentialsFromBasicAuth(c)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Authorization: Basic base64(client_id:client_secret) header is required"})
	}
	if h.appSvc == nil {
		return c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "application service not configured"})
	}

	tenantID, appID, err := h.appSvc.AuthenticateClient(c.Request().Context(), id, secret)
	if err != nil {
		// Do not reveal whether the client_id exists or the secret was wrong —
		// return the same generic 200 as an unknown email, extending the
		// enumeration protection (RESET-03) to the client credential check.
		if !errors.Is(err, auth.ErrInvalidClient) {
			h.logger.Error().Err(err).Msg("forgot-password: client authentication failed")
		}
		return c.JSON(http.StatusOK, genericOK)
	}

	var req ForgotPasswordRequest
	if err := c.Bind(&req); err != nil || req.Email == "" {
		return c.JSON(http.StatusOK, genericOK)
	}

	if err := h.resetSvc.ForgotPassword(c.Request().Context(), tenantID, &appID, req.Email); err != nil {
		h.logger.Error().Err(err).Msg("forgot-password: unexpected service error")
	}

	h.auditEvent(c, audit.Event{
		TenantID:      &tenantID,
		ApplicationID: &appID,
		ActorEmail:    req.Email,
		Action:        audit.ActionAuthPasswordResetReq,
		ResourceType:  "user",
		IPAddress:     c.RealIP(),
		UserAgent:     c.Request().UserAgent(),
	})

	return c.JSON(http.StatusOK, genericOK)
}

// ResetPasswordRequest is the JSON body for POST /api/v1/auth/reset-password.
type ResetPasswordRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

// ResetPassword handles POST /api/v1/auth/reset-password (RESET-02).
//
// @Summary      Reset password
// @Description  Validates the reset token, updates the user's password, and revokes all active refresh tokens.
// @Tags         AUTH
// @Accept       json
// @Produce      json
// @Param        body  body      ResetPasswordRequest  true  "Token + new password"
// @Success      200   {object}  map[string]string
// @Failure      400   {object}  map[string]string
// @Router       /api/v1/auth/reset-password [post]
func (h *AuthHandler) ResetPassword(c echo.Context) error {
	var req ResetPasswordRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}
	if req.Token == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "token is required"})
	}
	if req.NewPassword == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "new_password is required"})
	}

	err := h.resetSvc.ResetPassword(c.Request().Context(), auth.ResetPasswordInput{
		RawToken:    req.Token,
		NewPassword: req.NewPassword,
	})
	if err != nil {
		if errors.Is(err, auth.ErrInvalidResetToken) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid or expired reset token"})
		}
		if containsMsg(err, "at least 8 characters") {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "password must be at least 8 characters"})
		}
		h.logger.Error().Err(err).Msg("reset-password failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "password reset failed"})
	}

	h.auditEvent(c, audit.Event{
		Action:       audit.ActionAuthPasswordResetDone,
		ResourceType: "user",
		IPAddress:    c.RealIP(),
		UserAgent:    c.Request().UserAgent(),
	})

	return c.JSON(http.StatusOK, map[string]string{"message": "password updated successfully"})
}

// â”€â”€â”€ TOTP Handlers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

// TOTPEnrollRequest is the (optional) JSON body for POST /api/v1/auth/otp/enroll.
// Code is only required when the caller already has an ACTIVE enrollment and
// is rotating it (new phone): a valid current TOTP or backup code proves
// control of the existing second factor.
type TOTPEnrollRequest struct {
	Code string `json:"code"`
}

// TOTPEnroll handles POST /api/v1/auth/otp/enroll.
//
// @Summary      Enroll in TOTP 2FA
// @Description  Generates a TOTP secret and returns an otpauth:// URI plus backup codes. The authenticator issuer is the owning application's name for application-scoped users. Rejected when the application's MFA mode is 'disabled'. Re-enrolling while active requires a valid current TOTP or backup code in the body.
// @Tags         AUTH
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body  body      TOTPEnrollRequest  false  "Current code (required only when re-enrolling)"
// @Success      200  {object}  auth.EnrollResult
// @Failure      401  {object}  map[string]string
// @Failure      403  {object}  map[string]string  "MFA disabled for this application, or missing re-enrollment proof"
// @Router       /api/v1/auth/otp/enroll [post]
func (h *AuthHandler) TOTPEnroll(c echo.Context) error {
	if h.totpSvc == nil {
		return c.JSON(http.StatusNotImplemented, map[string]string{"error": "TOTP not configured on this server"})
	}
	claims, ok := c.Get("user").(*auth.Claims)
	if !ok || claims == nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}

	userID, err := strconv.ParseInt(claims.UserID, 10, 64)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid user_id in token"})
	}
	tenantID, err := strconv.ParseInt(claims.TenantID, 10, 64)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid tenant_id in token"})
	}

	var req TOTPEnrollRequest
	_ = c.Bind(&req) // body is optional — only needed as re-enrollment proof

	result, err := h.totpSvc.EnrollUser(c.Request().Context(), userID, tenantID, claims.Email, req.Code)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrMFAEnrollmentDisabled), errors.Is(err, auth.ErrTOTPReenrollProof):
			return c.JSON(http.StatusForbidden, map[string]string{"error": err.Error()})
		case errors.Is(err, auth.ErrUserNotFound):
			return c.JSON(http.StatusNotFound, map[string]string{"error": "user not found"})
		}
		h.logger.Error().Err(err).Str("user_id", claims.UserID).Msg("TOTP enroll failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "TOTP enrollment failed"})
	}

	h.auditEvent(c, audit.Event{
		TenantID:     &tenantID,
		UserID:       &userID,
		ActorEmail:   claims.Email,
		Action:       audit.ActionAuthMFAEnrolled,
		ResourceType: "user",
		IPAddress:    c.RealIP(),
		UserAgent:    c.Request().UserAgent(),
	})

	return c.JSON(http.StatusOK, result)
}

// TOTPActivateRequest is the JSON body for POST /api/v1/auth/otp/activate.
type TOTPActivateRequest struct {
	Code string `json:"code"`
}

// TOTPActivate handles POST /api/v1/auth/otp/activate.
//
// @Summary      Activate TOTP 2FA
// @Description  Verifies the first TOTP code and marks the enrollment active.
// @Tags         AUTH
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body  body      TOTPActivateRequest  true  "First TOTP code"
// @Success      200   {object}  map[string]string
// @Failure      400   {object}  map[string]string
// @Router       /api/v1/auth/otp/activate [post]
func (h *AuthHandler) TOTPActivate(c echo.Context) error {
	if h.totpSvc == nil {
		return c.JSON(http.StatusNotImplemented, map[string]string{"error": "TOTP not configured on this server"})
	}
	claims, ok := c.Get("user").(*auth.Claims)
	if !ok || claims == nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}

	var req TOTPActivateRequest
	if err := c.Bind(&req); err != nil || req.Code == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "code is required"})
	}

	userID, _ := strconv.ParseInt(claims.UserID, 10, 64)
	if err := h.totpSvc.VerifyAndActivate(c.Request().Context(), userID, req.Code); err != nil {
		if containsMsg(err, "invalid TOTP") {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid TOTP code — check your authenticator app"})
		}
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	tenantID, _ := strconv.ParseInt(claims.TenantID, 10, 64)
	h.auditEvent(c, audit.Event{
		TenantID:     &tenantID,
		UserID:       &userID,
		ActorEmail:   claims.Email,
		Action:       audit.ActionAuthMFAActivated,
		ResourceType: "user",
		IPAddress:    c.RealIP(),
		UserAgent:    c.Request().UserAgent(),
	})

	return c.JSON(http.StatusOK, map[string]string{"message": "TOTP 2FA activated successfully"})
}

// TOTPStatus handles GET /api/v1/auth/otp/status.
//
// @Summary      Get own MFA status
// @Description  Returns the authenticated user's TOTP enrollment state and how many single-use backup codes remain — clients should prompt regeneration when the count runs low.
// @Tags         AUTH
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  auth.TOTPStatus
// @Failure      401  {object}  map[string]string
// @Router       /api/v1/auth/otp/status [get]
func (h *AuthHandler) TOTPStatus(c echo.Context) error {
	if h.totpSvc == nil {
		return c.JSON(http.StatusNotImplemented, map[string]string{"error": "TOTP not configured on this server"})
	}
	claims, ok := c.Get("user").(*auth.Claims)
	if !ok || claims == nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}

	userID, err := strconv.ParseInt(claims.UserID, 10, 64)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid user_id in token"})
	}

	status, err := h.totpSvc.Status(c.Request().Context(), userID)
	if err != nil {
		h.logger.Error().Err(err).Str("user_id", claims.UserID).Msg("TOTP status failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to load MFA status"})
	}

	if h.emailSvc != nil {
		emailActive, err := h.emailSvc.IsActive(c.Request().Context(), userID)
		if err != nil {
			h.logger.Error().Err(err).Str("user_id", claims.UserID).Msg("email MFA status failed")
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to load MFA status"})
		}
		status.EmailActive = emailActive
	}
	return c.JSON(http.StatusOK, status)
}

// TOTPRegenerateCodesRequest is the JSON body for POST /api/v1/auth/otp/backup-codes.
type TOTPRegenerateCodesRequest struct {
	Code string `json:"code"`
}

// TOTPRegenerateCodes handles POST /api/v1/auth/otp/backup-codes.
//
// @Summary      Regenerate backup codes
// @Description  Replaces all remaining backup codes with a fresh set of 8 WITHOUT rotating the TOTP secret — the authenticator app keeps working. Requires a valid current TOTP or backup code. Every previous backup code is invalidated; the new plaintext codes are shown exactly once.
// @Tags         AUTH
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body  body      TOTPRegenerateCodesRequest  true  "Current TOTP or backup code"
// @Success      200   {object}  map[string][]string
// @Failure      400   {object}  map[string]string
// @Failure      403   {object}  map[string]string  "Missing or invalid proof code"
// @Router       /api/v1/auth/otp/backup-codes [post]
func (h *AuthHandler) TOTPRegenerateCodes(c echo.Context) error {
	if h.totpSvc == nil {
		return c.JSON(http.StatusNotImplemented, map[string]string{"error": "TOTP not configured on this server"})
	}
	claims, ok := c.Get("user").(*auth.Claims)
	if !ok || claims == nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}

	var req TOTPRegenerateCodesRequest
	if err := c.Bind(&req); err != nil || req.Code == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "code is required to regenerate backup codes"})
	}

	userID, _ := strconv.ParseInt(claims.UserID, 10, 64)
	codes, err := h.totpSvc.RegenerateBackupCodes(c.Request().Context(), userID, req.Code)
	if err != nil {
		if errors.Is(err, auth.ErrTOTPProofRequired) {
			return c.JSON(http.StatusForbidden, map[string]string{"error": err.Error()})
		}
		if containsMsg(err, "not active") || containsMsg(err, "no TOTP enrollment") {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "TOTP is not active for this account"})
		}
		h.logger.Error().Err(err).Str("user_id", claims.UserID).Msg("TOTP backup code regeneration failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to regenerate backup codes"})
	}

	tenantID, _ := strconv.ParseInt(claims.TenantID, 10, 64)
	h.auditEvent(c, audit.Event{
		TenantID:     &tenantID,
		UserID:       &userID,
		ActorEmail:   claims.Email,
		Action:       audit.ActionAuthMFACodesRegenerated,
		ResourceType: "user",
		IPAddress:    c.RealIP(),
		UserAgent:    c.Request().UserAgent(),
	})

	return c.JSON(http.StatusOK, map[string][]string{"backup_codes": codes})
}

// ─── Email MFA Handlers (issue #63) ─────────────────────────────────────────

// mfaClaimIDs extracts the numeric user and tenant ids from JWT claims.
func mfaClaimIDs(c echo.Context) (claims *auth.Claims, userID, tenantID int64, ok bool) {
	claims, valid := c.Get("user").(*auth.Claims)
	if !valid || claims == nil {
		return nil, 0, 0, false
	}
	userID, err := strconv.ParseInt(claims.UserID, 10, 64)
	if err != nil {
		return nil, 0, 0, false
	}
	tenantID, err = strconv.ParseInt(claims.TenantID, 10, 64)
	if err != nil {
		return nil, 0, 0, false
	}
	return claims, userID, tenantID, true
}

// auditMFA logs an MFA lifecycle event for the authenticated user.
func (h *AuthHandler) auditMFA(c echo.Context, tenantID, userID int64, email, action string) {
	h.auditEvent(c, audit.Event{
		TenantID:     &tenantID,
		UserID:       &userID,
		ActorEmail:   email,
		Action:       action,
		ResourceType: "user",
		IPAddress:    c.RealIP(),
		UserAgent:    c.Request().UserAgent(),
	})
}

// emailMFAErrorResponse maps EmailMFAService errors onto HTTP responses.
func emailMFAErrorResponse(c echo.Context, err error) error {
	switch {
	case errors.Is(err, auth.ErrMFAEnrollmentDisabled), errors.Is(err, auth.ErrMFAMethodNotAllowed), errors.Is(err, auth.ErrMFARequiredByPolicy):
		return c.JSON(http.StatusForbidden, map[string]string{"error": err.Error()})
	case errors.Is(err, auth.ErrTooManyOTPAttempts), errors.Is(err, auth.ErrTooManyResends):
		return c.JSON(http.StatusTooManyRequests, map[string]string{"error": err.Error()})
	case errors.Is(err, auth.ErrEmailCodeInvalid):
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": err.Error()})
	case errors.Is(err, auth.ErrEmailMFANotActive):
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	case errors.Is(err, auth.ErrUserNotFound):
		return c.JSON(http.StatusNotFound, map[string]string{"error": "user not found"})
	}
	return nil
}

// EmailMFAEnroll handles POST /api/v1/auth/otp/email/enroll.
//
// @Summary      Enroll in email MFA
// @Description  Starts email-OTP enrollment: sends a verification code to the account's email address. Activate with POST /auth/otp/email/activate. Rejected when the application's MFA mode is 'disabled' or its policy does not allow the email method.
// @Tags         AUTH
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      403  {object}  map[string]string  "MFA disabled or email method not allowed for this application"
// @Router       /api/v1/auth/otp/email/enroll [post]
func (h *AuthHandler) EmailMFAEnroll(c echo.Context) error {
	if h.emailSvc == nil {
		return c.JSON(http.StatusNotImplemented, map[string]string{"error": "email MFA not configured on this server"})
	}
	claims, userID, tenantID, ok := mfaClaimIDs(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}

	if err := h.emailSvc.BeginEnrollment(c.Request().Context(), userID, tenantID, claims.Email); err != nil {
		if resp := emailMFAErrorResponse(c, err); resp != nil {
			return resp
		}
		h.logger.Error().Err(err).Str("user_id", claims.UserID).Msg("email MFA enroll failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "email MFA enrollment failed"})
	}

	h.auditMFA(c, tenantID, userID, claims.Email, audit.ActionAuthMFAEmailEnrolled)
	return c.JSON(http.StatusOK, map[string]string{"message": "verification code sent — confirm with POST /auth/otp/email/activate"})
}

// EmailMFACodeRequest is the JSON body for the email-MFA code endpoints.
type EmailMFACodeRequest struct {
	Code string `json:"code"`
}

// EmailMFAActivate handles POST /api/v1/auth/otp/email/activate.
//
// @Summary      Activate email MFA
// @Description  Verifies the emailed code and marks email MFA active. From then on, logins are challenged with a one-time code sent to the account's inbox.
// @Tags         AUTH
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body  body      EmailMFACodeRequest  true  "Emailed verification code"
// @Success      200   {object}  map[string]string
// @Failure      400   {object}  map[string]string
// @Failure      401   {object}  map[string]string  "Invalid or expired code"
// @Failure      429   {object}  map[string]string  "Attempt budget exhausted"
// @Router       /api/v1/auth/otp/email/activate [post]
func (h *AuthHandler) EmailMFAActivate(c echo.Context) error {
	if h.emailSvc == nil {
		return c.JSON(http.StatusNotImplemented, map[string]string{"error": "email MFA not configured on this server"})
	}
	claims, userID, tenantID, ok := mfaClaimIDs(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}

	var req EmailMFACodeRequest
	if err := c.Bind(&req); err != nil || req.Code == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "code is required"})
	}

	if err := h.emailSvc.ActivateEnrollment(c.Request().Context(), userID, req.Code); err != nil {
		if resp := emailMFAErrorResponse(c, err); resp != nil {
			return resp
		}
		h.logger.Error().Err(err).Str("user_id", claims.UserID).Msg("email MFA activate failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "email MFA activation failed"})
	}

	h.auditMFA(c, tenantID, userID, claims.Email, audit.ActionAuthMFAEmailActivated)
	return c.JSON(http.StatusOK, map[string]string{"message": "email MFA activated successfully"})
}

// EmailMFASendCode handles POST /api/v1/auth/otp/email/send.
//
// @Summary      Send an email MFA verification code
// @Description  Sends a fresh one-time code to the account's inbox for an already-active email MFA enrollment — used as proof for self-service actions such as disabling email MFA.
// @Tags         AUTH
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  map[string]string
// @Failure      400  {object}  map[string]string  "Email MFA not active"
// @Failure      401  {object}  map[string]string
// @Router       /api/v1/auth/otp/email/send [post]
func (h *AuthHandler) EmailMFASendCode(c echo.Context) error {
	if h.emailSvc == nil {
		return c.JSON(http.StatusNotImplemented, map[string]string{"error": "email MFA not configured on this server"})
	}
	claims, userID, tenantID, ok := mfaClaimIDs(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}

	if err := h.emailSvc.SendVerificationCode(c.Request().Context(), userID, tenantID, claims.Email); err != nil {
		if resp := emailMFAErrorResponse(c, err); resp != nil {
			return resp
		}
		h.logger.Error().Err(err).Str("user_id", claims.UserID).Msg("email MFA send failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to send verification code"})
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "verification code sent"})
}

// EmailMFADisable handles DELETE /api/v1/auth/otp/email.
//
// @Summary      Disable email MFA
// @Description  Disables email MFA for the current user. Requires a fresh emailed code (request one via POST /auth/otp/email/send). Rejected when it is the user's last second factor under a 'required' application policy.
// @Tags         AUTH
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body  body      EmailMFACodeRequest  true  "Emailed verification code"
// @Success      200   {object}  map[string]string
// @Failure      400   {object}  map[string]string
// @Failure      401   {object}  map[string]string  "Invalid or expired code"
// @Failure      403   {object}  map[string]string  "MFA is required by the application's policy"
// @Router       /api/v1/auth/otp/email [delete]
func (h *AuthHandler) EmailMFADisable(c echo.Context) error {
	if h.emailSvc == nil {
		return c.JSON(http.StatusNotImplemented, map[string]string{"error": "email MFA not configured on this server"})
	}
	claims, userID, tenantID, ok := mfaClaimIDs(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}

	var req EmailMFACodeRequest
	if err := c.Bind(&req); err != nil || req.Code == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "code is required to disable email MFA"})
	}

	if err := h.emailSvc.Disable(c.Request().Context(), userID, tenantID, req.Code); err != nil {
		if resp := emailMFAErrorResponse(c, err); resp != nil {
			return resp
		}
		h.logger.Error().Err(err).Str("user_id", claims.UserID).Msg("email MFA disable failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to disable email MFA"})
	}

	h.auditMFA(c, tenantID, userID, claims.Email, audit.ActionAuthMFAEmailDisabled)
	return c.JSON(http.StatusOK, map[string]string{"message": "email MFA disabled"})
}

// LoginOTPResendRequest is the JSON body for POST /api/v1/auth/login/otp/resend.
type LoginOTPResendRequest struct {
	OTPSessionToken string `json:"otp_session_token"`
}

// LoginOTPResend handles POST /api/v1/auth/login/otp/resend — re-sends the
// emailed code for an open login challenge.
//
// @Summary      Resend login email code
// @Description  Re-sends the one-time email code for an open OTP challenge (max 3 re-sends per challenge). Only available when the challenge's methods include "email".
// @Tags         AUTH
// @Accept       json
// @Produce      json
// @Param        body  body      LoginOTPResendRequest  true  "OTP session token"
// @Success      200   {object}  map[string]string
// @Failure      400   {object}  map[string]string
// @Failure      401   {object}  map[string]string  "Invalid or expired session"
// @Failure      429   {object}  map[string]string  "Re-send budget exhausted"
// @Router       /api/v1/auth/login/otp/resend [post]
func (h *AuthHandler) LoginOTPResend(c echo.Context) error {
	var req LoginOTPResendRequest
	if err := c.Bind(&req); err != nil || req.OTPSessionToken == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "otp_session_token is required"})
	}

	if err := h.svc.ResendLoginOTP(c.Request().Context(), req.OTPSessionToken); err != nil {
		h.logger.Warn().Err(err).Msg("login OTP resend failed")
		if errors.Is(err, auth.ErrTooManyResends) {
			return c.JSON(http.StatusTooManyRequests, map[string]string{"error": err.Error()})
		}
		if containsMsg(err, "not configured") {
			return c.JSON(http.StatusNotImplemented, map[string]string{"error": "email MFA not configured on this server"})
		}
		if containsMsg(err, "invalid or expired") {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid or expired OTP session"})
		}
		if containsMsg(err, "not an available method") {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to resend code"})
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "code sent"})
}

// MFAEmailPendingRequest is the JSON body for POST /api/v1/auth/login/mfa/email.
type MFAEmailPendingRequest struct {
	EnrollmentToken string `json:"enrollment_token"`
}

// MFAEmailPending handles POST /api/v1/auth/login/mfa/email — the EMAIL path
// of a forced enrollment.
//
// @Summary      Begin forced MFA enrollment via email
// @Description  Sends a one-time code to the pending account's inbox for a login against a 'required'-MFA application. Submitting that code to /auth/login/mfa/activate enrolls the user in email MFA and completes the login. Available only when the application's allowed_methods include "email".
// @Tags         AUTH
// @Accept       json
// @Produce      json
// @Param        body  body      MFAEmailPendingRequest  true  "Enrollment token from the login response"
// @Success      200   {object}  map[string]string
// @Failure      400   {object}  map[string]string
// @Failure      401   {object}  map[string]string  "Invalid or expired enrollment token"
// @Failure      403   {object}  map[string]string  "Email method not allowed for this application"
// @Failure      429   {object}  map[string]string  "Re-send budget exhausted"
// @Router       /api/v1/auth/login/mfa/email [post]
func (h *AuthHandler) MFAEmailPending(c echo.Context) error {
	var req MFAEmailPendingRequest
	if err := c.Bind(&req); err != nil || req.EnrollmentToken == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "enrollment_token is required"})
	}

	_, err := h.svc.SendPendingEnrollmentCode(c.Request().Context(), req.EnrollmentToken)
	if err != nil {
		h.logger.Warn().Err(err).Msg("pending email MFA send failed")
		if errors.Is(err, auth.ErrMFAMethodNotAllowed) {
			return c.JSON(http.StatusForbidden, map[string]string{"error": err.Error()})
		}
		if errors.Is(err, auth.ErrTooManyResends) {
			return c.JSON(http.StatusTooManyRequests, map[string]string{"error": err.Error()})
		}
		if containsMsg(err, "not configured") {
			return c.JSON(http.StatusNotImplemented, map[string]string{"error": "email MFA not configured on this server"})
		}
		if containsMsg(err, "invalid or expired") {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid or expired enrollment token"})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to send enrollment code"})
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "code sent — activate with POST /auth/login/mfa/activate"})
}

// TOTPDisableRequest is the JSON body for DELETE /api/v1/auth/otp.
type TOTPDisableRequest struct {
	Code string `json:"code"`
}

// TOTPDisable handles DELETE /api/v1/auth/otp.
//
// @Summary      Disable TOTP 2FA
// @Description  Disables TOTP for the current user. Requires a valid TOTP code or backup code. Rejected when the user's application has MFA mode 'required' — users cannot opt out of a mandated policy.
// @Tags         AUTH
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body  body      TOTPDisableRequest  true  "Current TOTP or backup code"
// @Success      200   {object}  map[string]string
// @Failure      400   {object}  map[string]string
// @Failure      403   {object}  map[string]string  "MFA is required by the application's policy"
// @Router       /api/v1/auth/otp [delete]
func (h *AuthHandler) TOTPDisable(c echo.Context) error {
	if h.totpSvc == nil {
		return c.JSON(http.StatusNotImplemented, map[string]string{"error": "TOTP not configured on this server"})
	}
	claims, ok := c.Get("user").(*auth.Claims)
	if !ok || claims == nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}

	var req TOTPDisableRequest
	if err := c.Bind(&req); err != nil || req.Code == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "code is required to disable 2FA"})
	}

	userID, _ := strconv.ParseInt(claims.UserID, 10, 64)
	tenantID, _ := strconv.ParseInt(claims.TenantID, 10, 64)
	if err := h.totpSvc.DisableUser(c.Request().Context(), userID, tenantID, req.Code); err != nil {
		if errors.Is(err, auth.ErrMFARequiredByPolicy) {
			return c.JSON(http.StatusForbidden, map[string]string{"error": err.Error()})
		}
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	h.auditEvent(c, audit.Event{
		TenantID:     &tenantID,
		UserID:       &userID,
		ActorEmail:   claims.Email,
		Action:       audit.ActionAuthMFADisabled,
		ResourceType: "user",
		IPAddress:    c.RealIP(),
		UserAgent:    c.Request().UserAgent(),
	})

	return c.JSON(http.StatusOK, map[string]string{"message": "TOTP 2FA disabled"})
}

// â”€â”€â”€ API Key Handlers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

// CreateAPIKeyRequest is the JSON body for POST /api/v1/admin/api-keys.
type CreateAPIKeyRequest struct {
	Name        string   `json:"name"`
	Permissions []string `json:"permissions"`
}

// CreateAPIKey handles POST /api/v1/admin/api-keys.
//
// @Summary      Create API key
// @Description  Creates a new API key for machine-to-machine auth. The raw key is returned exactly once.
// @Tags         api-keys
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body  body      CreateAPIKeyRequest  true  "Key name and permissions"
// @Success      201   {object}  auth.APIKeyResult
// @Failure      400   {object}  map[string]string
// @Router       /api/v1/api-keys [post]
func (h *AuthHandler) CreateAPIKey(c echo.Context) error {
	if h.apiKeySvc == nil {
		return c.JSON(http.StatusNotImplemented, map[string]string{"error": "API keys not configured"})
	}
	claims, ok := c.Get("user").(*auth.Claims)
	if !ok || claims == nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}

	var req CreateAPIKeyRequest
	if err := c.Bind(&req); err != nil || req.Name == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "name is required"})
	}

	tenantID, _ := strconv.ParseInt(claims.TenantID, 10, 64)
	result, err := h.apiKeySvc.CreateAPIKey(c.Request().Context(), tenantID, req.Name, req.Permissions)
	if err != nil {
		h.logger.Error().Err(err).Msg("create API key failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to create API key"})
	}

	h.auditEvent(c, audit.Event{
		TenantID:     &tenantID,
		UserID:       parseUserID(claims.UserID),
		ActorEmail:   claims.Email,
		Action:       audit.ActionAuthAPIKeyCreated,
		AuthMethod:   audit.AuthMethodAPIKey,
		ResourceType: "api_key",
		IPAddress:    c.RealIP(),
		UserAgent:    c.Request().UserAgent(),
		Metadata:     map[string]any{"name": req.Name, "permissions": req.Permissions},
	})

	return c.JSON(http.StatusCreated, result)
}

// ListAPIKeys handles GET /api/v1/admin/api-keys.
//
// @Summary      List API keys
// @Description  Returns all active API keys for the caller's tenant. The raw key is never included.
// @Tags         api-keys
// @Produce      json
// @Security     BearerAuth
// @Success      200  {array}   auth.APIKeySummary
// @Failure      401  {object}  map[string]string
// @Router       /api/v1/api-keys [get]
func (h *AuthHandler) ListAPIKeys(c echo.Context) error {
	if h.apiKeySvc == nil {
		return c.JSON(http.StatusNotImplemented, map[string]string{"error": "API keys not configured"})
	}
	claims, ok := c.Get("user").(*auth.Claims)
	if !ok || claims == nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}

	tenantID, _ := strconv.ParseInt(claims.TenantID, 10, 64)
	keys, err := h.apiKeySvc.ListAPIKeys(c.Request().Context(), tenantID)
	if err != nil {
		h.logger.Error().Err(err).Msg("list API keys failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to list API keys"})
	}

	return c.JSON(http.StatusOK, keys)
}

// RevokeAPIKey handles DELETE /api/v1/admin/api-keys/:id.
//
// @Summary      Revoke API key
// @Description  Permanently revokes an API key. The key is immediately invalid.
// @Tags         api-keys
// @Produce      json
// @Security     BearerAuth
// @Param        id   path      string  true  "API key ID"
// @Success      200  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /api/v1/api-keys/{id} [delete]
func (h *AuthHandler) RevokeAPIKey(c echo.Context) error {
	if h.apiKeySvc == nil {
		return c.JSON(http.StatusNotImplemented, map[string]string{"error": "API keys not configured"})
	}
	claims, ok := c.Get("user").(*auth.Claims)
	if !ok || claims == nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}

	keyID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid key ID"})
	}

	tenantID, _ := strconv.ParseInt(claims.TenantID, 10, 64)
	if err := h.apiKeySvc.RevokeAPIKey(c.Request().Context(), tenantID, keyID); err != nil {
		if containsMsg(err, "not found") || containsMsg(err, "already revoked") {
			return c.JSON(http.StatusNotFound, map[string]string{"error": err.Error()})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to revoke API key"})
	}

	h.auditEvent(c, audit.Event{
		TenantID:     &tenantID,
		UserID:       parseUserID(claims.UserID),
		ActorEmail:   claims.Email,
		Action:       audit.ActionAuthAPIKeyRevoked,
		AuthMethod:   audit.AuthMethodAPIKey,
		ResourceType: "api_key",
		ResourceID:   strconv.FormatInt(keyID, 10),
		IPAddress:    c.RealIP(),
		UserAgent:    c.Request().UserAgent(),
	})

	return c.JSON(http.StatusOK, map[string]string{"message": "API key revoked"})
}

// ManagementToken exchanges an API key for a short-lived management JWT.
// The JWT carries the API key's permissions so it can call /admin/* endpoints
// for the key's tenant — equivalent to Auth0's client_credentials grant.
//
// ManagementToken handles POST /api/v1/auth/management-token.
//
// @Summary      Exchange API key for management JWT
// @Description  Authenticates an API key (X-API-Key or Authorization: ApiKey) and returns a short-lived management JWT valid for 15 minutes. Use the returned token as Bearer auth on admin endpoints.
// @Tags         AUTH
// @Produce      json
// @Param        X-API-Key  header    string  false  "API key (emck_…). Alternative: Authorization: ApiKey <key>"
// @Success      200        {object}  map[string]interface{}  "access_token, expires_in, token_type"
// @Failure      401        {object}  map[string]string
// @Failure      501        {object}  map[string]string  "Management tokens not configured"
// @Router       /api/v1/auth/management-token [post]
func (h *AuthHandler) ManagementToken(c echo.Context) error {
	if h.apiKeySvc == nil || h.jwtSvc == nil {
		return c.JSON(http.StatusNotImplemented, map[string]string{"error": "management tokens not configured"})
	}

	rawKey := c.Request().Header.Get(mw.APIKeyHeader)
	if rawKey == "" {
		authHdr := c.Request().Header.Get("Authorization")
		if strings.HasPrefix(authHdr, "ApiKey ") {
			rawKey = strings.TrimPrefix(authHdr, "ApiKey ")
		}
	}
	if rawKey == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{
			"error": "API key required — set X-API-Key or Authorization: ApiKey <key>",
		})
	}

	identity, err := h.apiKeySvc.AuthenticateAPIKey(c.Request().Context(), rawKey)
	if err != nil {
		metrics.APIKeyAuth.WithLabelValues("failure").Inc()
		h.auditFailure(c, audit.Event{
			Action:       audit.ActionAuthManagementTokenFailed,
			AuthMethod:   audit.AuthMethodAPIKey,
			ResourceType: "api_key",
			IPAddress:    c.RealIP(),
			UserAgent:    c.Request().UserAgent(),
		}, err)
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid or revoked API key"})
	}

	token, err := h.jwtSvc.SignManagement(c.Request().Context(), identity)
	if err != nil {
		h.logger.Error().Err(err).Msg("management token: sign failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to issue management token"})
	}

	metrics.APIKeyAuth.WithLabelValues("success").Inc()
	metrics.TokensIssued.WithLabelValues("management").Inc()
	h.auditEvent(c, audit.Event{
		TenantID:     &identity.TenantID,
		Action:       audit.ActionAuthManagementToken,
		AuthMethod:   audit.AuthMethodAPIKey,
		ResourceType: "api_key",
		IPAddress:    c.RealIP(),
		UserAgent:    c.Request().UserAgent(),
		Metadata:     map[string]any{"permissions": identity.Permissions},
	})

	return c.JSON(http.StatusOK, map[string]any{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   int(auth.ManagementTokenTTL.Seconds()),
		"permissions":  identity.Permissions,
		"tenant_id":    strconv.FormatInt(identity.TenantID, 10),
	})
}

// transactionID derives a stable, non-sensitive correlation id from a
// pending-login token (e.g. the OTP session token) so every step of one login
// flow — the failed OTP retries and the final success — shares a thread, like
// Auth0's transaction_id. The raw token is never stored; only a short hash.
func transactionID(token string) string {
	if token == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(token))
	return "txn_" + hex.EncodeToString(sum[:6])
}

// parseUserID converts a JWT UserID claim to *int64, or nil when it is not a
// real users.id (e.g. service tokens carry a public client_id there).
func parseUserID(s string) *int64 {
	if id, err := strconv.ParseInt(s, 10, 64); err == nil {
		return &id
	}
	return nil
}

// containsMsg is a simple substring check for error classification.
func containsMsg(err error, substr string) bool {
	if err == nil {
		return false
	}
	return includesSubstr(err.Error(), substr)
}

func includesSubstr(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// claimsFromToken decodes the JWT payload without signature verification to extract
// tenant_id, user_id, and app_id for audit logging. Safe on tokens we just generated.
// appID is nil for tenant-level tokens (empty app_id claim).
func claimsFromToken(tokenStr string) (tenantID, userID, appID *int64) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, nil, nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, nil
	}
	var c struct {
		TenantID string `json:"tenant_id"`
		UserID   string `json:"user_id"`
		AppID    string `json:"app_id"`
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, nil, nil
	}
	if tid, err := strconv.ParseInt(c.TenantID, 10, 64); err == nil {
		tenantID = &tid
	}
	if uid, err := strconv.ParseInt(c.UserID, 10, 64); err == nil {
		userID = &uid
	}
	appID = appIDFromClaim(c.AppID)
	return tenantID, userID, appID
}

// appIDFromClaim parses the string-encoded oauth_clients.id carried in the
// JWT app_id claim (and OTP session state). Returns nil when the claim is
// empty or not numeric — i.e. no application context.
func appIDFromClaim(s string) *int64 {
	if s == "" {
		return nil
	}
	id, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return nil
	}
	return &id
}

// ---------------------------------------------------------------------------
// Cookie-based session endpoints (browser / SPA integration)
// ---------------------------------------------------------------------------

// SessionLoginRequest is the body for POST /api/v1/auth/session.
type SessionLoginRequest = LoginRequest

// SessionLogin handles POST /api/v1/auth/session.
//
// @Summary      Cookie-based login
// @Description  Authenticates the user by email and password only, and stores tokens in HttpOnly SameSite=Lax cookies. The tenant is resolved automatically — no tenant slug or header is required.
// @Tags         auth-session
// @Accept       json
// @Produce      json
// @Param        body  body      SessionLoginRequest true  "Credentials"
// @Success      200   {object}  map[string]string
// @Failure      400   {object}  map[string]string
// @Failure      401   {object}  map[string]string
// @Router       /api/v1/auth/session [post]
func (h *AuthHandler) SessionLogin(c echo.Context) error {
	var req LoginRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}
	if req.Email == "" || req.Password == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "email and password are required"})
	}

	result, err := h.svc.Login(c.Request().Context(), auth.LoginInput{
		ClientID: clientIDFromCtx(c),
		Email:    req.Email,
		Password: req.Password,
	})
	if err != nil {
		h.logger.Warn().Err(err).Str("email", req.Email).Msg("session login failed")
		h.auditFailure(c, audit.Event{
			ActorEmail:   req.Email,
			Action:       audit.ActionAuthLoginFailed,
			AuthMethod:   audit.AuthMethodPassword,
			ResourceType: "user",
			IPAddress:    c.RealIP(),
			UserAgent:    c.Request().UserAgent(),
			Metadata:     map[string]any{"flow": "session"},
		}, err)
		if containsMsg(err, "invalid credentials") {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "login failed"})
	}

	if result.OTPChallenge != nil {
		return c.JSON(http.StatusOK, result.OTPChallenge)
	}
	if result.MFAEnrollment != nil {
		return c.JSON(http.StatusForbidden, result.MFAEnrollment)
	}

	setAuthCookies(c, result.Token.AccessToken, result.Token.RefreshToken, h.cookieCfg)

	tid, uid, appID := claimsFromToken(result.Token.AccessToken)
	h.auditEvent(c, audit.Event{
		TenantID:      tid,
		UserID:        uid,
		ApplicationID: appID,
		ActorEmail:    req.Email,
		Action:        audit.ActionAuthLogin,
		AuthMethod:    audit.AuthMethodPassword,
		ResourceType:  "user",
		IPAddress:     c.RealIP(),
		UserAgent:     c.Request().UserAgent(),
	})

	return c.JSON(http.StatusOK, map[string]string{
		"message":    "logged in",
		"expires_in": "3600",
	})
}

// SessionRefresh handles POST /api/v1/auth/session/refresh.
//
// @Summary      Cookie session refresh
// @Description  Rotates the access and refresh tokens using the refresh cookie.
// @Description  409 (`concurrent_refresh`) signals a sibling request already rotated the family within the grace window (the fresh cookies are on that sibling's response); 503 signals the session store (Redis) is temporarily unavailable — retry.
// @Tags         auth-session
// @Produce      json
// @Success      200  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      409  {object}  map[string]string  "concurrent_refresh — sibling request already rotated the family"
// @Failure      503  {object}  map[string]string  "session store unavailable — retry"
// @Router       /api/v1/auth/session/refresh [post]
func (h *AuthHandler) SessionRefresh(c echo.Context) error {
	cookie, err := c.Cookie(mw.RefreshTokenCookie)
	if err != nil || cookie.Value == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "refresh cookie missing or expired"})
	}

	result, grace, err := h.svc.RefreshWithLock(c.Request().Context(), cookie.Value, h.redisCli)
	if err != nil {
		h.logger.Warn().Err(err).Msg("session refresh failed")
		action := audit.ActionAuthTokenRefreshFailed
		if errors.Is(err, auth.ErrTokenReplay) {
			action = audit.ActionAuthReplayDetected
		}
		ev := audit.Event{
			Action:       action,
			AuthMethod:   audit.AuthMethodRefreshToken,
			ResourceType: "session",
			IPAddress:    c.RealIP(),
			UserAgent:    c.Request().UserAgent(),
			Metadata:     map[string]any{"flow": "session"},
		}
		attachTokenOwner(c.Request().Context(), &ev, h.svc, cookie.Value)
		h.auditFailure(c, ev, err)
		if errors.Is(err, auth.ErrTokenReplay) {
			clearAuthCookies(c, h.cookieCfg)
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "session terminated — security event detected"})
		}
		if errors.Is(err, auth.ErrInvalidRefreshToken) {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid or expired refresh token"})
		}
		if errors.Is(err, auth.ErrServiceUnavailable) {
			return c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "service temporarily unavailable — please retry"})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "token refresh failed"})
	}

	// Concurrent rotation already completed within the grace window; the sibling
	// request's response carries the fresh cookies. Signal the collision so the
	// client relies on those cookies instead of treating this as a hard failure.
	if grace != nil {
		return c.JSON(http.StatusConflict, map[string]string{
			"error": "refresh already completed by a concurrent request",
			"code":  "concurrent_refresh",
		})
	}

	setAuthCookies(c, result.AccessToken, result.RefreshToken, h.cookieCfg)

	tid, uid, appID := claimsFromToken(result.AccessToken)
	h.auditEvent(c, audit.Event{
		TenantID:      tid,
		UserID:        uid,
		ApplicationID: appID,
		Action:        audit.ActionAuthTokenRefresh,
		AuthMethod:    audit.AuthMethodRefreshToken,
		ResourceType:  "session",
		IPAddress:     c.RealIP(),
		UserAgent:     c.Request().UserAgent(),
	})

	return c.JSON(http.StatusOK, map[string]string{
		"message":    "session refreshed",
		"expires_in": "3600",
	})
}

// SessionLogout handles POST /api/v1/auth/session/logout.
//
// @Summary      Cookie session logout
// @Description  Revokes the refresh token stored in the cookie and clears both auth cookies.
// @Tags         auth-session
// @Produce      json
// @Success      200  {object}  map[string]string
// @Router       /api/v1/auth/session/logout [post]
func (h *AuthHandler) SessionLogout(c echo.Context) error {
	var refreshToken string
	if cookie, err := c.Cookie(mw.RefreshTokenCookie); err == nil && cookie.Value != "" {
		refreshToken = cookie.Value
		_ = h.svc.Logout(c.Request().Context(), refreshToken)
	}
	clearAuthCookies(c, h.cookieCfg)

	ev := audit.Event{
		Action:       audit.ActionAuthLogout,
		AuthMethod:   audit.AuthMethodRefreshToken,
		ResourceType: "session",
		IPAddress:    c.RealIP(),
		UserAgent:    c.Request().UserAgent(),
		Metadata:     map[string]any{"flow": "session"},
	}
	attachTokenOwner(c.Request().Context(), &ev, h.svc, refreshToken)
	h.auditEvent(c, ev)

	return c.JSON(http.StatusOK, map[string]string{"message": "logged out"})
}

// ---------------------------------------------------------------------------
// Client credentials token endpoint
// ---------------------------------------------------------------------------

// TokenRequest is the JSON body for POST /api/v1/auth/token.
// ClientID/ClientSecret are bound ONLY to detect and reject credentials sent
// in the body — the sole accepted channel is the Authorization: Basic header.
type TokenRequest struct {
	GrantType    string `json:"grant_type"`
	ClientID     string `json:"client_id" swaggerignore:"true"`
	ClientSecret string `json:"client_secret" swaggerignore:"true"`
}

// errBodyCredentials is the guidance returned when an integrator sends
// client credentials in the request body instead of the Basic auth header.
const errBodyCredentials = "client_id and client_secret must be sent via the Authorization: Basic header, not the request body"

// clientCredentialsFromBasicAuth extracts client_id + client_secret from an
// RFC 6749 §2.3.1 "Authorization: Basic base64(client_id:client_secret)"
// header. Returns ok=false when the header is absent; an error when the header
// is present but malformed — the two cases get different HTTP responses.
func clientCredentialsFromBasicAuth(c echo.Context) (clientID, clientSecret string, ok bool, err error) {
	return clientCredentialsFromHeader(c, echo.HeaderAuthorization)
}

// clientCredentialsFromHeader parses Basic base64(client_id:client_secret) from an
// arbitrary header.
//
// Extracted from clientCredentialsFromBasicAuth so /auth/apps/me can read the same
// credential format out of X-Client-Authorization — its Authorization header is
// occupied by the user's Bearer token (issue #96). One parser, two headers: the
// encoding, the validation, and the error messages cannot drift apart.
func clientCredentialsFromHeader(c echo.Context, headerName string) (clientID, clientSecret string, ok bool, err error) {
	header := c.Request().Header.Get(headerName)
	const prefix = "Basic "
	if header == "" || !strings.HasPrefix(header, prefix) {
		return "", "", false, nil
	}
	decoded, decodeErr := base64.StdEncoding.DecodeString(header[len(prefix):])
	if decodeErr != nil {
		return "", "", false, fmt.Errorf("invalid base64 in Basic authorization header")
	}
	id, secret, found := strings.Cut(string(decoded), ":")
	if !found || id == "" || secret == "" {
		return "", "", false, fmt.Errorf("basic authorization header must be base64(client_id:client_secret)")
	}
	return id, secret, true, nil
}

// Token handles POST /api/v1/auth/token.
//
// Client credentials are accepted ONLY via the Authorization header
// (RFC 6749 §2.3.1): Basic base64(client_id:client_secret). The JSON body
// carries grant_type alone; credentials in the body are rejected with
// guidance so misconfigured integrations fail loudly, not silently.
//
// @Summary      Client credentials token
// @Description  Issues a service-level access token. Credentials via Authorization: Basic base64(client_id:client_secret) header only. No user involved, no refresh token issued.
// @Tags         AUTH
// @Accept       json
// @Produce      json
// @Param        Authorization  header  string        true  "Basic base64(client_id:client_secret)"
// @Param        body           body    TokenRequest  true  "grant_type only"
// @Success      200   {object}  map[string]interface{}
// @Failure      400   {object}  map[string]string
// @Failure      401   {object}  map[string]string
// @Router       /api/v1/auth/token [post]
func (h *AuthHandler) Token(c echo.Context) error {
	var req TokenRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}
	if req.ClientID != "" || req.ClientSecret != "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": errBodyCredentials})
	}

	id, secret, ok, err := clientCredentialsFromBasicAuth(c)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	if !ok {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Authorization: Basic base64(client_id:client_secret) header is required"})
	}
	req.ClientID, req.ClientSecret = id, secret

	if req.GrantType != "client_credentials" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "unsupported grant_type — only client_credentials is accepted",
		})
	}
	if h.appSvc == nil {
		return c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "application service not configured"})
	}

	tenantID, appID, err := h.appSvc.AuthenticateClient(c.Request().Context(), req.ClientID, req.ClientSecret)
	if err != nil {
		ev := audit.Event{
			Action:       audit.ActionAuthClientCredentialsFailed,
			AuthMethod:   audit.AuthMethodClientCredentials,
			ResourceType: "oauth_client",
			ResourceID:   req.ClientID,
			IPAddress:    c.RealIP(),
			UserAgent:    c.Request().UserAgent(),
			Metadata:     map[string]any{"grant_type": req.GrantType},
		}
		// Attribute to the target application when the client_id is real (a
		// wrong-secret attempt against a known app); unknown ids stay un-attributed.
		attachAppContext(c.Request().Context(), &ev, h.appSvc, req.ClientID)
		h.auditFailure(c, ev, err)
		if errors.Is(err, auth.ErrInvalidClient) {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid client credentials"})
		}
		h.logger.Error().Err(err).Msg("client credentials auth failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "authentication failed"})
	}

	token, expiresIn, err := h.svc.IssueServiceToken(c.Request().Context(), tenantID, appID)
	if err != nil {
		h.logger.Error().Err(err).Msg("issue service token failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "token generation failed"})
	}

	metrics.TokensIssued.WithLabelValues(audit.AuthMethodClientCredentials).Inc()
	h.auditEvent(c, audit.Event{
		TenantID:      &tenantID,
		ApplicationID: &appID,
		Action:        audit.ActionAuthClientCredentials,
		AuthMethod:    audit.AuthMethodClientCredentials,
		ResourceType:  "oauth_client",
		ResourceID:    strconv.FormatInt(appID, 10),
		IPAddress:     c.RealIP(),
		UserAgent:     c.Request().UserAgent(),
		Metadata:      map[string]any{"grant_type": req.GrantType},
	})

	return c.JSON(http.StatusOK, map[string]interface{}{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   expiresIn,
	})
}

// ---------------------------------------------------------------------------
// Cookie helpers
// ---------------------------------------------------------------------------

func setAuthCookies(c echo.Context, accessToken, refreshToken string, cfg mw.CookieConfig) {
	for _, cookie := range mw.BuildAuthCookies(accessToken, refreshToken, cfg) {
		http.SetCookie(c.Response().Writer, cookie)
	}
}

func clearAuthCookies(c echo.Context, cfg mw.CookieConfig) {
	mw.ClearAuthCookies(c, cfg)
}
