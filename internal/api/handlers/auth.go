package handlers

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog"

	mw "github.com/engineersmind/emc-auth-server/internal/api/middleware"
	"github.com/engineersmind/emc-auth-server/internal/audit"
	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// AuthHandler holds HTTP handlers for auth endpoints.
type AuthHandler struct {
	svc       *auth.AuthService
	resetSvc  *auth.ResetService
	totpSvc   *auth.TOTPService // nil when TOTP not configured
	apiKeySvc *auth.APIKeyService
	appSvc    *auth.ApplicationService // nil until WithApplications is called
	jwtSvc    *auth.JWTService
	audit     *audit.Logger
	logger    zerolog.Logger
	cookieCfg mw.CookieConfig
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

	tid, uid := claimsFromToken(result.AccessToken)
	h.audit.Log(c.Request().Context(), audit.Event{
		TenantID:     tid,
		UserID:       uid,
		ActorEmail:   req.Email,
		Action:       audit.ActionAuthRegister,
		ResourceType: "user",
		IPAddress:    c.RealIP(),
		UserAgent:    c.Request().UserAgent(),
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
		h.audit.Log(c.Request().Context(), audit.Event{
			ActorEmail:   req.Email,
			Action:       audit.ActionAuthLoginFailed,
			ResourceType: "user",
			IPAddress:    c.RealIP(),
			UserAgent:    c.Request().UserAgent(),
		})
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

	tid, uid := claimsFromToken(result.Token.AccessToken)
	h.audit.Log(c.Request().Context(), audit.Event{
		TenantID:     tid,
		UserID:       uid,
		ActorEmail:   req.Email,
		Action:       audit.ActionAuthLogin,
		ResourceType: "user",
		IPAddress:    c.RealIP(),
		UserAgent:    c.Request().UserAgent(),
	})

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

	tid, uid := claimsFromToken(result.AccessToken)
	h.audit.Log(c.Request().Context(), audit.Event{
		TenantID:     tid,
		UserID:       uid,
		ActorEmail:   req.Email,
		Action:       audit.ActionAuthRegister,
		ResourceType: "user",
		IPAddress:    c.RealIP(),
		UserAgent:    c.Request().UserAgent(),
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
		h.audit.Log(c.Request().Context(), audit.Event{
			ActorEmail:   req.Email,
			Action:       audit.ActionAuthLoginFailed,
			ResourceType: "user",
			IPAddress:    c.RealIP(),
			UserAgent:    c.Request().UserAgent(),
		})
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

	tid, uid := claimsFromToken(result.Token.AccessToken)
	h.audit.Log(c.Request().Context(), audit.Event{
		TenantID:     tid,
		UserID:       uid,
		ActorEmail:   req.Email,
		Action:       audit.ActionAuthLogin,
		ResourceType: "user",
		IPAddress:    c.RealIP(),
		UserAgent:    c.Request().UserAgent(),
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
		h.audit.Log(c.Request().Context(), audit.Event{
			Action:       audit.ActionAuthMFAChallengeFailed,
			ResourceType: "user",
			IPAddress:    c.RealIP(),
			UserAgent:    c.Request().UserAgent(),
		})
		if errors.Is(err, auth.ErrTooManyOTPAttempts) {
			return c.JSON(http.StatusTooManyRequests, map[string]string{"error": err.Error()})
		}
		if containsMsg(err, "invalid TOTP") || containsMsg(err, "invalid or expired") || containsMsg(err, "invalid backup") {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid or expired OTP code"})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "OTP login failed"})
	}

	tid, uid := claimsFromToken(result.AccessToken)
	h.audit.Log(c.Request().Context(), audit.Event{
		TenantID:     tid,
		UserID:       uid,
		Action:       audit.ActionAuthLogin,
		ResourceType: "user",
		IPAddress:    c.RealIP(),
		UserAgent:    c.Request().UserAgent(),
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

	h.audit.Log(c.Request().Context(), audit.Event{
		TenantID:     &session.TenantID,
		UserID:       &session.UserID,
		ActorEmail:   session.Email,
		Action:       audit.ActionAuthMFAEnrolled,
		ResourceType: "user",
		IPAddress:    c.RealIP(),
		UserAgent:    c.Request().UserAgent(),
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
			ResourceType: "user",
			IPAddress:    c.RealIP(),
			UserAgent:    c.Request().UserAgent(),
		}
		if session != nil {
			event.TenantID, event.UserID, event.ActorEmail = &session.TenantID, &session.UserID, session.Email
		}
		h.audit.Log(c.Request().Context(), event)

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

	h.audit.Log(c.Request().Context(), audit.Event{
		TenantID:     &session.TenantID,
		UserID:       &session.UserID,
		ActorEmail:   session.Email,
		Action:       audit.ActionAuthMFAActivated,
		ResourceType: "user",
		IPAddress:    c.RealIP(),
		UserAgent:    c.Request().UserAgent(),
	})
	h.audit.Log(c.Request().Context(), audit.Event{
		TenantID:     &session.TenantID,
		UserID:       &session.UserID,
		ActorEmail:   session.Email,
		Action:       audit.ActionAuthLogin,
		ResourceType: "user",
		IPAddress:    c.RealIP(),
		UserAgent:    c.Request().UserAgent(),
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
// @Tags         AUTH
// @Accept       json
// @Produce      json
// @Param        body  body      RefreshRequest  true  "Refresh token"
// @Success      200   {object}  auth.AuthResult
// @Failure      400   {object}  map[string]string
// @Failure      401   {object}  map[string]string
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

	result, err := h.svc.Refresh(c.Request().Context(), req.RefreshToken)
	if err != nil {
		h.logger.Warn().Err(err).Msg("refresh failed")
		if errors.Is(err, auth.ErrTokenReplay) {
			clearAuthCookies(c, h.cookieCfg)
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "session terminated — security event detected"})
		}
		if errors.Is(err, auth.ErrInvalidRefreshToken) {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid or expired refresh token"})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "token refresh failed"})
	}

	tid, uid := claimsFromToken(result.AccessToken)
	h.audit.Log(c.Request().Context(), audit.Event{
		TenantID:     tid,
		UserID:       uid,
		Action:       audit.ActionAuthTokenRefresh,
		ResourceType: "session",
		IPAddress:    c.RealIP(),
		UserAgent:    c.Request().UserAgent(),
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

	h.audit.Log(c.Request().Context(), audit.Event{
		Action:    audit.ActionAuthLogout,
		IPAddress: c.RealIP(),
		UserAgent: c.Request().UserAgent(),
	})

	return c.JSON(http.StatusOK, map[string]string{"message": "logged out"})
}

// ForgotPasswordRequest is the JSON body for POST /api/v1/auth/forgot-password.
type ForgotPasswordRequest struct {
	Email string `json:"email"`
}

// ForgotPassword handles POST /api/v1/auth/forgot-password (RESET-01, RESET-03).
//
// @Summary      Request password reset
// @Description  Sends a reset link to the email address. ALWAYS returns 200 regardless of whether the email is registered (prevents email enumeration).
// @Tags         AUTH
// @Accept       json
// @Produce      json
// @Param        X-Tenant-Slug  header    string                 true  "Tenant slug"
// @Param        body           body      ForgotPasswordRequest  true  "Email address"
// @Success      200            {object}  map[string]string
// @Router       /api/v1/auth/forgot-password [post]
func (h *AuthHandler) ForgotPassword(c echo.Context) error {
	slug, ok := tenantSlugFromCtx(c)
	if !ok {
		h.logger.Debug().Msg("forgot-password: missing X-Tenant-Slug header")
		return c.JSON(http.StatusOK, map[string]string{
			"message": "if that email address is registered, a password reset link has been sent",
		})
	}

	var req ForgotPasswordRequest
	if err := c.Bind(&req); err != nil || req.Email == "" {
		return c.JSON(http.StatusOK, map[string]string{
			"message": "if that email address is registered, a password reset link has been sent",
		})
	}

	if err := h.resetSvc.ForgotPassword(c.Request().Context(), slug, req.Email); err != nil {
		h.logger.Error().Err(err).Msg("forgot-password: unexpected service error")
	}

	h.audit.Log(c.Request().Context(), audit.Event{
		ActorEmail:   req.Email,
		Action:       audit.ActionAuthPasswordResetReq,
		ResourceType: "user",
		IPAddress:    c.RealIP(),
		UserAgent:    c.Request().UserAgent(),
	})

	return c.JSON(http.StatusOK, map[string]string{
		"message": "if that email address is registered, a password reset link has been sent",
	})
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

	h.audit.Log(c.Request().Context(), audit.Event{
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

	h.audit.Log(c.Request().Context(), audit.Event{
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
	h.audit.Log(c.Request().Context(), audit.Event{
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

	h.audit.Log(c.Request().Context(), audit.Event{
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
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid or revoked API key"})
	}

	token, err := h.jwtSvc.SignManagement(c.Request().Context(), identity)
	if err != nil {
		h.logger.Error().Err(err).Msg("management token: sign failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to issue management token"})
	}

	return c.JSON(http.StatusOK, map[string]any{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   int(auth.ManagementTokenTTL.Seconds()),
		"permissions":  identity.Permissions,
		"tenant_id":    strconv.FormatInt(identity.TenantID, 10),
	})
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
// tenant_id and user_id for audit logging. Safe on tokens we just generated.
func claimsFromToken(tokenStr string) (tenantID, userID *int64) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil
	}
	var c struct {
		TenantID string `json:"tenant_id"`
		UserID   string `json:"user_id"`
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, nil
	}
	if tid, err := strconv.ParseInt(c.TenantID, 10, 64); err == nil {
		tenantID = &tid
	}
	if uid, err := strconv.ParseInt(c.UserID, 10, 64); err == nil {
		userID = &uid
	}
	return tenantID, userID
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
		h.audit.Log(c.Request().Context(), audit.Event{
			ActorEmail:   req.Email,
			Action:       audit.ActionAuthLoginFailed,
			ResourceType: "user",
			IPAddress:    c.RealIP(),
			UserAgent:    c.Request().UserAgent(),
		})
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

	tid, uid := claimsFromToken(result.Token.AccessToken)
	h.audit.Log(c.Request().Context(), audit.Event{
		TenantID:     tid,
		UserID:       uid,
		ActorEmail:   req.Email,
		Action:       audit.ActionAuthLogin,
		ResourceType: "user",
		IPAddress:    c.RealIP(),
		UserAgent:    c.Request().UserAgent(),
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
// @Tags         auth-session
// @Produce      json
// @Success      200  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Router       /api/v1/auth/session/refresh [post]
func (h *AuthHandler) SessionRefresh(c echo.Context) error {
	cookie, err := c.Cookie(mw.RefreshTokenCookie)
	if err != nil || cookie.Value == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "refresh cookie missing or expired"})
	}

	result, err := h.svc.Refresh(c.Request().Context(), cookie.Value)
	if err != nil {
		h.logger.Warn().Err(err).Msg("session refresh failed")
		if errors.Is(err, auth.ErrTokenReplay) {
			clearAuthCookies(c, h.cookieCfg)
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "session terminated — security event detected"})
		}
		if errors.Is(err, auth.ErrInvalidRefreshToken) {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid or expired refresh token"})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "token refresh failed"})
	}

	setAuthCookies(c, result.AccessToken, result.RefreshToken, h.cookieCfg)

	tid, uid := claimsFromToken(result.AccessToken)
	h.audit.Log(c.Request().Context(), audit.Event{
		TenantID:     tid,
		UserID:       uid,
		Action:       audit.ActionAuthTokenRefresh,
		ResourceType: "session",
		IPAddress:    c.RealIP(),
		UserAgent:    c.Request().UserAgent(),
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
	if cookie, err := c.Cookie(mw.RefreshTokenCookie); err == nil && cookie.Value != "" {
		_ = h.svc.Logout(c.Request().Context(), cookie.Value)
	}
	clearAuthCookies(c, h.cookieCfg)

	h.audit.Log(c.Request().Context(), audit.Event{
		Action:    audit.ActionAuthLogout,
		IPAddress: c.RealIP(),
		UserAgent: c.Request().UserAgent(),
	})

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
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// errBodyCredentials is the guidance returned when an integrator sends
// client credentials in the request body instead of the Basic auth header.
const errBodyCredentials = "client_id and client_secret must be sent via the Authorization: Basic header, not the request body"

// clientCredentialsFromBasicAuth extracts client_id + client_secret from an
// RFC 6749 §2.3.1 "Authorization: Basic base64(client_id:client_secret)"
// header. Returns ok=false when the header is absent; an error when the header
// is present but malformed — the two cases get different HTTP responses.
func clientCredentialsFromBasicAuth(c echo.Context) (clientID, clientSecret string, ok bool, err error) {
	header := c.Request().Header.Get(echo.HeaderAuthorization)
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

	h.audit.Log(c.Request().Context(), audit.Event{
		TenantID:     &tenantID,
		Action:       audit.ActionAuthClientCredentials,
		ResourceType: "oauth_client",
		ResourceID:   strconv.FormatInt(appID, 10),
		IPAddress:    c.RealIP(),
		UserAgent:    c.Request().UserAgent(),
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
