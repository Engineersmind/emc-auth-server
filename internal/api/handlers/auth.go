package handlers

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog"

	"github.com/engineersmind/emc-auth-server/internal/audit"
	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// AuthHandler holds HTTP handlers for auth endpoints.
type AuthHandler struct {
	svc      *auth.AuthService
	resetSvc *auth.ResetService
	audit    *audit.Logger
	logger   zerolog.Logger
}

// NewAuthHandler creates an AuthHandler.
func NewAuthHandler(svc *auth.AuthService, resetSvc *auth.ResetService, auditLog *audit.Logger, logger zerolog.Logger) *AuthHandler {
	return &AuthHandler{svc: svc, resetSvc: resetSvc, audit: auditLog, logger: logger}
}

// RegisterRequest is the JSON body for POST /api/v1/auth/register.
type RegisterRequest struct {
	Email     string `json:"email"     validate:"required,email"`
	Password  string `json:"password"  validate:"required,min=8"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

// LoginRequest is the JSON body for POST /api/v1/auth/login.
type LoginRequest struct {
	Email    string `json:"email"    validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

// tenantSlugFromCtx extracts the X-Tenant-Slug header.
// All public auth endpoints (register, login) require this header for tenant resolution.
func tenantSlugFromCtx(c echo.Context) (string, bool) {
	slug := c.Request().Header.Get("X-Tenant-Slug")
	return slug, slug != ""
}

// Register handles POST /api/v1/auth/register.
//
// @Summary      Register a new user
// @Description  Creates a user account in the specified tenant and returns a token pair.
// @Tags         auth
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
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "X-Tenant-Slug header is required"})
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

	// Audit: new user registered.
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

	return c.JSON(http.StatusCreated, result)
}

// Login handles POST /api/v1/auth/login.
//
// @Summary      Login
// @Description  Authenticates an existing user and returns a JWT access token + refresh token pair.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        X-Tenant-Slug  header    string        true  "Tenant slug (e.g. emc)"
// @Param        body           body      LoginRequest  true  "Login credentials"
// @Success      200            {object}  auth.AuthResult
// @Failure      400            {object}  map[string]string
// @Failure      401            {object}  map[string]string  "Invalid credentials"
// @Router       /api/v1/auth/login [post]
func (h *AuthHandler) Login(c echo.Context) error {
	slug, ok := tenantSlugFromCtx(c)
	if !ok {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "X-Tenant-Slug header is required"})
	}

	var req LoginRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}
	if req.Email == "" || req.Password == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "email and password are required"})
	}

	result, err := h.svc.Login(c.Request().Context(), auth.LoginInput{
		TenantSlug: slug,
		Email:      req.Email,
		Password:   req.Password,
	})
	if err != nil {
		h.logger.Warn().Err(err).Str("email", req.Email).Msg("login failed")
		// Audit: failed login attempt (no tenant_id — we don't confirm tenant exists).
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

	// Audit: successful login.
	tid, uid := claimsFromToken(result.AccessToken)
	h.audit.Log(c.Request().Context(), audit.Event{
		TenantID:     tid,
		UserID:       uid,
		ActorEmail:   req.Email,
		Action:       audit.ActionAuthLogin,
		ResourceType: "user",
		IPAddress:    c.RealIP(),
		UserAgent:    c.Request().UserAgent(),
	})

	return c.JSON(http.StatusOK, result)
}

// Me handles GET /api/v1/auth/me.
//
// @Summary      Get current user profile
// @Description  Returns the authenticated user's profile decoded from the JWT.
// @Tags         auth
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  auth.MeResult
// @Failure      401  {object}  map[string]string
// @Router       /api/v1/auth/me [get]
func (h *AuthHandler) Me(c echo.Context) error {
	// Claims are injected by JWTRequired middleware.
	// Until Plan 02-02 wires the middleware, this handler extracts from context manually
	// using the same context key ("user") the middleware will set.
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
// @Description  Issues a new access + refresh token pair and immediately invalidates the old refresh token. Replaying the old token returns 401.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        body  body      RefreshRequest  true  "Refresh token"
// @Success      200   {object}  auth.AuthResult
// @Failure      400   {object}  map[string]string
// @Failure      401   {object}  map[string]string  "Invalid or expired refresh token"
// @Router       /api/v1/auth/refresh [post]
func (h *AuthHandler) Refresh(c echo.Context) error {
	var req RefreshRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}
	if req.RefreshToken == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "refresh_token is required"})
	}

	result, err := h.svc.Refresh(c.Request().Context(), req.RefreshToken)
	if err != nil {
		h.logger.Warn().Err(err).Msg("refresh failed")
		if errors.Is(err, auth.ErrInvalidRefreshToken) {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid or expired refresh token"})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "token refresh failed"})
	}

	// Audit: token refreshed.
	tid, uid := claimsFromToken(result.AccessToken)
	h.audit.Log(c.Request().Context(), audit.Event{
		TenantID:     tid,
		UserID:       uid,
		Action:       audit.ActionAuthTokenRefresh,
		ResourceType: "session",
		IPAddress:    c.RealIP(),
		UserAgent:    c.Request().UserAgent(),
	})

	return c.JSON(http.StatusOK, result)
}

// Logout handles POST /api/v1/auth/logout (AUTH-04).
//
// @Summary      Logout
// @Description  Revokes the supplied refresh token. Idempotent — calling twice is safe.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        body  body      LogoutRequest  true  "Refresh token to revoke"
// @Success      200   {object}  map[string]string
// @Failure      400   {object}  map[string]string
// @Router       /api/v1/auth/logout [post]
func (h *AuthHandler) Logout(c echo.Context) error {
	var req LogoutRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}
	if req.RefreshToken == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "refresh_token is required"})
	}

	if err := h.svc.Logout(c.Request().Context(), req.RefreshToken); err != nil {
		h.logger.Error().Err(err).Msg("logout failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "logout failed"})
	}

	// Audit: logout (no access token available — tenant_id is nil).
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
// @Description  Sends a reset link to the email address. ALWAYS returns 200 regardless of whether the email is registered (prevents email enumeration). In development the link is logged to the server console instead of being emailed.
// @Tags         password-reset
// @Accept       json
// @Produce      json
// @Param        X-Tenant-Slug  header    string                 true  "Tenant slug"
// @Param        body           body      ForgotPasswordRequest  true  "Email address"
// @Success      200            {object}  map[string]string
// @Router       /api/v1/auth/forgot-password [post]
func (h *AuthHandler) ForgotPassword(c echo.Context) error {
	slug, ok := tenantSlugFromCtx(c)
	if !ok {
		// Even for missing tenant slug, return generic success to prevent enumeration.
		// Log at debug so we can diagnose misconfigured clients without leaking to callers.
		h.logger.Debug().Msg("forgot-password: missing X-Tenant-Slug header")
		return c.JSON(http.StatusOK, map[string]string{
			"message": "if that email address is registered, a password reset link has been sent",
		})
	}

	var req ForgotPasswordRequest
	if err := c.Bind(&req); err != nil || req.Email == "" {
		// Return generic 200 even on bad body (RESET-03).
		return c.JSON(http.StatusOK, map[string]string{
			"message": "if that email address is registered, a password reset link has been sent",
		})
	}

	// Errors from ForgotPassword are swallowed here — the service itself returns nil
	// for "user not found" cases (RESET-03). Any infrastructure errors are logged by the service.
	if err := h.resetSvc.ForgotPassword(c.Request().Context(), slug, req.Email); err != nil {
		h.logger.Error().Err(err).Msg("forgot-password: unexpected service error")
		// Still return generic 200 (RESET-03 — do not leak error details).
	}

	// Audit: reset requested (always logged regardless of whether email exists — RESET-03 preserved).
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
	// Token is the raw reset token from the email link query parameter.
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

// ResetPassword handles POST /api/v1/auth/reset-password (RESET-02).
//
// @Summary      Reset password
// @Description  Validates the reset token, updates the user's password, and revokes all active refresh tokens (logs out all sessions). Token is single-use and expires in 15 minutes.
// @Tags         password-reset
// @Accept       json
// @Produce      json
// @Param        body  body      ResetPasswordRequest  true  "Token + new password"
// @Success      200   {object}  map[string]string
// @Failure      400   {object}  map[string]string  "Invalid/expired token or weak password"
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

	// Audit: password reset completed.
	h.audit.Log(c.Request().Context(), audit.Event{
		Action:       audit.ActionAuthPasswordResetDone,
		ResourceType: "user",
		IPAddress:    c.RealIP(),
		UserAgent:    c.Request().UserAgent(),
	})

	return c.JSON(http.StatusOK, map[string]string{"message": "password updated successfully"})
}

// containsMsg is a simple substring check for error classification.
// Avoids importing strings for a trivial helper.
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

// claimsFromToken decodes the JWT payload (base64, not encrypted) without
// signature verification to extract tenant_id and user_id for audit logging.
// Safe to call on tokens we just generated — JWT payloads are always readable.
func claimsFromToken(tokenStr string) (tenantID, userID *uuid.UUID) {
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
	if tid, err := uuid.Parse(c.TenantID); err == nil {
		tenantID = &tid
	}
	if uid, err := uuid.Parse(c.UserID); err == nil {
		userID = &uid
	}
	return tenantID, userID
}

// uuidPtr returns a pointer to the given UUID (nil if it's uuid.Nil).
func uuidPtr(id uuid.UUID) *uuid.UUID {
	if id == uuid.Nil {
		return nil
	}
	return &id
}
