package handlers

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog"

	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// AuthHandler holds HTTP handlers for auth endpoints.
// Register, Login, and Me are implemented here.
// Refresh, Logout are added in Plan 02-02.
type AuthHandler struct {
	svc    *auth.AuthService
	logger zerolog.Logger
}

// NewAuthHandler creates an AuthHandler.
func NewAuthHandler(svc *auth.AuthService, logger zerolog.Logger) *AuthHandler {
	return &AuthHandler{svc: svc, logger: logger}
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
// Required header: X-Tenant-Slug: <slug>
// Body: { "email": "...", "password": "...", "first_name": "...", "last_name": "..." }
// Response 201: { "access_token": "...", "refresh_token": "...", "token_type": "Bearer", "expires_in": 3600 }
// Response 400: missing/invalid body
// Response 404: unknown tenant slug
// Response 409: duplicate email
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

	return c.JSON(http.StatusCreated, result)
}

// Login handles POST /api/v1/auth/login.
//
// Required header: X-Tenant-Slug: <slug>
// Body: { "email": "...", "password": "..." }
// Response 200: { "access_token": "...", "refresh_token": "...", "token_type": "Bearer", "expires_in": 3600 }
// Response 401: invalid credentials or inactive user
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
		if containsMsg(err, "invalid credentials") {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "login failed"})
	}

	return c.JSON(http.StatusOK, result)
}

// Me handles GET /api/v1/auth/me.
// This endpoint is protected by JWTRequired middleware (added in Plan 02-02).
// The middleware stores *auth.Claims under the context key "user".
//
// Response 200: { "user_id": "...", "tenant_id": "...", "email": "...", "role": "...", "permissions": [...] }
// Response 401: no or invalid JWT (enforced by middleware, not this handler)
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
