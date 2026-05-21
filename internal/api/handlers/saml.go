package handlers

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	samlsvc "github.com/engineersmind/emc-auth-server/internal/saml"
)

// SAMLHandler holds HTTP handlers for SAML 2.0 endpoints.
type SAMLHandler struct {
	svc    *samlsvc.Service
	jwtSvc *auth.JWTService
	logger zerolog.Logger
}

// NewSAMLHandler creates a SAMLHandler with the SAML service and JWT service
// required for metadata, SP-initiated login, ACS, and admin config endpoints.
func NewSAMLHandler(svc *samlsvc.Service, jwtSvc *auth.JWTService, logger zerolog.Logger) *SAMLHandler {
	return &SAMLHandler{svc: svc, jwtSvc: jwtSvc, logger: logger}
}

// GetMetadata handles GET /saml/metadata?tenant=<tenant_id>
// Returns SP metadata XML so IdPs can configure the service provider.
func (h *SAMLHandler) GetMetadata(c echo.Context) error {
	tenantID := c.QueryParam("tenant")
	if tenantID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "tenant query param required")
	}
	xmlBytes, err := h.svc.GenerateMetadata(tenantID)
	if err != nil {
		h.logger.Error().Err(err).Str("tenant_id", tenantID).Msg("saml: metadata generation failed")
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to generate metadata")
	}
	return c.Blob(http.StatusOK, "application/xml", xmlBytes)
}

// InitiateLogin handles GET /saml/login?tenant=<tenant_id>
// Redirects the browser to the IdP with a SAMLRequest (SP-initiated SSO).
func (h *SAMLHandler) InitiateLogin(c echo.Context) error {
	tenantID := c.QueryParam("tenant")
	if tenantID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "tenant query param required")
	}
	cfg, err := h.svc.GetConfig(c.Request().Context(), tenantID)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "SAML not configured for this tenant")
	}
	samlReq, err := h.svc.BuildAuthnRequest(tenantID, cfg.SSOURL)
	if err != nil {
		h.logger.Error().Err(err).Str("tenant_id", tenantID).Msg("saml: failed to build AuthnRequest")
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to build AuthnRequest")
	}
	redirectURL := cfg.SSOURL + "?SAMLRequest=" + samlReq + "&RelayState=" + tenantID
	return c.Redirect(http.StatusFound, redirectURL)
}

// HandleACS handles POST /saml/acs — Assertion Consumer Service.
// Parses the IdP POST response, JIT-provisions the user if needed, and issues a JWT.
//
// Security note: This implementation does NOT verify the IdP XML signature.
// Signature verification must be added before production use with a real IdP.
func (h *SAMLHandler) HandleACS(c echo.Context) error {
	// Tenant comes from RelayState (set in the AuthnRequest redirect) or query param fallback.
	tenantID := c.FormValue("RelayState")
	if tenantID == "" {
		tenantID = c.QueryParam("tenant")
	}
	if tenantID == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "tenant not found in RelayState")
	}

	samlResponse := c.FormValue("SAMLResponse")
	if samlResponse == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "SAMLResponse missing")
	}

	email, _, err := h.svc.ParseACSResponse(samlResponse)
	if err != nil {
		h.logger.Error().Err(err).Str("tenant_id", tenantID).Msg("saml: ACS response parse failed")
		return echo.NewHTTPError(http.StatusBadRequest, "invalid SAML response")
	}

	// JIT provisioning: find or create the user in this tenant.
	user, err := h.svc.FindOrCreateUser(c.Request().Context(), tenantID, email)
	if err != nil {
		h.logger.Error().Err(err).Str("email", email).Str("tenant_id", tenantID).Msg("saml: JIT provisioning failed")
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to provision user")
	}

	// Issue JWT using the per-tenant secret.
	tenantUUID, err := uuid.Parse(user.TenantID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "invalid tenant_id")
	}

	claims := &auth.Claims{
		UserID:      user.ID,
		TenantID:    user.TenantID,
		Email:       user.Email,
		Role:        user.Role,
		Permissions: []string{},
	}

	accessToken, err := h.jwtSvc.Sign(c.Request().Context(), tenantUUID, "emc-auth-server", claims)
	if err != nil {
		h.logger.Error().Err(err).Str("user_id", user.ID).Msg("saml: JWT sign failed")
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to issue token")
	}

	return c.JSON(http.StatusOK, map[string]any{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"user_id":      user.ID,
		"email":        user.Email,
	})
}

// GetSAMLConfig handles GET /api/v1/admin/saml-config (tenant-scoped, admin:access required).
func (h *SAMLHandler) GetSAMLConfig(c echo.Context) error {
	claims, ok := c.Get("user").(*auth.Claims)
	if !ok || claims == nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "authorization required")
	}
	cfg, err := h.svc.GetConfig(c.Request().Context(), claims.TenantID)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "SAML config not found")
	}
	return c.JSON(http.StatusOK, cfg)
}

// UpsertSAMLConfig handles PUT /api/v1/admin/saml-config (tenant-scoped, admin:access required).
func (h *SAMLHandler) UpsertSAMLConfig(c echo.Context) error {
	claims, ok := c.Get("user").(*auth.Claims)
	if !ok || claims == nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "authorization required")
	}
	tenantID := claims.TenantID
	var req samlsvc.SAMLConfig
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	cfg, err := h.svc.UpsertConfig(c.Request().Context(), tenantID, req)
	if err != nil {
		h.logger.Error().Err(err).Str("tenant_id", tenantID).Msg("saml: config upsert failed")
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to save SAML config")
	}
	return c.JSON(http.StatusOK, cfg)
}
