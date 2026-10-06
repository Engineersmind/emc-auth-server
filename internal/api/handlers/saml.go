package handlers

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	samlsvc "github.com/engineersmind/emc-auth-server/internal/saml"
)

// SAMLHandler holds HTTP handlers for SAML 2.0 endpoints.
type SAMLHandler struct {
	svc    *samlsvc.Service
	logger zerolog.Logger
}

// NewSAMLHandler creates a SAMLHandler with the SAML service required for
// metadata, SP-initiated login, and admin config endpoints. The ACS endpoint
// stays gated at 501 — no token-minting code exists to wire it to
// (GHSA-x432-mmvf-jvqf, L-01).
func NewSAMLHandler(svc *samlsvc.Service, logger zerolog.Logger) *SAMLHandler {
	return &SAMLHandler{svc: svc, logger: logger}
}

// GetMetadata handles GET /saml/metadata?tenant=<tenant_id>
//
// @Summary      Get SP metadata XML
// @Description  Returns SAML Service Provider metadata XML for the given tenant. Used by IdPs to configure the SP.
// @Tags         saml
// @Produce      application/xml
// @Param        tenant  query     string  true  "Tenant ID"
// @Success      200     {string}  string  "SP metadata XML"
// @Failure      400     {object}  map[string]string
// @Failure      500     {object}  map[string]string
// @Router       /saml/metadata [get]
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
//
// @Summary      Initiate SP-initiated SAML SSO
// @Description  Redirects the browser to the configured IdP with a signed SAMLRequest.
// @Tags         saml
// @Param        tenant  query  string  true  "Tenant ID"
// @Success      302  "Redirect to IdP"
// @Failure      400  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /saml/login [get]
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
//
// @Summary      SAML Assertion Consumer Service (disabled)
// @Description  Receives IdP SAMLResponse. Currently returns 501 — disabled until IdP XML signature verification is implemented.
// @Tags         saml
// @Accept       application/x-www-form-urlencoded
// @Produce      json
// @Success      501  {object}  map[string]string  "Not yet implemented"
// @Router       /saml/acs [post]
//
// SECURITY GATE: This endpoint is intentionally disabled until IdP XML signature
// verification is implemented via crewjam/saml or an equivalent library.
// The current ParseACSResponse does not verify the SAMLResponse signature, meaning
// any caller can craft a response asserting any NameID and authenticate as that user.
// Until the gate is lifted, 501 is returned so the risk surface is zero.
func (h *SAMLHandler) HandleACS(c echo.Context) error {
	return echo.NewHTTPError(
		http.StatusNotImplemented,
		"SAML ACS is not yet available: IdP XML signature verification is pending implementation",
	)
}

// GetSAMLConfig handles GET /api/v1/admin/saml-config (tenant-scoped, admin:access required).
//
// @Summary      Get tenant SAML configuration
// @Description  Returns the SAML IdP configuration for the requesting tenant. Requires admin:access.
// @Tags         saml
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  saml.SAMLConfig
// @Failure      401  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /api/v1/saml-config [get]
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
//
// @Summary      Create or update tenant SAML configuration
// @Description  Upserts the SAML IdP configuration for the requesting tenant. Requires admin:access.
// @Tags         saml
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body  body      saml.SAMLConfig  true  "SAML config"
// @Success      200   {object}  saml.SAMLConfig
// @Failure      400   {object}  map[string]string
// @Failure      401   {object}  map[string]string
// @Router       /api/v1/saml-config [put]
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
