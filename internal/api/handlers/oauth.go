package handlers

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog"

	"github.com/engineersmind/emc-auth-server/internal/audit"
	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/metrics"
)

// OAuthHandler holds HTTP handlers for social login (issue #64): the browser
// redirect endpoints, the login-code exchange, and the admin config API.
type OAuthHandler struct {
	svc    *auth.OAuthLoginService
	idpSvc *auth.IdentityProviderService
	audit  *audit.Logger
	logger zerolog.Logger
}

// NewOAuthHandler creates an OAuthHandler.
func NewOAuthHandler(svc *auth.OAuthLoginService, idpSvc *auth.IdentityProviderService, auditLog *audit.Logger, logger zerolog.Logger) *OAuthHandler {
	return &OAuthHandler{svc: svc, idpSvc: idpSvc, audit: auditLog, logger: logger}
}

// Login handles GET /oauth/:provider/login?client_id=...&redirect=...
//
// @Summary      Start social login
// @Description  Validates the application and redirect target, then redirects the browser to the provider's consent screen (Authorization Code + PKCE).
// @Tags         oauth
// @Param        provider   path   string  true   "Provider (google)"
// @Param        client_id  query  string  true   "Application client_id"
// @Param        redirect   query  string  false  "Post-login redirect target (must be in the application's allow-list; optional when the list has exactly one entry)"
// @Success      302  "Redirect to provider"
// @Failure      400  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /oauth/{provider}/login [get]
func (h *OAuthHandler) Login(c echo.Context) error {
	provider := c.Param("provider")
	clientID := c.QueryParam("client_id")
	redirect := c.QueryParam("redirect")

	authURL, err := h.svc.BuildAuthURL(c.Request().Context(), provider, clientID, redirect)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrProviderNotSupported):
			return echo.NewHTTPError(http.StatusNotFound, "unknown identity provider")
		case errors.Is(err, auth.ErrProviderNotConfigured):
			return echo.NewHTTPError(http.StatusNotFound, "social login is not available for this application")
		case errors.Is(err, auth.ErrInvalidClient):
			return echo.NewHTTPError(http.StatusBadRequest, "invalid client_id")
		case errors.Is(err, auth.ErrInvalidRedirectURI):
			return echo.NewHTTPError(http.StatusBadRequest, "redirect target is not allowed for this application")
		default:
			h.logger.Error().Err(err).Str("provider", provider).Msg("oauth: build auth url failed")
			return echo.NewHTTPError(http.StatusInternalServerError, "failed to start login")
		}
	}
	return c.Redirect(http.StatusFound, authURL)
}

// Callback handles GET /oauth/:provider/callback?code=...&state=...
//
// @Summary      Social login callback
// @Description  Consumes the single-use state, exchanges the code (PKCE), verifies the provider ID token, resolves/links/provisions the user, and redirects back to the application with a one-time login_code.
// @Tags         oauth
// @Param        provider  path   string  true   "Provider (google)"
// @Param        code      query  string  false  "Authorization code from the provider"
// @Param        state     query  string  true   "Opaque state issued at login start"
// @Param        error     query  string  false  "Provider error (e.g. access_denied)"
// @Success      302  "Redirect back to the application"
// @Failure      400  {object}  map[string]string
// @Router       /oauth/{provider}/callback [get]
func (h *OAuthHandler) Callback(c echo.Context) error {
	ctx := c.Request().Context()
	provider := c.Param("provider")

	// State is consumed FIRST and exactly once — even on provider-reported
	// errors — so the attempt can never be replayed and the validated
	// redirect target is recovered for user-facing failure redirects.
	st, err := h.svc.ConsumeState(ctx, provider, c.QueryParam("state"))
	if err != nil {
		if !errors.Is(err, auth.ErrOAuthStateInvalid) {
			h.logger.Error().Err(err).Str("provider", provider).Msg("oauth: consume state failed")
		}
		h.auditLoginFailed(c, nil, "state")
		return echo.NewHTTPError(http.StatusBadRequest, "login attempt is invalid or expired — please try again")
	}

	// Provider-reported error (user denied consent, etc.) — fail closed back
	// to the allow-listed target with a generic code.
	if errParam := c.QueryParam("error"); errParam != "" {
		h.auditLoginFailed(c, st, "consent_denied")
		return c.Redirect(http.StatusFound, auth.AppendLoginError(st.Redirect, "access_denied"))
	}

	result, err := h.svc.HandleCallback(ctx, st, c.QueryParam("code"))
	if err != nil {
		code := "login_failed"
		switch {
		case errors.Is(err, auth.ErrOAuthEmailNotVerified):
			code = "email_not_verified"
		case errors.Is(err, auth.ErrOAuthLinkConflict):
			code = "account_conflict"
		case errors.Is(err, auth.ErrProviderNotConfigured):
			// Disabled mid-flight — same generic failure as any other.
		default:
			h.logger.Error().Err(err).Str("provider", provider).Msg("oauth: callback failed")
		}
		h.auditLoginFailed(c, st, code)
		return c.Redirect(http.StatusFound, auth.AppendLoginError(st.Redirect, code))
	}

	metrics.SocialLogin.WithLabelValues("google", "success").Inc()
	h.auditEvent(c, audit.Event{
		TenantID:     &result.TenantID,
		UserID:       &result.UserID,
		ActorEmail:   result.Email,
		Action:       audit.ActionAuthGoogleLogin,
		AuthMethod:   audit.AuthMethodGoogle,
		ResourceType: "user",
		ResourceID:   strconv.FormatInt(result.UserID, 10),
		IPAddress:    c.RealIP(),
		UserAgent:    c.Request().UserAgent(),
	})
	if result.Outcome == "linked" {
		h.auditEvent(c, audit.Event{
			TenantID:     &result.TenantID,
			UserID:       &result.UserID,
			ActorEmail:   result.Email,
			Action:       audit.ActionAuthGoogleLinked,
			ResourceType: "user",
			ResourceID:   strconv.FormatInt(result.UserID, 10),
			IPAddress:    c.RealIP(),
			UserAgent:    c.Request().UserAgent(),
		})
	}

	return c.Redirect(http.StatusFound, result.RedirectURI)
}

// auditLoginFailed writes the failure audit event. st may be nil when the
// state itself was invalid (no tenant context is known in that case).
func (h *OAuthHandler) auditLoginFailed(c echo.Context, st *auth.OAuthState, reason string) {
	e := audit.Event{
		Action:       audit.ActionAuthGoogleLoginFailed,
		AuthMethod:   audit.AuthMethodGoogle,
		ResourceType: "user",
		ResourceID:   reason,
		IPAddress:    c.RealIP(),
		UserAgent:    c.Request().UserAgent(),
		Metadata:     map[string]any{"reason": reason, "error_code": reason, "provider": c.Param("provider")},
	}
	if st != nil {
		e.TenantID = &st.TenantID
	}
	metrics.SocialLogin.WithLabelValues("google", "failure").Inc()
	h.auditEvent(c, e)
}

// OAuthExchangeRequest is the payload for POST /api/v1/auth/oauth/exchange.
type OAuthExchangeRequest struct {
	ClientID  string `json:"client_id"`
	LoginCode string `json:"login_code"`
}

// Exchange handles POST /api/v1/auth/oauth/exchange — swaps the one-time
// login_code for the standard access + refresh token pair.
//
// @Summary      Exchange social login code for tokens
// @Description  Consumes the single-use login_code issued by the social login callback and returns the standard access + refresh token pair.
// @Tags         oauth
// @Accept       json
// @Produce      json
// @Param        body  body      OAuthExchangeRequest  true  "client_id + login_code"
// @Success      200   {object}  auth.AuthResult
// @Failure      400   {object}  map[string]string
// @Failure      401   {object}  map[string]string
// @Router       /api/v1/auth/oauth/exchange [post]
func (h *OAuthHandler) Exchange(c echo.Context) error {
	var req OAuthExchangeRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}
	if req.ClientID == "" || req.LoginCode == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "client_id and login_code are required")
	}

	tokens, err := h.svc.ExchangeLoginCode(c.Request().Context(), req.ClientID, req.LoginCode)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidLoginCode) {
			return echo.NewHTTPError(http.StatusUnauthorized, "invalid or expired login code")
		}
		h.logger.Error().Err(err).Msg("oauth: login code exchange failed")
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to exchange login code")
	}
	return c.JSON(http.StatusOK, tokens)
}

// ─── Admin: identity provider configuration ─────────────────────────────────

// UpsertProviderConfigRequest is the payload for the admin upsert endpoint.
// ClientSecret may be omitted on update to keep the stored secret unchanged.
type UpsertProviderConfigRequest struct {
	ClientID      string   `json:"client_id"`
	ClientSecret  string   `json:"client_secret"`
	Enabled       bool     `json:"enabled"`
	RedirectAllow []string `json:"redirect_allow"`
}

// adminTenantAndApp extracts the caller's tenant from JWT claims and the
// application row id from the :appID path param. The tenant in the JWT is
// authoritative — the service layer re-checks the app belongs to it.
func adminTenantAndApp(c echo.Context) (tenantID, appID int64, claims *auth.Claims, err error) {
	claims, ok := c.Get("user").(*auth.Claims)
	if !ok || claims == nil {
		return 0, 0, nil, echo.NewHTTPError(http.StatusUnauthorized, "authorization required")
	}
	tenantID, err = strconv.ParseInt(claims.TenantID, 10, 64)
	if err != nil {
		return 0, 0, nil, echo.NewHTTPError(http.StatusUnauthorized, "invalid tenant in token")
	}
	appID, err = strconv.ParseInt(c.Param("appID"), 10, 64)
	if err != nil {
		return 0, 0, nil, echo.NewHTTPError(http.StatusBadRequest, "invalid application id")
	}
	return tenantID, appID, claims, nil
}

// adminTenantAndUser mirrors adminTenantAndApp for the /users/:id/identities
// routes (flat user routes use :id, not :uid).
func adminTenantAndUser(c echo.Context) (tenantID, userID int64, claims *auth.Claims, err error) {
	claims, ok := c.Get("user").(*auth.Claims)
	if !ok || claims == nil {
		return 0, 0, nil, echo.NewHTTPError(http.StatusUnauthorized, "authorization required")
	}
	tenantID, err = strconv.ParseInt(claims.TenantID, 10, 64)
	if err != nil {
		return 0, 0, nil, echo.NewHTTPError(http.StatusUnauthorized, "invalid tenant in token")
	}
	userID, err = strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		return 0, 0, nil, echo.NewHTTPError(http.StatusBadRequest, "invalid user id")
	}
	return tenantID, userID, claims, nil
}

// ListUserIdentities handles GET /api/v1/users/:id/identities
//
// @Summary      List a user's linked social identities
// @Description  Returns the external identities (Google etc.) linked to one user in the caller's tenant. Requires users:read.
// @Tags         oauth
// @Produce      json
// @Security     BearerAuth
// @Param        id  path      string  true  "User ID"
// @Success      200 {array}   auth.UserIdentityDetail
// @Failure      400 {object}  map[string]string
// @Router       /api/v1/users/{id}/identities [get]
func (h *OAuthHandler) ListUserIdentities(c echo.Context) error {
	tenantID, userID, _, err := adminTenantAndUser(c)
	if err != nil {
		return err
	}
	identities, err := h.idpSvc.ListUserIdentities(c.Request().Context(), tenantID, userID)
	if err != nil {
		h.logger.Error().Err(err).Msg("oauth: list user identities failed")
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to list identities")
	}
	return c.JSON(http.StatusOK, identities)
}

// UnlinkUserIdentity handles DELETE /api/v1/users/:id/identities/:provider
//
// @Summary      Unlink a social identity from a user
// @Description  Removes the provider link. Refused when it is the user's only login method (no password and no other identity). Requires users:write.
// @Tags         oauth
// @Security     BearerAuth
// @Param        id        path  string  true  "User ID"
// @Param        provider  path  string  true  "Provider (google)"
// @Success      204  "Unlinked"
// @Failure      404  {object}  map[string]string
// @Failure      409  {object}  map[string]string
// @Router       /api/v1/users/{id}/identities/{provider} [delete]
func (h *OAuthHandler) UnlinkUserIdentity(c echo.Context) error {
	tenantID, userID, claims, err := adminTenantAndUser(c)
	if err != nil {
		return err
	}
	provider := c.Param("provider")
	if err := h.idpSvc.UnlinkUserIdentity(c.Request().Context(), tenantID, userID, provider); err != nil {
		switch {
		case errors.Is(err, auth.ErrProviderNotSupported), errors.Is(err, auth.ErrIdentityNotFound):
			return echo.NewHTTPError(http.StatusNotFound, "identity not found")
		case errors.Is(err, auth.ErrLastLoginMethod):
			return echo.NewHTTPError(http.StatusConflict, "cannot unlink the user's only login method")
		default:
			h.logger.Error().Err(err).Msg("oauth: unlink identity failed")
			return echo.NewHTTPError(http.StatusInternalServerError, "failed to unlink identity")
		}
	}

	h.auditEvent(c, audit.Event{
		TenantID:     &tenantID,
		ActorEmail:   claims.Email,
		Action:       audit.ActionAdminUserIdentityUnlinked,
		ResourceType: "user",
		ResourceID:   c.Param("id") + ":" + provider,
		IPAddress:    c.RealIP(),
		UserAgent:    c.Request().UserAgent(),
	})
	return c.NoContent(http.StatusNoContent)
}

// UpsertProviderConfig handles PUT /api/v1/applications/:appID/identity-providers/:provider
//
// @Summary      Configure a social login provider for an application
// @Description  Creates or updates the provider credentials (client secret stored AES-256-GCM encrypted) and the exact-match redirect allow-list. Requires apps:write.
// @Tags         oauth
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        appID     path      string                       true  "Application ID"
// @Param        provider  path      string                       true  "Provider (google)"
// @Param        body      body      UpsertProviderConfigRequest  true  "Provider config"
// @Success      200       {object}  auth.ProviderConfigDetail
// @Failure      400       {object}  map[string]string
// @Failure      404       {object}  map[string]string
// @Router       /api/v1/applications/{appID}/identity-providers/{provider} [put]
func (h *OAuthHandler) UpsertProviderConfig(c echo.Context) error {
	tenantID, appID, claims, err := adminTenantAndApp(c)
	if err != nil {
		return err
	}
	var req UpsertProviderConfigRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}

	detail, err := h.idpSvc.UpsertConfig(c.Request().Context(), tenantID, appID, auth.UpsertProviderConfigInput{
		Provider:      c.Param("provider"),
		ClientID:      req.ClientID,
		ClientSecret:  req.ClientSecret,
		Enabled:       req.Enabled,
		RedirectAllow: req.RedirectAllow,
	})
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrProviderNotSupported):
			return echo.NewHTTPError(http.StatusBadRequest, "unknown identity provider")
		case errors.Is(err, auth.ErrAppNotFound):
			return echo.NewHTTPError(http.StatusNotFound, "application not found")
		default:
			// Validation messages from the service are safe to surface.
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}
	}

	h.auditEvent(c, audit.Event{
		TenantID:      &tenantID,
		ApplicationID: &appID,
		ActorEmail:    claims.Email,
		Action:        audit.ActionAdminIdPConfigUpdated,
		ResourceType:  "application",
		ResourceID:    c.Param("appID") + ":" + detail.Provider,
		IPAddress:     c.RealIP(),
		UserAgent:     c.Request().UserAgent(),
	})
	return c.JSON(http.StatusOK, detail)
}

// ListProviderConfigs handles GET /api/v1/applications/:appID/identity-providers
//
// @Summary      List social login providers configured for an application
// @Description  Returns provider configs without secrets. Requires apps:read.
// @Tags         oauth
// @Produce      json
// @Security     BearerAuth
// @Param        appID  path      string  true  "Application ID"
// @Success      200    {array}   auth.ProviderConfigDetail
// @Failure      400    {object}  map[string]string
// @Router       /api/v1/applications/{appID}/identity-providers [get]
func (h *OAuthHandler) ListProviderConfigs(c echo.Context) error {
	tenantID, appID, _, err := adminTenantAndApp(c)
	if err != nil {
		return err
	}
	configs, err := h.idpSvc.ListConfigs(c.Request().Context(), tenantID, appID)
	if err != nil {
		h.logger.Error().Err(err).Msg("oauth: list provider configs failed")
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to list provider configs")
	}
	return c.JSON(http.StatusOK, configs)
}

// DeleteProviderConfig handles DELETE /api/v1/applications/:appID/identity-providers/:provider
//
// @Summary      Remove a social login provider from an application
// @Description  Deletes the provider config. Existing linked identities and sessions are unaffected; new logins via this provider stop immediately. Requires apps:write.
// @Tags         oauth
// @Security     BearerAuth
// @Param        appID     path  string  true  "Application ID"
// @Param        provider  path  string  true  "Provider (google)"
// @Success      204  "Deleted"
// @Failure      404  {object}  map[string]string
// @Router       /api/v1/applications/{appID}/identity-providers/{provider} [delete]
func (h *OAuthHandler) DeleteProviderConfig(c echo.Context) error {
	tenantID, appID, claims, err := adminTenantAndApp(c)
	if err != nil {
		return err
	}
	provider := c.Param("provider")
	if err := h.idpSvc.DeleteConfig(c.Request().Context(), tenantID, appID, provider); err != nil {
		switch {
		case errors.Is(err, auth.ErrProviderNotSupported), errors.Is(err, auth.ErrProviderNotConfigured):
			return echo.NewHTTPError(http.StatusNotFound, "provider config not found")
		default:
			h.logger.Error().Err(err).Msg("oauth: delete provider config failed")
			return echo.NewHTTPError(http.StatusInternalServerError, "failed to delete provider config")
		}
	}

	h.auditEvent(c, audit.Event{
		TenantID:      &tenantID,
		ApplicationID: &appID,
		ActorEmail:    claims.Email,
		Action:        audit.ActionAdminIdPConfigDeleted,
		ResourceType:  "application",
		ResourceID:    c.Param("appID") + ":" + provider,
		IPAddress:     c.RealIP(),
		UserAgent:     c.Request().UserAgent(),
	})
	return c.NoContent(http.StatusNoContent)
}
