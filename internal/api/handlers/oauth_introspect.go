package handlers

import (
	"net/http"

	"github.com/labstack/echo/v4"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/metrics"
)

// Introspect handles POST /oauth/introspect (RFC 7662).
//
// The live check behind a locally verified JWT: a relying party that cannot
// wait for a token to expire — before approving, revealing or sending — asks
// here whether it is still good. Revoked sessions, deactivated users and, for
// an organisation token, removed or suspended memberships all answer
// {"active": false}.
//
// Only a CONFIDENTIAL client may call it (RFC 7662 §2.1 requires the caller to
// be authorised), and only for tokens issued to its own application. A public
// client holds no secret, so it cannot prove it is the application it names.
//
// @Summary      Introspect a token
// @Description  RFC 7662. Confidential clients only, authenticated with client_secret_basic or client_secret_post. Returns {"active": false} for any token that is invalid, expired, revoked, issued to another application, or whose user or organization membership is no longer active; otherwise the token's claims, including org_id and org_permissions for an organization session.
// @Tags         oauth
// @Accept       application/x-www-form-urlencoded
// @Produce      json
// @Param        token            formData  string  true   "The token"
// @Param        token_type_hint  formData  string  false  "access_token or refresh_token"
// @Success      200  {object}  auth.IntrospectionResult
// @Failure      401  {object}  tokenError  "invalid_client"
// @Router       /oauth/introspect [post]
func (h *OAuthTokenHandler) Introspect(c echo.Context) error {
	c.Response().Header().Set("Cache-Control", "no-store")
	c.Response().Header().Set("Pragma", "no-cache")
	ctx := c.Request().Context()

	clientID, clientSecret := clientCredentialsFromRequest(c)
	if clientID == "" || clientSecret == "" {
		return h.failClient(c)
	}
	client, err := h.authenticateClient(c, clientID, clientSecret)
	if err != nil || !client.Confidential {
		return h.failClient(c)
	}

	res := h.authSvc.Introspect(ctx, auth.IntrospectionClient{
		ClientID: client.ClientID, TenantID: client.TenantID, AppRowID: client.RowID,
	}, c.FormValue("token"), c.FormValue("token_type_hint"))
	outcome := "inactive"
	if res.Active {
		outcome = "active"
	}
	metrics.OAuthGrants.WithLabelValues("introspection", outcome).Inc()
	return c.JSON(http.StatusOK, res)
}
