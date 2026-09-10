package handlers

import (
	"errors"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog"

	"github.com/engineersmind/emc-auth-server/internal/audit"
	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/metrics"
)

// RFC 6749 §5.2 error codes for the token endpoint.
const (
	errInvalidClient        = "invalid_client"
	errInvalidGrant         = "invalid_grant"
	errUnsupportedGrantType = "unsupported_grant_type"
)

// TokenResponse is the RFC 6749 §5.1 successful token response.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	// RefreshToken is omitted for client_credentials: RFC 6749 §4.4.3 says a
	// refresh token SHOULD NOT be issued, because a client that can present its
	// own credentials can simply ask for another token.
	RefreshToken string `json:"refresh_token,omitempty"`
	// IDToken appears only when the granted scopes include `openid`. Its
	// presence is what makes this an OIDC response rather than a plain OAuth 2.0 one.
	IDToken string `json:"id_token,omitempty"`
	// Scope is the GRANTED set, which may be narrower than what was requested
	// (RFC 6749 §3.3). Echoed so a client can see what it actually received
	// rather than assuming its request was honoured in full.
	Scope string `json:"scope,omitempty"`
}

// tokenError is the RFC 6749 §5.2 error response shape. Field names are fixed
// by the RFC — `error`, not `code`, and `error_description`, not `message` —
// because standard client libraries parse exactly these.
type tokenError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// OAuthTokenHandler serves POST /oauth/token and POST /oauth/revoke.
//
// This is the RFC 6749 token endpoint and it is form-encoded, unlike the
// pre-existing JSON POST /auth/token. That difference is not stylistic: every
// conformant OAuth client library posts application/x-www-form-urlencoded here,
// and #7b's discovery document will name this path as the token_endpoint.
// /auth/token keeps working unchanged as a documented-deprecated alias.
type OAuthTokenHandler struct {
	authz   *auth.AuthorizationServer
	authSvc *auth.AuthService
	jwtSvc  *auth.JWTService
	appSvc  *auth.ApplicationService
	audit   *audit.Logger
	logger  zerolog.Logger
}

// NewOAuthTokenHandler builds the handler.
func NewOAuthTokenHandler(
	authz *auth.AuthorizationServer,
	authSvc *auth.AuthService,
	jwtSvc *auth.JWTService,
	appSvc *auth.ApplicationService,
	auditLog *audit.Logger,
	logger zerolog.Logger,
) *OAuthTokenHandler {
	return &OAuthTokenHandler{
		authz: authz, authSvc: authSvc, jwtSvc: jwtSvc,
		appSvc: appSvc, audit: auditLog, logger: logger,
	}
}

// Token handles POST /oauth/token.
//
// @Summary      OAuth 2.0 token endpoint
// @Description  Exchanges credentials for tokens. Supports authorization_code (with mandatory PKCE), refresh_token, and client_credentials. Form-encoded per RFC 6749 — not JSON. Client authentication via Authorization Basic or client_secret_post; public clients authenticate with PKCE alone.
// @Tags         oauth
// @Accept       x-www-form-urlencoded
// @Produce      json
// @Param        grant_type     formData  string  true   "authorization_code | refresh_token | client_credentials"
// @Param        code           formData  string  false  "Required for authorization_code"
// @Param        code_verifier  formData  string  false  "Required for authorization_code"
// @Param        redirect_uri   formData  string  false  "Must match the value the code was issued against"
// @Param        refresh_token  formData  string  false  "Required for refresh_token"
// @Param        client_id      formData  string  false  "Required for public clients"
// @Param        client_secret  formData  string  false  "Confidential clients — prefer the Authorization Basic header"
// @Param        scope          formData  string  false  "client_credentials only"
// @Success      200  {object}  TokenResponse
// @Failure      400  {object}  tokenError
// @Failure      401  {object}  tokenError
// @Router       /oauth/token [post]
func (h *OAuthTokenHandler) Token(c echo.Context) error {
	// RFC 6749 §5.1 requires no-store on every token response, successful or
	// not. Set before any branch so no early return can skip it.
	c.Response().Header().Set("Cache-Control", "no-store")
	c.Response().Header().Set("Pragma", "no-cache")

	switch c.FormValue("grant_type") {
	case "authorization_code":
		return h.authorizationCodeGrant(c)
	case "refresh_token":
		return h.refreshTokenGrant(c)
	case "client_credentials":
		return h.clientCredentialsGrant(c)
	case "":
		return h.fail(c, http.StatusBadRequest, errInvalidRequest, "grant_type is required")
	default:
		return h.fail(c, http.StatusBadRequest, errUnsupportedGrantType,
			"supported grant types are authorization_code, refresh_token and client_credentials")
	}
}

// clientCredentials extracts client_id and client_secret from either the
// Authorization Basic header (RFC 6749 §2.3.1, the preferred form) or the
// request body (client_secret_post, §2.3.1's permitted alternative).
//
// Both are supported because real clients use both, and the discovery document
// will advertise both. The header takes precedence when present so a request
// carrying conflicting values cannot pick whichever set the caller prefers.
func clientCredentialsFromRequest(c echo.Context) (clientID, clientSecret string) {
	if h := c.Request().Header.Get("Authorization"); strings.HasPrefix(h, "Basic ") {
		if id, secret, ok := c.Request().BasicAuth(); ok {
			return id, secret
		}
	}
	return c.FormValue("client_id"), c.FormValue("client_secret")
}

// requestedAudience reads the audience the caller is asking for, accepting both
// spellings (issue #131).
//
// `audience` is Auth0's parameter name and is what an integrator arriving from
// there will send; `resource` is RFC 8707 §2 and is what a conformant library
// sends. Both are supported because both populations are real, and `audience`
// wins when they disagree — a client sending two different values is confused
// rather than hostile, and honouring the vendor-compatible one keeps the
// behaviour predictable for exactly the callers who send both.
//
// Only ONE value is honoured even though RFC 8707 permits `resource` to repeat:
// a token minted here carries exactly one audience. Multi-valued `aud` is legal
// JWT but means "valid at every one of these", which is the shared audience
// issue #131 exists to abolish.
func requestedAudience(c echo.Context) string {
	if v := c.FormValue("audience"); v != "" {
		return v
	}
	return c.FormValue("resource")
}

// authenticateClient resolves and, where required, authenticates the client.
//
// A confidential client (one with a stored secret) must present it. A public
// client presents none — for those, PKCE is the only proof, which is why PKCE
// is mandatory rather than optional in this server.
func (h *OAuthTokenHandler) authenticateClient(c echo.Context, clientID, clientSecret string) (*auth.AuthzClient, error) {
	client, err := h.authz.LookupClient(c.Request().Context(), clientID)
	if err != nil {
		return nil, auth.ErrInvalidClient
	}
	if !client.Confidential {
		// A public client that sends a secret is misconfigured, but rejecting
		// it would break nothing an attacker cares about and would surprise a
		// client that sends an empty one. The absence of a stored secret is
		// what makes it public; there is nothing to compare against.
		return client, nil
	}
	if clientSecret == "" {
		return nil, auth.ErrInvalidClient
	}
	// Delegated to the registry, which matches on the stored SHA-256 rather
	// than the raw secret. The comparison itself is a SQL equality and is not
	// constant-time, but the value being compared is a digest of the presented
	// secret: timing tells an attacker how much of a HASH they matched, and
	// walking that back to a secret needs a preimage. Same property the API-key
	// and refresh-token lookups already rely on.
	if _, _, err := h.appSvc.AuthenticateClient(c.Request().Context(), client.ClientID, clientSecret); err != nil {
		return nil, auth.ErrInvalidClient
	}
	return client, nil
}

// authorizationCodeGrant implements RFC 6749 §4.1.3.
func (h *OAuthTokenHandler) authorizationCodeGrant(c echo.Context) error {
	ctx := c.Request().Context()
	clientID, clientSecret := clientCredentialsFromRequest(c)

	client, err := h.authenticateClient(c, clientID, clientSecret)
	if err != nil {
		// 401 with a WWW-Authenticate challenge when credentials came through
		// the Authorization header, per RFC 6749 §5.2.
		return h.failClient(c)
	}
	if !auth.AllowsGrant(client, "authorization_code") {
		return h.fail(c, http.StatusBadRequest, errUnauthorizedClient,
			"this client is not permitted to use the authorization_code grant")
	}

	code := c.FormValue("code")
	verifier := c.FormValue("code_verifier")
	redirectURI := c.FormValue("redirect_uri")

	redeemed, err := h.authz.RedeemAuthorizationCode(ctx, client.ClientID, code, redirectURI, verifier)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrAuthorizationCodeReplayed):
			// A replayed code means the code was seen by someone who should not
			// have had it. Audited and counted separately from an ordinary
			// invalid code, even though the client is told the same thing.
			h.auditCode(c, "oauth.code_replayed", client, redeemed, false)
			metrics.OAuthGrants.WithLabelValues("authorization_code", "replayed").Inc()
			return h.fail(c, http.StatusBadRequest, errInvalidGrant,
				"authorization code is invalid or expired")
		case errors.Is(err, auth.ErrInvalidCodeVerifier),
			errors.Is(err, auth.ErrUnsupportedChallengeMethod):
			metrics.OAuthGrants.WithLabelValues("authorization_code", "pkce_failed").Inc()
			return h.fail(c, http.StatusBadRequest, errInvalidGrant,
				"code_verifier does not match the code_challenge")
		case errors.Is(err, auth.ErrInvalidAuthorizationCode):
			metrics.OAuthGrants.WithLabelValues("authorization_code", "invalid").Inc()
			return h.fail(c, http.StatusBadRequest, errInvalidGrant,
				"authorization code is invalid or expired")
		default:
			h.logger.Error().Err(err).Msg("token: authorization code redemption failed")
			metrics.OAuthGrants.WithLabelValues("authorization_code", "error").Inc()
			return h.fail(c, http.StatusInternalServerError, errServerError, "internal error")
		}
	}

	// Tenant cross-check. The code carries the tenant it was issued in and the
	// client carries its own; a mismatch would mean a code from one tenant
	// being redeemed by a client in another. It should be impossible — the code
	// is bound to client_id — but this is the boundary the whole system rests
	// on, so it is asserted rather than assumed.
	if redeemed.TenantID != client.TenantID {
		h.logger.Error().
			Int64("code_tenant", redeemed.TenantID).
			Int64("client_tenant", client.TenantID).
			Msg("token: tenant mismatch between code and client")
		return h.fail(c, http.StatusBadRequest, errInvalidGrant,
			"authorization code is invalid or expired")
	}

	// A caller that names an audience at exchange time is refused rather than
	// ignored (issue #131).
	//
	// The audience was fixed at /oauth/authorize, grant-checked there and
	// persisted on the code row, because that is the only point where a refusal
	// can still reach the CLIENT rather than a user who has already typed a
	// password. Silently ignoring a mismatched parameter here would leave a
	// client believing it had obtained a token for API B when the code was
	// granted for API A — a discrepancy it would discover only when the resource
	// server refused the token. An equal value is accepted so a client that
	// echoes its own request on both legs is not punished for it.
	if want := requestedAudience(c); want != "" && want != redeemed.Audience {
		metrics.OAuthGrants.WithLabelValues("authorization_code", "invalid_target").Inc()
		return h.fail(c, http.StatusBadRequest, errInvalidTarget,
			"the requested audience does not match the one this authorization code was issued for")
	}

	issued, err := h.authSvc.IssueTokensForAuthorizationCode(
		ctx, redeemed.TenantID, redeemed.UserID, client.RowID, redeemed.Scopes, redeemed.Audience)
	if err != nil {
		// The most likely cause is a user deactivated or deleted between the
		// authorize redirect and this exchange — 60 seconds is short but not
		// zero. invalid_grant is the correct code: the grant is no longer good.
		h.logger.Warn().Err(err).Int64("user_id", redeemed.UserID).
			Msg("token: could not issue tokens for redeemed code")
		metrics.OAuthGrants.WithLabelValues("authorization_code", "user_unavailable").Inc()
		return h.fail(c, http.StatusBadRequest, errInvalidGrant,
			"the authorization is no longer valid")
	}

	resp := TokenResponse{
		AccessToken:  issued.Tokens.AccessToken,
		TokenType:    "Bearer",
		ExpiresIn:    issued.Tokens.ExpiresIn,
		RefreshToken: issued.Tokens.RefreshToken,
		Scope:        strings.Join(redeemed.Scopes, " "),
	}

	// An ID token is issued only for an `openid` request. Sending one
	// unconditionally would turn every plain OAuth 2.0 exchange into an OIDC
	// response and hand identity claims to a client that asked only for
	// delegated access.
	if auth.HasScope(redeemed.Scopes, auth.ScopeOpenID) {
		idToken, err := h.jwtSvc.SignIDToken(ctx, auth.IDTokenParams{
			TenantID:      redeemed.TenantID,
			ClientID:      client.ClientID,
			GrantedScopes: redeemed.Scopes,
			Nonce:         redeemed.Nonce,
			AuthTime:      redeemed.AuthTime,
			AccessToken:   issued.Tokens.AccessToken,
		}, issued.Subject)
		if err != nil {
			h.logger.Error().Err(err).Msg("token: ID token signing failed")
			return h.fail(c, http.StatusInternalServerError, errServerError, "internal error")
		}
		resp.IDToken = idToken
	}

	h.auditCode(c, "oauth.code_exchanged", client, redeemed, true)
	metrics.OAuthGrants.WithLabelValues("authorization_code", "success").Inc()
	return c.JSON(http.StatusOK, resp)
}

// refreshTokenGrant implements RFC 6749 §6, delegating to the existing rotation
// logic so replay detection and session-family revocation behave identically
// whether a token is refreshed here or at /auth/refresh.
func (h *OAuthTokenHandler) refreshTokenGrant(c echo.Context) error {
	ctx := c.Request().Context()
	clientID, clientSecret := clientCredentialsFromRequest(c)

	// Client authentication is required here whenever the client is
	// confidential. RFC 6749 §6 requires it, and skipping it would let a
	// stolen refresh token be used without the secret that was needed to obtain
	// it in the first place.
	//
	// A request carrying NO client_id at all therefore proceeds unauthenticated,
	// and that is intended, not the unauthenticated-revocation bug PR #107 fixed
	// on /oauth/revoke. The two differ in what the caller must already hold. A
	// public client has no secret to authenticate with by definition (RFC 6749
	// §6, §2.1) — a native or browser app cannot keep one — so refusing an
	// unauthenticated refresh would make the grant unusable for exactly the
	// clients PKCE exists to serve. The refresh token itself is the credential
	// here: it is single-use, rotated on every call, and a replay revokes the
	// whole family, so presenting one is proof of possession in a way that
	// #107's case was not (revoke needed no valid token at all — any guessed
	// value reached the UPDATE).
	//
	// What this does NOT do is let a caller pick which client they are. Omitting
	// client_id skips authentication; it never grants a client's identity. The
	// tenant and application the new tokens are scoped to come from the stored
	// refresh-token row, not from the request: Refresh is handed the raw token
	// and nothing else.
	//
	// The converse is not checked — an authenticated client_id is not compared
	// against the application that owns the refresh token, so two clients in one
	// tenant could refresh each other's tokens if one obtained the other's. Same
	// missing column as CLAUDE.md deferred #22 (refresh_tokens has no
	// application_id) and it is fixed there, for both endpoints at once, rather
	// than half-solved here.
	if clientID != "" {
		client, err := h.authenticateClient(c, clientID, clientSecret)
		if err != nil {
			return h.failClient(c)
		}
		if !auth.AllowsGrant(client, "refresh_token") {
			return h.fail(c, http.StatusBadRequest, errUnauthorizedClient,
				"this client is not permitted to use the refresh_token grant")
		}
	}

	raw := c.FormValue("refresh_token")
	if raw == "" {
		return h.fail(c, http.StatusBadRequest, errInvalidRequest, "refresh_token is required")
	}

	result, err := h.authSvc.Refresh(ctx, raw)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidTarget) || errors.Is(err, auth.ErrAudienceRequired) {
			// A rotation cannot change the audience its chain was issued for, and
			// a grant revoked since the last rotation stops the chain here rather
			// than at the next fresh login (issue #131).
			metrics.OAuthGrants.WithLabelValues("refresh_token", "invalid_target").Inc()
			return h.fail(c, http.StatusBadRequest, errInvalidTarget,
				"the requested audience is not available to this client")
		}
		if errors.Is(err, auth.ErrTokenReplay) {
			metrics.OAuthGrants.WithLabelValues("refresh_token", "replayed").Inc()
			return h.fail(c, http.StatusBadRequest, errInvalidGrant,
				"refresh token was already used — the session has been revoked")
		}
		metrics.OAuthGrants.WithLabelValues("refresh_token", "invalid").Inc()
		return h.fail(c, http.StatusBadRequest, errInvalidGrant,
			"refresh token is invalid or expired")
	}

	metrics.OAuthGrants.WithLabelValues("refresh_token", "success").Inc()
	return c.JSON(http.StatusOK, TokenResponse{
		AccessToken:  result.AccessToken,
		TokenType:    "Bearer",
		ExpiresIn:    result.ExpiresIn,
		RefreshToken: result.RefreshToken,
	})
}

// clientCredentialsGrant implements RFC 6749 §4.4.
//
// Behaviourally identical to the pre-existing POST /auth/token, which continues
// to work. The difference is the wire format — form-encoded here, JSON there —
// and that this path is the one #7b's discovery document will advertise.
func (h *OAuthTokenHandler) clientCredentialsGrant(c echo.Context) error {
	ctx := c.Request().Context()
	clientID, clientSecret := clientCredentialsFromRequest(c)

	if clientID == "" || clientSecret == "" {
		return h.failClient(c)
	}
	// Always the full credential check: a public client cannot use
	// client_credentials at all, because the grant IS the client proving
	// itself, and a client with no secret has nothing to prove.
	tenantID, appRowID, err := h.appSvc.AuthenticateClient(ctx, clientID, clientSecret)
	if err != nil {
		metrics.OAuthGrants.WithLabelValues("client_credentials", "invalid_client").Inc()
		return h.failClient(c)
	}

	client, err := h.authz.LookupClient(ctx, clientID)
	if err == nil && !auth.AllowsGrant(client, "client_credentials") {
		return h.fail(c, http.StatusBadRequest, errUnauthorizedClient,
			"this client is not permitted to use the client_credentials grant")
	}

	// The audience parameter is honoured on this grant, unlike on
	// authorization_code where it is fixed by the code. There is no user and no
	// prior leg here: the client authenticates and asks in the same request, so
	// this IS the point of decision. Empty — every caller that exists today —
	// resolves to the client's own audience, which is what keeps a live
	// client_credentials integration working with no changes at all.
	token, expiresIn, err := h.authSvc.IssueServiceToken(ctx, tenantID, appRowID, requestedAudience(c))
	if err != nil {
		if errors.Is(err, auth.ErrInvalidTarget) || errors.Is(err, auth.ErrAudienceRequired) {
			// invalid_target for both, byte-identical. ErrAudienceRequired means
			// this client has require_audience = true and nothing resolved, which
			// is a configuration fault on our side of the boundary — but reporting
			// it distinctly would tell a caller which clients have enforcement
			// switched on, and that is a map of the #132 rollout.
			metrics.OAuthGrants.WithLabelValues("client_credentials", "invalid_target").Inc()
			return h.fail(c, http.StatusBadRequest, errInvalidTarget,
				"the requested audience is not available to this client")
		}
		h.logger.Error().Err(err).Msg("token: service token issuance failed")
		metrics.OAuthGrants.WithLabelValues("client_credentials", "error").Inc()
		return h.fail(c, http.StatusInternalServerError, errServerError, "internal error")
	}

	metrics.OAuthGrants.WithLabelValues("client_credentials", "success").Inc()
	return c.JSON(http.StatusOK, TokenResponse{
		AccessToken: token,
		TokenType:   "Bearer",
		ExpiresIn:   expiresIn,
		// No refresh token — RFC 6749 §4.4.3.
	})
}

// Revoke handles POST /oauth/revoke — RFC 7009.
//
// @Summary      OAuth 2.0 token revocation
// @Description  Revokes a refresh token. Client authentication is REQUIRED (RFC 7009 §2.1) — the same credentials the token endpoint takes. Returns 200 for an unknown or already-revoked token, per RFC 7009 §2.2; a bad or missing client credential is a 401 invalid_client.
// @Tags         oauth
// @Accept       x-www-form-urlencoded
// @Produce      json
// @Param        token            formData  string  true   "The token to revoke"
// @Param        token_type_hint  formData  string  false  "refresh_token | access_token"
// @Param        client_id        formData  string  true   "Required — prefer the Authorization Basic header"
// @Param        client_secret    formData  string  false  "Confidential clients only"
// @Success      200  "Token revoked, or did not exist"
// @Failure      401  {object}  tokenError  "client authentication failed"
// @Router       /oauth/revoke [post]
func (h *OAuthTokenHandler) Revoke(c echo.Context) error {
	c.Response().Header().Set("Cache-Control", "no-store")
	ctx := c.Request().Context()

	// Client authentication is REQUIRED here, exactly as at the token endpoint
	// (RFC 7009 §2.1) — and it is checked BEFORE the token parameter is read, so
	// an unauthenticated request cannot have any effect at all.
	//
	// There is deliberately no "client_id omitted, so skip the check" branch.
	// With one, possession of a refresh token would itself be sufficient
	// authority to destroy it, and anyone who intercepted one could log the user
	// out from the public internet without presenting a single credential.
	// Revocation is a destructive operation; the bar to reach it is the same bar
	// as the one to mint a token.
	clientID, clientSecret := clientCredentialsFromRequest(c)
	if clientID == "" {
		return h.failClient(c)
	}
	client, err := h.authenticateClient(c, clientID, clientSecret)
	if err != nil {
		return h.failClient(c)
	}

	token := c.FormValue("token")
	if token == "" {
		// Nothing named, nothing to do. Still a 200 — an empty token parameter is
		// a malformed request, not a hint about any token's existence.
		return c.NoContent(http.StatusOK)
	}

	// Scoped to the authenticated client's tenant. An authenticated client must
	// not be able to revoke a token minted in someone else's tenant just by
	// presenting the string.
	//
	// An access token cannot be revoked — it is a self-contained JWT with no
	// server-side record, and it expires in 15 minutes. Revoking the refresh
	// token stops the session continuing past that, which is the meaningful
	// action. token_type_hint is accepted and ignored for the same reason.
	// client.RowID scopes the revocation to the tokens this client actually
	// minted — CLAUDE.md deferred #22, now that refresh_tokens carries
	// application_id (migration 00087). Tenant scoping alone let two clients in
	// one tenant revoke each other's tokens.
	revoked, err := h.authSvc.RevokeRefreshTokenForTenant(ctx, token, client.TenantID, client.RowID)
	if err != nil {
		// A storage fault is ours, not the caller's, and still must not change
		// the response: a 500 here for a token that happens to exist would be
		// exactly the oracle §2.2 forbids.
		h.logger.Error().Err(err).Str("client_id", client.ClientID).
			Msg("revoke: could not revoke refresh token")
		return c.NoContent(http.StatusOK)
	}

	if revoked {
		// Audited only when something was actually revoked, and attributed to the
		// client that has now been authenticated — an audit row for every probe
		// of an unknown string would bury the real revocations in noise.
		h.auditRevoke(c, client)
	} else {
		h.logger.Debug().Str("client_id", client.ClientID).
			Msg("revoke: token not found, already revoked, or belongs to another tenant")
	}

	return c.NoContent(http.StatusOK)
}

// fail writes an RFC 6749 §5.2 error body.
func (h *OAuthTokenHandler) fail(c echo.Context, status int, code, description string) error {
	return c.JSON(status, tokenError{Error: code, ErrorDescription: description})
}

// failClient writes the 401 for a client-authentication failure.
//
// The WWW-Authenticate header is required by RFC 6749 §5.2 whenever the client
// attempted to authenticate via the Authorization header, and several client
// libraries need it to distinguish "bad credentials" from a transport fault.
func (h *OAuthTokenHandler) failClient(c echo.Context) error {
	c.Response().Header().Set("WWW-Authenticate", `Basic realm="oauth", charset="UTF-8"`)
	return c.JSON(http.StatusUnauthorized, tokenError{
		Error:            errInvalidClient,
		ErrorDescription: "client authentication failed",
	})
}

func (h *OAuthTokenHandler) auditCode(c echo.Context, action string, client *auth.AuthzClient, redeemed *auth.RedeemedCode, success bool) {
	if h.audit == nil || client == nil {
		return
	}
	tenantID := client.TenantID
	appRowID := client.RowID
	ev := audit.Event{
		Action:        action,
		TenantID:      &tenantID,
		ApplicationID: &appRowID,
		ResourceType:  "oauth_client",
		ResourceID:    client.ClientID,
		Status:        audit.StatusSuccess,
		AuthMethod:    "authorization_code",
		IPAddress:     c.RealIP(),
		UserAgent:     c.Request().UserAgent(),
	}
	if !success {
		ev.Status = audit.StatusFailure
	}
	if redeemed != nil && redeemed.UserID != 0 {
		userID := redeemed.UserID
		ev.UserID = &userID
		ev.Metadata = map[string]any{"scopes": redeemed.Scopes}
	}
	h.audit.Log(c.Request().Context(), ev)
}

// auditRevoke records a successful revocation against the client that performed
// it. The client is fully authenticated by the time this is called, so tenant and
// application are facts rather than caller-supplied values — which is the whole
// point of an audit row for a destructive operation.
func (h *OAuthTokenHandler) auditRevoke(c echo.Context, client *auth.AuthzClient) {
	if h.audit == nil || client == nil {
		return
	}
	tenantID := client.TenantID
	appRowID := client.RowID
	h.audit.Log(c.Request().Context(), audit.Event{
		Action:        "oauth.token_revoked",
		TenantID:      &tenantID,
		ApplicationID: &appRowID,
		ResourceType:  "oauth_client",
		ResourceID:    client.ClientID,
		Status:        audit.StatusSuccess,
		AuthMethod:    "client_credentials",
		IPAddress:     c.RealIP(),
		UserAgent:     c.Request().UserAgent(),
	})
}
