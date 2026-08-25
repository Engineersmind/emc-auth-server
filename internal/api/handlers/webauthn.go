package handlers

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog"

	mw "github.com/engineersmind/emc-auth-server/internal/api/middleware"
	"github.com/engineersmind/emc-auth-server/internal/audit"
	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// ---------------------------------------------------------------------------
// Passkey (WebAuthn) endpoints — issue #112.
//
// Two ceremonies, each two round trips, because WebAuthn is challenge-response:
// "begin" mints a challenge the server remembers, the authenticator signs it,
// "complete" verifies the signature. That is the only structural difference from
// the one-shot TOTP endpoints next door.
//
// Ceremony state never travels through the browser. Both "begin" calls return an
// opaque token that points at server-side Redis state, exactly like the existing
// otp_session_token — so nothing security-relevant can be edited by the client
// between the two calls.
//
// ROUTE NAMING. These are mounted under /auth/passkey and /auth/me/passkeys, not
// /auth/webauthn: "passkey" is the product word a user and a tenant integrator
// read, "WebAuthn" is the protocol word, and the protocol name belongs in the
// implementation rather than in the URL a frontend hardcodes.
// ---------------------------------------------------------------------------

// WebAuthnHandler serves the passkey ceremonies.
type WebAuthnHandler struct {
	svc     *auth.WebAuthnService
	authSvc *auth.AuthService
	// cookieCfg is needed only by the cookie-session variant (SessionLoginFinish).
	cookieCfg mw.CookieConfig
	audit     *audit.Logger
	logger    zerolog.Logger
}

// NewWebAuthnHandler builds the handler. svc may be nil, in which case the
// routes are never registered.
func NewWebAuthnHandler(svc *auth.WebAuthnService, authSvc *auth.AuthService, cookieCfg mw.CookieConfig, auditLog *audit.Logger, logger zerolog.Logger) *WebAuthnHandler {
	return &WebAuthnHandler{svc: svc, authSvc: authSvc, cookieCfg: cookieCfg, audit: auditLog, logger: logger}
}

// webauthnBeginResponse wraps the browser options with the ceremony token.
//
// The options go to navigator.credentials.{create,get} untouched; ceremony_token
// comes back to us on the matching "complete" call.
type webauthnBeginResponse struct {
	CeremonyToken string `json:"ceremony_token"`
	PublicKey     any    `json:"publicKey"`
}

// renamePasskeyRequest is the body of PATCH /auth/me/passkeys/:id.
type renamePasskeyRequest struct {
	Name string `json:"name"`
}

// requestOrigin returns the normalised origin of the page making the request.
//
// The Origin header is the browser's own statement of where the page came from
// and is unforgeable by page script, which is what makes it usable here. It is
// present on every cross-origin request and on same-origin POSTs in every
// browser that supports WebAuthn.
//
// Referer is a fallback and nothing more. It carries a full URL rather than an
// origin, so it is trimmed to one; a caller sending neither header gets "",
// which every policy check treats as not allowed. Note that the header only
// selects WHICH policy applies — the credential's own tenant is what authorises
// a sign-in (see WebAuthnService.LoginFinish), and the library independently
// verifies the origin inside the signed clientDataJSON. A lying client changes
// which relying party it is refused by, not whether it is refused.
func requestOrigin(c echo.Context) string {
	if o := auth.NormalizeOrigin(c.Request().Header.Get(echo.HeaderOrigin)); o != "" {
		return o
	}
	return auth.NormalizeOrigin(c.Request().Header.Get("Referer"))
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

// RegisterBegin handles POST /api/v1/auth/passkey/register/begin.
//
// @Summary      Begin passkey registration
// @Description  Returns PublicKeyCredentialCreationOptions for navigator.credentials.create(). Requires an authenticated caller (bearer token or session cookie).
// @Tags         Passkeys
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  webauthnBeginResponse
// @Failure      401  {object}  map[string]string
// @Failure      403  {object}  map[string]string  "passkeys disabled for this tenant, or origin not allowed"
// @Failure      409  {object}  map[string]string  "credential limit reached"
// @Router       /api/v1/auth/passkey/register/begin [post]
func (h *WebAuthnHandler) RegisterBegin(c echo.Context) error {
	claims, ok := c.Get("user").(*auth.Claims)
	if !ok || claims == nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	userID, tenantID, err := idsFromClaims(claims)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid token claims"})
	}

	creation, token, err := h.svc.RegisterBegin(
		c.Request().Context(), userID, tenantID, claims.Email, claims.AppID, requestOrigin(c),
	)
	if err != nil {
		return h.passkeyError(c, claims.UserID, "passkey register begin", err)
	}
	return c.JSON(http.StatusOK, webauthnBeginResponse{CeremonyToken: token, PublicKey: creation.Response})
}

// RegisterComplete handles POST /api/v1/auth/passkey/register/complete.
//
// The attestation is read from the raw request body by the WebAuthn library, so
// the ceremony token and the credential label travel as query parameters rather
// than in the JSON — the body belongs to the protocol, and re-encoding it to add
// our own fields would mean re-serialising the exact bytes the signature covers.
//
// @Summary      Complete passkey registration
// @Description  Verifies the attestation and stores the credential. The request body is the raw PublicKeyCredential from the browser.
// @Tags         Passkeys
// @Produce      json
// @Security     BearerAuth
// @Param        ceremony_token  query  string  true   "Token from register/begin"
// @Param        name            query  string  false  "User-facing label for this passkey (max 64 chars)"
// @Success      201  {object}  auth.StoredCredential
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Failure      403  {object}  map[string]string
// @Failure      409  {object}  map[string]string
// @Router       /api/v1/auth/passkey/register/complete [post]
func (h *WebAuthnHandler) RegisterComplete(c echo.Context) error {
	claims, ok := c.Get("user").(*auth.Claims)
	if !ok || claims == nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	userID, tenantID, err := idsFromClaims(claims)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid token claims"})
	}

	cred, err := h.svc.RegisterComplete(
		c.Request().Context(), userID, tenantID, claims.Email,
		c.QueryParam("ceremony_token"), c.QueryParam("name"), c.Request(),
	)
	if err != nil {
		return h.passkeyError(c, claims.UserID, "passkey register complete", err)
	}

	h.auditPasskey(c, tenantID, userID, claims.Email, audit.ActionAuthPasskeyRegistered, cred.ID, map[string]any{
		"passkey_name":       cred.Name,
		"rp_id":              cred.RPID,
		"authenticator_name": cred.AuthenticatorName,
		"aaguid":             cred.AAGUID,
		"synced":             cred.Synced,
	})
	return c.JSON(http.StatusCreated, cred)
}

// ---------------------------------------------------------------------------
// Passwordless login
// ---------------------------------------------------------------------------

// LoginBegin handles POST /api/v1/auth/passkey/login/begin.
//
// Takes NO parameters, by design. No email, no login hint, nothing that
// identifies an account: the authenticator tells us who the user is at the
// complete step. That is what makes this endpoint useless as an
// account-enumeration oracle, and it is also what conditional-mediation autofill
// needs — the browser calls get() on page load, before the user has typed
// anything.
//
// Because of that, this endpoint is hit once per login-page view by every
// visitor, whether or not they own a passkey.
//
// @Summary      Begin passwordless passkey sign-in
// @Description  Returns PublicKeyCredentialRequestOptions with an empty allowCredentials, usable with either the default mediation (a "sign in with a passkey" button) or mediation:"conditional" (autofill).
// @Tags         Passkeys
// @Produce      json
// @Success      200  {object}  webauthnBeginResponse
// @Failure      403  {object}  map[string]string  "passkeys or passwordless sign-in disabled, or origin not allowed"
// @Router       /api/v1/auth/passkey/login/begin [post]
func (h *WebAuthnHandler) LoginBegin(c echo.Context) error {
	assertion, token, err := h.svc.LoginBegin(c.Request().Context(), requestOrigin(c))
	if err != nil {
		// No audit event here on purpose. This endpoint is hit by every visitor
		// to every login page, so a row per rejection would be a row per bot
		// scan — and nothing has been attempted yet at this point, let alone
		// failed. The refusal is in the server log, which is where an operator
		// looks when a tenant reports the button missing.
		return h.passkeyError(c, "", "passkey login begin", err)
	}
	return c.JSON(http.StatusOK, webauthnBeginResponse{CeremonyToken: token, PublicKey: assertion.Response})
}

// LoginComplete handles POST /api/v1/auth/passkey/login/complete.
//
// @Summary      Complete passwordless passkey sign-in
// @Description  Verifies the assertion and returns a token pair. The request body is the raw PublicKeyCredential from the browser.
// @Tags         Passkeys
// @Produce      json
// @Param        ceremony_token  query  string  true  "Token from login/begin"
// @Success      200  {object}  auth.AuthResult
// @Failure      401  {object}  map[string]string
// @Failure      403  {object}  map[string]string
// @Router       /api/v1/auth/passkey/login/complete [post]
func (h *WebAuthnHandler) LoginComplete(c echo.Context) error {
	result, id, err := h.authSvc.LoginWebAuthn(c.Request().Context(), c.QueryParam("ceremony_token"), c.Request())
	if err != nil {
		return h.loginFailure(c, err)
	}
	h.auditPasskeyLogin(c, id)
	return c.JSON(http.StatusOK, result)
}

// SessionLoginComplete handles POST /api/v1/auth/passkey/session.
//
// The cookie-session counterpart of LoginComplete: identical verification, but
// the token pair lands in HttpOnly cookies instead of the response body.
//
// A separate endpoint rather than a mode flag, because that is the split this
// codebase already made — /auth/login returns tokens and /auth/session sets
// cookies, both over one Login service call. A browser client cannot use body
// tokens (nothing in JavaScript may write an HttpOnly cookie) and an API client
// cannot use cookies, so the two callers never want a choice; they want
// different endpoints.
//
// @Summary      Cookie-session passkey sign-in
// @Description  Verifies a passkey assertion and stores the token pair in HttpOnly cookies. Browser/console counterpart of /auth/passkey/login/complete.
// @Tags         Passkeys
// @Produce      json
// @Param        ceremony_token  query  string  true  "Token from login/begin"
// @Success      200  {object}  map[string]string
// @Failure      400  {object}  map[string]string  "application-scoped account — cookies are not available"
// @Failure      401  {object}  map[string]string
// @Failure      403  {object}  map[string]string
// @Router       /api/v1/auth/passkey/session [post]
func (h *WebAuthnHandler) SessionLoginComplete(c echo.Context) error {
	result, id, err := h.authSvc.LoginWebAuthn(c.Request().Context(), c.QueryParam("ceremony_token"), c.Request())
	if err != nil {
		return h.loginFailure(c, err)
	}

	// An application-scoped identity never gets cookies. setAuthCookies enforces
	// that itself by silently declining, which would leave the caller holding a
	// 200 that looks like a session and is not — so refuse explicitly instead,
	// exactly as SessionLogin does. Reachable whenever a passkey was registered
	// through an application rather than at tenant level.
	if _, _, appID := claimsFromToken(result.AccessToken); appID != nil {
		return errCookieSessionForApps(c)
	}

	h.auditPasskeyLogin(c, id)
	setAuthCookies(c, result.AccessToken, result.RefreshToken, h.cookieCfg)

	// Deliberately no tokens in this response. The whole point of the cookie
	// flow is that JavaScript never holds the credential; echoing it back would
	// undo that while looking harmless.
	return c.JSON(http.StatusOK, map[string]string{
		"message":    "logged in",
		"expires_in": accessTokenExpiresIn,
	})
}

// loginFailure maps a failed sign-in onto a response and an audit event.
//
// Shared by both login endpoints, and that matters: keeping the bodies identical
// between them is itself a security property — a difference would let a caller
// compare the two to learn which failure occurred.
func (h *WebAuthnHandler) loginFailure(c echo.Context, err error) error {
	// A clone detection is the one failure that names a user, because the
	// assertion verified before the flag comparison rejected it. It is also the
	// one that has already had side effects: the credential is deactivated and
	// every session for the account is revoked by the time we get here.
	var cloned *auth.ClonedCredentialError
	if errors.As(err, &cloned) {
		h.auditPasskey(c, cloned.TenantID, cloned.UserID, "", audit.ActionAuthPasskeyCloneDetected,
			strconv.FormatInt(cloned.CredentialRowID, 10), map[string]any{
				"passkey_name":       cloned.CredentialLabel,
				"reason":             cloned.Reason,
				"credential_revoked": true,
				"sessions_revoked":   true,
			})
		// Reported to the client as an ordinary failure. Telling a caller
		// holding a copied key that we noticed is free intelligence, and the
		// user learns about it from the session-ended notification and their
		// passkey list, not from this response.
		return h.loginRejected(c)
	}

	// Policy refusals are told apart from verification failures: "your
	// organisation has not enabled this" is actionable and reveals nothing about
	// any account, since the decision was made before a credential was named.
	switch {
	case errors.Is(err, auth.ErrPasskeysNotAllowed),
		errors.Is(err, auth.ErrPasswordlessNotAllowed),
		errors.Is(err, auth.ErrOriginNotAllowed),
		errors.Is(err, auth.ErrWebAuthnNotConfigured):
		// Audited like any other refused sign-in. A policy refusal at COMPLETE has
		// already resolved a credential to an account, so this is a real failed
		// attempt against a real account and the one thing an auditor asking "who
		// tried to sign in while passkeys were switched off" has to be able to
		// find. Recorded before the response so the return path cannot skip it.
		h.auditLoginFailed(c, err)
		return h.passkeyError(c, "", "passkey login", err)
	}

	// challenge_expired is the one verification-side failure the client is told
	// apart from the rest, so it can silently re-arm instead of showing an error
	// for a tab that simply sat open too long. See ErrChallengeExpired.
	if errors.Is(err, auth.ErrChallengeExpired) {
		h.auditLoginFailed(c, err)
		return c.JSON(http.StatusUnauthorized, map[string]string{
			"error": "Sign-in request expired.",
			"code":  "challenge_expired",
		})
	}

	h.auditLoginFailed(c, err)
	h.logger.Warn().Err(err).Msg("passkey sign-in rejected")
	return h.loginRejected(c)
}

// loginRejected is the single opaque failure response.
//
// Every genuine verification failure — bad signature, wrong origin, unknown
// credential, missing user verification, a cloned authenticator — returns THIS
// and nothing else. Saying which would let a caller probe for valid credentials.
// The detail is in the server log and the audit row, where it belongs.
func (h *WebAuthnHandler) loginRejected(c echo.Context) error {
	return c.JSON(http.StatusUnauthorized, map[string]string{
		"error": "Passkey sign-in failed.",
		"code":  "webauthn_failed",
	})
}

// ---------------------------------------------------------------------------
// Credential management — /auth/me/passkeys
// ---------------------------------------------------------------------------

// ListCredentials handles GET /api/v1/auth/me/passkeys.
//
// @Summary      List my passkeys
// @Tags         Passkeys
// @Produce      json
// @Security     BearerAuth
// @Success      200  {array}   auth.StoredCredential
// @Failure      401  {object}  map[string]string
// @Router       /api/v1/auth/me/passkeys [get]
func (h *WebAuthnHandler) ListCredentials(c echo.Context) error {
	claims, ok := c.Get("user").(*auth.Claims)
	if !ok || claims == nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	userID, tenantID, err := idsFromClaims(claims)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid token claims"})
	}

	creds, err := h.svc.ListCredentials(c.Request().Context(), userID, tenantID)
	if err != nil {
		h.logger.Error().Err(err).Str("user_id", claims.UserID).Msg("passkey list failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not load passkeys"})
	}
	return c.JSON(http.StatusOK, creds)
}

// RenameCredential handles PATCH /api/v1/auth/me/passkeys/:id.
//
// @Summary      Rename one of my passkeys
// @Description  Relabels a passkey. The label is the only thing distinguishing several passkeys in a list, and the name chosen mid-ceremony at registration is the one most likely to be wrong.
// @Tags         Passkeys
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id    path  string                true  "Credential row id"
// @Param        body  body  renamePasskeyRequest  true  "New name (1-64 characters)"
// @Success      200  {object}  auth.StoredCredential
// @Failure      400  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Router       /api/v1/auth/me/passkeys/{id} [patch]
func (h *WebAuthnHandler) RenameCredential(c echo.Context) error {
	claims, ok := c.Get("user").(*auth.Claims)
	if !ok || claims == nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	userID, tenantID, err := idsFromClaims(claims)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid token claims"})
	}

	var req renamePasskeyRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}

	cred, err := h.svc.RenameCredential(c.Request().Context(), userID, tenantID, c.Param("id"), req.Name)
	if err != nil {
		return h.passkeyError(c, claims.UserID, "passkey rename", err)
	}

	h.auditPasskey(c, tenantID, userID, claims.Email, audit.ActionAuthPasskeyRenamed, cred.ID, map[string]any{
		"passkey_name": cred.Name,
	})
	return c.JSON(http.StatusOK, cred)
}

// RevokeCredential handles DELETE /api/v1/auth/me/passkeys/:id.
//
// @Summary      Remove one of my passkeys
// @Description  Removes a passkey. Refused with last_factor when it is the account's only way to sign in — a passwordless account with one passkey has no recoverable route back in.
// @Tags         Passkeys
// @Produce      json
// @Security     BearerAuth
// @Param        id   path      string  true  "Credential row id"
// @Success      204  "removed"
// @Failure      404  {object}  map[string]string
// @Failure      409  {object}  map[string]string  "last remaining sign-in method"
// @Router       /api/v1/auth/me/passkeys/{id} [delete]
func (h *WebAuthnHandler) RevokeCredential(c echo.Context) error {
	claims, ok := c.Get("user").(*auth.Claims)
	if !ok || claims == nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	userID, tenantID, err := idsFromClaims(claims)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid token claims"})
	}

	credID := c.Param("id")
	if err := h.svc.RevokeCredential(c.Request().Context(), userID, tenantID, credID, false); err != nil {
		return h.passkeyError(c, claims.UserID, "passkey revoke", err)
	}

	h.auditPasskey(c, tenantID, userID, claims.Email, audit.ActionAuthPasskeyRemoved, credID, nil)
	return c.NoContent(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// Errors and audit
// ---------------------------------------------------------------------------

// passkeyError maps service errors onto responses.
//
// Registration and management are allowed to say what went wrong — the caller is
// already authenticated as themselves, so there is no account to enumerate and a
// vague error just leaves a user stuck. Login is not, which is why its failures
// route through loginFailure instead and collapse to one response.
func (h *WebAuthnHandler) passkeyError(c echo.Context, userID, op string, err error) error {
	type body struct {
		Error string `json:"error"`
		Code  string `json:"code"`
	}
	switch {
	case errors.Is(err, auth.ErrPasskeysNotAllowed):
		return c.JSON(http.StatusForbidden, body{
			"Passkeys are not enabled for your organisation.", "passkeys_disabled"})
	case errors.Is(err, auth.ErrPasswordlessNotAllowed):
		return c.JSON(http.StatusForbidden, body{
			"Signing in with a passkey is not enabled for your organisation.", "passwordless_disabled"})
	case errors.Is(err, auth.ErrOriginNotAllowed):
		return c.JSON(http.StatusForbidden, body{
			"Passkeys cannot be used from this address.", "origin_not_allowed"})
	case errors.Is(err, auth.ErrWebAuthnNotConfigured):
		// 501, not 403: nothing the tenant can change fixes this — the
		// deployment has no relying party configured at all.
		return c.JSON(http.StatusNotImplemented, body{
			"Passkeys are not available on this server.", "not_configured"})
	case errors.Is(err, auth.ErrTooManyCredentials):
		return c.JSON(http.StatusConflict, body{
			"You already have the maximum number of passkeys. Remove one before adding another.", "too_many_passkeys"})
	case errors.Is(err, auth.ErrLastFactor):
		return c.JSON(http.StatusConflict, body{
			"This is the only way to sign in to your account. Set a password or add another passkey first.", "last_factor"})
	case errors.Is(err, auth.ErrCredentialNotFound):
		// Scoped by user and tenant in the query, so someone else's credential
		// is reported as missing rather than refused — refusing would confirm it
		// exists.
		return c.JSON(http.StatusNotFound, body{"Passkey not found.", "not_found"})
	case errors.Is(err, auth.ErrInvalidPasskeyName):
		return c.JSON(http.StatusBadRequest, body{
			"A passkey name must be between 1 and 64 characters.", "invalid_name"})
	case errors.Is(err, auth.ErrChallengeExpired):
		return c.JSON(http.StatusBadRequest, body{
			"This took too long. Please try again.", "challenge_expired"})
	case errors.Is(err, auth.ErrCredentialAlreadyRegistered):
		return c.JSON(http.StatusConflict, body{
			"This device already has a passkey for your account.", "already_registered"})
	case errors.Is(err, auth.ErrCredentialNotDiscoverable):
		// Worth its own message: the user did nothing wrong, but the credential
		// could never have satisfied a passwordless sign-in, so silently
		// accepting it would leave them with a passkey that never works.
		return c.JSON(http.StatusBadRequest, body{
			"This authenticator cannot create a passkey that works for sign-in. Try a different device or your device's built-in passkey.", "not_discoverable"})
	case errors.Is(err, auth.ErrWebAuthnVerification),
		errors.Is(err, auth.ErrUserVerificationRequired):
		// Deliberately one arm and one message. ErrUserVerificationRequired is a
		// separate sentinel so the LOG and the audit row can say which refusal it
		// was; telling the client apart would hand a caller a way to learn that a
		// credential exists and only the gesture was missing.
		return c.JSON(http.StatusBadRequest, body{
			"The passkey could not be verified.", "verification_failed"})
	default:
		h.logger.Error().Err(err).Str("user_id", userID).Msg(op + " failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Something went wrong. Please try again."})
	}
}

// auditPasskey records a successful passkey lifecycle event.
func (h *WebAuthnHandler) auditPasskey(c echo.Context, tenantID, userID int64, email, action, credID string, meta map[string]any) {
	ev := audit.Event{
		TenantID:     &tenantID,
		UserID:       &userID,
		ActorEmail:   email,
		Action:       action,
		AuthMethod:   audit.AuthMethodPasskey,
		ResourceType: "passkey",
		ResourceID:   credID,
		IPAddress:    c.RealIP(),
		UserAgent:    c.Request().UserAgent(),
		Metadata:     meta,
	}
	logOrStage(c, h.audit, ev)
}

// auditPasskeyLogin records a successful passkey sign-in.
//
// user_verified is recorded because it is the difference between one factor and
// two, and it is read off the authenticator's response rather than off what we
// asked for. An auditor reading "passkey login" without it cannot tell whether a
// biometric actually happened.
func (h *WebAuthnHandler) auditPasskeyLogin(c echo.Context, id *auth.WebAuthnIdentity) {
	if id == nil {
		return
	}
	tenantID, userID := id.TenantID, id.UserID
	ev := audit.Event{
		TenantID:      &tenantID,
		UserID:        &userID,
		ApplicationID: appRowID(id.AppID),
		ActorEmail:    id.Email,
		Action:        audit.ActionAuthPasskeyLogin,
		AuthMethod:    audit.AuthMethodPasskey,
		ResourceType:  "passkey",
		ResourceID:    strconv.FormatInt(id.CredentialRowID, 10),
		IPAddress:     c.RealIP(),
		UserAgent:     c.Request().UserAgent(),
		Metadata: map[string]any{
			"passkey_name":  id.CredentialLabel,
			"user_verified": id.UserVerified,
		},
	}
	logOrStage(c, h.audit, ev)
}

// appRowID parses the app_id claim shape used across the auth handlers into the
// nullable column the audit table wants.
func appRowID(appID string) *int64 {
	if appID == "" {
		return nil
	}
	id, err := strconv.ParseInt(appID, 10, 64)
	if err != nil {
		return nil
	}
	return &id
}

// auditLoginFailed records a rejected passkey sign-in.
//
// There is no user id to record, and that is inherent rather than an omission: a
// passwordless assertion is the only thing that would have named the account, and
// it did not verify. What the row does carry is the IP, the user agent, and the
// reason — which is what a brute-force or credential-stuffing pattern is visible
// in.
func (h *WebAuthnHandler) auditLoginFailed(c echo.Context, err error) {
	ev := audit.Event{
		Action:       audit.ActionAuthPasskeyLoginFailed,
		AuthMethod:   audit.AuthMethodPasskey,
		ResourceType: "user",
		IPAddress:    c.RealIP(),
		UserAgent:    c.Request().UserAgent(),
		HTTPStatus:   http.StatusUnauthorized,
	}
	applyFailure(&ev, err)
	logOrStage(c, h.audit, ev)
}

// idsFromClaims parses the numeric user and tenant ids out of a verified token.
// Both are authoritative from the JWT and never read from the request body —
// non-negotiable #4.
func idsFromClaims(claims *auth.Claims) (userID, tenantID int64, err error) {
	if userID, err = strconv.ParseInt(claims.UserID, 10, 64); err != nil {
		return 0, 0, err
	}
	if tenantID, err = strconv.ParseInt(claims.TenantID, 10, 64); err != nil {
		return 0, 0, err
	}
	return userID, tenantID, nil
}
