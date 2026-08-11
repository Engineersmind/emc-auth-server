package handlers

import (
	"context"
	"embed"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog"

	"github.com/engineersmind/emc-auth-server/internal/audit"
	"github.com/engineersmind/emc-auth-server/internal/auth"
)

//go:embed templates/*.html
var authzTemplateFS embed.FS

// authzTemplates are parsed once at init. A parse failure is a programming
// error in an embedded asset — it cannot be fixed at runtime and every
// authorize request would fail, so panicking at startup is the honest outcome
// rather than discovering it on the first login.
var authzTemplates = template.Must(template.ParseFS(authzTemplateFS, "templates/*.html"))

// OAuth 2.0 error codes, RFC 6749 §4.1.2.1. Returned in the `error` query
// parameter on the redirect, or rendered when redirecting is unsafe.
const (
	errInvalidRequest          = "invalid_request"
	errUnauthorizedClient      = "unauthorized_client"
	errUnsupportedResponseType = "unsupported_response_type"
	errInvalidScope            = "invalid_scope"
	errServerError             = "server_error"
	errConsentRequired         = "consent_required"
)

// pageData is the view model for every hosted page.
type pageData struct {
	Title         string
	AppName       string
	RequestHandle string
	Email         string
	Error         string
	Message       string
	Detail        string
}

// OAuthAuthorizeHandler serves GET /oauth/authorize and the two hosted login
// pages behind it (issue #6).
//
// Why this server renders HTML at all: the Authorization Code grant exists so a
// third-party client never sees the user's password. That requires the
// credential form to be served from THIS origin. A JSON API cannot satisfy it —
// if the client rendered the form, the client would handle the password, which
// is the exact thing the grant prevents. The frontend admin console cannot
// serve it either: it is admin-only, not tenant- or application-aware, has no
// return-URL support, and hard-fails MFA.
type OAuthAuthorizeHandler struct {
	authz    *auth.AuthorizationServer
	sessions *auth.AuthzSessionStore
	authSvc  *auth.AuthService
	audit    *audit.Logger
	logger   zerolog.Logger
	secure   bool
}

// NewOAuthAuthorizeHandler builds the handler. secure controls the Secure flag
// on the SSO cookie and must be true in production.
func NewOAuthAuthorizeHandler(
	authz *auth.AuthorizationServer,
	sessions *auth.AuthzSessionStore,
	authSvc *auth.AuthService,
	auditLog *audit.Logger,
	logger zerolog.Logger,
	secure bool,
) *OAuthAuthorizeHandler {
	return &OAuthAuthorizeHandler{
		authz: authz, sessions: sessions, authSvc: authSvc,
		audit: auditLog, logger: logger, secure: secure,
	}
}

// Authorize handles GET /oauth/authorize — RFC 6749 §4.1.1.
//
// @Summary      OAuth 2.0 authorization endpoint
// @Description  Starts the Authorization Code flow with PKCE. Validates the client and redirect_uri, authenticates the user through a server-rendered login page, and redirects back to redirect_uri with a single-use code. Browser endpoint — returns HTML or a 302, never JSON.
// @Tags         oauth
// @Produce      html
// @Param        client_id              query  string  true   "Registered client_id"
// @Param        redirect_uri           query  string  false  "Must exactly match a registered redirect_uri. Optional only when exactly one is registered."
// @Param        response_type          query  string  true   "Must be 'code'"
// @Param        scope                  query  string  false  "Space-delimited. Unregistered scopes are dropped, not rejected."
// @Param        state                  query  string  false  "Opaque value echoed back on the redirect"
// @Param        nonce                  query  string  false  "OIDC nonce, echoed into the ID token"
// @Param        code_challenge         query  string  true   "base64url(SHA256(code_verifier))"
// @Param        code_challenge_method  query  string  true   "Must be 'S256'"
// @Success      302  "Redirect to redirect_uri with code and state"
// @Failure      400  "HTML error page — client_id or redirect_uri invalid"
// @Router       /oauth/authorize [get]
func (h *OAuthAuthorizeHandler) Authorize(c echo.Context) error {
	ctx := c.Request().Context()
	q := c.QueryParams()

	clientID := q.Get("client_id")
	requestedRedirect := q.Get("redirect_uri")

	// ---- Phase 1: establish a trustworthy redirect target -------------------
	//
	// Nothing may be reported by redirect until BOTH the client and the
	// redirect_uri are known good. An error sent to an unvalidated URI is an
	// open redirect, and one that reflects attacker-controlled input is worse
	// than the missing feature it reports.
	client, err := h.authz.LookupClient(ctx, clientID)
	if err != nil {
		if errors.Is(err, auth.ErrClientNotFound) {
			return h.renderError(c, http.StatusBadRequest, "Unknown application",
				"This sign-in link refers to an application that does not exist or has been deactivated.",
				"invalid client_id")
		}
		h.logger.Error().Err(err).Msg("authorize: client lookup failed")
		return h.renderError(c, http.StatusInternalServerError, "Something went wrong",
			"We could not start the sign-in process. Please try again.", "")
	}

	redirectURI, err := auth.ResolveRedirectURI(client, requestedRedirect)
	if err != nil {
		// Rendered, never redirected — see the comment above and error.html.
		switch {
		case errors.Is(err, auth.ErrNoRedirectURIsRegistered):
			return h.renderError(c, http.StatusBadRequest, "Application is not configured",
				"This application has no registered redirect URIs, so it cannot use the sign-in flow.",
				"no redirect_uri registered for this client")
		default:
			return h.renderError(c, http.StatusBadRequest, "Invalid redirect",
				"The address this application asked us to return to is not registered for it.",
				"redirect_uri does not exactly match a registered value")
		}
	}

	// From here the redirect target is trusted, so errors go back to the client
	// as RFC 6749 §4.1.2.1 requires, with state echoed so the client can match
	// the response to its own request.
	state := q.Get("state")

	// ---- Phase 2: validate the request itself -------------------------------

	if rt := q.Get("response_type"); rt != "code" {
		return h.redirectError(c, redirectURI, state, errUnsupportedResponseType,
			"only response_type=code is supported")
	}

	if !auth.AllowsGrant(client, "authorization_code") {
		return h.redirectError(c, redirectURI, state, errUnauthorizedClient,
			"this client is not permitted to use the authorization_code grant")
	}

	// Consent. first_party = false means a genuinely third-party client, which
	// requires a consent screen this server does not have yet. Refusing is
	// deliberate: skipping consent by default would hand a stranger's
	// application a token for a user who was never told — the exact harm
	// consent prevents. Failing closed makes the gap impossible to ship past.
	if !client.FirstParty {
		return h.redirectError(c, redirectURI, state, errConsentRequired,
			"user consent is required for third-party clients and is not yet supported")
	}

	challenge := q.Get("code_challenge")
	method := q.Get("code_challenge_method")
	if client.RequirePKCE || challenge != "" {
		if challenge == "" {
			return h.redirectError(c, redirectURI, state, errInvalidRequest,
				"code_challenge is required")
		}
		// Method defaults to 'plain' in RFC 7636 when omitted. We do not accept
		// plain, so an omitted method is an error rather than a silent
		// downgrade to the weaker mode.
		if method == "" {
			return h.redirectError(c, redirectURI, state, errInvalidRequest,
				"code_challenge_method is required and must be S256")
		}
		if err := auth.ValidateCodeChallenge(challenge, method); err != nil {
			if errors.Is(err, auth.ErrUnsupportedChallengeMethod) {
				return h.redirectError(c, redirectURI, state, errInvalidRequest,
					"code_challenge_method must be S256")
			}
			return h.redirectError(c, redirectURI, state, errInvalidRequest,
				"code_challenge is malformed")
		}
	}

	granted := auth.FilterScopes(auth.ParseScopeParam(q.Get("scope")), client.Scopes)
	// A request that asked for scopes and got none back would otherwise proceed
	// to mint a token granting nothing, which reads to the client as a server
	// bug rather than a registration problem.
	if q.Get("scope") != "" && len(granted) == 0 {
		return h.redirectError(c, redirectURI, state, errInvalidScope,
			"none of the requested scopes are registered for this client")
	}

	req := &auth.AuthzRequest{
		ClientID:      client.ClientID,
		TenantID:      client.TenantID,
		AppRowID:      client.RowID,
		RedirectURI:   redirectURI,
		Scopes:        granted,
		State:         state,
		Nonce:         q.Get("nonce"),
		CodeChallenge: challenge,
	}

	// ---- Phase 3: is the user already signed in here? -----------------------
	if sess := h.currentSession(c); sess != nil && sess.TenantID == client.TenantID {
		// Tenant equality is checked, not assumed. An SSO session belongs to a
		// user in one tenant; letting it satisfy an authorize request for a
		// client in another would cross the isolation boundary that the rest of
		// this codebase enforces on every query.
		//
		// No parked request to clean up on this path — nothing was stored.
		return h.issueCodeAndRedirect(c, "", req, sess)
	}

	handle, err := h.sessions.SaveRequest(ctx, req)
	if err != nil {
		h.logger.Error().Err(err).Msg("authorize: could not park request")
		return h.redirectError(c, redirectURI, state, errServerError, "could not start sign-in")
	}
	return h.renderLogin(c, http.StatusOK, client.Name, handle, "", "")
}

// currentSession resolves the SSO cookie, or nil.
func (h *OAuthAuthorizeHandler) currentSession(c echo.Context) *auth.AuthzSession {
	ck, err := c.Cookie(auth.AuthzSessionCookie)
	if err != nil || ck.Value == "" {
		return nil
	}
	sess, err := h.sessions.GetSession(c.Request().Context(), ck.Value)
	if err != nil {
		return nil
	}
	return sess
}

// LoginSubmit handles POST /oauth/authorize/login — the password step.
func (h *OAuthAuthorizeHandler) LoginSubmit(c echo.Context) error {
	ctx := c.Request().Context()
	handle := c.FormValue("request")

	req, err := h.sessions.GetRequest(ctx, handle)
	if err != nil {
		// No redirect target is available: the handle is how we know where the
		// user was going, and it is gone.
		return h.renderError(c, http.StatusBadRequest, "Sign-in expired",
			"This sign-in request has expired. Please start again from the application.", "")
	}

	email := c.FormValue("email")
	password := c.FormValue("password")
	appName := h.appName(ctx, req)

	result, err := h.authSvc.Login(ctx, auth.LoginInput{
		Email:    email,
		Password: password,
		ClientID: req.ClientID,
		// The application was resolved from oauth_clients at /oauth/authorize,
		// so its identity is already established. A public client (SPA, native)
		// holds no secret, and without this the login would search only
		// tenant-level users and never find the application's own accounts.
		// See LoginInput.VerifiedApp for the security contract.
		VerifiedApp: &auth.VerifiedApp{TenantID: req.TenantID, AppRowID: req.AppRowID},
	})
	if err != nil {
		// The application's MFA policy is 'required' and this account has no
		// second factor. Not a credential failure — say so specifically rather
		// than telling the user their correct password was wrong.
		if errors.Is(err, auth.ErrMFARequiredByPolicy) {
			return h.renderEnrollmentDeadEnd(c)
		}
		h.logger.Warn().Str("email", email).Str("client_id", req.ClientID).
			Msg("authorize: hosted login failed")
		// One message for every failure mode. Distinguishing "no such account"
		// from "wrong password" here would make this page an account-existence
		// oracle for any tenant's user base — the same rule /forgot-password
		// follows.
		return h.renderLogin(c, http.StatusUnauthorized, appName, handle, email,
			"Incorrect email or password.")
	}

	// Forced-enrollment challenge: the application's MFA policy is 'required'
	// and this user has never enrolled. The hosted login is two pages by
	// decision (issue #6 plan §3) and does not include an enrollment screen, so
	// this is a genuine dead end. Saying so explicitly beats a generic error the
	// user cannot act on.
	if result.MFAEnrollment != nil {
		return h.renderEnrollmentDeadEnd(c)
	}

	// The password has been proven from here on, so the email is now a fact
	// about this request rather than user input.
	req.Email = email

	if result.OTPChallenge != nil {
		req.OTPSessionToken = result.OTPChallenge.OTPSessionToken
		req.OTPMethods = result.OTPChallenge.Methods
		if err := h.sessions.UpdateRequest(ctx, handle, req); err != nil {
			h.logger.Error().Err(err).Msg("authorize: could not attach OTP challenge")
			return h.redirectError(c, req.RedirectURI, req.State, errServerError, "sign-in failed")
		}
		return h.renderMFA(c, http.StatusOK, appName, handle, "")
	}

	return h.completeLogin(c, handle, req)
}

// MFASubmit handles POST /oauth/authorize/mfa — the second-factor step.
func (h *OAuthAuthorizeHandler) MFASubmit(c echo.Context) error {
	ctx := c.Request().Context()
	handle := c.FormValue("request")

	req, err := h.sessions.GetRequest(ctx, handle)
	if err != nil {
		return h.renderError(c, http.StatusBadRequest, "Sign-in expired",
			"This sign-in request has expired. Please start again from the application.", "")
	}
	if req.OTPSessionToken == "" {
		// Reaching the MFA page without having passed the password step. Send
		// the user back rather than accepting a code for a login that never
		// began.
		return h.renderLogin(c, http.StatusBadRequest, h.appName(ctx, req), handle, "",
			"Please sign in again.")
	}

	if _, err := h.authSvc.LoginOTP(ctx, auth.LoginOTPInput{
		OTPSessionToken: req.OTPSessionToken,
		Code:            c.FormValue("code"),
	}); err != nil {
		h.logger.Warn().Str("client_id", req.ClientID).Msg("authorize: OTP verification failed")
		return h.renderMFA(c, http.StatusUnauthorized, h.appName(ctx, req), handle,
			"That code is not valid. Please try again.")
	}

	return h.completeLogin(c, handle, req)
}

// completeLogin records the SSO session and issues the code.
//
// The token pair that Login/LoginOTP just produced is deliberately DISCARDED.
// Those tokens belong to a direct first-party login; the client at the other
// end of this flow must obtain its own tokens by exchanging the code with its
// verifier at /oauth/token. Handing over a pair here would bypass PKCE entirely
// and make the code ceremonial.
func (h *OAuthAuthorizeHandler) completeLogin(c echo.Context, handle string, req *auth.AuthzRequest) error {
	ctx := c.Request().Context()

	// req.Email was recorded at the password step, after the credential was
	// verified — never taken from the form on this request.
	userID, email, err := h.authSvc.LookupUserForApp(ctx, req.TenantID, req.AppRowID, req.Email)
	if err != nil {
		// The credentials were just accepted, so failing to re-read the user is
		// a server fault, not a rejection.
		h.logger.Error().Err(err).Msg("authorize: could not resolve authenticated user")
		return h.redirectError(c, req.RedirectURI, req.State, errServerError, "sign-in failed")
	}

	sess := &auth.AuthzSession{
		UserID:   userID,
		TenantID: req.TenantID,
		Email:    email,
		AuthTime: time.Now().UTC(),
	}
	sessHandle, err := h.sessions.CreateSession(ctx, sess)
	if err != nil {
		h.logger.Error().Err(err).Msg("authorize: could not create SSO session")
		return h.redirectError(c, req.RedirectURI, req.State, errServerError, "sign-in failed")
	}
	h.setSessionCookie(c, sessHandle)

	return h.issueCodeAndRedirect(c, handle, req, sess)
}

// issueCodeAndRedirect mints the authorization code and sends the browser back.
// handle is the parked-request key to consume, or "" when the request was
// satisfied straight from an existing SSO session and never parked.
func (h *OAuthAuthorizeHandler) issueCodeAndRedirect(c echo.Context, handle string, req *auth.AuthzRequest, sess *auth.AuthzSession) error {
	ctx := c.Request().Context()

	code, err := h.authz.IssueAuthorizationCode(ctx, auth.IssueAuthorizationCodeParams{
		TenantID:      req.TenantID,
		ClientID:      req.ClientID,
		UserID:        sess.UserID,
		RedirectURI:   req.RedirectURI,
		Scopes:        req.Scopes,
		CodeChallenge: req.CodeChallenge,
		Nonce:         req.Nonce,
		AuthTime:      sess.AuthTime,
	})
	if err != nil {
		h.logger.Error().Err(err).Msg("authorize: could not issue code")
		return h.redirectError(c, req.RedirectURI, req.State, errServerError, "sign-in failed")
	}

	h.auditEvent(c, "oauth.authorize_granted", req, sess.UserID, true, "")

	target, err := url.Parse(req.RedirectURI)
	if err != nil {
		// Unreachable: the URI came from a validated registration. Handled
		// rather than ignored because silently redirecting to a broken URL is
		// worse than saying so.
		h.logger.Error().Err(err).Str("redirect_uri", req.RedirectURI).
			Msg("authorize: registered redirect_uri does not parse")
		return h.renderError(c, http.StatusInternalServerError, "Something went wrong",
			"We could not complete the sign-in.", "")
	}
	qs := target.Query()
	qs.Set("code", code)
	if req.State != "" {
		qs.Set("state", req.State)
	}
	target.RawQuery = qs.Encode()

	// The parked request has served its purpose; leaving it live would keep a
	// resumable half-login in Redis for the rest of its TTL.
	if handle != "" {
		h.sessions.DeleteRequest(ctx, handle)
	}
	return c.Redirect(http.StatusFound, target.String())
}

// setSessionCookie writes the SSO cookie.
func (h *OAuthAuthorizeHandler) setSessionCookie(c echo.Context, handle string) {
	c.SetCookie(&http.Cookie{
		Name:  auth.AuthzSessionCookie,
		Value: handle,
		Path:  "/oauth",
		// Scoped to /oauth deliberately. This cookie is only ever read by the
		// authorize endpoint; sending it on every API request would widen its
		// exposure for no benefit and put it alongside the portal's cookies,
		// which it is specifically meant not to be confused with.
		HttpOnly: true,
		Secure:   h.secure,
		// Lax, not Strict: the user arrives here by a top-level cross-site
		// navigation from the client application, which is exactly the case Lax
		// permits and Strict blocks. Strict would drop the cookie on arrival
		// and re-prompt for a password on every single authorize request,
		// defeating SSO entirely. Lax is safe because this cookie authorizes
		// nothing by itself — it only avoids a re-prompt, and every state
		// change still goes through a POST carrying the request handle.
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(auth.AuthzSessionTTL.Seconds()),
	})
}

// redirectError reports a failure to the client per RFC 6749 §4.1.2.1.
// Only ever called with a redirect target already proven to be registered.
func (h *OAuthAuthorizeHandler) redirectError(c echo.Context, redirectURI, state, code, description string) error {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return h.renderError(c, http.StatusBadRequest, "Invalid redirect",
			"The application's return address could not be used.", "")
	}
	q := u.Query()
	q.Set("error", code)
	if description != "" {
		q.Set("error_description", description)
	}
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	return c.Redirect(http.StatusFound, u.String())
}

func (h *OAuthAuthorizeHandler) renderLogin(c echo.Context, status int, appName, handle, email, errMsg string) error {
	return h.render(c, status, "login.html", pageData{
		Title: "Sign in", AppName: appName, RequestHandle: handle,
		Email: email, Error: errMsg,
	})
}

func (h *OAuthAuthorizeHandler) renderMFA(c echo.Context, status int, appName, handle, errMsg string) error {
	return h.render(c, status, "mfa.html", pageData{
		Title: "Two-factor authentication", AppName: appName,
		RequestHandle: handle, Error: errMsg,
	})
}

func (h *OAuthAuthorizeHandler) renderEnrollmentDeadEnd(c echo.Context) error {
	return h.renderError(c, http.StatusForbidden, "Two-factor setup required",
		"This application requires two-factor authentication, and your account has not set it up yet. "+
			"Please sign in to the application directly to enrol, then try again.",
		"")
}

func (h *OAuthAuthorizeHandler) renderError(c echo.Context, status int, title, message, detail string) error {
	return h.render(c, status, "error.html", pageData{
		Title: title, Message: message, Detail: detail,
	})
}

// render executes a page. Both headers matter:
//
//	no-store          — these pages carry a live request handle and, on the
//	                    login page, a form the user is about to type a password
//	                    into. A cached copy is a replayable login.
//	no-referrer       — the request handle is in the URL; without this it would
//	                    travel in the Referer of any outbound request.
func (h *OAuthAuthorizeHandler) render(c echo.Context, status int, page string, data pageData) error {
	c.Response().Header().Set("Cache-Control", "no-store")
	c.Response().Header().Set("Pragma", "no-cache")
	c.Response().Header().Set("Referrer-Policy", "no-referrer")

	// Clone per request: templates are shared and Lookup+Execute on the shared
	// set is safe, but the two-file (layout + page) composition needs the page's
	// "content" definition bound alongside "layout" for this render only.
	t, err := authzTemplates.Clone()
	if err == nil {
		_, err = t.ParseFS(authzTemplateFS, "templates/"+page)
	}
	if err != nil {
		h.logger.Error().Err(err).Str("page", page).Msg("authorize: template render failed")
		return c.String(http.StatusInternalServerError, "internal error")
	}
	c.Response().Header().Set(echo.HeaderContentType, echo.MIMETextHTMLCharsetUTF8)
	c.Response().WriteHeader(status)
	return t.ExecuteTemplate(c.Response().Writer, "layout", data)
}

// appName resolves a display name for the page, falling back to the client_id.
// Cosmetic only — never used for a security decision.
func (h *OAuthAuthorizeHandler) appName(ctx context.Context, req *auth.AuthzRequest) string {
	client, err := h.authz.LookupClient(ctx, req.ClientID)
	if err != nil || client.Name == "" {
		return req.ClientID
	}
	return client.Name
}

// auditEvent records an authorize outcome. Fire-and-forget per the house rule:
// an audit failure must never block an auth operation.
func (h *OAuthAuthorizeHandler) auditEvent(c echo.Context, action string, req *auth.AuthzRequest, userID int64, success bool, reason string) {
	if h.audit == nil {
		return
	}
	tenantID := req.TenantID
	appRowID := req.AppRowID
	ev := audit.Event{
		Action:        action,
		TenantID:      &tenantID,
		ApplicationID: &appRowID,
		ResourceType:  "oauth_client",
		ResourceID:    req.ClientID,
		Status:        audit.StatusSuccess,
		IPAddress:     c.RealIP(),
		UserAgent:     c.Request().UserAgent(),
		Metadata:      map[string]any{"scopes": req.Scopes},
	}
	if !success {
		ev.Status = audit.StatusFailure
	}
	if userID != 0 {
		ev.UserID = &userID
	}
	if reason != "" {
		ev.Metadata["reason"] = reason
	}
	h.audit.Log(c.Request().Context(), ev)
}
