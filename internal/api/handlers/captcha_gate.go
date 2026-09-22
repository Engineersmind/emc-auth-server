package handlers

import (
	"errors"
	"net/http"

	"github.com/labstack/echo/v4"

	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// ---------------------------------------------------------------------------
// The CAPTCHA gate on the auth handlers (issue #145).
//
// Three helpers, called from six handlers. Everything they do is conditional on
// the feature being enabled, so with CAPTCHA_ENABLED unset each one is a nil
// check and a return — the protected endpoints behave byte-identically to how
// they did before this file existed.
//
// WHY THE GATE IS HERE AND NOT IN THE SERVICE
//
// auth.LoginInput carries no client address, and the gate needs one: the
// adaptive counter is keyed by IP. Threading an IP through the service would
// mean changing the signature every caller uses, and reordering authentication
// logic around a speed bump. The handler already has c.RealIP() and already has
// a failure branch, so the gate costs two lines per handler and nothing in
// internal/auth/service.go changes.
//
// WHY THE CHECK COMES BEFORE AUTHENTICATION
//
// A refused request must not consume a cost-12 bcrypt. That is the entire point
// of the tier: an attacker who cannot answer the challenge should not be able to
// make the server do the expensive part anyway.
//
// WHY 428 AND NOT 401
//
// Both refusals answer 428 Precondition Required (RFC 6585 §3), not 401. They
// used to be 401, and that was a mistake worth recording rather than quietly
// correcting, because of how it failed.
//
// 401 is the status an integrator's login code already handles, and it already
// means one thing to them: the credentials were wrong. A real integration —
// EMC Insurance's apps/api — collapsed every 401 from this server into
//
//	throw new AuthError('INVALID_CREDENTIALS', 'Invalid email or password')
//
// before looking at the body. Our `captcha_required` therefore reached the end
// user as "Invalid email or password", for a password that was correct, with no
// captcha shown and no way out: retyping the right password produced the same
// message forever. The signal was not ignored — it was structurally
// unreachable, because it arrived wearing the status code of a different event.
//
// 428 says "you have not satisfied a precondition", which is exactly true here
// and is not on any integrator's authentication path, so a generic 401 branch
// cannot swallow it. It is deliberately not 403 (that asserts the caller is not
// permitted, which is untrue — they are permitted, once they answer) and not 429
// (integrators auto-retry that one on a Retry-After timer, which would hammer
// the endpoint rather than show a challenge).
//
// Both refusals share the status on purpose, and the body's `error` field is the
// only thing that distinguishes them. A client branches the same way either way:
// fetch a challenge and retry. `captcha_invalid` additionally means "burn the id
// you were holding" — hence previous_challenge_id.
//
// This is a breaking change for anything that branched on 401 for these two
// error codes. Nothing did: the feature is off by default in every deployment,
// and a repo-wide search found no consumer. If that stops being true, the cost
// of changing it later is far higher than the cost of changing it now.
// ---------------------------------------------------------------------------

// captchaScope is what a handler knows about who is calling, at the moment the
// gate runs — which is BEFORE authentication, so it is only ever what the
// request itself established.
type captchaScope struct {
	// TenantID is 0 when the flow cannot identify a tenant before
	// authenticating. See captchaCheck for what that means.
	TenantID int64
	// ApplicationID is nil unless the request authenticated an application.
	ApplicationID *int64
	// ClientID is the application's client_id, empty for first-party flows. The
	// challenge is bound to it, so a challenge minted for one application cannot
	// be spent by another.
	ClientID string
}

// captchaCheck runs the gate for one request.
//
// Returns handled=false when the request may proceed. When handled=true the
// response has ALREADY been written and the caller must return err immediately
// without doing anything else.
//
// Two return values rather than one error, and this is not style. echo's c.JSON
// returns nil when the write SUCCEEDS, so a helper that returned only its result
// would report "no error" for a request it had just refused. A caller testing
// `if err != nil` would then carry on and write a second body — in this case a
// 401 followed by a real token pair, in one response. That is exactly what
// happened before this signature was fixed, and nothing but running the server
// would have shown it.
//
// # ON THE ZERO TENANT
//
// /auth/login, /auth/session and /auth/login/otp have no tenant at this point,
// and cannot have one: the tenant is discovered during authentication by looking
// the email up across tenants (which is also why deferred #17 exists). Passing 0
// resolves to the PLATFORM-DEFAULT policy row, because that is the only scope
// that can answer the question at the time it is asked.
//
// The consequence is worth stating plainly: a tenant who enables captchas on
// their own policy row does NOT get them on /auth/login. They get them on the
// application-authenticated flows, where the tenant is known from the client
// credentials. Covering the slug-less flows per tenant would require identifying
// the tenant from the email before checking the password, which is the
// enumeration oracle this whole design is built to avoid.
func (h *AuthHandler) captchaCheck(
	c echo.Context,
	scope captchaScope,
	flow auth.CaptchaFlow,
	challengeID, answer string,
) (handled bool, err error) {
	if h.captchaSvc == nil || !h.captchaSvc.Enabled() {
		return false, nil
	}

	checkErr := h.captchaSvc.Check(c.Request().Context(), auth.CaptchaRequest{
		TenantID:      scope.TenantID,
		ApplicationID: scope.ApplicationID,
		ClientID:      scope.ClientID,
		Flow:          flow,
		IP:            c.RealIP(),
		ChallengeID:   challengeID,
		Answer:        answer,
	})
	switch {
	case checkErr == nil:
		return false, nil
	case errors.Is(checkErr, auth.ErrCaptchaRequired):
		return true, c.JSON(http.StatusPreconditionRequired, map[string]string{"error": "captcha_required"})
	case errors.Is(checkErr, auth.ErrCaptchaInvalid):
		return true, c.JSON(http.StatusPreconditionRequired, map[string]string{"error": "captcha_invalid"})
	default:
		// Check returns only those two sentinels; anything else is a bug. Let
		// the request through rather than inventing a refusal: this is a speed
		// bump, and an unexpected error in it must not become an outage.
		h.logger.Error().Err(checkErr).Msg("captcha: unexpected gate error, allowing request")
		return false, nil
	}
}

// captchaRecordFailure counts a failed attempt so the next one from this origin
// may be challenged.
//
// Called from the failure branch of each protected handler, and deliberately
// counts EVERY failure — wrong password, unknown account, locked account alike.
// Counting only failures that named a real account would reintroduce the
// enumeration signal from the other direction.
func (h *AuthHandler) captchaRecordFailure(c echo.Context, scope captchaScope) {
	if h.captchaSvc == nil || !h.captchaSvc.Enabled() {
		return
	}
	h.captchaSvc.RecordFailure(c.Request().Context(), scope.TenantID, scope.ApplicationID, scope.ClientID, c.RealIP())
}

// captchaClearFailures drops the origin's counter after a successful
// authentication.
//
// Without this a shared address — an office NAT, a university, a mobile carrier
// — stays gated for the rest of the window because one person mistyped their
// password this morning. One good sign-in is decent evidence that the origin is
// not being driven by a script.
func (h *AuthHandler) captchaClearFailures(c echo.Context, scope captchaScope) {
	if h.captchaSvc == nil || !h.captchaSvc.Enabled() {
		return
	}
	h.captchaSvc.ClearFailures(c.Request().Context(), scope.ClientID, c.RealIP())
}

// appCaptchaScope builds the scope for an application-authenticated flow, where
// the tenant and application are known from the client credentials.
func appCaptchaScope(tenantID, appID int64, clientID string) captchaScope {
	return captchaScope{TenantID: tenantID, ApplicationID: &appID, ClientID: clientID}
}

// firstPartyCaptchaScope builds the scope for a slug-less first-party flow,
// which resolves against the platform-default policy. See captchaCheck.
func firstPartyCaptchaScope() captchaScope {
	return captchaScope{}
}

// appCaptchaScopeFor builds the scope for an application-authenticated flow
// from the client_id alone, BEFORE the client secret has been verified.
//
// # WHY THIS EXISTS
//
// The obvious version — captchaScope{ClientID: clientID} — looks like it reaches
// the application's policy, because the client_id is carried on the request. It
// does not. CaptchaPolicyService.Resolve keys on tenant id and application id
// and never reads ClientID, so a scope carrying only a client_id resolves
// tenant 0 / application nil, which matches only the platform-default row:
//
//	WHERE (application_id = NULL AND tenant_id = 0)      -- NULL, never true
//	   OR (application_id IS NULL AND tenant_id = 0)     -- no tenant has id 0
//	   OR (application_id IS NULL AND tenant_id IS NULL) -- the platform row
//
// The consequence was that a tenant enabling captchas on their own application
// row got nothing on /auth/apps/login and /auth/apps/register, and the only way
// to enable the feature for one tenant was the platform row — which enables it
// for every tenant at once. RecordFailure resolved the same way, so in adaptive
// mode the counter never incremented either and the gate could not arm at all.
//
// It also put Issue and Check into disagreement: POST /captcha/challenge looks
// the client up and issues against the APPLICATION policy, while the gate
// verified against the platform one. A tenant whose application policy differed
// from the platform row could be handed a challenge the gate would not ask for,
// or asked for one the issuer would refuse with 404.
//
// # COST
//
// One indexed lookup on oauth_clients(client_id), and only when the captcha
// feature is actually switched on — with CAPTCHA_ENABLED unset this is a nil
// check and a return, so a deployment that has not opted in pays nothing. That
// guard matters: this sits ahead of authentication on a path an attacker drives
// hard, and an unconditional query here would make a brute-force attempt double
// as a load amplifier against oauth_clients.
//
// An unknown client_id resolves to the platform scope with the client binding
// still in place. That is deliberate — refusing differently would tell an
// unauthenticated caller whether a client_id exists, the same oracle the
// challenge endpoint avoids by answering 404 captcha_disabled for both cases.
// ON WHICH LOOKUP, AND WHY IT MUST BE THIS ONE
//
// AuthorizationServer.LookupClient, not ApplicationService.ResolveClient. The
// two disagree: ResolveClient omits `AND is_active` (deliberately — it exists to
// attribute audit events for suspended applications too), while LookupClient
// includes it and is what POST /captcha/challenge uses.
//
// Using ResolveClient here made a suspended application with an enabled captcha
// policy unsatisfiable: the gate resolved its policy and answered 428
// captcha_required, while the challenge endpoint answered 404 captcha_disabled
// for the same client_id, so no request sequence could get through. Reported on
// PR #147. Both sides of the gate now run the same query, which is the property
// that has to hold — whatever that query filters on.
//
// A suspended client now resolves to the platform scope, so it is gated only if
// the platform policy says so, and Login rejects it a few lines later for being
// inactive. That is the correct order: the captcha is a speed bump, not the
// thing that enforces suspension.
func (h *AuthHandler) appCaptchaScopeFor(c echo.Context, clientID string) captchaScope {
	scope := captchaScope{ClientID: clientID}
	if h.captchaSvc == nil || !h.captchaSvc.Enabled() || h.authz == nil || clientID == "" {
		return scope
	}
	client, err := h.authz.LookupClient(c.Request().Context(), clientID)
	if err != nil {
		// Unknown, deleted or suspended. Fall back to the platform scope rather
		// than refusing differently — answering differently here would tell an
		// unauthenticated caller whether a client_id exists, the same oracle the
		// challenge endpoint avoids by returning 404 captcha_disabled for both.
		if !errors.Is(err, auth.ErrClientNotFound) {
			h.logger.Warn().Err(err).Msg("captcha: client lookup failed, using platform scope")
		}
		return scope
	}
	rowID := client.RowID
	scope.TenantID = client.TenantID
	scope.ApplicationID = &rowID
	return scope
}
