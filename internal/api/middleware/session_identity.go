package middleware

import (
	"context"
	"net/http"

	"github.com/labstack/echo/v4"

	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// SessionUserHeader carries the caller's own belief about which user it is
// acting as. It is an assertion from a cooperating client, never a credential:
// authority comes from the cookie alone, and this only ever causes a request to
// be REFUSED, never allowed.
const SessionUserHeader = "X-Session-User"

// authSourceKey records how the request authenticated: the session-identity
// check applies to browser cookie sessions only.
const authSourceKey = "auth_source"

const (
	authSourceCookie = "cookie"
	authSourceBearer = "bearer"
)

// proceedAuthenticated is the single gate every authenticating middleware passes
// through once it has resolved claims. It publishes the claims and the auth
// source for downstream handlers, applies the session-identity check, and only
// then invokes the handler.
//
// It exists so the check cannot be forgotten. JWTRenew alone reaches the handler
// from three different places (verified token, grace path, post-rotation), and a
// guard mounted per-route-group would have to be remembered by every future
// admin group.
func proceedAuthenticated(c echo.Context, claims *auth.Claims, viaCookie bool, next echo.HandlerFunc) error {
	c.Set(userContextKey, claims)
	if viaCookie {
		c.Set(authSourceKey, authSourceCookie)
	} else {
		c.Set(authSourceKey, authSourceBearer)
	}

	if rejection, blocked := checkSessionRevoked(c, claims); blocked {
		return rejection
	}
	if rejection, blocked := checkSessionIdentity(c, claims, viaCookie); blocked {
		return rejection
	}
	return next(c)
}

// SessionRevocationChecker reports whether a session has been revoked recently
// enough that its outstanding access tokens must be refused. Implemented by
// *auth.AuthService.
type SessionRevocationChecker interface {
	SessionDenied(ctx context.Context, sessionID, userID, tenantID string, issuedAt int64) bool
}

// sessionRevocation is the process-wide revocation checker.
//
// A package-level dependency rather than a middleware parameter because the check
// belongs in proceedAuthenticated, which is reached from three separate places
// inside JWTRenew alone (verified token, grace path, post-rotation) and from
// JWTRequired besides. Threading a service through all of them would mean every
// future authenticating path has to remember to pass it, and one that forgot would
// silently stop honouring revocations — a failure with no symptom until somebody
// tries to revoke a session during an incident.
//
// nil disables the check, which is the correct default: unset, revocation still
// takes effect at the next refresh, exactly as it did before this existed.
var sessionRevocation SessionRevocationChecker

// SetSessionRevocationChecker installs the revocation checker. Called once during
// route registration, before the server accepts traffic.
//
// Test contract: because the variable is process-wide, a test that installs a
// checker MUST restore it, or it leaks into every later test in the package and
// makes ordering significant:
//
//	middleware.SetSessionRevocationChecker(fake)
//	t.Cleanup(func() { middleware.SetSessionRevocationChecker(nil) })
//
// nil is the correct zero to restore to, not the previously-installed value: no
// test should be depending on one having been installed by another.
func SetSessionRevocationChecker(checker SessionRevocationChecker) {
	sessionRevocation = checker
}

// checkSessionRevoked refuses a request whose session has been revoked.
//
// Returns 401 with code "session_revoked" rather than the generic token_invalid:
// the credential is genuinely well-formed and correctly signed, and the client's
// correct response is to stop and re-authenticate rather than to attempt a refresh
// that will also fail. Naming the case lets the client skip a pointless round trip
// and lets an operator tell revocations apart from malformed tokens in the logs.
//
// Both a single-session revoke and an account-wide one are caught, which is why
// the user and tenant claims are passed alongside the session id: an account-wide
// revocation (revoke-all, an operator block, a password reset) does not know which
// sessions exist, so it is recorded against the account instead. Checking only the
// session id — the first version of this — left every account-wide revocation with
// no effect at all on tokens already issued.
//
// A token with neither a "sid" nor a parseable user/tenant is allowed through:
// those are client-credentials and agent tokens, which have no session and no
// account to revoke, plus any access token minted before the sid claim existed.
// Blocking on their absence would refuse every machine client in the deployment.
func checkSessionRevoked(c echo.Context, claims *auth.Claims) (rejection error, blocked bool) {
	if sessionRevocation == nil {
		return nil, false
	}
	// The token's issue time distinguishes "in circulation when the account was
	// revoked" from "minted afterwards". Without it an account-wide revocation would
	// also refuse the tokens the user receives when they sign back in, locking them
	// out for the denylist entry's whole lifetime.
	var issuedAt int64
	if claims.IssuedAt != nil {
		issuedAt = claims.IssuedAt.Unix()
	}
	if !sessionRevocation.SessionDenied(c.Request().Context(), claims.SessionID, claims.UserID, claims.TenantID, issuedAt) {
		return nil, false
	}
	return c.JSON(http.StatusUnauthorized, map[string]string{
		"error": "this session has been signed out",
		"code":  "session_revoked",
	}), true
}

// checkSessionIdentity refuses a mutating request whose caller believes it is
// acting as somebody other than the user the cookie actually proves.
//
// The problem it solves: a browser has one cookie jar per origin, so signing in
// as a second user silently overwrites the session for every open tab. A tab
// left on the admin dashboard goes on rendering admin UI while its requests now
// carry the second user's cookie. Authorization stays correct — the server
// enforces whatever that second user may do — but the operator is looking at one
// identity and acting as another, and the audit trail records the wrong actor.
// Mis-attributed audit entries are the real damage; for an auth product they are
// worse than an outright error.
//
// The check engages only when all three hold:
//
//   - the method is mutating. A stale read renders stale data, which the tab
//     will correct on its next identity check; a stale WRITE cannot be undone.
//   - the request authenticated by cookie. A Bearer client holds its token
//     explicitly and cannot have it swapped underneath by another tab, so the
//     mismatch this guards against is not reachable there.
//   - the client sent the header. Absence means "not a participant" — older
//     frontend builds, curl, server-to-server callers — and must keep working.
//     This is safe precisely because the header cannot grant anything.
//
// Returned separately as (rejection, blocked) to match checkTrustedOrigin in
// csrf.go: echo's c.JSON returns nil on success, so a lone error return would
// read as "allowed" immediately after the 409 body was written.
func checkSessionIdentity(c echo.Context, claims *auth.Claims, viaCookie bool) (rejection error, blocked bool) {
	if !viaCookie || !isMutating(c.Request().Method) {
		return nil, false
	}
	asserted := c.Request().Header.Get(SessionUserHeader)
	if asserted == "" || asserted == claims.UserID {
		return nil, false
	}

	// 409 rather than 401/403: nothing is wrong with the credential and
	// re-authenticating would not help. The tab's view of the world is stale and
	// the fix is to reload.
	//
	// No identity is named. It is tempting to return claims.Email so the UI can
	// say who the browser switched to, and it looks safe — the caller holds that
	// session's cookie and /auth/me would tell them the same thing. But the
	// reader of that message is whoever is looking at the STALE tab, and on a
	// shared machine that is not the person who just signed in: it would tell
	// the previous occupant the new one's address. The message is just as useful
	// without it.
	return c.JSON(http.StatusConflict, map[string]string{
		"error": "this browser is now signed in to a different account — reload the page to continue",
		"code":  "session_identity_changed",
	}), true
}
