package middleware

import (
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

	if rejection, blocked := checkSessionIdentity(c, claims, viaCookie); blocked {
		return rejection
	}
	return next(c)
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
