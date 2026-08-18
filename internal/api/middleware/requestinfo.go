package middleware

import (
	"github.com/labstack/echo/v4"

	"github.com/engineersmind/emc-auth-server/internal/requestctx"
)

// RequestInfo attaches the caller's client IP and User-Agent to the request
// context so the service layer can record which device a session belongs to.
//
// Mounted globally and early: the token-minting flows that consume it are spread
// across password login, registration, MFA completion, magic link, and every
// social/SAML callback, and a per-group mount would have to be remembered for
// each new one. A session row with no device attribution cannot be recovered
// after the fact, so the cost of forgetting is permanent while the cost of
// carrying two strings on every request is nil.
//
// c.RealIP() is used rather than the raw RemoteAddr so the value reflects the
// true client behind a load balancer. That makes it only as trustworthy as the
// proxy chain, which is why nothing authorizes on it — see requestctx.
func RequestInfo() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			req := c.Request()
			ctx := requestctx.WithRequestInfo(req.Context(), c.RealIP(), req.UserAgent())
			c.SetRequest(req.WithContext(ctx))
			return next(c)
		}
	}
}
