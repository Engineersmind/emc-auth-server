package handlers

import (
	"github.com/labstack/echo/v4"

	mw "github.com/engineersmind/emc-auth-server/internal/api/middleware"
)

// clientIP is the address a request is attributed to in audit events, the
// captcha failure counter and risk checks.
//
// On application end-user routes whose backend is trusted to forward the user's
// address (see middleware.AppS2S), that is the end user's IP. Everywhere else it
// is c.RealIP(), exactly as before. Without this, every user of a product that
// signs people in from its own server shared one address: one person's failed
// logins put a captcha in front of all of them, and audit, geo and risk saw the
// product's data centre instead of the person.
func clientIP(c echo.Context) string {
	return mw.EndUserIP(c)
}
