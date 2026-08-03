package middleware

import (
	"bytes"
	"net/http"

	"github.com/labstack/echo/v4"
)

// bufferedResponseWriter captures a response without writing it through, so a
// wrapping middleware can inspect the final status and rewrite the body
// before anything reaches the client.
type bufferedResponseWriter struct {
	header     http.Header
	body       bytes.Buffer
	statusCode int
}

func newBufferedResponseWriter() *bufferedResponseWriter {
	return &bufferedResponseWriter{header: make(http.Header)}
}

func (w *bufferedResponseWriter) Header() http.Header { return w.header }

func (w *bufferedResponseWriter) Write(b []byte) (int, error) {
	if w.statusCode == 0 {
		w.statusCode = http.StatusOK
	}
	return w.body.Write(b)
}

func (w *bufferedResponseWriter) WriteHeader(code int) {
	if w.statusCode == 0 {
		w.statusCode = code
	}
}

// NormalizeAppScopeUnauthorized wraps jwtRenew (and anything else in the
// chain) so that every 401 it produces comes back as the single generic
// {"code":"token_invalid"} body AppMe itself uses for every rejection reason.
//
// Without this, a caller hitting /auth/apps/me with an EXPIRED bearer token
// never reaches AppMe at all: jwtRenew rejects it first with
// {"code":"token_expired"}, a distinguishable code the endpoint's no-oracle
// contract explicitly forbids (see AppMe's doc comment in handlers/auth.go).
// jwtRenew's other codes (token_missing, service_unavailable, unauthenticated)
// leak the same way and are normalized here too — this endpoint's contract is
// "every rejection is 401 token_invalid," full stop, not "every rejection
// AppMe itself produces."
//
// Must be the OUTERMOST middleware on the route (listed before jwtRenew) so it
// wraps every downstream rejection, not just the ones after the handler runs.
func NormalizeAppScopeUnauthorized(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		realWriter := c.Response().Writer
		buf := newBufferedResponseWriter()
		c.Response().Writer = buf

		err := next(c)

		c.Response().Writer = realWriter

		if buf.statusCode == http.StatusUnauthorized {
			return c.JSON(http.StatusUnauthorized, map[string]string{
				"error": "invalid token",
				"code":  "token_invalid",
			})
		}

		status := buf.statusCode
		if status == 0 {
			status = http.StatusOK
		}
		for k, values := range buf.header {
			for _, v := range values {
				realWriter.Header().Add(k, v)
			}
		}
		realWriter.WriteHeader(status)
		if buf.body.Len() > 0 {
			if _, werr := realWriter.Write(buf.body.Bytes()); werr != nil {
				return werr
			}
		}
		return err
	}
}
