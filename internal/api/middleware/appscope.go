package middleware

import (
	"bytes"
	"errors"
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

// Flush satisfies http.Flusher. Nothing to do — the whole point of this writer
// is that nothing leaves it until the wrapping middleware decides what the
// response is. It exists so a middleware that type-asserts the writer to
// http.Flusher (Echo's own gzip middleware does) finds the interface it expects
// rather than silently degrading.
func (w *bufferedResponseWriter) Flush() {}

// isUnauthorized reports whether this exchange ended in a 401, whether the
// downstream wrote the response itself or reported it as an error.
//
// Both forms occur on this route: jwtRenew writes its own 401 body, while a
// middleware failing early returns echo.NewHTTPError(401) and lets Echo render
// it. Normalization has to cover both, or the error form becomes the oracle the
// written form was closed against.
func isUnauthorized(err error, bufferedStatus int) bool {
	if bufferedStatus == http.StatusUnauthorized {
		return true
	}
	var httpErr *echo.HTTPError
	return errors.As(err, &httpErr) && httpErr.Code == http.StatusUnauthorized
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
		resp := c.Response()
		realWriter := resp.Writer
		buf := newBufferedResponseWriter()
		resp.Writer = buf

		err := next(c)

		resp.Writer = realWriter

		// Everything downstream wrote went into the buffer, so nothing has
		// actually reached the client — but Echo's Response still believes it is
		// committed and will refuse to write a status onto it. Clearing the flag
		// is what makes the rewrite below take effect; without it Echo skipped the
		// 401 header and emitted only the body, so every normalized rejection went
		// out as HTTP 200 carrying a token_invalid payload.
		wasCommitted := resp.Committed
		resp.Committed = false
		resp.Size = 0

		if isUnauthorized(err, buf.statusCode) {
			return c.JSON(http.StatusUnauthorized, map[string]string{
				"error": "invalid token",
				"code":  "token_invalid",
			})
		}

		// Any other error: discard the buffer and let Echo's error handler own the
		// response. Replaying the buffer first would commit a header — a buffered
		// status of 0 defaults to 200 — and the error handler would then write a
		// second body onto it, so a 5xx reached the client as a garbled 200.
		if err != nil {
			return err
		}

		resp.Committed = wasCommitted
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
		resp.Status = status
		resp.Committed = true
		if buf.body.Len() > 0 {
			n, werr := realWriter.Write(buf.body.Bytes())
			resp.Size = int64(n)
			if werr != nil {
				return werr
			}
		}
		return nil
	}
}
