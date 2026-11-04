package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
)

// A browser on another origin can read Retry-After only if the server lists it
// in Access-Control-Expose-Headers. Without it a 429 reaches the page with the
// header hidden, and the page can only guess how long to wait.
func TestTenantCORSExposesRetryAfter(t *testing.T) {
	const origin = "https://app.example.com"
	svc := &TenantCORSService{globalOrigins: []string{origin}}

	e := echo.New()
	e.Use(TenantCORS(svc))
	e.POST("/limited", func(c echo.Context) error {
		c.Response().Header().Set("Retry-After", "42")
		return c.NoContent(http.StatusTooManyRequests)
	})

	req := httptest.NewRequest(http.MethodPost, "/limited", nil)
	req.Header.Set("Origin", origin)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if got := rec.Header().Get("Access-Control-Expose-Headers"); got != "Retry-After" {
		t.Errorf("Access-Control-Expose-Headers = %q, want Retry-After", got)
	}
	if got := rec.Header().Get("Retry-After"); got != "42" {
		t.Errorf("Retry-After = %q, want it passed through unchanged", got)
	}
}
