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

	tests := []struct {
		name       string
		allowed    []string
		origin     string
		wantExpose string
		wantACAO   string
	}{
		{"allow-listed origin", []string{origin}, origin, "Retry-After", origin},
		{"wildcard origin", []string{"*"}, origin, "Retry-After", "*"},
		{"no Origin header (server-to-server)", []string{origin}, "", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := &TenantCORSService{globalOrigins: tt.allowed}

			e := echo.New()
			e.Use(TenantCORS(svc))
			e.POST("/limited", func(c echo.Context) error {
				c.Response().Header().Set("Retry-After", "42")
				return c.NoContent(http.StatusTooManyRequests)
			})

			req := httptest.NewRequest(http.MethodPost, "/limited", nil)
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, req)

			if got := rec.Header().Get("Access-Control-Expose-Headers"); got != tt.wantExpose {
				t.Errorf("Access-Control-Expose-Headers = %q, want %q", got, tt.wantExpose)
			}
			if got := rec.Header().Get("Access-Control-Allow-Origin"); got != tt.wantACAO {
				t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, tt.wantACAO)
			}
			if got := rec.Header().Get("Retry-After"); got != "42" {
				t.Errorf("Retry-After = %q, want it passed through unchanged", got)
			}
		})
	}
}
