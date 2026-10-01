package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
)

// newDeadBackendCORSService builds a TenantCORSService whose Redis and Postgres
// both point at closed ports. Every IsOriginAllowed lookup then exercises the
// fail-closed path: a CORS decision made without data must deny, not allow.
func newDeadBackendCORSService(globalOrigins []string) *TenantCORSService {
	pool, err := pgxpool.New(context.Background(), "postgres://127.0.0.1:1/dead")
	if err != nil {
		panic(err)
	}
	redisCli := redis.NewClient(&redis.Options{
		Addr:        "127.0.0.1:1",
		DialTimeout: 100 * time.Millisecond,
		MaxRetries:  -1, // never retry — the test wants the failure, not a stall
	})
	return NewTenantCORSService(pool, redisCli, zerolog.Nop()).
		WithGlobalOrigins(globalOrigins)
}

// TestTenantCORS_OriginDecision is the M-01 regression test: the deployment-wide
// permissive policy the advisory flagged must not reappear — an origin is
// allowed only when it is explicitly listed, and a failed backend lookup denies.
func TestTenantCORS_OriginDecision(t *testing.T) {
	svc := newDeadBackendCORSService([]string{"https://admin.engineersmind.com"})

	tests := []struct {
		name       string
		method     string
		origin     string
		wantStatus int
		wantACAO   string // expected Access-Control-Allow-Origin ("" = none)
	}{
		{
			name:       "listed global origin is allowed with credentials",
			method:     http.MethodGet,
			origin:     "https://admin.engineersmind.com",
			wantStatus: http.StatusOK,
			wantACAO:   "https://admin.engineersmind.com",
		},
		{
			name:       "unlisted origin is forbidden even when the backend lookup fails",
			method:     http.MethodGet,
			origin:     "https://evil.example.com",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "unlisted sibling subdomain is forbidden",
			method:     http.MethodGet,
			origin:     "https://staging.engineersmind.com",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "no origin means a non-browser request — passes without CORS headers",
			method:     http.MethodGet,
			wantStatus: http.StatusOK,
		},
		{
			name:       "preflight for a listed origin answers 204",
			method:     http.MethodOptions,
			origin:     "https://admin.engineersmind.com",
			wantStatus: http.StatusNoContent,
			wantACAO:   "https://admin.engineersmind.com",
		},
		{
			name:       "preflight for an unlisted origin is forbidden",
			method:     http.MethodOptions,
			origin:     "https://evil.example.com",
			wantStatus: http.StatusForbidden,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/api/v1/tenants", nil)
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			if tc.method == http.MethodOptions {
				req.Header.Set("Access-Control-Request-Method", "POST")
			}
			rec := httptest.NewRecorder()
			c := echo.New().NewContext(req, rec)

			reached := false
			handler := TenantCORS(svc)(func(c echo.Context) error {
				reached = true
				return c.NoContent(http.StatusOK)
			})
			if err := handler(c); err != nil {
				t.Fatalf("handler returned error: %v", err)
			}

			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			if got := rec.Header().Get("Access-Control-Allow-Origin"); got != tc.wantACAO {
				t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, tc.wantACAO)
			}
			if tc.wantStatus == http.StatusForbidden && reached {
				t.Error("handler was reached for a rejected origin")
			}
		})
	}
}

// TestTenantCORS_NoConfiguredOrigins pins the other half of the advisory: with
// no global list configured and no tenant permitting the origin, the middleware
// adds no CORS headers at all rather than falling back to a permissive
// wildcard. The request still reaches the handler — the browser is what
// enforces the denial — but no credentialed cross-origin read can ever succeed.
func TestTenantCORS_NoConfiguredOrigins(t *testing.T) {
	svc := newDeadBackendCORSService(nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	rec := httptest.NewRecorder()
	c := echo.New().NewContext(req, rec)

	reached := false
	handler := TenantCORS(svc)(func(c echo.Context) error {
		reached = true
		return c.NoContent(http.StatusOK)
	})
	if err := handler(c); err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	if !reached {
		t.Error("handler not reached — an unconfigured deployment must pass through, not 403")
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Access-Control-Allow-Origin = %q, want none — no headers without configured origins", got)
	}
}
