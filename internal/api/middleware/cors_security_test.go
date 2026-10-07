package middleware

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
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

// ---------------------------------------------------------------------------
// GHSA-8jgj-mwx4-q9wr — per-tenant isolation
// ---------------------------------------------------------------------------

// seedCORSTenant inserts an active tenant with exactly one cors_origin and
// returns its id. Each caller gets a unique slug/origin pair so the 60s Redis
// decision cache cannot leak a verdict between cases.
func seedCORSTenant(t *testing.T, pool *pgxpool.Pool, slug, origin string) int64 {
	t.Helper()
	var id int64
	err := pool.QueryRow(context.Background(), `
		INSERT INTO tenants (name, slug, jwt_secret, is_active, cors_origins)
		VALUES ($1, $2, 'test-secret', true, ARRAY[$3]::text[])
		RETURNING id
	`, slug+" tenant", slug, origin).Scan(&id)
	if err != nil {
		t.Fatalf("seedCORSTenant %s: %v", slug, err)
	}
	return id
}

// testTokenForTenant mints a JWT carrying tenant_id. The signature is a
// throwaway key — CORS reads the claim unverified, which is exactly the point
// the test pins: the claim scopes the lookup, it does not authenticate.
func testTokenForTenant(t *testing.T, tenantID int64) string {
	t.Helper()
	tok, err := gojwt.NewWithClaims(gojwt.SigningMethodHS256, &auth.Claims{
		TenantID: fmt.Sprint(tenantID),
	}).SignedString([]byte("test-signing-key"))
	if err != nil {
		t.Fatalf("testTokenForTenant: %v", err)
	}
	return tok
}

// TestIsOriginAllowed_TenantScoped is the core GHSA-8jgj-mwx4-q9wr regression
// test, run against real Postgres and Redis: tenant A whitelisting an origin
// must not authorize that origin for tenant B.
func TestIsOriginAllowed_TenantScoped(t *testing.T) {
	pool := testhelper.NewTestDB(t)
	rdb := testhelper.NewTestRedis(t)
	testhelper.CleanupTables(t, pool)

	svc := NewTenantCORSService(pool, rdb, testhelper.TestLogger())
	ctx := context.Background()

	aOrigin := fmt.Sprintf("https://app-a-%d.example", time.Now().UnixNano())
	bOrigin := fmt.Sprintf("https://app-b-%d.example", time.Now().UnixNano())
	aID := seedCORSTenant(t, pool, fmt.Sprintf("cors-a-%d", time.Now().UnixNano()), aOrigin)
	bID := seedCORSTenant(t, pool, fmt.Sprintf("cors-b-%d", time.Now().UnixNano()), bOrigin)

	t.Run("origin is allowed for the tenant that listed it", func(t *testing.T) {
		if !svc.IsOriginAllowed(ctx, aOrigin, corsScope{tenantID: aID}) {
			t.Error("tenant A's origin rejected for tenant A")
		}
	})

	t.Run("tenant A origin is rejected for tenant B", func(t *testing.T) {
		if svc.IsOriginAllowed(ctx, aOrigin, corsScope{tenantID: bID}) {
			t.Error("tenant A's origin was allowed while scoped to tenant B — cross-tenant leak")
		}
	})

	t.Run("tenant B origin is rejected for tenant A", func(t *testing.T) {
		if svc.IsOriginAllowed(ctx, bOrigin, corsScope{tenantID: aID}) {
			t.Error("tenant B's origin was allowed while scoped to tenant A — cross-tenant leak")
		}
	})

	t.Run("credentialess request naming no tenant still matches any tenant", func(t *testing.T) {
		// Preflights and cross-origin logins carry no credential; the response
		// they could reach is unauthenticated, so the broad check stays —
		// but only here.
		if !svc.IsOriginAllowed(ctx, aOrigin, corsScope{any: true}) {
			t.Error("any-tenant scope rejected tenant A's own origin")
		}
	})

	t.Run("unreadable credential scope denies per-tenant origins", func(t *testing.T) {
		if svc.IsOriginAllowed(ctx, aOrigin, corsScope{deny: true}) {
			t.Error("deny scope permitted a per-tenant origin")
		}
	})
}

// TestRequestCORSScope pins the resolution order: credentials first (their
// tenant_id decides), then the slug the request names, then the credentialess
// any-tenant fallback. No DB needed — scope resolution never queries.
func TestRequestCORSScope(t *testing.T) {
	newCtx := func() echo.Context {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants", nil)
		return echo.New().NewContext(req, httptest.NewRecorder())
	}

	t.Run("bearer token scopes to its tenant_id claim", func(t *testing.T) {
		c := newCtx()
		c.Request().Header.Set("Authorization", "Bearer "+testTokenForTenant(t, 7))
		if got := requestCORSScope(c); got.tenantID != 7 {
			t.Errorf("scope = %+v, want tenantID 7", got)
		}
	})

	t.Run("access-token cookie scopes to its tenant_id claim", func(t *testing.T) {
		c := newCtx()
		c.Request().AddCookie(&http.Cookie{Name: AccessTokenCookie, Value: testTokenForTenant(t, 9)})
		if got := requestCORSScope(c); got.tenantID != 9 {
			t.Errorf("scope = %+v, want tenantID 9", got)
		}
	})

	t.Run("credential tenant wins over a caller-named slug", func(t *testing.T) {
		// A victim's tenant-B cookie plus a forged X-Tenant-Slug: A must scope
		// to B — otherwise claiming A would unlock A's allowlist for a request
		// that reaches B's data.
		c := newCtx()
		c.Request().AddCookie(&http.Cookie{Name: AccessTokenCookie, Value: testTokenForTenant(t, 9)})
		c.Request().Header.Set("X-Tenant-Slug", "tenant-a")
		if got := requestCORSScope(c); got.tenantID != 9 {
			t.Errorf("scope = %+v, want tenantID 9 — slug must not override the credential", got)
		}
	})

	t.Run("unparseable bearer fails closed", func(t *testing.T) {
		c := newCtx()
		c.Request().Header.Set("Authorization", "Bearer not-a-jwt")
		if got := requestCORSScope(c); !got.deny {
			t.Errorf("scope = %+v, want deny", got)
		}
	})

	t.Run("api key is credentialed but unscoped — fails closed", func(t *testing.T) {
		c := newCtx()
		c.Request().Header.Set(APIKeyHeader, "emck_testkey")
		if got := requestCORSScope(c); !got.deny {
			t.Errorf("scope = %+v, want deny", got)
		}
	})

	t.Run("slug header scopes credentialess request", func(t *testing.T) {
		c := newCtx()
		c.Request().Header.Set("X-Tenant-Slug", "acme")
		if got := requestCORSScope(c); got.slug != "acme" {
			t.Errorf("scope = %+v, want slug acme", got)
		}
	})

	t.Run("no credential and no slug means any-tenant", func(t *testing.T) {
		c := newCtx()
		if got := requestCORSScope(c); !got.any {
			t.Errorf("scope = %+v, want any", got)
		}
	})
}

// TestTenantCORS_CrossTenantCredential runs the full middleware against real
// DB+Redis: a request authenticating as tenant B whose Origin is only listed by
// tenant A must be denied — the exact hole the advisory describes.
func TestTenantCORS_CrossTenantCredential(t *testing.T) {
	pool := testhelper.NewTestDB(t)
	rdb := testhelper.NewTestRedis(t)
	testhelper.CleanupTables(t, pool)

	// A non-empty global list keeps the "no configured origins → pass through"
	// shortcut out of the way so an unlisted origin gets the hard 403.
	svc := NewTenantCORSService(pool, rdb, testhelper.TestLogger()).
		WithGlobalOrigins([]string{"https://console.example"})

	aOrigin := fmt.Sprintf("https://only-a-%d.example", time.Now().UnixNano())
	aID := seedCORSTenant(t, pool, fmt.Sprintf("mw-a-%d", time.Now().UnixNano()), aOrigin)
	bID := seedCORSTenant(t, pool, fmt.Sprintf("mw-b-%d", time.Now().UnixNano()),
		fmt.Sprintf("https://only-b-%d.example", time.Now().UnixNano()))

	call := func(origin string, cookieTenant int64) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
		req.Header.Set("Origin", origin)
		req.AddCookie(&http.Cookie{Name: AccessTokenCookie, Value: testTokenForTenant(t, cookieTenant)})
		rec := httptest.NewRecorder()
		c := echo.New().NewContext(req, rec)
		if err := TenantCORS(svc)(func(c echo.Context) error {
			return c.NoContent(http.StatusOK)
		})(c); err != nil {
			t.Fatalf("middleware error: %v", err)
		}
		return rec
	}

	t.Run("origin listed by tenant A is forbidden for a tenant-B session", func(t *testing.T) {
		rec := call(aOrigin, bID)
		if rec.Code != http.StatusForbidden {
			t.Errorf("status = %d, want 403 — tenant A's origin authorized a tenant-B credential", rec.Code)
		}
	})

	t.Run("same origin is allowed for a tenant-A session", func(t *testing.T) {
		rec := call(aOrigin, aID)
		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", rec.Code)
		}
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != aOrigin {
			t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, aOrigin)
		}
	})
}
