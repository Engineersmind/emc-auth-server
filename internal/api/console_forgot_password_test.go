package api_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog"

	"github.com/engineersmind/emc-auth-server/internal/api"
	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/store"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// TestConsoleForgotPassword_Route drives POST /api/v1/auth/console/forgot-password
// (issue #179) through the real router: the limiters it is mounted with, the
// enumeration-safe response, and that the application route beside it is
// unchanged. Which accounts are mailed is pinned in internal/auth.
func TestConsoleForgotPassword_Route(t *testing.T) {
	pool := testhelper.NewTestDB(t)
	// RegisterRoutes backfills a signing key for every tenant, sealed with the
	// test fallback key. Left behind, it fails every later test in this package
	// that seals keys with its own (jwks_http_test.go: "gcm open: message
	// authentication failed").
	testhelper.CleanupTables(t, pool)
	rdb := testhelper.NewTestRedis(t)
	logger := testhelper.TestLogger()
	ctx := context.Background()
	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}

	e := echo.New()
	stop := api.RegisterRoutes(e, api.Deps{
		Logger: zerolog.New(os.Stderr).Level(zerolog.FatalLevel), Pool: pool, Redis: rdb,
		Config: api.RoutesConfig{JWTIssuer: "https://auth.test", Env: "test", AppBaseURL: "http://localhost:8080", OIDCIssuerBaseURL: "http://localhost:8080"},
	})
	defer stop()

	// Buckets persist in Redis between runs, so every address and email here is
	// unique to this run rather than flushing a database other packages share.
	run := time.Now().UnixNano()
	ip := func(scenario, i int) string { return fmt.Sprintf("2001:db8:%x:%x::%x", run&0xffff, scenario, i) }
	email := func(label string) string { return fmt.Sprintf("console-%s-%d@example.test", label, run) }

	post := func(path, addr, authz, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		if authz != "" {
			req.Header.Set(echo.HeaderAuthorization, authz)
		}
		req.RemoteAddr = "[" + addr + "]:40000"
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		return rec
	}
	const route = "/api/v1/auth/console/forgot-password"
	forgot := func(addr, authz, to string) *httptest.ResponseRecorder {
		return post(route, addr, authz, fmt.Sprintf(`{"email":%q}`, to))
	}
	limiter := func(t *testing.T, rec *httptest.ResponseRecorder) string {
		t.Helper()
		var body map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("429 body is not JSON: %s", rec.Body.String())
		}
		return body["limiter"]
	}

	t.Run("registered and unknown emails get the identical 200 with no credentials", func(t *testing.T) {
		// admin@emc.local is the seeded first-party console account.
		known := forgot(ip(1, 1), "", "admin@emc.local")
		unknown := forgot(ip(1, 2), "", email("nobody"))
		if known.Code != http.StatusOK || unknown.Code != http.StatusOK {
			t.Fatalf("status known=%d unknown=%d, want 200 for both", known.Code, unknown.Code)
		}
		if known.Body.String() != unknown.Body.String() {
			t.Errorf("bodies differ (RESET-03):\n known:   %s\n unknown: %s", known.Body.String(), unknown.Body.String())
		}
	})

	t.Run("per-IP limit answers 429 limiter=ip", func(t *testing.T) {
		addr := ip(2, 1)
		for i := 0; i < 5; i++ {
			if rec := forgot(addr, "", email(fmt.Sprintf("ip-%d", i))); rec.Code != http.StatusOK {
				t.Fatalf("request %d: status %d, want 200 within the 5/min per IP", i+1, rec.Code)
			}
		}
		rec := forgot(addr, "", email("ip-6"))
		if rec.Code != http.StatusTooManyRequests || limiter(t, rec) != "ip" {
			t.Fatalf("6th request: status %d body %s, want 429 limiter=ip", rec.Code, rec.Body.String())
		}
	})

	t.Run("per-email limit holds across addresses and answers 429 limiter=user", func(t *testing.T) {
		// Mixed case and padding normalise into the same recipient bucket, which
		// allows PerTenantRate (10/min) per address.
		to := email("flood")
		for i := 0; i < 10; i++ {
			variant := to
			if i%2 == 1 {
				variant = "  " + strings.ToUpper(to)
			}
			if rec := forgot(ip(3, i), "", variant); rec.Code != http.StatusOK {
				t.Fatalf("request %d: status %d, want 200", i+1, rec.Code)
			}
		}
		rec := forgot(ip(3, 99), "", to)
		if rec.Code != http.StatusTooManyRequests || limiter(t, rec) != "user" {
			t.Fatalf("11th request for one recipient: status %d body %s, want 429 limiter=user", rec.Code, rec.Body.String())
		}
	})

	t.Run("valid application credentials do not lift the per-IP limit", func(t *testing.T) {
		var tenantID int64
		if err := pool.QueryRow(ctx, `SELECT id FROM tenants WHERE slug = 'emc' AND deleted_at IS NULL`).Scan(&tenantID); err != nil {
			t.Fatalf("seed tenant: %v", err)
		}
		app, err := auth.NewApplicationService(pool, logger).CreateApplication(ctx, tenantID, fmt.Sprintf("console-reset-%d", run), "web", nil)
		if err != nil {
			t.Fatalf("CreateApplication: %v", err)
		}
		t.Cleanup(func() {
			_, _ = pool.Exec(context.Background(), `DELETE FROM oauth_clients WHERE client_id = $1`, app.ClientID)
		})
		basic := "Basic " + base64.StdEncoding.EncodeToString([]byte(app.ClientID+":"+app.ClientSecret))

		addr := ip(4, 1)
		for i := 0; i < 5; i++ {
			forgot(addr, basic, email(fmt.Sprintf("creds-%d", i)))
		}
		rec := forgot(addr, basic, email("creds-6"))
		if rec.Code != http.StatusTooManyRequests || limiter(t, rec) != "ip" {
			t.Fatalf("6th request with credentials: status %d body %s, want 429 limiter=ip — credentials must not lift it", rec.Code, rec.Body.String())
		}
	})

	t.Run("a body the limiter cannot key on sends no email", func(t *testing.T) {
		// PasswordResetRateLimiter reads the email with json.Unmarshal; a body it
		// rejects skips the per-email bucket. If the handler still accepted such
		// a body (c.Bind takes the first JSON value, or form fields), rotating
		// addresses would mail one recipient without limit.
		const to = "admin@emc.local"
		var before int64
		if err := pool.QueryRow(ctx, `SELECT COALESCE(MAX(t.id), 0) FROM password_reset_tokens t
			JOIN users u ON u.id = t.user_id WHERE u.email = $1`, to).Scan(&before); err != nil {
			t.Fatalf("read tokens: %v", err)
		}
		issuedSince := func() int {
			var n int
			if err := pool.QueryRow(ctx, `SELECT count(*) FROM password_reset_tokens t
				JOIN users u ON u.id = t.user_id WHERE u.email = $1 AND t.id > $2`, to, before).Scan(&n); err != nil {
				t.Fatalf("count tokens: %v", err)
			}
			return n
		}

		for i, body := range []string{
			fmt.Sprintf(`{"email":%q} {}`, to),
			fmt.Sprintf(`{"email":%q}{"email":"other@example.test"}`, to),
		} {
			if rec := post(route, ip(6, i), "", body); rec.Code != http.StatusOK {
				t.Fatalf("trailing JSON %d: status %d, want the generic 200", i+1, rec.Code)
			}
		}
		req := httptest.NewRequest(http.MethodPost, route, strings.NewReader("email="+to))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		req.RemoteAddr = "[" + ip(6, 9) + "]:40000"
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("form body: status %d, want the generic 200", rec.Code)
		}
		if n := issuedSince(); n != 0 {
			t.Fatalf("%d reset token(s) issued for bodies the per-email limiter cannot read", n)
		}

		// Control: the same recipient with a well-formed body IS mailed, so the
		// zero above is the refusal and not a broken probe.
		if rec := forgot(ip(6, 10), "", to); rec.Code != http.StatusOK {
			t.Fatalf("well-formed body: status %d, want 200", rec.Code)
		}
		if n := issuedSince(); n != 1 {
			t.Fatalf("well-formed body issued %d token(s), want 1", n)
		}
	})
	t.Run("application forgot-password still requires client credentials", func(t *testing.T) {
		rec := post("/api/v1/auth/forgot-password", ip(5, 1), "", fmt.Sprintf(`{"email":%q}`, email("app")))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status %d, want 401 — the application route must stay application-only", rec.Code)
		}
	})
}
