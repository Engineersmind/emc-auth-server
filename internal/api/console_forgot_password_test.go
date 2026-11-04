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

	// A first-party console account with an address unique to this run. The
	// seeded admin@emc.local would share one per-email bucket across every run
	// and every package that resets it.
	var seedTenant int64
	if err := pool.QueryRow(ctx, `SELECT id FROM tenants WHERE slug = 'emc' AND deleted_at IS NULL`).Scan(&seedTenant); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	consoleUser := func(t *testing.T, label string) (userID int64, address string) {
		t.Helper()
		address = email(label)
		if err := pool.QueryRow(ctx, `
			INSERT INTO users (tenant_id, application_id, email, first_name, last_name, is_active, email_verified)
			VALUES ($1, NULL, $2, 'C', 'R', true, true) RETURNING id
		`, seedTenant, address).Scan(&userID); err != nil {
			t.Fatalf("seed console user: %v", err)
		}
		return userID, address
	}
	tokens := func(t *testing.T, userID int64) int {
		t.Helper()
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM password_reset_tokens WHERE user_id = $1`, userID).Scan(&n); err != nil {
			t.Fatalf("count tokens: %v", err)
		}
		return n
	}
	// The fan-out runs after the response, so issuance is observed by polling.
	awaitTokens := func(t *testing.T, userID int64, want int) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for tokens(t, userID) < want && time.Now().Before(deadline) {
			time.Sleep(50 * time.Millisecond)
		}
		if got := tokens(t, userID); got != want {
			t.Fatalf("reset tokens = %d, want %d", got, want)
		}
	}

	t.Run("registered and unknown emails get the identical 200 with no credentials", func(t *testing.T) {
		userID, address := consoleUser(t, "known")
		known := forgot(ip(1, 1), "", address)
		unknown := forgot(ip(1, 2), "", email("nobody"))
		if known.Code != http.StatusOK || unknown.Code != http.StatusOK {
			t.Fatalf("status known=%d unknown=%d, want 200 for both", known.Code, unknown.Code)
		}
		if known.Body.String() != unknown.Body.String() {
			t.Errorf("bodies differ (RESET-03):\n known:   %s\n unknown: %s", known.Body.String(), unknown.Body.String())
		}
		awaitTokens(t, userID, 1)
	})

	t.Run("per-IP limit answers 429 limiter=ip", func(t *testing.T) {
		addr := ip(2, 1)
		for i := 0; i < 5; i++ {
			if rec := forgot(addr, "", email(fmt.Sprintf("ip-%d", i))); rec.Code != http.StatusOK {
				t.Fatalf("request %d: status %d, want 200 within AUTH-07's 5/min", i+1, rec.Code)
			}
		}
		rec := forgot(addr, "", email("ip-6"))
		if rec.Code != http.StatusTooManyRequests || limiter(t, rec) != "ip" {
			t.Fatalf("6th request: status %d body %s, want 429 limiter=ip", rec.Code, rec.Body.String())
		}
	})

	t.Run("asking for links does not spend the budget for redeeming one", func(t *testing.T) {
		// An admin behind one address who asks five times must still be able to
		// use the link: /reset-password is on a different surface.
		addr := ip(7, 1)
		for i := 0; i < 5; i++ {
			forgot(addr, "", email(fmt.Sprintf("surface-%d", i)))
		}
		rec := post("/api/v1/auth/reset-password", addr, "", `{"token":"not-a-real-token","new_password":"Whatever-Passw0rd!"}`)
		if rec.Code == http.StatusTooManyRequests {
			t.Fatalf("reset-password from the same address: 429 %s — the console route spent its budget", rec.Body.String())
		}
	})

	t.Run("per-email limit holds across addresses and answers 429 limiter=user", func(t *testing.T) {
		// Mixed case and padding normalise into the same recipient bucket.
		to := email("flood")
		for i := 0; i < 5; i++ {
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
			t.Fatalf("6th request for one recipient: status %d body %s, want 429 limiter=user", rec.Code, rec.Body.String())
		}
	})

	t.Run("valid application credentials do not lift the per-IP limit", func(t *testing.T) {
		app, err := auth.NewApplicationService(pool, logger).CreateApplication(ctx, seedTenant, fmt.Sprintf("console-reset-%d", run), "web", nil)
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
			t.Fatalf("6th request with credentials: status %d body %s, want 429 limiter=ip — credentials must be ignored here", rec.Code, rec.Body.String())
		}
	})

	t.Run("a body the limiter cannot key on sends no email", func(t *testing.T) {
		// The per-email limiter reads a form body as no email at all. If the
		// handler still acted on it (c.Bind reads form fields), rotating
		// addresses would mail one recipient without limit.
		userID, address := consoleUser(t, "form")
		req := httptest.NewRequest(http.MethodPost, route, strings.NewReader("email="+address))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		req.RemoteAddr = "[" + ip(6, 1) + "]:40000"
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("form body: status %d, want the generic 200", rec.Code)
		}

		// Checked before the control, which the per-account cooldown would
		// otherwise mask: the fan-out takes milliseconds, so a second is ample.
		time.Sleep(time.Second)
		if n := tokens(t, userID); n != 0 {
			t.Fatalf("%d reset token(s) issued for a body the per-email limiter cannot read", n)
		}

		// Control: a well-formed body for the same recipient IS mailed, so the
		// zero above is the refusal and not a broken probe.
		if rec := forgot(ip(6, 2), "", address); rec.Code != http.StatusOK {
			t.Fatalf("well-formed body: status %d, want 200", rec.Code)
		}
		awaitTokens(t, userID, 1)
	})

	t.Run("application forgot-password still requires client credentials", func(t *testing.T) {
		rec := post("/api/v1/auth/forgot-password", ip(5, 1), "", fmt.Sprintf(`{"email":%q}`, email("app")))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status %d, want 401 — the application route must stay application-only", rec.Code)
		}
	})
}
