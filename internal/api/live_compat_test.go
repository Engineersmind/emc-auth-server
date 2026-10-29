package api_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
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

// TestLiveIntegrationRateLimits drives the real router with the call patterns
// live integrations send, and counts how many requests are rate limited (429).
//
// It exists to answer one question before a rate-limit change ships: does any
// application that works today get a 429 it did not get before? Every scenario
// is something a deployed backend actually does — most importantly, every
// request in a scenario comes from ONE address, because that is how a product
// backend reaches these routes.
//
// LIVE_COMPAT_REPORT=1 logs the counts without asserting, so the same file can
// be run against an older build for a before/after comparison.
func TestLiveIntegrationRateLimits(t *testing.T) {
	pool := testhelper.NewTestDB(t)
	rdb := testhelper.NewTestRedis(t)
	logger := testhelper.TestLogger()
	ctx := context.Background()
	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}
	// Buckets live in Redis once the router configures distributed limiting;
	// start from empty so an earlier run's buckets cannot leak in.
	if err := rdb.FlushDB(ctx).Err(); err != nil {
		t.Fatalf("flush redis: %v", err)
	}
	var tenantID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM tenants WHERE slug = 'emc' AND deleted_at IS NULL`).Scan(&tenantID); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}

	appSvc := auth.NewApplicationService(pool, logger)
	newApp := func(name string) *auth.AppResult {
		app, err := appSvc.CreateApplication(ctx, tenantID, fmt.Sprintf("%s-%d", name, time.Now().UnixNano()), "web", nil)
		if err != nil {
			t.Fatalf("CreateApplication: %v", err)
		}
		id, _ := strconv.ParseInt(app.ID, 10, 64)
		t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM oauth_clients WHERE id = $1`, id) })
		return app
	}
	// A busy live product: it has sized its quota, like InsuredDesk's row.
	big := newApp("live-sized")
	bigID, _ := strconv.ParseInt(big.ID, 10, 64)
	if _, err := auth.NewAppRateLimitService(pool, rdb, logger).SetAppLimit(ctx, tenantID, bigID, 10000, 1000, "sized"); err != nil {
		t.Fatalf("SetAppLimit: %v", err)
	}
	// An application that never configured a quota (server default).
	plain := newApp("live-default")

	e := echo.New()
	stop := api.RegisterRoutes(e, api.Deps{
		// Fatal-only to stderr: router setup exits the process on misconfiguration,
		// and a silent logger would hide why.
		Logger: zerolog.New(os.Stderr).Level(zerolog.FatalLevel), Pool: pool, Redis: rdb,
		Config: api.RoutesConfig{JWTIssuer: "https://auth.test", Env: "test", AppBaseURL: "http://localhost:8080", OIDCIssuerBaseURL: "http://localhost:8080"},
	})
	defer stop()

	basic := func(app *auth.AppResult, secret string) string {
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(app.ClientID+":"+secret))
	}
	send := func(method, path, ip, authz, body string) int {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if authz != "" {
			req.Header.Set(echo.HeaderAuthorization, authz)
		}
		req.RemoteAddr = ip + ":40000"
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		return rec.Code
	}
	const password = "Corr3ct-Horse-Battery-Staple-91"
	email := func(app string, i int) string { return fmt.Sprintf("live-%s-%d@example.test", app, i) }

	// Users that already exist, each registered once from its own address so
	// that setup is identical under any limiter.
	//
	// The default-quota application gets 10: its quota (60/min, burst 10) is
	// the same under any version of these limiters, and the pause afterwards
	// lets the burst refill before its scenario runs.
	for _, setup := range []struct {
		app   *auth.AppResult
		users int
	}{{big, 40}, {plain, 10}} {
		for i := 0; i < setup.users; i++ {
			body := fmt.Sprintf(`{"email":%q,"password":%q}`, email(setup.app.ID, i), password)
			ip := fmt.Sprintf("10.%s.%d.1", setup.app.ID[len(setup.app.ID)-1:], i)
			if code := send(http.MethodPost, "/api/v1/auth/apps/register", ip, basic(setup.app, setup.app.ClientSecret), body); code != http.StatusCreated {
				t.Fatalf("setup register %d for app %s: %d", i, setup.app.ID, code)
			}
		}
	}
	// Two signed-in users, for the change-email scenario. Each signs in from
	// its own address so setup costs nothing on any limiter being compared.
	var accessTokens []string
	for i, n := range []int{38, 39} {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/apps/login",
			strings.NewReader(fmt.Sprintf(`{"email":%q,"password":%q}`, email(big.ID, n), password)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(echo.HeaderAuthorization, basic(big, big.ClientSecret))
		req.RemoteAddr = fmt.Sprintf("10.250.%d.1:40000", i)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		var tok struct {
			AccessToken string `json:"access_token"`
		}
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &tok) != nil || tok.AccessToken == "" {
			t.Fatalf("setup login for user %d: %d %s", n, rec.Code, rec.Body.String())
		}
		accessTokens = append(accessTokens, tok.AccessToken)
	}

	time.Sleep(11 * time.Second)

	type result struct {
		name      string
		sent, hit int
		maxHit    int // the most 429s acceptable on this branch
	}
	var results []result
	run := func(name string, maxHit int, n int, fn func(i int) int) {
		r := result{name: name, sent: n, maxHit: maxHit}
		for i := 0; i < n; i++ {
			if fn(i) == http.StatusTooManyRequests {
				r.hit++
			}
		}
		results = append(results, r)
	}

	// Each scenario gets its own backend address so their per-IP buckets do
	// not interact.
	run("30 new users register from one backend IP", 0, 30, func(i int) int {
		return send(http.MethodPost, "/api/v1/auth/apps/register", "203.0.113.1", basic(big, big.ClientSecret),
			fmt.Sprintf(`{"email":"new-%d-%d@example.test","password":%q}`, i, time.Now().UnixNano(), password))
	})
	run("30 users sign in from one backend IP", 0, 30, func(i int) int {
		return send(http.MethodPost, "/api/v1/auth/apps/login", "203.0.113.2", basic(big, big.ClientSecret),
			fmt.Sprintf(`{"email":%q,"password":%q}`, email(big.ID, i), password))
	})
	run("1 user mistypes the password 5 times", 0, 5, func(int) int {
		return send(http.MethodPost, "/api/v1/auth/apps/login", "203.0.113.3", basic(big, big.ClientSecret),
			fmt.Sprintf(`{"email":%q,"password":"wrong-password-1"}`, email(big.ID, 35)))
	})
	run("15 users request a reset from one backend IP", 0, 15, func(i int) int {
		return send(http.MethodPost, "/api/v1/auth/forgot-password", "203.0.113.4", basic(big, big.ClientSecret),
			fmt.Sprintf(`{"email":%q}`, email(big.ID, i)))
	})
	run("1 user requests a reset 5 times", 0, 5, func(int) int {
		return send(http.MethodPost, "/api/v1/auth/forgot-password", "203.0.113.5", basic(big, big.ClientSecret),
			fmt.Sprintf(`{"email":%q}`, email(big.ID, 36)))
	})
	// The insurance platform calls reset-password from its backend with no
	// credentials. Unchanged here: 5/min per address, as before.
	run("reset-password without credentials, 5 calls", 0, 5, func(int) int {
		return send(http.MethodPost, "/api/v1/auth/reset-password", "203.0.113.6", "",
			`{"token":"not-a-real-token","new_password":"Another-Passw0rd-77"}`)
	})
	// Same address: captcha fetches must not eat into the reset budget, as
	// they did not before (separate buckets).
	run("reset-password after 5 captcha fetches, same IP", 0, 5, func(i int) int {
		if i == 0 {
			for j := 0; j < 5; j++ {
				send(http.MethodPost, "/api/v1/captcha/challenge", "203.0.113.7", "",
					fmt.Sprintf(`{"client_id":%q,"purpose":"login"}`, big.ClientID))
			}
		}
		return send(http.MethodPost, "/api/v1/auth/reset-password", "203.0.113.7", "",
			`{"token":"not-a-real-token","new_password":"Another-Passw0rd-77"}`)
	})
	run("app with default quota: 10 users sign in", 0, 10, func(i int) int {
		return send(http.MethodPost, "/api/v1/auth/apps/login", "203.0.113.8", basic(plain, plain.ClientSecret),
			fmt.Sprintf(`{"email":%q,"password":%q}`, email(plain.ID, i), password))
	})
	run("browser fetches 5 captchas", 0, 5, func(int) int {
		return send(http.MethodPost, "/api/v1/captcha/challenge", "198.51.100.9", "",
			fmt.Sprintf(`{"client_id":%q,"purpose":"login"}`, big.ClientID))
	})
	run("machine client: 10 token requests", 0, 10, func(int) int {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/token", strings.NewReader("grant_type=client_credentials"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set(echo.HeaderAuthorization, basic(big, big.ClientSecret))
		req.RemoteAddr = "203.0.113.10:40000"
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		return rec.Code
	})
	// ── Flows where client credentials are optional ──────────────────────────
	// Junk session tokens and codes: the handler refuses them, but only after
	// the limiters have run, which is what is being counted.
	otp := func(i int) string {
		return fmt.Sprintf(`{"otp_session_token":"sess-%d-%d","code":"123456"}`, i, time.Now().UnixNano())
	}
	// Today's integrations send no credentials here: must stay exactly as is.
	run("MFA completion, no credentials (10 = old per-IP limit)", 0, 10, func(i int) int {
		return send(http.MethodPost, "/api/v1/auth/login/otp", "203.0.113.20", "", otp(i))
	})
	// A backend that opts in with its credentials completes MFA for many users.
	run("MFA completion for 30 users, backend sends credentials", 0, 30, func(i int) int {
		return send(http.MethodPost, "/api/v1/auth/login/otp", "203.0.113.21", basic(big, big.ClientSecret), otp(i))
	})
	exchange := fmt.Sprintf(`{"client_id":%q,"login_code":"not-a-code"}`, big.ClientID)
	run("Google code exchange, no credentials (5 = old limit)", 0, 5, func(int) int {
		return send(http.MethodPost, "/api/v1/auth/oauth/exchange", "203.0.113.22", "", exchange)
	})
	run("Google code exchange for 20 users, backend sends credentials", 0, 20, func(int) int {
		return send(http.MethodPost, "/api/v1/auth/oauth/exchange", "203.0.113.23", basic(big, big.ClientSecret), exchange)
	})
	run("resend-verification for 15 users, backend sends credentials", 0, 15, func(i int) int {
		return send(http.MethodPost, "/api/v1/auth/resend-verification", "203.0.113.24", basic(big, big.ClientSecret),
			fmt.Sprintf(`{"email":%q}`, email(big.ID, i)))
	})
	run("change-email: 2 signed-in users x 5, one backend IP", 0, 10, func(i int) int {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/change-email",
			strings.NewReader(fmt.Sprintf(`{"new_email":"moved-%d-%d@example.test"}`, i, time.Now().UnixNano())))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+accessTokens[i%2])
		req.RemoteAddr = "203.0.113.25:40000"
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		return rec.Code
	})
	run("OIDC client: 150 /oauth/token calls (old fixed cap 120)", 0, 150, func(int) int {
		req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader("grant_type=refresh_token&refresh_token=not-a-token"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set(echo.HeaderAuthorization, basic(big, big.ClientSecret))
		req.RemoteAddr = "203.0.113.26:40000"
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		return rec.Code
	})
	run("backend revokes 80 tokens on sign-out (old cap 60/IP)", 0, 80, func(int) int {
		req := httptest.NewRequest(http.MethodPost, "/oauth/revoke", strings.NewReader("token=not-a-token"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set(echo.HeaderAuthorization, basic(big, big.ClientSecret))
		req.RemoteAddr = "203.0.113.27:40000"
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		return rec.Code
	})

	// Protection that must remain: a wrong secret is still held to 5/min.
	run("attacker: 10 wrong client secrets from one IP", 10, 10, func(int) int {
		return send(http.MethodPost, "/api/v1/auth/apps/login", "198.51.100.66", basic(big, "guess"),
			fmt.Sprintf(`{"email":%q,"password":%q}`, email(big.ID, 37), password))
	})

	report := os.Getenv("LIVE_COMPAT_REPORT") == "1"
	t.Logf("%-55s %5s %5s", "scenario", "sent", "429s")
	for _, r := range results {
		t.Logf("%-55s %5d %5d", r.name, r.sent, r.hit)
		if !report && r.hit > r.maxHit {
			t.Errorf("%s: %d of %d rate limited, want at most %d", r.name, r.hit, r.sent, r.maxHit)
		}
	}
	// The protection scenario must actually still protect.
	if last := results[len(results)-1]; !report && last.hit < 5 {
		t.Errorf("wrong client secrets: only %d of %d rate limited, want at least 5", last.hit, last.sent)
	}
}
