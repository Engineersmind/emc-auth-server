package middleware_test

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/engineersmind/emc-auth-server/internal/api/middleware"
	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/store"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// Regression tests for the second human review of PR #174.

// #1: on the optional routes, a verified backend is trusted only for subjects in
// its own tenant (and application, when the subject belongs to one). Another
// tenant's or application's subject gets exactly what a caller without
// credentials gets. A session that does not resolve belongs to nobody and keeps
// the backend trusted, or expired sessions would throttle a real backend.
func TestReview174b_BackendTrustedOnlyForItsOwnSubjects(t *testing.T) {
	s, _ := newS2S(middleware.AppS2SConfig{}, nil)
	sessions := map[string][2]int64{
		"own":          {appTenantID, appRowID},
		"tenant-level": {appTenantID, 0},
		"other-tenant": {99, 0},
		"other-app":    {appTenantID, 55},
	}
	lookup := func(_ context.Context, token string) (int64, int64, bool) {
		v, ok := sessions[token]
		return v[0], v[1], ok
	}
	trusted := map[string]bool{}
	probe := func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			var body struct {
				Token string `json:"otp_session_token"`
			}
			_ = c.Bind(&body)
			trusted[body.Token] = true
			return next(c)
		}
	}
	chain := []echo.MiddlewareFunc{
		s.ResolveOptional(middleware.SurfaceMFA),
		middleware.ScopeToCaller(middleware.ScopeByBodyToken("otp_session_token", lookup)),
		middleware.BackendsOnly(probe),
	}
	for _, token := range []string{"own", "tenant-level", "other-tenant", "other-app", "expired"} {
		runS2S(t, chain, s2sReq{remote: backendIP, clientID: appClient, secret: appSecret,
			body: `{"otp_session_token":"` + token + `","code":"123456"}`})
	}
	for token, want := range map[string]bool{"own": true, "tenant-level": true, "other-tenant": false, "other-app": false, "expired": true} {
		if trusted[token] != want {
			t.Errorf("session %q: trusted backend = %v, want %v", token, trusted[token], want)
		}
	}
}

// #1, change-email: another tenant's signed-in user keeps TokenRateLimiter's
// 5/min per IP even when the caller's credentials verify; the caller's own
// tenant's users do not share it.
func TestReview174b_ChangeEmailKeepsPerIPLimitForOtherTenantsUsers(t *testing.T) {
	s, _ := newS2S(middleware.AppS2SConfig{}, nil)
	chain := []echo.MiddlewareFunc{
		verifiedClaimsFromBearer,
		s.ResolveOptional(middleware.SurfaceAccount),
		middleware.ScopeToCaller(middleware.ScopeSignedInUser),
		middleware.BackendsOnly(middleware.SignedInUserRateLimiter("change_email_user", 5)),
		middleware.TokenRateLimiter(middleware.DefaultRateLimitConfig()),
	}
	send := func(tenant, user string) int {
		return runS2S(t, chain, s2sReq{remote: backendIP, clientID: appClient, secret: appSecret,
			header: middleware.ClientAuthHeader, bearer: bearerFor(tenant, user),
			body: `{"new_email":"x@example.com"}`}).code
	}
	for i := 0; i < 20; i++ {
		if got := send(strconv.FormatInt(appTenantID, 10), strconv.Itoa(1000+i)); got != http.StatusOK {
			t.Fatalf("own-tenant user %d: got %d, want 200", i, got)
		}
	}
	for i := 0; i < 5; i++ {
		send("99", strconv.Itoa(2000+i))
	}
	if got := send("99", "2999"); got != http.StatusTooManyRequests {
		t.Fatalf("6th other-tenant user from one IP: got %d, want 429 (per-IP limit kept)", got)
	}
}

// #3: leading whitespace used to shift the 254-byte cut and give one victim a
// fresh per-email bucket per padding length.
func TestReview174b_EmailPaddingDoesNotBuyBuckets(t *testing.T) {
	s, _ := newS2S(middleware.AppS2SConfig{}, trustWith([]string{backendIP + "/32"}, false))
	chain := []echo.MiddlewareFunc{
		s.Resolve(middleware.SurfaceReset),
		s.UserLimit("app_forgot_password_user", 5, middleware.SubjectEmail),
	}
	var codes []int
	for pad := 242; pad <= 254; pad++ {
		res := runS2S(t, chain, s2sReq{remote: backendIP, clientID: appClient, secret: appSecret,
			body: `{"email":"` + strings.Repeat(" ", pad) + `Victim@X.com"}`})
		codes = append(codes, res.code)
	}
	for i, code := range codes {
		want := http.StatusOK
		if i >= 5 {
			want = http.StatusTooManyRequests
		}
		if code != want {
			t.Fatalf("request %d for the same victim: got %d, want %d (codes %v)", i+1, code, want, codes)
		}
	}
}

// #4: a forged token naming a victim must not spend the victim's /apps/me
// bucket. The per-user limit keys on VERIFIED claims, behind the JWT middleware.
func TestReview174b_ForgedTokenCannotSpendVictimsBucket(t *testing.T) {
	s, _ := newS2S(middleware.AppS2SConfig{Users: middleware.AppUserLimits{Me: 2}}, nil)
	fakeJWT := func(next echo.HandlerFunc) echo.HandlerFunc {
		verify := verifiedClaimsFromBearer(next)
		return func(c echo.Context) error {
			if !strings.HasSuffix(c.Request().Header.Get(echo.HeaderAuthorization), ".sig") {
				return c.JSON(http.StatusUnauthorized, map[string]string{"code": "token_invalid"})
			}
			return verify(c)
		}
	}
	chain := []echo.MiddlewareFunc{
		s.Resolve(middleware.SurfaceApp),
		fakeJWT,
		s.UserLimit("app_me_user", s.UserLimits().Me, middleware.SubjectSignedInUser),
	}
	victim := bearerFor("7", "100")
	forged := strings.TrimSuffix(victim, ".sig") + ".forged"
	for i := 0; i < 30; i++ {
		runS2S(t, chain, s2sReq{remote: backendIP, clientID: appClient, secret: appSecret,
			header: middleware.ClientAuthHeader, bearer: forged})
	}
	for i := 0; i < 2; i++ {
		if res := runS2S(t, chain, s2sReq{remote: backendIP, clientID: appClient, secret: appSecret,
			header: middleware.ClientAuthHeader, bearer: victim}); res.code != http.StatusOK {
			t.Fatalf("victim's own request %d after 30 forged ones: got %d %v, want 200", i+1, res.code, res.body)
		}
	}
}

// #5: during a secret rotation, an instance still sending the old secret from
// the application's registered server IP must not lock out the instances on
// that address that hold the new one.
func TestReview174b_StaleSecretFromServerIPDoesNotLockOutTheRightOne(t *testing.T) {
	s, _ := newS2S(middleware.AppS2SConfig{}, trustWith([]string{backendIP + "/32"}, false))
	chain := loginChain(s)
	if res := runS2S(t, chain, s2sReq{remote: backendIP, clientID: appClient, secret: appSecret, body: emailBody("a@x.com")}); res.code != http.StatusOK {
		t.Fatalf("first request: got %d", res.code)
	}
	for i := 0; i < 20; i++ {
		runS2S(t, chain, s2sReq{remote: backendIP, clientID: appClient, secret: "old-secret", body: emailBody(fmt.Sprintf("s%d@x.com", i))})
	}
	for i := 0; i < 20; i++ {
		res := runS2S(t, chain, s2sReq{remote: backendIP, clientID: appClient, secret: appSecret, body: emailBody(fmt.Sprintf("n%d@x.com", i))})
		if res.code != http.StatusOK {
			t.Fatalf("new-secret request %d during rotation: got %d %v, want 200", i+1, res.code, res.body)
		}
	}
}

// #5, the guard on the fix: with the address-wide wrong-secret check gone for
// server IPs, a cached right secret must still be refused once the attempt
// budget is exhausted — otherwise wrong guesses get 429 while the right one
// passes, an oracle for anyone sharing that egress.
func TestReview174b_ServerIPExhaustedBudgetIsNotAnOracle(t *testing.T) {
	s, _ := newS2S(middleware.AppS2SConfig{}, trustWith([]string{backendIP + "/32"}, false))
	chain := loginChain(s)
	runS2S(t, chain, s2sReq{remote: backendIP, clientID: appClient, secret: appSecret, body: emailBody("a@x.com")}) // now cached
	var wrong int
	for i := 0; i < 40; i++ {
		wrong = runS2S(t, chain, s2sReq{remote: backendIP, clientID: appClient, secret: fmt.Sprintf("guess-%d", i), body: emailBody("g@x.com")}).code
	}
	if wrong != http.StatusTooManyRequests {
		t.Fatalf("40th distinct wrong secret: got %d, want 429 (attempt budget)", wrong)
	}
	if got := runS2S(t, chain, s2sReq{remote: backendIP, clientID: appClient, secret: appSecret, body: emailBody("b@x.com")}).code; got != wrong {
		t.Fatalf("right (cached) secret while the budget is exhausted: got %d, wrong ones got %d — the difference is an oracle", got, wrong)
	}
}

// #2 (integration, DB + Redis): a body client_id on /captcha/challenge carries
// no secret, so it must not spend the application's real quota — the bucket the
// product backend's verified traffic depends on.
func TestReview174b_CaptchaBodyClientIDCannotDrainTheRealQuota(t *testing.T) {
	pool := testhelper.NewTestDB(t)
	rdb := testhelper.NewTestRedis(t)
	logger := testhelper.TestLogger()
	ctx := context.Background()
	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}
	var tenantID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM tenants WHERE slug = 'emc' AND deleted_at IS NULL`).Scan(&tenantID); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	appSvc := auth.NewApplicationService(pool, logger)
	app, err := appSvc.CreateApplication(ctx, tenantID, fmt.Sprintf("s2s-captcha-%d", time.Now().UnixNano()), "web", nil)
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}
	appID, _ := strconv.ParseInt(app.ID, 10, 64)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM oauth_clients WHERE id = $1`, appID)
	})
	limitSvc := auth.NewAppRateLimitService(pool, rdb, logger)
	if _, err := limitSvc.SetAppLimit(ctx, tenantID, appID, 3, 3, "test"); err != nil {
		t.Fatalf("SetAppLimit: %v", err)
	}
	for _, prefix := range []string{"appauth:", "appauth-unverified:"} {
		rdb.Del(ctx, "rate:"+prefix+strconv.FormatInt(tenantID, 10)+":"+app.ID)
	}

	trust := auth.NewAppTrustService(pool, logger)
	middleware.ResetStoresForTest()
	s := middleware.NewAppS2S(middleware.AppS2SConfig{}, trust, appSvc, logger)
	captcha := []echo.MiddlewareFunc{s.ResolveBodyClient(middleware.SurfaceApp), middleware.AppClientBodyRateLimiter(limitSvc, rdb, logger)}
	login := []echo.MiddlewareFunc{s.Resolve(middleware.SurfaceApp), middleware.AppClientRateLimiter(limitSvc, rdb, logger)}

	// A stranger, from many addresses so the per-IP limit does not stop them.
	for i := 0; i < 10; i++ {
		runS2S(t, captcha, s2sReq{remote: fmt.Sprintf("198.51.100.%d", 60+i), body: `{"client_id":"` + app.ClientID + `"}`})
	}
	for i := 0; i < 3; i++ {
		if res := runS2S(t, login, s2sReq{remote: "203.0.113.10", clientID: app.ClientID, secret: app.ClientSecret}); res.code != http.StatusOK {
			t.Fatalf("verified request %d after a captcha flood naming the app: got %d %v, want 200", i+1, res.code, res.body)
		}
	}
}
