package middleware_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"

	"github.com/engineersmind/emc-auth-server/internal/api/middleware"
	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// Routes where application credentials are optional: MFA completion, the
// social login-code exchange, passkey sign-in, resend-verification, and the
// RFC 6749 token/revoke endpoints. The rule each test pins: a caller that does
// not identify itself sees EXACTLY the old limiter; only a proven backend is
// lifted off the per-IP bucket, and then onto per-user and per-app limits.

func mfaChain(s *middleware.AppS2S) []echo.MiddlewareFunc {
	return []echo.MiddlewareFunc{
		s.ResolveOptional(middleware.SurfaceMFA),
		s.UserLimit("app_mfa_challenge_user", s.UserLimits().MFAChallenge, middleware.SubjectEndUserIP),
		middleware.OTPRateLimiter(middleware.DefaultRateLimitConfig()),
	}
}

func otpBody(i int) string {
	return fmt.Sprintf(`{"otp_session_token":"sess-%d","code":"123456"}`, i)
}

func TestOptionalRoutes_AnonymousCallersUnchanged(t *testing.T) {
	s, _ := newS2S(middleware.AppS2SConfig{}, trustWith([]string{backendIP + "/32"}, true))
	chain := mfaChain(s)
	// OTPRateLimiter's per-IP allowance is PerIPRate*2 = 10.
	for i := 0; i < 10; i++ {
		if res := runS2S(t, chain, s2sReq{remote: strangerIP, body: otpBody(i)}); res.code != http.StatusOK {
			t.Fatalf("anonymous call %d: got %d, want 200", i+1, res.code)
		}
	}
	if res := runS2S(t, chain, s2sReq{remote: strangerIP, body: otpBody(99)}); res.code != http.StatusTooManyRequests {
		t.Fatalf("anonymous call 11: got %d, want 429 — the old per-IP limit must still apply", res.code)
	}
}

func TestOptionalRoutes_VerifiedBackendLimitedPerUserNotPerIP(t *testing.T) {
	s, _ := newS2S(middleware.AppS2SConfig{}, trustWith([]string{backendIP + "/32"}, true))
	chain := mfaChain(s)
	// 100 different users completing MFA through one backend IP.
	for i := 0; i < 100; i++ {
		res := runS2S(t, chain, s2sReq{remote: backendIP, clientID: appClient, secret: appSecret,
			forwarded: fmt.Sprintf("49.36.%d.%d", i/250, i%250+1), body: otpBody(i)})
		if res.code != http.StatusOK {
			t.Fatalf("user %d: got %d %v, want 200", i+1, res.code, res.body)
		}
	}
	// The per-session bucket still bounds guessing on one challenge.
	for i := 0; i < 10; i++ {
		runS2S(t, chain, s2sReq{remote: backendIP, clientID: appClient, secret: appSecret,
			forwarded: fmt.Sprintf("49.37.0.%d", i+1), body: otpBody(5000)})
	}
	res := runS2S(t, chain, s2sReq{remote: backendIP, clientID: appClient, secret: appSecret,
		forwarded: "49.37.1.1", body: otpBody(5000)})
	if res.code != http.StatusTooManyRequests {
		t.Fatalf("11th attempt on one challenge: got %d, want 429", res.code)
	}
}

func TestOptionalRoutes_WrongSecretGetsStrictLimit(t *testing.T) {
	s, _ := newS2S(middleware.AppS2SConfig{}, nil)
	chain := mfaChain(s)
	for i := 0; i < middleware.DefaultAppUnverifiedPerIPRate; i++ {
		runS2S(t, chain, s2sReq{remote: strangerIP, clientID: appClient, secret: "guess", body: otpBody(i)})
	}
	res := runS2S(t, chain, s2sReq{remote: strangerIP, clientID: appClient, secret: "guess", body: otpBody(77)})
	if res.code != http.StatusTooManyRequests || res.body["limiter"] != "ip" {
		t.Fatalf("wrong secret past the strict limit: got %d %v, want 429 limiter=ip", res.code, res.body)
	}
}

func TestOAuthExchange_ServerIPWithBodyClientID(t *testing.T) {
	s, _ := newS2S(middleware.AppS2SConfig{}, trustWith([]string{backendIP + "/32"}, false))
	chain := []echo.MiddlewareFunc{
		s.ResolveOptionalBodyClient(middleware.SurfaceOAuth),
		middleware.OAuthRateLimiter(middleware.DefaultRateLimitConfig()),
	}
	body := `{"client_id":"` + appClient + `","login_code":"x"}`
	// From the registered server IP: no per-IP cap (was 5/min for the product).
	for i := 0; i < 50; i++ {
		if res := runS2S(t, chain, s2sReq{remote: backendIP, body: body}); res.code != http.StatusOK {
			t.Fatalf("exchange %d from the server IP: got %d, want 200", i+1, res.code)
		}
	}
	// From anywhere else: the old 5/min per IP.
	for i := 0; i < 5; i++ {
		runS2S(t, chain, s2sReq{remote: strangerIP, body: body})
	}
	if res := runS2S(t, chain, s2sReq{remote: strangerIP, body: body}); res.code != http.StatusTooManyRequests {
		t.Fatalf("6th exchange from an unregistered IP: got %d, want 429", res.code)
	}
}

func TestBackendsOnly_QuotaOnlyForTrustedBackends(t *testing.T) {
	s, _ := newS2S(middleware.AppS2SConfig{}, nil)
	var quotaRuns int
	quota := func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error { quotaRuns++; return next(c) }
	}
	chain := []echo.MiddlewareFunc{s.ResolveOptional(middleware.SurfacePasskey), middleware.BackendsOnly(quota)}
	runS2S(t, chain, s2sReq{remote: strangerIP, body: `{}`})
	if quotaRuns != 0 {
		t.Fatal("the quota must not apply to an anonymous caller — that would be a limit it never had")
	}
	runS2S(t, chain, s2sReq{remote: backendIP, clientID: appClient, secret: appSecret, body: `{}`})
	if quotaRuns != 1 {
		t.Fatal("the quota must apply to a verified backend")
	}
}

// Without a resolver on the route, TrustedBackend is false and the legacy
// limiter must behave exactly as before — this is every route not rewired.
func TestTokenRateLimiter_UnchangedWithoutResolver(t *testing.T) {
	middleware.ResetStoresForTest()
	tok := []echo.MiddlewareFunc{middleware.TokenRateLimiter(middleware.DefaultRateLimitConfig())}
	for i := 0; i < 5; i++ {
		runS2S(t, tok, s2sReq{remote: strangerIP, clientID: appClient, secret: appSecret})
	}
	if res := runS2S(t, tok, s2sReq{remote: strangerIP, clientID: appClient, secret: appSecret}); res.code != http.StatusTooManyRequests {
		t.Fatalf("TokenRateLimiter on a route with no resolver: got %d, want 429", res.code)
	}
}

type fakeLimits struct{ rpm int }

func (f fakeLimits) GetLimit(context.Context, int64, int64) (int, int) { return f.rpm, f.rpm }

func TestOAuthTokenLimit_VerifiedClientGetsItsQuota(t *testing.T) {
	s, _ := newS2S(middleware.AppS2SConfig{}, nil)
	s.WithAppLimits(fakeLimits{rpm: 300})
	chain := []echo.MiddlewareFunc{s.ResolveOAuthClient(middleware.SurfaceOAuth, middleware.OAuthTokenLegacyExhausted), s.OAuthTokenLimit()}

	for i := 0; i < 300; i++ {
		if res := runS2S(t, chain, s2sReq{remote: backendIP, clientID: appClient, secret: appSecret}); res.code != http.StatusOK {
			t.Fatalf("verified token request %d of a 300/min quota: got %d, want 200", i+1, res.code)
		}
	}
	res := runS2S(t, chain, s2sReq{remote: backendIP, clientID: appClient, secret: appSecret})
	if res.code != http.StatusTooManyRequests || res.body["error"] != "slow_down" {
		t.Fatalf("request past the quota: got %d %v, want 429 slow_down", res.code, res.body)
	}

	// Never below the fixed 120 when the quota is smaller.
	s2, _ := newS2S(middleware.AppS2SConfig{}, nil)
	s2.WithAppLimits(fakeLimits{rpm: 60})
	chain2 := []echo.MiddlewareFunc{s2.ResolveOAuthClient(middleware.SurfaceOAuth, middleware.OAuthTokenLegacyExhausted), s2.OAuthTokenLimit()}
	for i := 0; i < middleware.OAuthTokenPerClientRate; i++ {
		if res := runS2S(t, chain2, s2sReq{remote: backendIP, clientID: appClient, secret: appSecret}); res.code != http.StatusOK {
			t.Fatalf("request %d with a 60/min quota: got %d, want 200 (floor is %d)",
				i+1, res.code, middleware.OAuthTokenPerClientRate)
		}
	}
}

// Public clients and unverified secrets keep the legacy per-client limiter.
func TestOAuthTokenLimit_UnverifiedKeepsLegacy(t *testing.T) {
	s, _ := newS2S(middleware.AppS2SConfig{}, nil)
	s.WithAppLimits(fakeLimits{rpm: 10000})
	chain := []echo.MiddlewareFunc{s.ResolveOAuthClient(middleware.SurfaceOAuth, middleware.OAuthTokenLegacyExhausted), s.OAuthTokenLimit()}
	// A public client: client_id in the form, no secret.
	for i := 0; i < middleware.OAuthTokenPerClientRate; i++ {
		runOAuthForm(t, chain, "client_id="+appClient+"&grant_type=authorization_code")
	}
	if got := runOAuthForm(t, chain, "client_id="+appClient+"&grant_type=authorization_code"); got != http.StatusTooManyRequests {
		t.Fatalf("public client past %d: got %d, want 429", middleware.OAuthTokenPerClientRate, got)
	}
}

func runOAuthForm(t *testing.T, chain []echo.MiddlewareFunc, form string) int {
	t.Helper()
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = backendIP + ":1"
	rec := httptest.NewRecorder()
	h := func(c echo.Context) error { return c.NoContent(http.StatusOK) }
	for i := len(chain) - 1; i >= 0; i-- {
		h = chain[i](h)
	}
	_ = h(e.NewContext(req, rec))
	return rec.Code
}

func TestSignedInUserRateLimiter_PerUser(t *testing.T) {
	middleware.ResetStoresForTest()
	lim := middleware.SignedInUserRateLimiter("change_email_user", 5)
	call := func(user string) int {
		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
		req.RemoteAddr = backendIP + ":1"
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("user", &auth.Claims{TenantID: "7", UserID: user})
		_ = lim(func(c echo.Context) error { return c.NoContent(http.StatusOK) })(c)
		return rec.Code
	}
	for i := 0; i < 5; i++ {
		call("100")
	}
	if got := call("100"); got != http.StatusTooManyRequests {
		t.Fatalf("user 100 sixth request: got %d, want 429", got)
	}
	if got := call("200"); got != http.StatusOK {
		t.Fatalf("user 200 from the same IP: got %d, want 200", got)
	}
}
