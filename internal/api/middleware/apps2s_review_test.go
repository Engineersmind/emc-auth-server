package middleware_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog"

	"github.com/engineersmind/emc-auth-server/internal/api/middleware"
)

// Regression tests for the findings of the independent security review of the
// S2S rate-limit change. Each test names the finding it pins.

// Finding 1: once an address has spent its wrong-secret budget, the RIGHT
// secret must be refused too, and without a credential lookup — otherwise the
// 429 tells a guesser which secret was right.
func TestReview1_NoSecretOracleAfterBudget(t *testing.T) {
	s, clients := newS2S(middleware.AppS2SConfig{}, nil)
	chain := loginChain(s)
	for i := 0; i < middleware.DefaultAppUnverifiedPerIPRate; i++ {
		runS2S(t, chain, s2sReq{remote: strangerIP, clientID: appClient, secret: fmt.Sprintf("guess-%d", i), body: emailBody("a@x.com")})
	}
	before := clients.calls.Load()
	right := runS2S(t, chain, s2sReq{remote: strangerIP, clientID: appClient, secret: appSecret, body: emailBody("a@x.com")})
	wrong := runS2S(t, chain, s2sReq{remote: strangerIP, clientID: appClient, secret: "guess-x", body: emailBody("a@x.com")})
	if right.code != http.StatusTooManyRequests || wrong.code != http.StatusTooManyRequests {
		t.Fatalf("after the budget: right secret %d, wrong secret %d — both must be 429 or the response is an oracle", right.code, wrong.code)
	}
	if clients.calls.Load() != before {
		t.Fatal("no credential lookup may happen once the budget is spent")
	}
}

// Finding 1: wrong secrets for one client_id are bounded across addresses
// (the per-client_id rate the old limiter had), but the application's own
// registered server IP is never locked out by them.
func TestReview1_PerClientBudgetAcrossIPs(t *testing.T) {
	s, _ := newS2S(middleware.AppS2SConfig{}, trustWith([]string{backendIP + "/32"}, false))
	chain := loginChain(s)
	for i := 0; i < middleware.DefaultBadCredentialsPerClientRate; i++ {
		runS2S(t, chain, s2sReq{remote: fmt.Sprintf("198.51.100.%d", 100+i), clientID: appClient, secret: "guess", body: emailBody("a@x.com")})
	}
	if res := runS2S(t, chain, s2sReq{remote: "198.51.100.200", clientID: appClient, secret: "guess", body: emailBody("a@x.com")}); res.code != http.StatusTooManyRequests {
		t.Fatalf("wrong secret from a fresh IP after the per-client budget: got %d, want 429", res.code)
	}
	if res := runS2S(t, chain, s2sReq{remote: backendIP, clientID: appClient, secret: appSecret, body: emailBody("b@x.com")}); res.code != http.StatusOK {
		t.Fatalf("the real backend on its registered IP: got %d, want 200 — strangers must not lock it out", res.code)
	}
}

// Finding 2: Basic credentials for one application with a body naming another
// must not make the request a trusted backend for the second.
func TestReview2_ExchangeCredentialsMustMatchBodyClient(t *testing.T) {
	s, _ := newS2S(middleware.AppS2SConfig{}, nil)
	var quotaRuns int
	quota := func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error { quotaRuns++; return next(c) }
	}
	chain := []echo.MiddlewareFunc{
		s.ResolveOptionalBodyClient(middleware.SurfaceOAuth),
		middleware.BackendsOnly(quota),
		middleware.OAuthRateLimiter(middleware.DefaultRateLimitConfig()),
	}
	body := `{"client_id":"` + appClient + `","login_code":"x"}` // names app A…
	for i := 0; i < 5; i++ {
		runS2S(t, chain, s2sReq{remote: strangerIP, clientID: otherClient, secret: otherSecret, body: body}) // …with app B's secret
	}
	if quotaRuns != 0 {
		t.Fatal("app B's credentials must not charge or lift limits for app A")
	}
	if res := runS2S(t, chain, s2sReq{remote: strangerIP, clientID: otherClient, secret: otherSecret, body: body}); res.code != http.StatusTooManyRequests {
		t.Fatalf("mismatched credentials must keep the per-IP limit: got %d, want 429 on the 6th", res.code)
	}
}

// Finding 3: "Basic client_id:" (public client, empty secret) and a public
// client sending a secret the handler ignores keep the legacy OAuth limit.
func TestReview3_PublicOAuthClientsKeepLegacyLimit(t *testing.T) {
	s, _ := newS2S(middleware.AppS2SConfig{}, nil)
	chain := []echo.MiddlewareFunc{s.ResolveOAuthClient(middleware.SurfaceOAuth, middleware.OAuthTokenLegacyExhausted), s.OAuthTokenLimit()}
	for i := 0; i < 20; i++ {
		if res := runS2S(t, chain, s2sReq{remote: strangerIP, clientID: appClient, secret: ""}); res.code != http.StatusOK {
			t.Fatalf("empty-secret Basic request %d: got %d, want 200 (legacy limit is 120/min per client)", i+1, res.code)
		}
	}
	for i := 0; i < 20; i++ {
		if got := runOAuthForm(t, chain, "client_id="+otherClient+"&client_secret=ignored&grant_type=authorization_code"); got != http.StatusOK {
			t.Fatalf("public client with an ignored secret, request %d: got %d, want 200", i+1, got)
		}
	}
}

// Finding 4: a verified client revoking from several addresses keeps at least
// 60/min on each, as before.
func TestReview4_RevokeStaysPerIP(t *testing.T) {
	s, _ := newS2S(middleware.AppS2SConfig{}, nil)
	s.WithAppLimits(fakeLimits{rpm: 60})
	chain := []echo.MiddlewareFunc{s.ResolveOAuthClient(middleware.SurfaceOAuth, middleware.OAuthTokenLegacyExhausted), s.OAuthRevokeLimit()}
	for _, ip := range []string{"203.0.113.31", "203.0.113.32"} {
		for i := 0; i < middleware.RevokePerIPRate; i++ {
			if res := runS2S(t, chain, s2sReq{remote: ip, clientID: appClient, secret: appSecret}); res.code != http.StatusOK {
				t.Fatalf("revoke %d from %s: got %d, want 200 — 60/min per IP as before", i+1, ip, res.code)
			}
		}
	}
}

// Finding 5: an anonymous caller of /resend-verification must not be given a
// per-email bucket that anyone could drain.
func TestReview5_AnonymousResendHasNoPerEmailBucket(t *testing.T) {
	s, _ := newS2S(middleware.AppS2SConfig{}, nil)
	chain := []echo.MiddlewareFunc{
		s.ResolveOptional(middleware.SurfaceAccount),
		middleware.BackendsOnly(s.UserLimit("app_resend_verification_user", s.UserLimits().ResendVerification, middleware.SubjectEmail)),
		middleware.TokenRateLimiter(middleware.DefaultRateLimitConfig()),
	}
	for i := 0; i < 20; i++ {
		res := runS2S(t, chain, s2sReq{remote: fmt.Sprintf("198.51.100.%d", 10+i), body: `{"email":"victim@x.com"}`})
		if res.code != http.StatusOK {
			t.Fatalf("anonymous resend %d from its own IP: got %d, want 200", i+1, res.code)
		}
	}
}

// Finding 6: a verified backend that does not forward user IPs gets one guess
// budget for the whole application on token-redeeming routes.
func TestReview6_GuessBudgetWithoutForwarding(t *testing.T) {
	s, _ := newS2S(middleware.AppS2SConfig{}, trustWith([]string{backendIP + "/32"}, true))
	limit := s.UserLimits().ResetPassword
	chain := []echo.MiddlewareFunc{
		s.Resolve(middleware.SurfaceReset),
		s.UserLimit("app_reset_password_user", limit, middleware.SubjectGuessBudget),
	}
	for i := 0; i < limit; i++ {
		runS2S(t, chain, s2sReq{remote: backendIP, clientID: appClient, secret: appSecret, body: `{"token":"t"}`})
	}
	if res := runS2S(t, chain, s2sReq{remote: backendIP, clientID: appClient, secret: appSecret, body: `{"token":"t"}`}); res.code != http.StatusTooManyRequests {
		t.Fatalf("unforwarded guess %d: got %d, want 429", limit+1, res.code)
	}
	// Forwarding restores a budget per user.
	if res := runS2S(t, chain, s2sReq{remote: backendIP, clientID: appClient, secret: appSecret, forwarded: "49.36.1.7", body: `{"token":"t"}`}); res.code != http.StatusOK {
		t.Fatalf("forwarded user after the unforwarded budget: got %d, want 200", res.code)
	}
}

type flakyClients struct{ calls atomic.Int32 }

func (f *flakyClients) AuthenticateClient(context.Context, string, string) (int64, int64, error) {
	f.calls.Add(1)
	return 0, 0, errors.New("connection refused")
}

// A database error while verifying is not a wrong secret: it must not spend
// the bad-credential budgets (a DB blip would otherwise turn into a lockout
// for the real backend once the database recovers) and the request is treated
// as presenting no credentials.
//
// Ten requests, not more: each uncached check from an address that is not
// known good spends the outcome-blind attempt budget (10/min), by design.
func TestReview_DatabaseErrorIsNotAGuess(t *testing.T) {
	middleware.ResetStoresForTest()
	s := middleware.NewAppS2S(middleware.AppS2SConfig{}, nil, &flakyClients{}, zerolog.Nop())
	chain := []echo.MiddlewareFunc{s.ResolveOptional(middleware.SurfaceMFA)}
	for i := 0; i < 10; i++ {
		res := runS2S(t, chain, s2sReq{remote: backendIP, clientID: appClient, secret: appSecret, body: otpBody(i)})
		if res.code != http.StatusOK {
			t.Fatalf("request %d during a DB error: got %d, want 200 (the handler decides)", i+1, res.code)
		}
		if res.caller.Failed || res.caller.Verified {
			t.Fatalf("request %d: a DB error is neither failed nor verified, got %+v", i+1, res.caller)
		}
	}
}

var _ middleware.ClientAuthenticator = (*flakyClients)(nil)

// After the database recovers, the same address must not be locked out by the
// errors: none of them spent the wrong-secret budget.
func TestReview_DatabaseErrorDoesNotSpendFailureBudget(t *testing.T) {
	middleware.ResetStoresForTest()
	flaky := middleware.NewAppS2S(middleware.AppS2SConfig{}, nil, &flakyClients{}, zerolog.Nop())
	for i := 0; i < 8; i++ {
		runS2S(t, loginChain(flaky), s2sReq{remote: backendIP, clientID: appClient, secret: appSecret, body: emailBody("a@x.com")})
	}
	// Same stores (package-level), working database now.
	healthy := middleware.NewAppS2S(middleware.AppS2SConfig{}, nil, &fakeClients{}, zerolog.Nop())
	if res := runS2S(t, loginChain(healthy), s2sReq{remote: backendIP, clientID: appClient, secret: appSecret, body: emailBody("b@x.com")}); res.code != http.StatusOK {
		t.Fatalf("after the database recovers: got %d %v, want 200", res.code, res.body)
	}
}
