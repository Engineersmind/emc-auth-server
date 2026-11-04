package middleware_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"

	"github.com/engineersmind/emc-auth-server/internal/api/middleware"
	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// Regression tests for the human code review of PR #174.

// #2: trailing junk must not hide the body's client_id from the mismatch
// check. The handler's json.Decoder ignores trailing data, so the limiter must
// read the same client_id — and an unreadable one is a mismatch, never a pass.
func TestReview174_ExchangeTrailingJunkIsStillAMismatch(t *testing.T) {
	s, _ := newS2S(middleware.AppS2SConfig{}, nil)
	var trustedRuns int
	probe := func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error { trustedRuns++; return next(c) }
	}
	chain := []echo.MiddlewareFunc{
		s.ResolveOptionalBodyClient(middleware.SurfaceOAuth),
		middleware.BackendsOnly(probe),
	}
	for _, body := range []string{
		`{"client_id":"` + appClient + `","login_code":"x"} junk`, // app A's id, app B's credentials
		`{"login_code":"x"}`, // no client_id at all
		`not json`,           // unreadable
	} {
		runS2S(t, chain, s2sReq{remote: strangerIP, clientID: otherClient, secret: otherSecret, body: body})
	}
	if trustedRuns != 0 {
		t.Fatalf("%d requests were treated as a trusted backend despite naming another (or no) application", trustedRuns)
	}
	// The genuine case still works: credentials and body name the same app.
	runS2S(t, chain, s2sReq{remote: strangerIP, clientID: appClient, secret: appSecret, body: `{"client_id":"` + appClient + `","login_code":"x"}`})
	if trustedRuns != 1 {
		t.Fatal("matching credentials and body must be treated as a trusted backend")
	}
}

// The shared body reader decodes a prefix but must hand the handler the WHOLE
// body: it used to put back only the first 8 / 64 KiB.
func TestReview174_BodyReaderKeepsTheWholeBody(t *testing.T) {
	s, _ := newS2S(middleware.AppS2SConfig{}, nil)
	big := `{"email":"a@x.com","pad":"` + strings.Repeat("x", 200_000) + `"}`
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(big))
	req.RemoteAddr = backendIP + ":1"
	req.Header.Set(echo.HeaderAuthorization, basicHeader(appClient, appSecret))
	rec := httptest.NewRecorder()
	var got int
	h := s.Resolve(middleware.SurfaceApp)(s.UserLimit("app_login_user", 5, middleware.SubjectEmail)(func(c echo.Context) error {
		b, _ := io.ReadAll(c.Request().Body)
		got = len(b)
		return c.NoContent(http.StatusOK)
	}))
	_ = h(e.NewContext(req, rec))
	if got != len(big) {
		t.Fatalf("handler read %d bytes, want the full %d", got, len(big))
	}
}

// #4: change-email keeps the legacy 5/min per IP for callers that are not a
// verified backend, so one address holding many accounts cannot multiply the
// mail it sends.
func TestReview174_ChangeEmailKeepsPerIPLimitForNonBackends(t *testing.T) {
	s, _ := newS2S(middleware.AppS2SConfig{}, nil)
	chain := []echo.MiddlewareFunc{
		s.ResolveOptional(middleware.SurfaceAccount),
		middleware.BackendsOnly(middleware.SignedInUserRateLimiter("change_email_user", 5)),
		middleware.TokenRateLimiter(middleware.DefaultRateLimitConfig()),
	}
	send := func(user string, withClient bool) int {
		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/change-email", strings.NewReader(`{}`))
		req.RemoteAddr = strangerIP + ":1"
		if withClient {
			req.Header.Set(middleware.ClientAuthHeader, basicHeader(appClient, appSecret))
		}
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Set("user", &auth.Claims{TenantID: "7", UserID: user})
		h := func(c echo.Context) error { return c.NoContent(http.StatusOK) }
		for i := len(chain) - 1; i >= 0; i-- {
			h = chain[i](h)
		}
		_ = h(c)
		return rec.Code
	}
	// Ten different accounts from one address, no application credentials.
	limited := 0
	for i := 0; i < 10; i++ {
		if send(string(rune('a'+i)), false) == http.StatusTooManyRequests {
			limited++
		}
	}
	if limited != 5 {
		t.Fatalf("10 accounts from one IP without credentials: %d limited, want 5 (per-IP 5/min as before)", limited)
	}
	// A verified backend is limited per user instead.
	middleware.ResetStoresForTest()
	for i := 0; i < 10; i++ {
		if got := send(string(rune('a'+i)), true); got != http.StatusOK {
			t.Fatalf("verified backend, user %d: got %d, want 200", i, got)
		}
	}
}

// #5: a server-IP caller presenting no secret is a trusted backend, so the
// token-redemption guess budget must apply to it.
func TestReview174_GuessBudgetAppliesToServerIPCallers(t *testing.T) {
	s, _ := newS2S(middleware.AppS2SConfig{}, trustWith([]string{backendIP + "/32"}, false))
	limit := middleware.OAuthTokenPerClientRate // the per-application budget without forwarding
	chain := []echo.MiddlewareFunc{
		s.Resolve(middleware.SurfaceReset),
		s.GuessLimit("app_reset_password_user", s.UserLimits().ResetPassword),
	}
	for i := 0; i < limit; i++ {
		runS2S(t, chain, s2sReq{remote: backendIP, clientID: appClient, secret: "", body: `{"token":"t"}`})
	}
	if res := runS2S(t, chain, s2sReq{remote: backendIP, clientID: appClient, secret: "", body: `{"token":"t"}`}); res.code != http.StatusTooManyRequests {
		t.Fatalf("server-IP caller without a secret, guess %d: got %d, want 429", limit+1, res.code)
	}
}

// #6: with forwarded user IPs, an attacker failing a victim's password through
// the product's sign-in form exhausts only their own bucket.
func TestReview174_AttackerCannotLockOutVictimWhenIPsForwarded(t *testing.T) {
	s, _ := newS2S(middleware.AppS2SConfig{}, trustWith([]string{backendIP + "/32"}, true))
	limit := s.UserLimits().Login
	chain := []echo.MiddlewareFunc{
		s.Resolve(middleware.SurfaceApp),
		s.UserLimit("app_login_user", limit, middleware.SubjectEmailAndUserIP),
	}
	login := func(userIP string) int {
		return runS2S(t, chain, s2sReq{remote: backendIP, clientID: appClient, secret: appSecret,
			forwarded: userIP, body: emailBody("victim@x.com")}).code
	}
	for i := 0; i < limit; i++ {
		login("198.51.100.66") // the attacker
	}
	if got := login("198.51.100.66"); got != http.StatusTooManyRequests {
		t.Fatalf("attacker past the limit: got %d, want 429", got)
	}
	if got := login("49.36.1.7"); got != http.StatusOK {
		t.Fatalf("victim from their own address: got %d, want 200 — must not be locked out", got)
	}
}
