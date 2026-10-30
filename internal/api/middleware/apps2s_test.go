package middleware_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog"

	"github.com/engineersmind/emc-auth-server/internal/api/middleware"
	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/requestctx"
)

// These tests send everything from ONE IP with ONE client_id, because that is
// how a product backend reaches these routes — the case the old per-IP and
// per-client limits got wrong.

const (
	backendIP    = "203.0.113.10"
	strangerIP   = "198.51.100.77"
	appClient    = "insureddesk"
	appSecret    = "s3cret-s3cret-s3cret"
	appTenantID  = int64(7)
	appRowID     = int64(12)
	otherClient  = "other-app"
	otherSecret  = "other-secret"
	otherRowID   = int64(13)
	endUserIPOne = "49.36.1.7"
)

type fakeClients struct {
	calls atomic.Int32
}

func (f *fakeClients) AuthenticateClient(_ context.Context, id, secret string) (int64, int64, error) {
	f.calls.Add(1)
	switch {
	case id == appClient && secret == appSecret:
		return appTenantID, appRowID, nil
	case id == otherClient && secret == otherSecret:
		return appTenantID, otherRowID, nil
	}
	return 0, 0, auth.ErrInvalidClient
}

type fakeTrust map[string]auth.ServerTrust

func (f fakeTrust) Lookup(id string) (auth.ServerTrust, bool) {
	t, ok := f[id]
	return t, ok
}

func trustWith(serverIPs []string, forward bool) fakeTrust {
	t := auth.ServerTrust{TenantID: appTenantID, ApplicationID: appRowID, TrustForwardedIP: forward}
	for _, ip := range serverIPs {
		t.Prefixes = append(t.Prefixes, netip.MustParsePrefix(ip))
	}
	return fakeTrust{appClient: t}
}

type s2sReq struct {
	remote    string
	clientID  string
	secret    string
	header    string // credentials header; default Authorization
	body      string
	forwarded string
	bearer    string
}

type s2sResult struct {
	code      int
	body      map[string]string
	caller    *middleware.AppCaller
	endUserIP string
	ctxIP     string
	header    http.Header
}

func runS2S(t *testing.T, chain []echo.MiddlewareFunc, r s2sReq) s2sResult {
	t.Helper()
	e := echo.New()
	body := r.body
	if body == "" {
		body = `{}`
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/apps/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = r.remote + ":40000"
	if r.clientID != "" {
		h := r.header
		if h == "" {
			h = echo.HeaderAuthorization
		}
		req.Header.Set(h, "Basic "+base64.StdEncoding.EncodeToString([]byte(r.clientID+":"+r.secret)))
	}
	if r.forwarded != "" {
		req.Header.Set(middleware.ForwardedForHeader, r.forwarded)
	}
	if r.bearer != "" {
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+r.bearer)
	}
	// Mirror production, where RequestInfo runs globally first.
	req = req.WithContext(requestctx.WithRequestInfo(req.Context(), r.remote, "backend/1.0"))
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	var res s2sResult
	h := func(c echo.Context) error {
		res.caller, _ = middleware.CallerFrom(c)
		res.endUserIP = middleware.EndUserIP(c)
		res.ctxIP = requestctx.FromContext(c.Request().Context()).IPAddress
		return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
	}
	for i := len(chain) - 1; i >= 0; i-- {
		h = chain[i](h)
	}
	_ = h(c)
	res.code = rec.Code
	res.header = rec.Header()
	_ = json.Unmarshal(rec.Body.Bytes(), &res.body)
	return res
}

func newS2S(cfg middleware.AppS2SConfig, trust middleware.ServerTrustLookup) (*middleware.AppS2S, *fakeClients) {
	middleware.ResetStoresForTest()
	clients := &fakeClients{}
	return middleware.NewAppS2S(cfg, trust, clients, zerolog.Nop()), clients
}

func loginChain(s *middleware.AppS2S) []echo.MiddlewareFunc {
	return []echo.MiddlewareFunc{
		s.Resolve(middleware.SurfaceApp),
		s.UserLimit("app_login_user", s.UserLimits().Login, middleware.SubjectEmail),
	}
}

func emailBody(email string) string { return `{"email":"` + email + `","password":"x"}` }

// The point of the change: one registered backend IP, one client_id, many users.
func TestAppS2S_ManyUsersFromOneRegisteredServerIP(t *testing.T) {
	s, _ := newS2S(middleware.AppS2SConfig{}, trustWith([]string{backendIP + "/32"}, false))
	chain := loginChain(s)

	for i := 0; i < 2000; i++ {
		res := runS2S(t, chain, s2sReq{remote: backendIP, clientID: appClient, secret: appSecret,
			body: emailBody(fmt.Sprintf("user%d@example.com", i))})
		if res.code != http.StatusOK {
			t.Fatalf("user %d: got %d %v, want 200 — distinct users from one server IP must not share a limit", i, res.code, res.body)
		}
	}
}

// An unregistered IP still gets a generous flood guard, not the 5/min that used
// to throttle a product as one person.
func TestAppS2S_UnregisteredIPHitsFloodGuard(t *testing.T) {
	s, _ := newS2S(middleware.AppS2SConfig{PerIPRate: 20}, nil)
	chain := loginChain(s)

	for i := 0; i < 20; i++ {
		res := runS2S(t, chain, s2sReq{remote: backendIP, clientID: appClient, secret: appSecret,
			body: emailBody(fmt.Sprintf("u%d@example.com", i))})
		if res.code != http.StatusOK {
			t.Fatalf("request %d: got %d, want 200", i+1, res.code)
		}
	}
	res := runS2S(t, chain, s2sReq{remote: backendIP, clientID: appClient, secret: appSecret, body: emailBody("late@example.com")})
	if res.code != http.StatusTooManyRequests || res.body["limiter"] != "ip" {
		t.Fatalf("request 21: got %d %v, want 429 limiter=ip", res.code, res.body)
	}
}

func TestAppS2S_DefaultFloodGuardIsAboveOnePersonsRate(t *testing.T) {
	if middleware.DefaultAppPerIPRate < 100*middleware.DefaultAppUnverifiedPerIPRate {
		t.Fatalf("DefaultAppPerIPRate %d is too close to the per-person rate %d: an unregistered backend would be throttled as one user",
			middleware.DefaultAppPerIPRate, middleware.DefaultAppUnverifiedPerIPRate)
	}
}

func TestAppS2S_PerUserLimitIsolatesUsers(t *testing.T) {
	s, _ := newS2S(middleware.AppS2SConfig{}, trustWith([]string{backendIP + "/32"}, false))
	chain := loginChain(s)
	limit := s.UserLimits().Login

	for i := 0; i < limit; i++ {
		// Case and padding must not buy a fresh bucket.
		email := []string{"bob@x.com", " Bob@X.com ", "BOB@x.com"}[i%3]
		if res := runS2S(t, chain, s2sReq{remote: backendIP, clientID: appClient, secret: appSecret, body: emailBody(email)}); res.code != http.StatusOK {
			t.Fatalf("attempt %d for bob: got %d, want 200", i+1, res.code)
		}
	}
	res := runS2S(t, chain, s2sReq{remote: backendIP, clientID: appClient, secret: appSecret, body: emailBody("bob@x.com")})
	if res.code != http.StatusTooManyRequests || res.body["limiter"] != "user" {
		t.Fatalf("attempt %d for bob: got %d %v, want 429 limiter=user", limit+1, res.code, res.body)
	}
	if res := runS2S(t, chain, s2sReq{remote: backendIP, clientID: appClient, secret: appSecret, body: emailBody("alice@x.com")}); res.code != http.StatusOK {
		t.Fatalf("alice after bob was limited: got %d, want 200", res.code)
	}
}

func TestAppS2S_SameEmailInTwoAppsHasTwoBudgets(t *testing.T) {
	s, _ := newS2S(middleware.AppS2SConfig{}, nil)
	chain := loginChain(s)
	limit := s.UserLimits().Login

	for i := 0; i < limit; i++ {
		runS2S(t, chain, s2sReq{remote: backendIP, clientID: appClient, secret: appSecret, body: emailBody("bob@x.com")})
	}
	res := runS2S(t, chain, s2sReq{remote: backendIP, clientID: otherClient, secret: otherSecret, body: emailBody("bob@x.com")})
	if res.code != http.StatusOK {
		t.Fatalf("bob in another application: got %d, want 200", res.code)
	}
}

// A malformed body must not be a way around the per-user limit.
func TestAppS2S_UnreadableBodyStillLimited(t *testing.T) {
	s, _ := newS2S(middleware.AppS2SConfig{}, nil)
	chain := loginChain(s)
	limit := s.UserLimits().Login

	for i := 0; i < limit; i++ {
		runS2S(t, chain, s2sReq{remote: backendIP, clientID: appClient, secret: appSecret, body: `not json`})
	}
	res := runS2S(t, chain, s2sReq{remote: backendIP, clientID: appClient, secret: appSecret, body: `{"email": 42}`})
	if res.code != http.StatusTooManyRequests {
		t.Fatalf("unreadable bodies: got %d, want 429", res.code)
	}
}

// Wrong secrets get AUTH-07's 5/min per IP — the bound on secret guessing — and
// do NOT spend the victim's per-user budget.
func TestAppS2S_UnverifiedCredentialsGetStrictIPLimit(t *testing.T) {
	s, _ := newS2S(middleware.AppS2SConfig{}, trustWith([]string{backendIP + "/32"}, false))
	chain := loginChain(s)

	for i := 0; i < middleware.DefaultAppUnverifiedPerIPRate; i++ {
		res := runS2S(t, chain, s2sReq{remote: strangerIP, clientID: appClient, secret: "guess", body: emailBody("bob@x.com")})
		if res.code != http.StatusOK {
			t.Fatalf("guess %d: got %d, want 200 (the handler refuses it, not the limiter)", i+1, res.code)
		}
		if res.caller == nil || res.caller.Verified {
			t.Fatalf("guess %d: caller should be resolved and unverified, got %+v", i+1, res.caller)
		}
	}
	res := runS2S(t, chain, s2sReq{remote: strangerIP, clientID: appClient, secret: "guess", body: emailBody("bob@x.com")})
	if res.code != http.StatusTooManyRequests || res.body["limiter"] != "ip" {
		t.Fatalf("guess %d: got %d %v, want 429 limiter=ip", middleware.DefaultAppUnverifiedPerIPRate+1, res.code, res.body)
	}

	// Bob's own budget is untouched: a stranger who knows the public client_id
	// and Bob's email cannot lock Bob out.
	for i := 0; i < s.UserLimits().Login; i++ {
		if res := runS2S(t, chain, s2sReq{remote: backendIP, clientID: appClient, secret: appSecret, body: emailBody("bob@x.com")}); res.code != http.StatusOK {
			t.Fatalf("bob's real login %d after the guesses: got %d, want 200", i+1, res.code)
		}
	}
}

// Even from a registered server IP, a wrong secret is strictly limited.
func TestAppS2S_WrongSecretFromServerIPStillStrict(t *testing.T) {
	s, _ := newS2S(middleware.AppS2SConfig{}, trustWith([]string{backendIP + "/32"}, false))
	chain := loginChain(s)
	for i := 0; i < middleware.DefaultAppUnverifiedPerIPRate; i++ {
		runS2S(t, chain, s2sReq{remote: backendIP, clientID: appClient, secret: "wrong", body: emailBody(fmt.Sprintf("u%d@x.com", i))})
	}
	if res := runS2S(t, chain, s2sReq{remote: backendIP, clientID: appClient, secret: "wrong", body: emailBody("z@x.com")}); res.code != http.StatusTooManyRequests {
		t.Fatalf("got %d, want 429", res.code)
	}
}

// A browser calling /reset-password directly carries no credentials: AUTH-07 per
// IP, exactly as before. A backend calling it for its users sends its
// credentials, and is then not throttled as one person.
func TestAppS2S_AnonymousCallers(t *testing.T) {
	s, _ := newS2S(middleware.AppS2SConfig{}, trustWith([]string{backendIP + "/32"}, false))
	chain := []echo.MiddlewareFunc{
		s.Resolve(middleware.SurfaceApp),
		s.UserLimit("app_reset_password_user", s.UserLimits().ResetPassword, middleware.SubjectEndUserIP),
	}

	for i := 0; i < middleware.DefaultAppUnverifiedPerIPRate; i++ {
		if res := runS2S(t, chain, s2sReq{remote: strangerIP, body: `{"token":"t"}`}); res.code != http.StatusOK {
			t.Fatalf("browser request %d: got %d, want 200", i+1, res.code)
		}
	}
	if res := runS2S(t, chain, s2sReq{remote: strangerIP, body: `{"token":"t"}`}); res.code != http.StatusTooManyRequests {
		t.Fatalf("browser request 6: got %d, want 429", res.code)
	}

	for i := 0; i < 50; i++ {
		res := runS2S(t, chain, s2sReq{remote: backendIP, clientID: appClient, secret: appSecret, body: `{"token":"t"}`})
		if res.code != http.StatusOK {
			t.Fatalf("backend request %d with credentials: got %d, want 200", i+1, res.code)
		}
	}

	// Without credentials nothing identifies the application, so even its
	// server IP is treated as an anonymous caller.
	middleware.ResetStoresForTest()
	for i := 0; i < middleware.DefaultAppUnverifiedPerIPRate; i++ {
		runS2S(t, chain, s2sReq{remote: backendIP, body: `{"token":"t"}`})
	}
	if res := runS2S(t, chain, s2sReq{remote: backendIP, body: `{"token":"t"}`}); res.code != http.StatusTooManyRequests {
		t.Fatalf("anonymous request from a server IP: got %d, want 429", res.code)
	}
}

func TestAppS2S_ForwardedIP(t *testing.T) {
	cases := []struct {
		name        string
		trust       fakeTrust
		remote      string
		secret      string
		forwarded   string
		wantForward bool
	}{
		{"trusted, verified, from server IP", trustWith([]string{backendIP + "/32"}, true), backendIP, appSecret, endUserIPOne, true},
		{"forwarding on but no server IPs registered", trustWith(nil, true), strangerIP, appSecret, endUserIPOne, false},
		{"forwarding off", trustWith([]string{backendIP + "/32"}, false), backendIP, appSecret, endUserIPOne, false},
		{"not from a registered server IP", trustWith([]string{backendIP + "/32"}, true), strangerIP, appSecret, endUserIPOne, false},
		{"secret did not verify", trustWith(nil, true), backendIP, "wrong", endUserIPOne, false},
		{"not an address", trustWith([]string{backendIP + "/32"}, true), backendIP, appSecret, "49.36.1.7, 10.0.0.1", false},
		{"unspecified address", trustWith([]string{backendIP + "/32"}, true), backendIP, appSecret, "0.0.0.0", false},
		{"application unknown to trust", fakeTrust{}, backendIP, appSecret, endUserIPOne, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := newS2S(middleware.AppS2SConfig{}, tc.trust)
			res := runS2S(t, loginChain(s), s2sReq{remote: tc.remote, clientID: appClient, secret: tc.secret,
				forwarded: tc.forwarded, body: emailBody("bob@x.com")})
			if res.code != http.StatusOK {
				t.Fatalf("got %d %v, want 200", res.code, res.body)
			}
			if tc.wantForward {
				if !res.caller.Forwarded || res.endUserIP != endUserIPOne || res.ctxIP != endUserIPOne {
					t.Fatalf("forwarded IP not applied: caller=%+v EndUserIP=%q session IP=%q", res.caller, res.endUserIP, res.ctxIP)
				}
				return
			}
			if res.caller.Forwarded || res.endUserIP != tc.remote || res.ctxIP != tc.remote {
				t.Fatalf("forwarded IP must be ignored: caller=%+v EndUserIP=%q session IP=%q", res.caller, res.endUserIP, res.ctxIP)
			}
		})
	}
}

// One-time-token routes limit per forwarded end-user IP: one attacker cannot
// spend the budget of the backend's other users.
func TestAppS2S_TokenRoutesLimitPerEndUserIP(t *testing.T) {
	s, _ := newS2S(middleware.AppS2SConfig{Users: middleware.AppUserLimits{MagicLinkVerify: 3}},
		trustWith([]string{backendIP + "/32"}, true))
	chain := []echo.MiddlewareFunc{
		s.Resolve(middleware.SurfaceApp),
		s.UserLimit("app_magic_link_verify_user", s.UserLimits().MagicLinkVerify, middleware.SubjectEndUserIP),
	}
	for i := 0; i < 3; i++ {
		runS2S(t, chain, s2sReq{remote: backendIP, clientID: appClient, secret: appSecret, forwarded: "198.51.100.1",
			body: fmt.Sprintf(`{"token":"guess-%d"}`, i)})
	}
	if res := runS2S(t, chain, s2sReq{remote: backendIP, clientID: appClient, secret: appSecret, forwarded: "198.51.100.1",
		body: `{"token":"guess-x"}`}); res.code != http.StatusTooManyRequests {
		t.Fatalf("4th guess from one end user: got %d, want 429", res.code)
	}
	if res := runS2S(t, chain, s2sReq{remote: backendIP, clientID: appClient, secret: appSecret, forwarded: "198.51.100.2",
		body: `{"token":"real"}`}); res.code != http.StatusOK {
		t.Fatalf("another end user: got %d, want 200", res.code)
	}
}

func bearerFor(tenantID, userID string) string {
	enc := base64.RawURLEncoding
	payload, _ := json.Marshal(map[string]string{"tenant_id": tenantID, "user_id": userID})
	return enc.EncodeToString([]byte(`{"alg":"RS256"}`)) + "." + enc.EncodeToString(payload) + ".sig"
}

func TestAppS2S_MeLimitsPerTokenUser(t *testing.T) {
	s, _ := newS2S(middleware.AppS2SConfig{Users: middleware.AppUserLimits{Me: 2}}, nil)
	chain := []echo.MiddlewareFunc{
		s.Resolve(middleware.SurfaceApp),
		s.UserLimit("app_me_user", s.UserLimits().Me, middleware.SubjectBearerUser),
	}
	me := func(user string) int {
		return runS2S(t, chain, s2sReq{remote: backendIP, clientID: appClient, secret: appSecret,
			header: middleware.ClientAuthHeader, bearer: bearerFor("7", user)}).code
	}
	me("100")
	me("100")
	if got := me("100"); got != http.StatusTooManyRequests {
		t.Fatalf("user 100 third call: got %d, want 429", got)
	}
	if got := me("200"); got != http.StatusOK {
		t.Fatalf("user 200: got %d, want 200", got)
	}
}

// Steady backend traffic must not cost a credential query per request.
func TestAppS2S_VerifiedSecretIsCached(t *testing.T) {
	s, clients := newS2S(middleware.AppS2SConfig{}, nil)
	for i := 0; i < 50; i++ {
		runS2S(t, loginChain(s), s2sReq{remote: backendIP, clientID: appClient, secret: appSecret,
			body: emailBody(fmt.Sprintf("u%d@x.com", i))})
	}
	if n := clients.calls.Load(); n != 1 {
		t.Fatalf("AuthenticateClient called %d times for one secret, want 1", n)
	}
	// A wrong secret is never served from the cache.
	runS2S(t, loginChain(s), s2sReq{remote: backendIP, clientID: appClient, secret: "wrong", body: emailBody("a@x.com")})
	runS2S(t, loginChain(s), s2sReq{remote: backendIP, clientID: appClient, secret: "wrong", body: emailBody("a@x.com")})
	if n := clients.calls.Load(); n != 3 {
		t.Fatalf("AuthenticateClient called %d times, want 3 (failures are not cached)", n)
	}
}

func TestAppS2S_ResolveBodyClient(t *testing.T) {
	s, _ := newS2S(middleware.AppS2SConfig{}, trustWith([]string{backendIP + "/32"}, true))
	chain := []echo.MiddlewareFunc{s.ResolveBodyClient(middleware.SurfaceApp)}
	body := `{"client_id":"` + appClient + `","flow":"login"}`

	for i := 0; i < middleware.DefaultAppUnverifiedPerIPRate; i++ {
		runS2S(t, chain, s2sReq{remote: strangerIP, body: body})
	}
	if res := runS2S(t, chain, s2sReq{remote: strangerIP, body: body}); res.code != http.StatusTooManyRequests {
		t.Fatalf("browser fetching challenges: got %d, want 429 after %d", res.code, middleware.DefaultAppUnverifiedPerIPRate)
	}
	for i := 0; i < 50; i++ {
		res := runS2S(t, chain, s2sReq{remote: backendIP, body: body, forwarded: endUserIPOne})
		if res.code != http.StatusOK {
			t.Fatalf("backend fetching challenge %d from its server IP: got %d, want 200", i+1, res.code)
		}
		if res.caller.Forwarded {
			t.Fatal("a body client_id carries no secret: the forwarded IP must never be believed")
		}
	}
}

func TestAppS2S_RejectionsCarryLimiterAndHeaders(t *testing.T) {
	s, _ := newS2S(middleware.AppS2SConfig{Users: middleware.AppUserLimits{Login: 1}}, nil)
	chain := loginChain(s)
	runS2S(t, chain, s2sReq{remote: backendIP, clientID: appClient, secret: appSecret, body: emailBody("a@x.com")})

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(emailBody("a@x.com")))
	req.RemoteAddr = backendIP + ":1"
	req.Header.Set(echo.HeaderAuthorization, "Basic "+base64.StdEncoding.EncodeToString([]byte(appClient+":"+appSecret)))
	rec := httptest.NewRecorder()
	h := chain[0](chain[1](func(c echo.Context) error { return c.NoContent(http.StatusOK) }))
	_ = h(e.NewContext(req, rec))

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("got %d, want 429", rec.Code)
	}
	for _, name := range []string{"Retry-After", "X-RateLimit-Limit", "X-RateLimit-Remaining"} {
		if rec.Header().Get(name) == "" {
			t.Errorf("429 is missing %s", name)
		}
	}
}

// Anonymous calls on one surface must not spend another surface's strict
// budget: before this change /reset-password (reset-ip) and the app routes
// (token-ip) had separate per-IP buckets, and live integrations rely on that.
func TestAppS2S_SurfacesHaveSeparateStrictBuckets(t *testing.T) {
	s, _ := newS2S(middleware.AppS2SConfig{}, nil)
	app := []echo.MiddlewareFunc{s.ResolveBodyClient(middleware.SurfaceApp)}
	reset := []echo.MiddlewareFunc{s.Resolve(middleware.SurfaceReset)}

	for i := 0; i < middleware.DefaultAppUnverifiedPerIPRate; i++ {
		runS2S(t, app, s2sReq{remote: strangerIP, body: `{"client_id":"` + appClient + `"}`})
	}
	if res := runS2S(t, app, s2sReq{remote: strangerIP, body: `{"client_id":"` + appClient + `"}`}); res.code != http.StatusTooManyRequests {
		t.Fatalf("app surface past its budget: got %d, want 429", res.code)
	}
	for i := 0; i < middleware.DefaultAppUnverifiedPerIPRate; i++ {
		if res := runS2S(t, reset, s2sReq{remote: strangerIP, body: `{"token":"t"}`}); res.code != http.StatusOK {
			t.Fatalf("reset call %d after the app surface was exhausted: got %d, want 200", i+1, res.code)
		}
	}
}

// No per-user default may be below what one user could do through a single
// backend IP before (5/min per IP on each of these routes). Lower would give a
// live integration a 429 it did not get before.
func TestAppS2S_UserDefaultsNotStricterThanBefore(t *testing.T) {
	const before = 5
	d := middleware.DefaultAppUserLimits()
	for name, v := range map[string]int{
		"Register": d.Register, "Login": d.Login, "MagicLink": d.MagicLink,
		"MagicLinkVerify": d.MagicLinkVerify, "ForgotPassword": d.ForgotPassword,
		"ResetPassword": d.ResetPassword, "Roles": d.Roles, "Me": d.Me,
		"MFAChallenge": d.MFAChallenge, "OAuthExchange": d.OAuthExchange,
		"PasskeyLogin": d.PasskeyLogin, "ResendVerification": d.ResendVerification,
	} {
		if v < before {
			t.Errorf("default %s limit %d is below the %d/min a user had before", name, v, before)
		}
	}
}
