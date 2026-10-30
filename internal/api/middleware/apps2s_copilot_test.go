package middleware_test

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog"

	"github.com/engineersmind/emc-auth-server/internal/api/middleware"
)

// Regression tests for the Copilot review of PR #174.

// Copilot #3: concurrent wrong secrets admitted by the attempt budget must all
// reach the handler; no refusal may be decided after the check, or a wrong
// secret (429) and a right one (handler) would answer differently.
func TestCopilot_NoRefusalAfterTheCheck(t *testing.T) {
	middleware.ResetStoresForTest()
	clients := &slowWrongClients{release: make(chan struct{})}
	s := middleware.NewAppS2S(middleware.AppS2SConfig{}, nil, clients, zerolog.Nop())
	chain := loginChain(s)

	const burst = 8 // under the per-IP attempt budget, over the 5 failure budget
	var wg sync.WaitGroup
	codes := make([]int, burst)
	for i := 0; i < burst; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			codes[i] = runS2S(t, chain, s2sReq{remote: strangerIP, clientID: appClient, secret: fmt.Sprintf("g%d", i), body: emailBody("a@x.com")}).code
		}(i)
	}
	go func() {
		for clients.calls.Load() < burst {
		}
		close(clients.release)
	}()
	wg.Wait()
	for i, code := range codes {
		if code == http.StatusTooManyRequests {
			t.Fatalf("request %d was refused after its credential check (429); admitted requests must reach the handler", i)
		}
	}
	// The failures were recorded: the next request is refused BEFORE any check.
	if res := runS2S(t, chain, s2sReq{remote: strangerIP, clientID: appClient, secret: "next", body: emailBody("a@x.com")}); res.code != http.StatusTooManyRequests {
		t.Fatalf("after the recorded failures: got %d, want 429", res.code)
	}
}

// Copilot #4: from a trusted address, once the wrong-secret budget is spent, a
// cached right secret must be refused like a wrong one.
func TestCopilot_TrustedCacheHitDoesNotBypassAdmission(t *testing.T) {
	s, _ := newS2S(middleware.AppS2SConfig{}, trustWith([]string{backendIP + "/32"}, false))
	chain := loginChain(s)
	// The real backend warms the cache.
	if res := runS2S(t, chain, s2sReq{remote: backendIP, clientID: appClient, secret: appSecret, body: emailBody("u@x.com")}); res.code != http.StatusOK {
		t.Fatalf("warm-up: %d", res.code)
	}
	// Someone sharing the backend's egress spends the wrong-secret budget.
	for i := 0; i < middleware.DefaultAppUnverifiedPerIPRate; i++ {
		runS2S(t, chain, s2sReq{remote: backendIP, clientID: appClient, secret: fmt.Sprintf("g%d", i), body: emailBody("x@x.com")})
	}
	right := runS2S(t, chain, s2sReq{remote: backendIP, clientID: appClient, secret: appSecret, body: emailBody("u@x.com")})
	wrong := runS2S(t, chain, s2sReq{remote: backendIP, clientID: appClient, secret: "g-next", body: emailBody("u@x.com")})
	if right.code != wrong.code {
		t.Fatalf("right secret %d, wrong secret %d — the responses must not differ", right.code, wrong.code)
	}
}

// Copilot #5: the limiter must read the same email the handler binds.
// encoding/json matches field names case-insensitively and the last duplicate
// wins, so {"email":"decoy","Email":"victim"} targets the victim.
func TestCopilot_DuplicateKeysBucketTheHandlersValue(t *testing.T) {
	s, _ := newS2S(middleware.AppS2SConfig{}, nil)
	chain := loginChain(s)
	limit := s.UserLimits().Login
	for i := 0; i < limit; i++ {
		body := fmt.Sprintf(`{"email":"decoy%d@x.com","Email":"victim@x.com","password":"x"}`, i)
		runS2S(t, chain, s2sReq{remote: backendIP, clientID: appClient, secret: appSecret, body: body})
	}
	body := `{"email":"decoy-new@x.com","Email":"victim@x.com","password":"x"}`
	if res := runS2S(t, chain, s2sReq{remote: backendIP, clientID: appClient, secret: appSecret, body: body}); res.code != http.StatusTooManyRequests {
		t.Fatalf("victim behind rotating decoys: got %d, want 429", res.code)
	}
}

// Copilot #6: user_id spellings the handler treats as one user share a bucket.
func TestCopilot_UserIDSpellingsShareABucket(t *testing.T) {
	s, _ := newS2S(middleware.AppS2SConfig{Users: middleware.AppUserLimits{Roles: 3}}, nil)
	chain := []echo.MiddlewareFunc{
		s.Resolve(middleware.SurfaceApp),
		s.UserLimit("app_roles_user", s.UserLimits().Roles, middleware.SubjectUserID),
	}
	for _, id := range []string{"12", "012", "+12"} {
		runS2S(t, chain, s2sReq{remote: backendIP, clientID: appClient, secret: appSecret, body: `{"user_id":"` + id + `","roles":["r"]}`})
	}
	if res := runS2S(t, chain, s2sReq{remote: backendIP, clientID: appClient, secret: appSecret, body: `{"user_id":"0012","roles":["r"]}`}); res.code != http.StatusTooManyRequests {
		t.Fatalf("fourth change to user 12 under another spelling: got %d, want 429", res.code)
	}
}

// Copilot #7: every token form JWTRenew accepts is bucketed per user, not in
// one shared bucket.
func TestCopilot_TokenFormsAreBucketedPerUser(t *testing.T) {
	s, _ := newS2S(middleware.AppS2SConfig{Users: middleware.AppUserLimits{Me: 1}}, nil)
	chain := []echo.MiddlewareFunc{
		s.Resolve(middleware.SurfaceApp),
		s.UserLimit("app_me_user", s.UserLimits().Me, middleware.SubjectBearerUser),
	}
	send := func(set func(*http.Request)) int {
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/apps/me", strings.NewReader(""))
		req.RemoteAddr = backendIP + ":1"
		req.Header.Set(middleware.ClientAuthHeader, basicHeader(appClient, appSecret))
		set(req)
		rec := httptest.NewRecorder()
		h := func(c echo.Context) error { return c.NoContent(http.StatusOK) }
		for i := len(chain) - 1; i >= 0; i-- {
			h = chain[i](h)
		}
		_ = h(e.NewContext(req, rec))
		return rec.Code
	}
	forms := map[string]func(*http.Request){
		"lower-case bearer": func(r *http.Request) { r.Header.Set("Authorization", "bearer "+bearerFor("7", "201")) },
		"raw JWT":           func(r *http.Request) { r.Header.Set("Authorization", bearerFor("7", "202")) },
		"access cookie": func(r *http.Request) {
			r.AddCookie(&http.Cookie{Name: middleware.AccessTokenCookie, Value: bearerFor("7", "203")})
		},
	}
	// One request each: with a limit of 1, a shared bucket would refuse the
	// second and third.
	for name, set := range forms {
		if got := send(set); got != http.StatusOK {
			t.Fatalf("%s: got %d, want 200 — each user must have their own bucket", name, got)
		}
	}
}

func basicHeader(id, secret string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(id+":"+secret))
}
