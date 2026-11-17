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
)

// The end-user organisation and session routes (/apps/login/organization,
// /apps/switch-organization, the invitation preview/accept routes, /refresh,
// /logout). A product backend sends its client credentials and is charged to
// its application's shared quota; everyone else keeps the per-IP limit. The
// rule each test pins: a backend is trusted only for ITS OWN users' tokens.

// scopeOf stands in for the token lookups (selection token, refresh token,
// invitation token): "own-*" belongs to the calling application, "foreign-*" to
// another tenant, anything else is unknown (expired or made up).
func scopeOf(_ context.Context, token string) (tenantID, appID int64, ok bool) {
	switch {
	case strings.HasPrefix(token, "own-"):
		return appTenantID, appRowID, true
	case strings.HasPrefix(token, "foreign-"):
		return appTenantID + 1, 99, true
	}
	return 0, 0, false
}

// orgFlowTestChain mirrors orgFlowChain in routes.go, with a counting stand-in
// for the application quota.
func orgFlowTestChain(s *middleware.AppS2S, charged *int) []echo.MiddlewareFunc {
	quota := func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error { *charged++; return next(c) }
	}
	return []echo.MiddlewareFunc{
		s.ResolveOptional(middleware.SurfaceOrg),
		middleware.ScopeToCaller(middleware.ScopeByBodyToken("refresh_token", scopeOf)),
		middleware.BackendsOnly(quota),
		middleware.TokenRateLimiter(middleware.DefaultRateLimitConfig()),
	}
}

func refreshBody(token string, i int) string {
	return fmt.Sprintf(`{"refresh_token":"%s-%d"}`, token, i)
}

func TestOrgFlow_BackendWithCredentialsSharesTheAppQuotaNotPerIP(t *testing.T) {
	s, _ := newS2S(middleware.AppS2SConfig{}, nil)
	var charged int
	chain := orgFlowTestChain(s, &charged)
	// One backend IP and one client_id, many users: the old limit was 5/min.
	for i := 0; i < 100; i++ {
		res := runS2S(t, chain, s2sReq{remote: backendIP, clientID: appClient, secret: appSecret, body: refreshBody("own", i)})
		if res.code != http.StatusOK {
			t.Fatalf("request %d: got %d %v, want 200", i+1, res.code, res.body)
		}
	}
	if charged != 100 {
		t.Fatalf("charged to the application quota %d times, want 100", charged)
	}
}

func TestOrgFlow_AnonymousCallersKeepThePerIPLimit(t *testing.T) {
	s, _ := newS2S(middleware.AppS2SConfig{}, nil)
	var charged int
	chain := orgFlowTestChain(s, &charged)
	for i := 0; i < 5; i++ {
		if res := runS2S(t, chain, s2sReq{remote: strangerIP, body: refreshBody("own", i)}); res.code != http.StatusOK {
			t.Fatalf("anonymous call %d: got %d, want 200", i+1, res.code)
		}
	}
	if res := runS2S(t, chain, s2sReq{remote: strangerIP, body: refreshBody("own", 9)}); res.code != http.StatusTooManyRequests {
		t.Fatalf("anonymous call 6: got %d, want 429 — the per-IP limit must still apply", res.code)
	}
	if charged != 0 {
		t.Fatalf("an anonymous caller was charged to an application quota %d times", charged)
	}
}

func TestOrgFlow_BackendIsNotTrustedForAnotherTenantsTokens(t *testing.T) {
	s, _ := newS2S(middleware.AppS2SConfig{}, nil)
	var charged int
	chain := orgFlowTestChain(s, &charged)
	// Valid credentials must not lift the limit on someone else's tokens.
	for i := 0; i < 5; i++ {
		runS2S(t, chain, s2sReq{remote: backendIP, clientID: appClient, secret: appSecret, body: refreshBody("foreign", i)})
	}
	res := runS2S(t, chain, s2sReq{remote: backendIP, clientID: appClient, secret: appSecret, body: refreshBody("foreign", 9)})
	if res.code != http.StatusTooManyRequests {
		t.Fatalf("6th request on a foreign token: got %d, want 429", res.code)
	}
	if charged != 0 {
		t.Fatalf("a foreign token was charged to this application's quota %d times", charged)
	}
}

// An expired session must not push a real backend back onto the shared per-IP
// limit: it belongs to nobody, so there is nobody to protect.
func TestOrgFlow_UnknownTokenStaysTrusted(t *testing.T) {
	s, _ := newS2S(middleware.AppS2SConfig{}, nil)
	var charged int
	chain := orgFlowTestChain(s, &charged)
	for i := 0; i < 50; i++ {
		res := runS2S(t, chain, s2sReq{remote: backendIP, clientID: appClient, secret: appSecret, body: refreshBody("expired", i)})
		if res.code != http.StatusOK {
			t.Fatalf("request %d with an unknown token: got %d, want 200", i+1, res.code)
		}
	}
	if charged != 50 {
		t.Fatalf("charged %d times, want 50", charged)
	}
}

func TestOrgFlow_WrongSecretGetsStrictLimit(t *testing.T) {
	s, _ := newS2S(middleware.AppS2SConfig{}, nil)
	var charged int
	chain := orgFlowTestChain(s, &charged)
	for i := 0; i < middleware.DefaultAppUnverifiedPerIPRate; i++ {
		runS2S(t, chain, s2sReq{remote: strangerIP, clientID: appClient, secret: "guess", body: refreshBody("own", i)})
	}
	res := runS2S(t, chain, s2sReq{remote: strangerIP, clientID: appClient, secret: "guess", body: refreshBody("own", 77)})
	if res.code != http.StatusTooManyRequests {
		t.Fatalf("wrong secret past the strict limit: got %d %v, want 429", res.code, res.body)
	}
	if charged != 0 {
		t.Fatalf("a request with a wrong secret was charged to an application quota %d times", charged)
	}
}

func TestScopeByQueryToken(t *testing.T) {
	scope := middleware.ScopeByQueryToken("token", scopeOf)
	e := echo.New()
	for _, tc := range []struct {
		query      string
		wantTenant int64
		wantOK     bool
	}{
		{"?token=own-1", appTenantID, true},
		{"?token=foreign-1", appTenantID + 1, true},
		{"?token=expired", 0, false},
		{"", 0, false},
	} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/apps/organizations/invitations/preview"+tc.query, nil)
		tenant, _, ok := scope(e.NewContext(req, httptest.NewRecorder()))
		if tenant != tc.wantTenant || ok != tc.wantOK {
			t.Errorf("query %q: got tenant=%d ok=%v, want tenant=%d ok=%v", tc.query, tenant, ok, tc.wantTenant, tc.wantOK)
		}
	}
}
