package middleware_test

import (
	"net/http"
	"testing"

	"github.com/labstack/echo/v4"

	"github.com/engineersmind/emc-auth-server/internal/api/middleware"
	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// fakeOverrides is an in-memory auth.AppUserLimitService.
type fakeOverrides map[int64]map[string]int

func (f fakeOverrides) UserLimitOverride(appID int64, key string) (int, bool) {
	v, ok := f[appID][key]
	return v, ok
}

// countAllowed sends n logins for one email and counts the 200s.
func countAllowed(t *testing.T, chain []echo.MiddlewareFunc, clientID, secret, email string, n int) int {
	t.Helper()
	ok := 0
	for i := 0; i < n; i++ {
		if runS2S(t, chain, s2sReq{remote: backendIP, clientID: clientID, secret: secret, body: emailBody(email)}).code == http.StatusOK {
			ok++
		}
	}
	return ok
}

// An application's override replaces the default for that application only.
func TestUserLimitOverride_AppliesToItsApplicationOnly(t *testing.T) {
	s, _ := newS2S(middleware.AppS2SConfig{}, nil)
	s.WithUserLimitOverrides(fakeOverrides{appRowID: {auth.UserLimitLogin: 12}})
	def := s.UserLimits().Login
	chain := []echo.MiddlewareFunc{
		s.Resolve(middleware.SurfaceApp),
		s.UserLimit("app_login_user", def, middleware.SubjectEmail),
	}
	if got := countAllowed(t, chain, appClient, appSecret, "a@x.com", 20); got != 12 {
		t.Fatalf("overridden application: %d allowed, want 12", got)
	}
	if got := countAllowed(t, chain, otherClient, otherSecret, "a@x.com", 20); got != def {
		t.Fatalf("other application: %d allowed, want the default %d", got, def)
	}
}

// Lowering works too, and the 429 reports the effective limit.
func TestUserLimitOverride_LowerAndHeader(t *testing.T) {
	s, _ := newS2S(middleware.AppS2SConfig{}, nil)
	s.WithUserLimitOverrides(fakeOverrides{appRowID: {auth.UserLimitLogin: 2}})
	chain := []echo.MiddlewareFunc{
		s.Resolve(middleware.SurfaceApp),
		s.UserLimit("app_login_user", s.UserLimits().Login, middleware.SubjectEmail),
	}
	if got := countAllowed(t, chain, appClient, appSecret, "b@x.com", 2); got != 2 {
		t.Fatalf("first 2: %d allowed", got)
	}
	res := runS2S(t, chain, s2sReq{remote: backendIP, clientID: appClient, secret: appSecret, body: emailBody("b@x.com")})
	if res.code != http.StatusTooManyRequests || res.header.Get("X-RateLimit-Limit") != "2" {
		t.Fatalf("third: %d, X-RateLimit-Limit %q; want 429 and 2", res.code, res.header.Get("X-RateLimit-Limit"))
	}
}

// The per-application half of GuessLimit is not a per-user limit and must not
// follow the reset_password override.
func TestUserLimitOverride_DoesNotResizeUnforwardedGuessBudget(t *testing.T) {
	s, _ := newS2S(middleware.AppS2SConfig{}, trustWith([]string{backendIP + "/32"}, true))
	s.WithUserLimitOverrides(fakeOverrides{appRowID: {auth.UserLimitResetPassword: 60}})
	chain := []echo.MiddlewareFunc{
		s.Resolve(middleware.SurfaceReset),
		s.GuessLimit("app_reset_password_user", s.UserLimits().ResetPassword),
	}
	allowed := 0
	for i := 0; i < middleware.OAuthTokenPerClientRate+5; i++ {
		if runS2S(t, chain, s2sReq{remote: backendIP, clientID: appClient, secret: appSecret, body: `{"token":"t"}`}).code == http.StatusOK {
			allowed++
		}
	}
	if allowed != middleware.OAuthTokenPerClientRate {
		t.Fatalf("unforwarded budget: %d allowed, want %d", allowed, middleware.OAuthTokenPerClientRate)
	}
	// The per-user-IP half does follow it.
	allowed = 0
	for i := 0; i < 70; i++ {
		if runS2S(t, chain, s2sReq{remote: backendIP, clientID: appClient, secret: appSecret, forwarded: "49.36.1.7", body: `{"token":"t"}`}).code == http.StatusOK {
			allowed++
		}
	}
	if allowed != 60 {
		t.Fatalf("forwarded user with override 60: %d allowed", allowed)
	}
}

// Every limit an administrator can override has a default to show.
func TestUserLimitsByKey_CoversEveryDefinition(t *testing.T) {
	byKey := middleware.DefaultAppUserLimits().ByKey()
	for _, d := range auth.UserLimitDefs {
		if byKey[d.Key] < 1 {
			t.Fatalf("no default for %q", d.Key)
		}
	}
	if len(byKey) != len(auth.UserLimitDefs) {
		t.Fatalf("%d defaults for %d definitions", len(byKey), len(auth.UserLimitDefs))
	}
}
