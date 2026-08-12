package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"

	mw "github.com/engineersmind/emc-auth-server/internal/api/middleware"
	"github.com/engineersmind/emc-auth-server/internal/audit"
	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/store"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// Issue #108. POST /api/v1/auth/refresh delivered the rotated pair only through
// setAuthCookies, which deliberately writes nothing for an application-scoped
// identity ("cookies are for the portal, headers are for applications"). The
// body carried no tokens either, so an app-scoped client received a 200 with
// nothing usable in it, retried with the old refresh token, and that forced
// retry was correctly classified as a replay — revoking the whole family and
// hard-logging the user out of every session.
//
// These tests pin both halves of the contract: app-scoped callers get the pair
// in the body, and first-party callers keep the cookie-only response they
// already had. The second half matters as much as the first — collapsing the
// two return paths would hand the portal a JS-readable refresh token.

// refreshScopeFixture is the shared harness: real DB, real Redis, a seeded
// tenant, and an AuthHandler wired the way routes.go wires it (Redis for the
// rotation lock, a development cookie config so first-party cookies are
// actually emitted, and a live audit logger because the success path — unlike
// the grace path in refresh_grace_test.go — does reach auditEvent).
type refreshScopeFixture struct {
	h      *AuthHandler
	svc    *auth.AuthService
	jwtSvc *auth.JWTService
	app    *auth.AppResult
	ctx    context.Context
}

func newRefreshScopeFixture(t *testing.T) *refreshScopeFixture {
	t.Helper()

	pool := testhelper.NewTestDB(t)
	rdb := testhelper.NewTestRedis(t)
	logger := testhelper.TestLogger()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)

	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}
	t.Cleanup(func() { testhelper.CleanupTables(t, pool) })

	var tenantID int64
	if err := pool.QueryRow(ctx,
		`SELECT id FROM tenants WHERE slug = 'emc' AND deleted_at IS NULL`,
	).Scan(&tenantID); err != nil {
		t.Fatalf("fetch seed tenant id: %v", err)
	}

	appSvc := auth.NewApplicationService(pool, logger)
	app, err := appSvc.CreateApplication(ctx, tenantID, fmt.Sprintf("refresh-scope-%d", time.Now().UnixNano()), "web", nil)
	if err != nil {
		t.Fatalf("CreateApplication() error = %v", err)
	}

	jwtSvc, err := auth.NewJWTService(pool, "https://auth.emc.local")
	if err != nil {
		t.Fatalf("NewJWTService: %v", err)
	}
	svc := auth.NewAuthService(pool, jwtSvc, logger).WithApplications(appSvc)

	auditLog := audit.New(pool, logger)
	t.Cleanup(func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer closeCancel()
		if err := auditLog.Close(closeCtx); err != nil {
			t.Logf("audit logger close: %v", err)
		}
	})

	h := NewAuthHandler(svc, nil, auditLog, logger).
		WithRedis(rdb).
		WithApplications(appSvc).
		// Development config: Secure=false, no Domain — cookies are emitted, so
		// TestRefresh_FirstPartyResponseUnchanged can prove they still arrive.
		WithCookieConfig(mw.BuildCookieConfig("development", ""))

	return &refreshScopeFixture{h: h, svc: svc, jwtSvc: jwtSvc, app: app, ctx: ctx}
}

// appScopedLogin registers and logs a user in through the fixture's
// application, returning the app-scoped refresh token. Register already returns
// a token pair, but going through Login as well mirrors the issue's repro steps
// (step 2 then step 3) and proves the token under test came from the same path
// the integrator uses.
func (f *refreshScopeFixture) appScopedLogin(t *testing.T) *auth.AuthResult {
	t.Helper()

	email := fmt.Sprintf("app-refresh-%d@test.example.com", time.Now().UnixNano())
	if _, err := f.svc.Register(f.ctx, auth.RegisterInput{
		ClientID:     f.app.ClientID,
		ClientSecret: f.app.ClientSecret,
		Email:        email,
		Password:     "Password123!",
		FirstName:    "App",
		LastName:     "Scoped",
	}); err != nil {
		t.Fatalf("Register(app credentials) error = %v", err)
	}

	login, err := f.svc.Login(f.ctx, auth.LoginInput{
		ClientID:     f.app.ClientID,
		ClientSecret: f.app.ClientSecret,
		Email:        email,
		Password:     "Password123!",
	})
	if err != nil {
		t.Fatalf("Login(app credentials) error = %v", err)
	}
	if login.Token == nil {
		t.Fatalf("Login(app credentials) returned no token pair (challenge = %+v)", login.OTPChallenge)
	}

	// Sanity: without an app_id claim this test would be measuring the
	// first-party path and would pass for the wrong reason.
	claims, err := f.jwtSvc.Verify(f.ctx, login.Token.AccessToken)
	if err != nil {
		t.Fatalf("Verify(app login access token) error = %v", err)
	}
	if claims.AppID != f.app.ID {
		t.Fatalf("app login token AppID = %q, want %q — fixture is not app-scoped", claims.AppID, f.app.ID)
	}

	return login.Token
}

// firstPartyLogin registers a tenant-level user (no client credentials), whose
// tokens carry no app_id and therefore belong to the cookie path.
func (f *refreshScopeFixture) firstPartyLogin(t *testing.T) *auth.AuthResult {
	t.Helper()

	reg, err := f.svc.Register(f.ctx, auth.RegisterInput{
		TenantSlug: "emc",
		Email:      fmt.Sprintf("portal-refresh-%d@test.example.com", time.Now().UnixNano()),
		Password:   "Password123!",
		FirstName:  "First",
		LastName:   "Party",
	})
	if err != nil {
		t.Fatalf("Register(tenant slug) error = %v", err)
	}

	claims, err := f.jwtSvc.Verify(f.ctx, reg.AccessToken)
	if err != nil {
		t.Fatalf("Verify(first-party access token) error = %v", err)
	}
	if claims.AppID != "" {
		t.Fatalf("first-party token unexpectedly carries AppID %q — fixture is wrong", claims.AppID)
	}

	return reg
}

// callRefresh invokes the body-based POST /api/v1/auth/refresh handler.
func callRefresh(t *testing.T, h *AuthHandler, refreshToken string) *httptest.ResponseRecorder {
	t.Helper()

	e := echo.New()
	body := fmt.Sprintf(`{"refresh_token":%q}`, refreshToken)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", strings.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()

	if err := h.Refresh(e.NewContext(req, rec)); err != nil {
		t.Fatalf("Refresh() returned error: %v", err)
	}
	return rec
}

// tokenPairBody is the auth.AuthResult shape, plus message so a first-party
// response can be decoded with the same struct.
type tokenPairBody struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	ExpiresAt    int64  `json:"expires_at"`
	Message      string `json:"message"`
}

func decodeRefreshBody(t *testing.T, rec *httptest.ResponseRecorder) tokenPairBody {
	t.Helper()
	var body tokenPairBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v (raw: %s)", err, rec.Body.String())
	}
	return body
}

func cookieNames(rec *httptest.ResponseRecorder) []string {
	cookies := rec.Result().Cookies()
	names := make([]string, 0, len(cookies))
	for _, ck := range cookies {
		names = append(names, ck.Name)
	}
	sort.Strings(names)
	return names
}

// TestRefresh_AppScopedReturnsTokensInBody is issue #108 in one assertion: an
// application-scoped caller must receive the rotated pair in the JSON body,
// and must still receive no cookies.
func TestRefresh_AppScopedReturnsTokensInBody(t *testing.T) {
	f := newRefreshScopeFixture(t)
	tok := f.appScopedLogin(t)

	rec := callRefresh(t, f.h, tok.RefreshToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}

	body := decodeRefreshBody(t, rec)
	if body.AccessToken == "" {
		t.Errorf("access_token is empty — an app-scoped client has no other delivery path; " +
			"it will retry with the old refresh token and lose the whole token family (issue #108)")
	}
	if body.RefreshToken == "" {
		t.Errorf("refresh_token is empty — this is the destructive half of issue #108: " +
			"the client cannot rotate, retries the old token, and trips replay detection")
	}
	if body.TokenType != "Bearer" {
		t.Errorf("token_type = %q, want %q", body.TokenType, "Bearer")
	}
	if body.ExpiresIn <= 0 {
		t.Errorf("expires_in = %d, want > 0", body.ExpiresIn)
	}
	if body.ExpiresAt <= 0 {
		t.Errorf("expires_at = %d, want > 0", body.ExpiresAt)
	}

	// The cookie invariant must survive the fix: applications authenticate with
	// Authorization: Bearer and must never be handed an ambient credential.
	if names := cookieNames(rec); len(names) != 0 {
		t.Errorf("app-scoped refresh set cookies %v — applications must stay header-only", names)
	}
}

// TestRefresh_AppScopedRotatedTokenWorks is what actually proves the bug is
// dead. Taking the refresh token from the *body* and refreshing again must
// succeed: the destructive retry loop is broken because the client finally has
// something to send. Replaying the superseded token must still be rejected —
// the security control has to survive the fix.
func TestRefresh_AppScopedRotatedTokenWorks(t *testing.T) {
	f := newRefreshScopeFixture(t)
	tok := f.appScopedLogin(t)

	first := decodeRefreshBody(t, callRefresh(t, f.h, tok.RefreshToken))
	if first.RefreshToken == "" {
		t.Fatalf("first refresh returned no refresh_token — cannot exercise rotation (issue #108)")
	}

	rec := callRefresh(t, f.h, first.RefreshToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("second refresh (using the body-delivered token) status = %d, want 200 (body: %s)",
			rec.Code, rec.Body.String())
	}
	second := decodeRefreshBody(t, rec)
	if second.RefreshToken == "" {
		t.Errorf("second refresh returned no refresh_token")
	}
	if second.RefreshToken == first.RefreshToken {
		t.Errorf("refresh token was not rotated — both hops returned the same value")
	}

	// Replaying the now-superseded token must terminate the session, exactly as
	// before the fix. Without this the fix could pass by disabling the control.
	replay := callRefresh(t, f.h, first.RefreshToken)
	if replay.Code != http.StatusUnauthorized {
		t.Errorf("replay of a rotated token: status = %d, want 401 — replay detection must survive the fix (body: %s)",
			replay.Code, replay.Body.String())
	}
}

// TestRefresh_AppScopedPreservesAppIDAcrossBodyDelivery checks the token handed
// back in the body is genuinely still application-scoped. The service preserves
// app_id across rotation (#82, TestRefreshWithLock_PreservesAppID); this pins
// that the new delivery path does not lose it.
func TestRefresh_AppScopedPreservesAppIDAcrossBodyDelivery(t *testing.T) {
	f := newRefreshScopeFixture(t)
	tok := f.appScopedLogin(t)

	body := decodeRefreshBody(t, callRefresh(t, f.h, tok.RefreshToken))
	if body.AccessToken == "" {
		t.Fatalf("no access_token in body — cannot inspect claims (issue #108)")
	}

	claims, err := f.jwtSvc.Verify(f.ctx, body.AccessToken)
	if err != nil {
		t.Fatalf("Verify(rotated access token) error = %v", err)
	}
	if claims.AppID != f.app.ID {
		t.Errorf("rotated access token AppID = %q, want %q", claims.AppID, f.app.ID)
	}
}

// TestRefresh_FirstPartyResponseUnchanged is the anti-regression test. A
// tenant-level session must get exactly {message, expires_in, expires_at} with
// both cookies set and no tokens in the body. It fails loudly if anyone later
// "simplifies" the branch away and returns auth.AuthResult unconditionally —
// which would put a refresh token where portal JavaScript can read it.
func TestRefresh_FirstPartyResponseUnchanged(t *testing.T) {
	f := newRefreshScopeFixture(t)
	reg := f.firstPartyLogin(t)

	rec := callRefresh(t, f.h, reg.RefreshToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}

	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode body: %v (raw: %s)", err, rec.Body.String())
	}
	got := make([]string, 0, len(raw))
	for k := range raw {
		got = append(got, k)
	}
	sort.Strings(got)
	want := []string{"expires_at", "expires_in", "message"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("first-party refresh body keys = %v, want exactly %v — the portal response must not change, "+
			"and must never carry a JS-readable refresh token", got, want)
	}

	if names := cookieNames(rec); strings.Join(names, ",") !=
		strings.Join([]string{mw.AccessTokenCookie, mw.RefreshTokenCookie}, ",") {
		t.Errorf("first-party refresh set cookies %v, want both %q and %q",
			names, mw.AccessTokenCookie, mw.RefreshTokenCookie)
	}
}

// TestSessionRefresh_NeverReturnsTokens pins constraint 1 of the issue
// permanently: the cookie endpoint serves browsers, so putting tokens in its
// body would hand the portal a JS-readable copy of a refresh token and defeat
// the point of HttpOnly cookies. This test exists so a future edit to the
// shared refresh area cannot leak them there.
func TestSessionRefresh_NeverReturnsTokens(t *testing.T) {
	f := newRefreshScopeFixture(t)
	reg := f.firstPartyLogin(t)

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/session/refresh", nil)
	req.AddCookie(&http.Cookie{Name: mw.RefreshTokenCookie, Value: reg.RefreshToken})
	rec := httptest.NewRecorder()
	if err := f.h.SessionRefresh(e.NewContext(req, rec)); err != nil {
		t.Fatalf("SessionRefresh() returned error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}

	// Decoded as a raw map rather than into tokenPairBody: this endpoint's
	// expires_in is JSON-encoded as a string, and the assertion here is about
	// which keys are absent, not about their types.
	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode body: %v (raw: %s)", err, rec.Body.String())
	}
	for _, key := range []string{"access_token", "refresh_token"} {
		if _, present := raw[key]; present {
			t.Errorf("/auth/session/refresh returned %q in the body — a cookie session must never receive "+
				"a JS-readable credential (body keys: %v)", key, raw)
		}
	}
}
