package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/redis/go-redis/v9"

	"github.com/engineersmind/emc-auth-server/internal/admin"
	mw "github.com/engineersmind/emc-auth-server/internal/api/middleware"
	"github.com/engineersmind/emc-auth-server/internal/audit"
	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/metrics"
	"github.com/engineersmind/emc-auth-server/internal/store"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// ---------------------------------------------------------------------------
// Issue #226 — metric wiring regression tests.
//
// emc_auth_operations_total and emc_auth_tokens_revoked_total were both defined
// with no writers: RecordOp had no callers and TokensRevoked was never
// incremented. These tests prove a real call through each endpoint moves the
// right labelled counter exactly once.
//
// Counter assertions are DELTAS, not absolutes — other tests in this package
// exercise the same endpoints against the shared global registry, so a test
// that reads "1" without a baseline would pass or fail on execution order.
// ---------------------------------------------------------------------------

func opCount(t *testing.T, operation, outcome string) float64 {
	t.Helper()
	return testutil.ToFloat64(metrics.AuthOperations.WithLabelValues(operation, outcome))
}

func revokedCount(t *testing.T, reason string) float64 {
	t.Helper()
	return testutil.ToFloat64(metrics.TokensRevoked.WithLabelValues(reason))
}

// metricsFixture is the shared integration environment for the #226 tests:
// real Postgres + seed, a registered application, and every handler the
// counters hang off. Redis is attached lazily (withRedis) so DB-only tests
// still run where only DATABASE_URL is set.
type metricsFixture struct {
	ctx      context.Context
	pool     *pgxpool.Pool
	tenantID int64

	app      *auth.AppResult
	appRowID int64
	appSvc   *auth.ApplicationService
	authSvc  *auth.AuthService
	jwtSvc   *auth.JWTService

	authH  *AuthHandler
	adminH *AdminHandler
	agentH *AgentHandler

	rdb *redis.Client
}

func newMetricsFixture(t *testing.T) *metricsFixture {
	t.Helper()
	pool := testhelper.NewTestDB(t)
	testhelper.CleanupTables(t, pool)

	ctx := context.Background()
	logger := testhelper.TestLogger()
	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}

	f := &metricsFixture{ctx: ctx, pool: pool}
	if err := pool.QueryRow(ctx,
		`SELECT id FROM tenants WHERE slug = 'emc' AND deleted_at IS NULL`).Scan(&f.tenantID); err != nil {
		t.Fatalf("fetch seed tenant: %v", err)
	}

	f.appSvc = auth.NewApplicationService(pool, logger)
	app, err := f.appSvc.CreateApplicationWithOptions(ctx, f.tenantID,
		"metrics226-"+uniqueSuffix(), "web", nil,
		auth.AppUpdate{RedirectURIs: []string{"https://app.test/cb"}})
	if err != nil {
		t.Fatalf("CreateApplicationWithOptions: %v", err)
	}
	f.app = app
	if f.appRowID, err = strconv.ParseInt(app.ID, 10, 64); err != nil {
		t.Fatalf("parse app row id %q: %v", app.ID, err)
	}

	jwtSvc, err := auth.NewJWTService(pool, "https://auth.emc.local")
	if err != nil {
		t.Fatalf("NewJWTService: %v", err)
	}
	f.jwtSvc = jwtSvc
	f.authSvc = auth.NewAuthService(pool, jwtSvc, logger).WithApplications(f.appSvc)

	auditLog := audit.New(pool, logger)
	t.Cleanup(func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := auditLog.Close(closeCtx); err != nil {
			t.Logf("audit logger close: %v", err)
		}
	})

	f.authH = NewAuthHandler(f.authSvc, nil, auditLog, logger).
		WithApplications(f.appSvc).
		WithAPIKeys(auth.NewAPIKeyService(pool, logger)).
		WithCookieConfig(mw.BuildCookieConfig("development", ""))

	f.adminH = NewAdminHandler(
		admin.New(pool, nil, logger).WithAuthService(f.authSvc), auditLog, logger)

	f.agentH = NewAgentHandler(auth.NewAgentService(pool, logger), jwtSvc, logger)
	return f
}

// withRedis attaches a real Redis (skipping without REDIS_URL) to both the
// service — WithTOTP is where AuthService takes its redisCli — and the
// handler's cookie-session plumbing. Returns the client for tests that need
// stores of their own (the parked authorize request).
func (f *metricsFixture) withRedis(t *testing.T) *redis.Client {
	t.Helper()
	if f.rdb == nil {
		f.rdb = testhelper.NewTestRedis(t)
		f.authSvc.WithTOTP(nil, f.rdb)
		f.authH.WithRedis(f.rdb)
	}
	return f.rdb
}

// registerUser creates a tenant-level account through the service — the same
// pre-state every login test needs.
func (f *metricsFixture) registerUser(t *testing.T, email, password string) {
	t.Helper()
	if _, err := f.authSvc.Register(f.ctx, auth.RegisterInput{
		Email: email, Password: password, FirstName: "Metrics", LastName: "Test",
	}); err != nil {
		t.Fatalf("Register(%q): %v", email, err)
	}
}

// loginTokens signs the user in at the service boundary and returns the
// issued pair — the raw refresh token is what the revocation tests revoke.
func (f *metricsFixture) loginTokens(t *testing.T, email, password string) *auth.AuthResult {
	t.Helper()
	res, err := f.authSvc.Login(f.ctx, auth.LoginInput{Email: email, Password: password})
	if err != nil {
		t.Fatalf("Login(%q): %v", email, err)
	}
	if res.Token == nil {
		t.Fatalf("Login(%q) returned a challenge, want tokens", email)
	}
	return res.Token
}

func jsonCtx(method, path, body string) (echo.Context, *httptest.ResponseRecorder) {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	return echo.New().NewContext(req, rec), rec
}

// postLogin calls POST /api/v1/auth/login on the fixture handler.
func postLogin(t *testing.T, h *AuthHandler, email, password string) *httptest.ResponseRecorder {
	t.Helper()
	c, rec := jsonCtx(http.MethodPost, "/api/v1/auth/login",
		fmt.Sprintf(`{"email":%q,"password":%q}`, email, password))
	if err := h.Login(c); err != nil {
		t.Fatalf("Login() returned error: %v", err)
	}
	return rec
}

// ---------------------------------------------------------------------------
// Item 1 — emc_auth_operations_total{operation,outcome} on first-factor logins
// ---------------------------------------------------------------------------

func TestMetrics226_PasswordLoginFailureCounts(t *testing.T) {
	f := newMetricsFixture(t)
	email := "pw-fail-" + uniqueSuffix() + "@test.example.com"
	f.registerUser(t, email, "Password123!")

	before := opCount(t, "login_password", "failure")
	rec := postLogin(t, f.authH, email, "not-the-password")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if got := opCount(t, "login_password", "failure") - before; got != 1 {
		t.Errorf("login_password/failure delta = %v, want 1", got)
	}
}

func TestMetrics226_PasswordLoginSuccessCounts(t *testing.T) {
	f := newMetricsFixture(t)
	email := "pw-ok-" + uniqueSuffix() + "@test.example.com"
	f.registerUser(t, email, "Password123!")

	before := opCount(t, "login_password", "success")
	rec := postLogin(t, f.authH, email, "Password123!")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := opCount(t, "login_password", "success") - before; got != 1 {
		t.Errorf("login_password/success delta = %v, want 1", got)
	}
}

func TestMetrics226_SessionLoginCounts(t *testing.T) {
	f := newMetricsFixture(t)
	email := "sess-" + uniqueSuffix() + "@test.example.com"
	f.registerUser(t, email, "Password123!")

	before := opCount(t, "login_password", "success")
	c, rec := jsonCtx(http.MethodPost, "/api/v1/auth/session",
		fmt.Sprintf(`{"email":%q,"password":%q}`, email, "Password123!"))
	if err := f.authH.SessionLogin(c); err != nil {
		t.Fatalf("SessionLogin() returned error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := opCount(t, "login_password", "success") - before; got != 1 {
		t.Errorf("login_password/success delta = %v, want 1", got)
	}
}

func TestMetrics226_AppLoginCounts(t *testing.T) {
	f := newMetricsFixture(t)
	email := "app-" + uniqueSuffix() + "@test.example.com"
	if _, err := f.authSvc.Register(f.ctx, auth.RegisterInput{
		ClientID: f.app.ClientID, ClientSecret: f.app.ClientSecret,
		Email: email, Password: "Password123!",
	}); err != nil {
		t.Fatalf("Register(app user): %v", err)
	}

	before := opCount(t, "login_password", "failure")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/apps/login",
		strings.NewReader(fmt.Sprintf(`{"email":%q,"password":%q}`, email, "wrong-password")))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.SetBasicAuth(f.app.ClientID, f.app.ClientSecret)
	rec := httptest.NewRecorder()
	if err := f.authH.AppLogin(echo.New().NewContext(req, rec)); err != nil {
		t.Fatalf("AppLogin() returned error: %v", err)
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if got := opCount(t, "login_password", "failure") - before; got != 1 {
		t.Errorf("login_password/failure delta = %v, want 1", got)
	}
}

func TestMetrics226_HostedLoginCounts(t *testing.T) {
	f := newMetricsFixture(t)
	rdb := f.withRedis(t)

	sessions := auth.NewAuthzSessionStore(rdb)
	h := NewOAuthAuthorizeHandler(
		auth.NewAuthorizationServer(f.pool, testhelper.TestLogger()),
		sessions, f.authSvc, nil, testhelper.TestLogger(), false, false)

	handle, err := sessions.SaveRequest(f.ctx, &auth.AuthzRequest{
		ClientID: f.app.ClientID, TenantID: f.tenantID, AppRowID: f.appRowID,
		RedirectURI: "https://app.test/cb", State: "state-1", AppName: "metrics-app",
	})
	if err != nil {
		t.Fatalf("SaveRequest: %v", err)
	}

	before := opCount(t, "login_password", "failure")
	form := url.Values{
		"request":  {handle},
		"email":    {"nobody@test.example.com"},
		"password": {"any-password"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/authorize/login", strings.NewReader(form.Encode()))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	rec := httptest.NewRecorder()
	if err := h.LoginSubmit(echo.New().NewContext(req, rec)); err != nil {
		t.Fatalf("LoginSubmit() returned error: %v", err)
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if got := opCount(t, "login_password", "failure") - before; got != 1 {
		t.Errorf("login_password/failure delta = %v, want 1", got)
	}
}

func TestMetrics226_MagicLinkVerifyCounts(t *testing.T) {
	f := newMetricsFixture(t)
	f.withRedis(t) // VerifyMagicLink refuses early when redisCli is nil

	before := opCount(t, "login_magic_link", "failure")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/apps/login/magic/verify",
		strings.NewReader(`{"token":"not-a-real-magic-link-token"}`))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.SetBasicAuth(f.app.ClientID, f.app.ClientSecret)
	rec := httptest.NewRecorder()
	if err := f.authH.AppMagicLinkVerify(echo.New().NewContext(req, rec)); err != nil {
		t.Fatalf("AppMagicLinkVerify() returned error: %v", err)
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if got := opCount(t, "login_magic_link", "failure") - before; got != 1 {
		t.Errorf("login_magic_link/failure delta = %v, want 1", got)
	}
}

func TestMetrics226_PasswordlessVerifyCounts(t *testing.T) {
	f := newMetricsFixture(t)
	rdb := f.withRedis(t)

	// pwlessReady needs the policy service, Redis, the application service and
	// the email service wired; a nil mailer is fine because a failed verify
	// never sends anything.
	f.authSvc.
		WithEmailMFA(auth.NewEmailMFAService(f.pool, rdb, nil, testhelper.TestLogger())).
		WithPasswordless(auth.NewPasswordlessPolicyService(f.pool, testhelper.TestLogger()),
			[]byte("0123456789abcdef0123456789abcdef"), nil)
	f.authH.WithPasswordless(true)

	before := opCount(t, "login_passwordless", "failure")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/apps/passwordless/verify",
		strings.NewReader(`{"challenge_id":"`+strings.Repeat("0", 64)+`","code":"000000"}`))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.SetBasicAuth(f.app.ClientID, f.app.ClientSecret)
	rec := httptest.NewRecorder()
	if err := f.authH.PasswordlessVerify(echo.New().NewContext(req, rec)); err != nil {
		t.Fatalf("PasswordlessVerify() returned error: %v", err)
	}
	if got := opCount(t, "login_passwordless", "failure") - before; got != 1 {
		t.Errorf("login_passwordless/failure delta = %v, want 1", got)
	}
}

// ---------------------------------------------------------------------------
// Item 3 — emc_auth_tokens_revoked_total{reason} on every revoke path
// ---------------------------------------------------------------------------

func TestMetrics226_OAuthRevokeCounts(t *testing.T) {
	f := newRevokeFixture(t) // shared fixture: postgres + an oauth client
	token := f.issueRefreshToken(t, f.tenantID)

	before := revokedCount(t, "oauth_revoke")
	rec := f.postRevoke(t, url.Values{
		"token":         {token},
		"client_id":     {f.clientID},
		"client_secret": {f.clientSecret},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := revokedCount(t, "oauth_revoke") - before; got != 1 {
		t.Errorf("tokens_revoked{oauth_revoke} delta = %v, want 1", got)
	}
}

func TestMetrics226_LogoutCounts(t *testing.T) {
	f := newMetricsFixture(t)
	email := "logout-" + uniqueSuffix() + "@test.example.com"
	f.registerUser(t, email, "Password123!")
	tokens := f.loginTokens(t, email, "Password123!")

	before := revokedCount(t, "logout")
	c, rec := jsonCtx(http.MethodPost, "/api/v1/auth/logout",
		fmt.Sprintf(`{"refresh_token":%q}`, tokens.RefreshToken))
	if err := f.authH.Logout(c); err != nil {
		t.Fatalf("Logout() returned error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := revokedCount(t, "logout") - before; got != 1 {
		t.Errorf("tokens_revoked{logout} delta = %v, want 1", got)
	}
}

func TestMetrics226_SessionLogoutCounts(t *testing.T) {
	f := newMetricsFixture(t)
	email := "sessout-" + uniqueSuffix() + "@test.example.com"
	f.registerUser(t, email, "Password123!")
	tokens := f.loginTokens(t, email, "Password123!")

	before := revokedCount(t, "logout")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/session/logout", nil)
	req.AddCookie(&http.Cookie{Name: mw.RefreshTokenCookie, Value: tokens.RefreshToken})
	rec := httptest.NewRecorder()
	if err := f.authH.SessionLogout(echo.New().NewContext(req, rec)); err != nil {
		t.Fatalf("SessionLogout() returned error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := revokedCount(t, "logout") - before; got != 1 {
		t.Errorf("tokens_revoked{logout} delta = %v, want 1", got)
	}
}

// liveSessionID returns the user's live session row id — the familyID the
// admin endpoints take.
func (f *metricsFixture) liveSessionID(t *testing.T, email string) (userID, sessionID int64) {
	t.Helper()
	if err := f.pool.QueryRow(f.ctx,
		`SELECT s.user_id, s.id FROM user_sessions s
		 JOIN users u ON u.id = s.user_id
		 WHERE u.email = $1 AND s.revoked_at IS NULL`, email,
	).Scan(&userID, &sessionID); err != nil {
		t.Fatalf("fetch live session for %q: %v", email, err)
	}
	return userID, sessionID
}

func (f *metricsFixture) adminCtx(method, path string, names, values []string) (echo.Context, *httptest.ResponseRecorder) {
	req := httptest.NewRequest(method, path, nil)
	rec := httptest.NewRecorder()
	c := echo.New().NewContext(req, rec)
	c.Set("user", &auth.Claims{
		TenantID: strconv.FormatInt(f.tenantID, 10),
		UserID:   "1",
		Email:    "admin@emc.local",
	})
	c.SetParamNames(names...)
	c.SetParamValues(values...)
	return c, rec
}

func TestMetrics226_AdminRevokeOneSessionCounts(t *testing.T) {
	f := newMetricsFixture(t)
	email := "adm-one-" + uniqueSuffix() + "@test.example.com"
	f.registerUser(t, email, "Password123!")
	f.loginTokens(t, email, "Password123!")
	userID, sessionID := f.liveSessionID(t, email)

	before := revokedCount(t, "admin_revoked")
	c, rec := f.adminCtx(http.MethodDelete, "/api/v1/users/x/sessions/y",
		[]string{"id", "familyID"},
		[]string{strconv.FormatInt(userID, 10), strconv.FormatInt(sessionID, 10)})
	if err := f.adminH.RevokeUserSession(c); err != nil {
		t.Fatalf("RevokeUserSession() returned error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := revokedCount(t, "admin_revoked") - before; got != 1 {
		t.Errorf("tokens_revoked{admin_revoked} delta = %v, want 1", got)
	}
}

func TestMetrics226_AdminRevokeAllSessionsCounts(t *testing.T) {
	f := newMetricsFixture(t)
	email := "adm-all-" + uniqueSuffix() + "@test.example.com"
	f.registerUser(t, email, "Password123!")
	f.loginTokens(t, email, "Password123!")
	userID, _ := f.liveSessionID(t, email)

	before := revokedCount(t, "admin_revoked_all")
	c, rec := f.adminCtx(http.MethodDelete, "/api/v1/users/x/sessions",
		[]string{"id"}, []string{strconv.FormatInt(userID, 10)})
	if err := f.adminH.RevokeAllUserSessions(c); err != nil {
		t.Fatalf("RevokeAllUserSessions() returned error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := revokedCount(t, "admin_revoked_all") - before; got != 1 {
		t.Errorf("tokens_revoked{admin_revoked_all} delta = %v, want 1", got)
	}
}

func TestMetrics226_ReplayDetectionCounts(t *testing.T) {
	f := newMetricsFixture(t)
	f.withRedis(t)
	email := "replay-" + uniqueSuffix() + "@test.example.com"
	f.registerUser(t, email, "Password123!")
	tokens := f.loginTokens(t, email, "Password123!")

	// Legitimate rotation — the presented token is now revoked.
	c, rec := jsonCtx(http.MethodPost, "/api/v1/auth/refresh",
		fmt.Sprintf(`{"refresh_token":%q}`, tokens.RefreshToken))
	if err := f.authH.Refresh(c); err != nil {
		t.Fatalf("first Refresh() returned error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("first refresh status = %d, want 200", rec.Code)
	}

	// Presenting the rotated token again is a replay: the family is revoked.
	before := revokedCount(t, "replay_detected")
	c, rec = jsonCtx(http.MethodPost, "/api/v1/auth/refresh",
		fmt.Sprintf(`{"refresh_token":%q}`, tokens.RefreshToken))
	if err := f.authH.Refresh(c); err != nil {
		t.Fatalf("replayed Refresh() returned error: %v", err)
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("replay status = %d, want 401", rec.Code)
	}
	if got := revokedCount(t, "replay_detected") - before; got != 1 {
		t.Errorf("tokens_revoked{replay_detected} delta = %v, want 1", got)
	}
}

func TestMetrics226_RevokeAPIKeyCounts(t *testing.T) {
	f := newMetricsFixture(t)
	key, err := f.authH.apiKeySvc.CreateAPIKey(f.ctx, f.tenantID, "metrics-key", nil)
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}

	before := revokedCount(t, "api_key_revoked")
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/api-keys/x", nil)
	rec := httptest.NewRecorder()
	c := echo.New().NewContext(req, rec)
	c.Set("user", &auth.Claims{
		TenantID: strconv.FormatInt(f.tenantID, 10),
		UserID:   "1",
		Email:    "admin@emc.local",
	})
	c.SetParamNames("id")
	c.SetParamValues(key.ID)
	if err := f.authH.RevokeAPIKey(c); err != nil {
		t.Fatalf("RevokeAPIKey() returned error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := revokedCount(t, "api_key_revoked") - before; got != 1 {
		t.Errorf("tokens_revoked{api_key_revoked} delta = %v, want 1", got)
	}
}

func TestMetrics226_RevokeAgentCounts(t *testing.T) {
	f := newMetricsFixture(t)
	agent, err := f.agentH.agentSvc.RegisterAgent(f.ctx, f.tenantID,
		"metrics-agent", "service", nil)
	if err != nil {
		t.Fatalf("RegisterAgent: %v", err)
	}

	before := revokedCount(t, "agent_revoked")
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/agents/x", nil)
	rec := httptest.NewRecorder()
	c := echo.New().NewContext(req, rec)
	c.Set("user", &auth.Claims{
		TenantID: strconv.FormatInt(f.tenantID, 10),
		UserID:   "1",
		Email:    "admin@emc.local",
	})
	c.SetParamNames("id")
	c.SetParamValues(agent.ID)
	if err := f.agentH.RevokeAgent(c); err != nil {
		t.Fatalf("RevokeAgent() returned error: %v", err)
	}
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
	if got := revokedCount(t, "agent_revoked") - before; got != 1 {
		t.Errorf("tokens_revoked{agent_revoked} delta = %v, want 1", got)
	}
}
