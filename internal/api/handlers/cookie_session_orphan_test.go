package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"

	mw "github.com/engineersmind/emc-auth-server/internal/api/middleware"
	"github.com/engineersmind/emc-auth-server/internal/audit"
	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/store"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// Issue #116, item 1. The cookie-session endpoints minted a token pair, then
// discovered the identity was application-scoped, then returned 400 and set no
// cookies — abandoning a live user_sessions row and refresh_tokens row nobody
// held.
//
// The stale row was not the expensive part. enforceSessionCap ranks a user's
// live sessions by last_seen_at DESC and revokes everything at position >= the
// cap, INSIDE the minting transaction. An orphan is brand new, so it holds the
// freshest last_seen_at, ranks first, survives, and pushes a genuine session
// past the cap — where it is revoked as cap_evicted. A client retrying against
// an app-scoped account therefore signed the user out of their other devices,
// while every response read as a clean 400, and the logout was attributed to
// ordinary session pressure.
//
// That eviction is what makes "revoke the orphan afterwards" insufficient: the
// eviction has already committed and no later revocation undoes it. So these
// tests assert on the absence of a mint, not on a tidy-up after one.

type orphanFixture struct {
	h        *AuthHandler
	svc      *auth.AuthService
	jwtSvc   *auth.JWTService
	app      *auth.AppResult
	pool     *pgxpool.Pool
	tenantID int64
	ctx      context.Context
}

func newOrphanFixture(t *testing.T) *orphanFixture {
	t.Helper()

	pool := testhelper.NewTestDB(t)
	rdb := testhelper.NewTestRedis(t)
	logger := testhelper.TestLogger()

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
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
	app, err := appSvc.CreateApplication(ctx, tenantID,
		fmt.Sprintf("orphan-session-%d", time.Now().UnixNano()), "web", nil)
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
		WithCookieConfig(mw.BuildCookieConfig("development", ""))

	return &orphanFixture{
		h: h, svc: svc, jwtSvc: jwtSvc, app: app,
		pool: pool, tenantID: tenantID, ctx: ctx,
	}
}

// appScopedUser registers a user through the fixture's application and returns
// the email and the user id. Registration does not mint, so nothing exists in
// user_sessions yet — which is the precondition every test here depends on.
func (f *orphanFixture) appScopedUser(t *testing.T) (string, int64) {
	t.Helper()

	email := fmt.Sprintf("orphan-app-%d@test.example.com", time.Now().UnixNano())
	if _, err := f.svc.Register(f.ctx, auth.RegisterInput{
		ClientID:     f.app.ClientID,
		ClientSecret: f.app.ClientSecret,
		Email:        email,
		Password:     "Password123!",
		FirstName:    "Orphan",
		LastName:     "App",
	}); err != nil {
		t.Fatalf("Register(app credentials) error = %v", err)
	}

	var userID int64
	if err := f.pool.QueryRow(f.ctx,
		`SELECT id FROM users WHERE email = $1 AND tenant_id = $2`, email, f.tenantID,
	).Scan(&userID); err != nil {
		t.Fatalf("fetch app-scoped user id: %v", err)
	}
	return email, userID
}

func (f *orphanFixture) tenantUser(t *testing.T) (string, int64) {
	t.Helper()

	email := fmt.Sprintf("orphan-portal-%d@test.example.com", time.Now().UnixNano())
	if _, err := f.svc.Register(f.ctx, auth.RegisterInput{
		TenantSlug: "emc",
		Email:      email,
		Password:   "Password123!",
		FirstName:  "Orphan",
		LastName:   "Portal",
	}); err != nil {
		t.Fatalf("Register(tenant slug) error = %v", err)
	}

	var userID int64
	if err := f.pool.QueryRow(f.ctx,
		`SELECT id FROM users WHERE email = $1 AND tenant_id = $2`, email, f.tenantID,
	).Scan(&userID); err != nil {
		t.Fatalf("fetch tenant user id: %v", err)
	}
	return email, userID
}

func (f *orphanFixture) liveSessions(t *testing.T, userID int64) int {
	t.Helper()
	var n int
	if err := f.pool.QueryRow(f.ctx,
		`SELECT count(*) FROM user_sessions WHERE user_id = $1 AND revoked_at IS NULL`, userID,
	).Scan(&n); err != nil {
		t.Fatalf("count live sessions: %v", err)
	}
	return n
}

func (f *orphanFixture) allSessionRows(t *testing.T, userID int64) int {
	t.Helper()
	var n int
	if err := f.pool.QueryRow(f.ctx,
		`SELECT count(*) FROM user_sessions WHERE user_id = $1`, userID,
	).Scan(&n); err != nil {
		t.Fatalf("count session rows: %v", err)
	}
	return n
}

func (f *orphanFixture) refreshTokenRows(t *testing.T, userID int64) int {
	t.Helper()
	var n int
	if err := f.pool.QueryRow(f.ctx,
		`SELECT count(*) FROM refresh_tokens WHERE user_id = $1`, userID,
	).Scan(&n); err != nil {
		t.Fatalf("count refresh tokens: %v", err)
	}
	return n
}

// callSessionLogin invokes POST /api/v1/auth/session. clientID, when non-empty,
// is sent as X-Client-ID — the header that scopes the login to an application.
func callSessionLogin(t *testing.T, h *AuthHandler, email, password, clientID string) *httptest.ResponseRecorder {
	t.Helper()

	e := echo.New()
	body := fmt.Sprintf(`{"email":%q,"password":%q}`, email, password)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/session", strings.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	if clientID != "" {
		req.Header.Set("X-Client-ID", clientID)
	}
	rec := httptest.NewRecorder()

	if err := h.SessionLogin(e.NewContext(req, rec)); err != nil {
		t.Fatalf("SessionLogin() returned error: %v", err)
	}
	return rec
}

// TestSessionLogin_AppScopedMintsNothing is the core assertion of item 1: the
// refusal happens before any write, so there is no session to orphan and
// nothing for the cap to evict.
//
// The account here is TENANT-LEVEL, with X-Client-ID sent — and that combination
// is not incidental, it is the only one that ever produced the orphan. Login's
// candidate query gives a generic login (ClientID without a secret) only users
// with application_id IS NULL, so a genuinely app-scoped ACCOUNT cannot
// authenticate on this path at all and got a 401 long before reaching the cookie
// check. What minted the orphan was legacy tagging mode: a tenant-level user
// authenticates normally, then Login stamps the validated client_id into the
// claims, and the token that comes back is app-scoped even though the account is
// not. See service.go's "Legacy tagging mode" branch, which runs AFTER the MFA
// gate and immediately before issueTokenPair.
func TestSessionLogin_AppScopedMintsNothing(t *testing.T) {
	f := newOrphanFixture(t)
	email, userID := f.tenantUser(t)

	rec := callSessionLogin(t, f.h, email, "Password123!", f.app.ClientID)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (body %s)", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "cookie_session_not_available_for_applications") {
		t.Errorf("body = %s, want the cookie_session_not_available_for_applications code", rec.Body.String())
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Errorf("response set %d cookies, want 0", len(rec.Result().Cookies()))
	}

	// The point of the fix. Not "no LIVE session" but no session row at all: a
	// revoked-after-the-fact row would mean tokens were minted, which is what
	// made the cap evict a real session.
	if n := f.allSessionRows(t, userID); n != 0 {
		t.Errorf("user_sessions rows = %d, want 0 — tokens were minted before the refusal", n)
	}
	if n := f.refreshTokenRows(t, userID); n != 0 {
		t.Errorf("refresh_tokens rows = %d, want 0 — tokens were minted before the refusal", n)
	}
}

// TestSessionLogin_AppScopedDoesNotEvictExistingSessions is the checkbox the
// ticket's own proposed fix could not have satisfied.
//
// The tenant's cap is lowered to 2 and filled, so the very next mint would evict
// something. If the endpoint mints before refusing, one of the two live sessions
// comes back cap_evicted — and revoking the orphan afterwards would not restore
// it.
func TestSessionLogin_AppScopedDoesNotEvictExistingSessions(t *testing.T) {
	f := newOrphanFixture(t)

	// UPDATE-then-INSERT rather than ON CONFLICT: the scopes are enforced by
	// PARTIAL unique indexes (migration 00068), and an inference clause has to
	// restate the whole index predicate to match one.
	tag, err := f.pool.Exec(f.ctx, `
		UPDATE session_policies SET max_concurrent_sessions = 2, updated_at = NOW()
		WHERE tenant_id = $1 AND application_id IS NULL
	`, f.tenantID)
	if err != nil {
		t.Fatalf("update tenant session cap: %v", err)
	}
	if tag.RowsAffected() == 0 {
		if _, err := f.pool.Exec(f.ctx, `
			INSERT INTO session_policies (tenant_id, application_id, max_concurrent_sessions)
			VALUES ($1, NULL, 2)
		`, f.tenantID); err != nil {
			t.Fatalf("insert tenant session cap: %v", err)
		}
	}

	// A tenant-level account holding sessions at the cap. It is a DIFFERENT
	// account from the app-scoped one below, which is the realistic shape: the
	// cap is per user, and the eviction the ticket describes hits the sessions of
	// the account being logged in to.
	portalEmail, portalUserID := f.tenantUser(t)
	for i := 0; i < 2; i++ {
		if _, err := f.svc.Login(f.ctx, auth.LoginInput{Email: portalEmail, Password: "Password123!"}); err != nil {
			t.Fatalf("seed login %d: %v", i, err)
		}
	}
	if n := f.liveSessions(t, portalUserID); n != 2 {
		t.Fatalf("seeded live sessions = %d, want 2 (cap not applied as expected)", n)
	}

	// The same account, now reached with an X-Client-ID header — which is exactly
	// the misconfigured client the ticket describes, retrying against an endpoint
	// that can never succeed.
	rec := callSessionLogin(t, f.h, portalEmail, "Password123!", f.app.ClientID)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (body %s)", rec.Code, http.StatusBadRequest, rec.Body.String())
	}

	if n := f.liveSessions(t, portalUserID); n != 2 {
		t.Errorf("live sessions after the refused attempt = %d, want 2 — a genuine session was evicted", n)
	}

	var evicted int
	if err := f.pool.QueryRow(f.ctx, `
		SELECT count(*) FROM user_sessions
		WHERE user_id = $1 AND revoked_reason = $2
	`, portalUserID, auth.RevokeReasonCapEvicted).Scan(&evicted); err != nil {
		t.Fatalf("count cap_evicted: %v", err)
	}
	if evicted != 0 {
		t.Errorf("sessions revoked as cap_evicted = %d, want 0 — the refused login displaced a real session", evicted)
	}
}

// TestSessionLogin_AppScopedRefusedBeforeCredentialsAreChecked pins the
// behaviour change the pre-check introduces, so it is a decision on the record
// rather than an accident: a wrong password with the header present yields the
// 400, not a 401.
//
// This is the better order — it reports the misconfiguration instead of a
// symptom the caller cannot act on — and it leaks nothing, because the refusal
// depends only on a header the caller sent and never on whether the account
// exists.
func TestSessionLogin_AppScopedRefusedBeforeCredentialsAreChecked(t *testing.T) {
	f := newOrphanFixture(t)
	email, _ := f.appScopedUser(t)

	for _, tc := range []struct{ name, email, password string }{
		{"wrong password", email, "WrongPassword123!"},
		{"unknown account", "definitely-not-registered@test.example.com", "Password123!"},
		// An app-scoped ACCOUNT. Before the pre-check this returned 401 rather
		// than the cookie refusal — a generic login cannot see users with an
		// application_id at all — so the caller was told their credentials were
		// wrong when the real problem was the endpoint. Now all three agree.
		{"app-scoped account", email, "Password123!"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := callSessionLogin(t, f.h, tc.email, tc.password, f.app.ClientID)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, http.StatusBadRequest, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "cookie_session_not_available_for_applications") {
				t.Errorf("body = %s, want the cookie-session refusal", rec.Body.String())
			}
		})
	}
}

// TestSessionLogin_FirstPartyStillGetsCookies guards the other direction. A
// pre-check keyed on a header is only correct if the header is absent for every
// caller that must keep working.
func TestSessionLogin_FirstPartyStillGetsCookies(t *testing.T) {
	f := newOrphanFixture(t)
	email, userID := f.tenantUser(t)

	rec := callSessionLogin(t, f.h, email, "Password123!", "")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (body %s)", rec.Code, http.StatusOK, rec.Body.String())
	}
	var access, refresh bool
	for _, ck := range rec.Result().Cookies() {
		switch ck.Name {
		case mw.AccessTokenCookie:
			access = true
		case mw.RefreshTokenCookie:
			refresh = true
		}
	}
	if !access || !refresh {
		t.Errorf("cookies: access=%v refresh=%v, want both", access, refresh)
	}
	if n := f.liveSessions(t, userID); n != 1 {
		t.Errorf("live sessions = %d, want 1", n)
	}
}

// TestSessionRefresh_AppScopedRevokesRotatedSession covers the third orphan,
// which is the one that genuinely cannot be pre-checked: the app_id is only
// knowable from the token RefreshWithLock has just signed.
//
// So here the fix IS revoke-after-the-fact, and the assertion is that the
// rotated session ends with the distinct reason rather than staying live behind a
// response that told the caller the session was over. No cap concern on this
// path — a rotation reuses the session row instead of inserting one.
func TestSessionRefresh_AppScopedRevokesRotatedSession(t *testing.T) {
	f := newOrphanFixture(t)
	email, userID := f.appScopedUser(t)

	login, err := f.svc.Login(f.ctx, auth.LoginInput{
		ClientID:     f.app.ClientID,
		ClientSecret: f.app.ClientSecret,
		Email:        email,
		Password:     "Password123!",
	})
	if err != nil {
		t.Fatalf("app-scoped Login: %v", err)
	}
	if login.Token == nil {
		t.Fatalf("app-scoped Login returned no tokens")
	}
	if n := f.liveSessions(t, userID); n != 1 {
		t.Fatalf("live sessions after app login = %d, want 1", n)
	}

	// The app-scoped refresh token arriving in the cookie is the state a build
	// predating the cookie/header split leaves behind.
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/session/refresh", nil)
	req.AddCookie(&http.Cookie{Name: mw.RefreshTokenCookie, Value: login.Token.RefreshToken})
	rec := httptest.NewRecorder()
	if err := f.h.SessionRefresh(e.NewContext(req, rec)); err != nil {
		t.Fatalf("SessionRefresh() returned error: %v", err)
	}

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (body %s)", rec.Code, http.StatusBadRequest, rec.Body.String())
	}

	if n := f.liveSessions(t, userID); n != 0 {
		t.Errorf("live sessions after the refused refresh = %d, want 0 — the rotated session was left live with a token nobody holds", n)
	}

	var reason *string
	if err := f.pool.QueryRow(f.ctx, `
		SELECT revoked_reason FROM user_sessions WHERE user_id = $1 ORDER BY id DESC LIMIT 1
	`, userID).Scan(&reason); err != nil {
		t.Fatalf("read revoked_reason: %v", err)
	}
	if reason == nil || *reason != auth.RevokeReasonSessionRejected {
		got := "<null>"
		if reason != nil {
			got = *reason
		}
		// The reason is the whole point: cap_evicted or logout here would put the
		// next person to debug this back where issue #116 started.
		t.Errorf("revoked_reason = %s, want %s", got, auth.RevokeReasonSessionRejected)
	}
}
