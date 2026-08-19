package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/store"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// ---------------------------------------------------------------------------
// Nonce burn-on-use at the route — security audit 2026-08-07, FED-3.
//
// internal/auth/authznonce_test.go proves BurnNonce itself is atomic and
// correctly scoped. That is not the same claim as "the authorize endpoint refuses
// a replayed nonce", and the difference is exactly the one PR #7a got wrong: a
// test that calls a handler's helper directly cannot see whether the route in
// front of it reaches that helper at all. So these drive GET /oauth/authorize
// over HTTP and read the Location header.
//
// The requests come in over the SSO short-circuit — a valid session cookie, so
// Authorize mints a code without a login page. Deliberate: that is one of the two
// paths to a code, it needs no password step or template, and the burn sits at
// the single chokepoint both paths funnel through (issueCodeAndRedirect), so
// covering one covers the placement.
// ---------------------------------------------------------------------------

type nonceFixture struct {
	echo     *echo.Echo
	sessions *auth.AuthzSessionStore
	pool     *pgxpool.Pool
	ctx      context.Context

	clientID    string
	redirectURI string
	cookie      *http.Cookie
}

func newNonceFixture(t *testing.T) *nonceFixture {
	t.Helper()

	pool := testhelper.NewTestDB(t)
	rdb := testhelper.NewTestRedis(t)
	testhelper.CleanupTables(t, pool)

	ctx := context.Background()
	logger := testhelper.TestLogger()
	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}

	f := &nonceFixture{pool: pool, ctx: ctx, redirectURI: "https://app.test/cb"}

	var tenantID, userID int64
	if err := pool.QueryRow(ctx,
		`SELECT id FROM tenants WHERE slug = 'emc' AND deleted_at IS NULL`).Scan(&tenantID); err != nil {
		t.Fatalf("fetch seed tenant: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`SELECT id FROM users WHERE email = 'admin@emc.local' AND deleted_at IS NULL`).Scan(&userID); err != nil {
		t.Fatalf("fetch seed user: %v", err)
	}

	appSvc := auth.NewApplicationService(pool, logger)
	app, err := appSvc.CreateApplicationWithOptions(ctx, tenantID,
		"nonce-fixture-"+uniqueSuffix(), "web", nil,
		auth.AppUpdate{RedirectURIs: []string{f.redirectURI}})
	if err != nil {
		t.Fatalf("CreateApplicationWithOptions: %v", err)
	}
	f.clientID = app.ClientID

	f.sessions = auth.NewAuthzSessionStore(rdb)
	handle, err := f.sessions.CreateSession(ctx, &auth.AuthzSession{
		UserID:   userID,
		TenantID: tenantID,
		Email:    "admin@emc.local",
		AuthTime: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	f.cookie = &http.Cookie{Name: auth.AuthzSessionCookie, Value: handle}

	// authSvc and the audit logger are nil on purpose: the SSO short-circuit
	// authenticates nobody (the session already did) and auditEvent returns early
	// on a nil logger. Standing them up would add dependencies these assertions
	// do not touch.
	h := NewOAuthAuthorizeHandler(
		auth.NewAuthorizationServer(pool, logger), f.sessions, nil, nil, logger, false)

	f.echo = echo.New()
	f.echo.GET("/oauth/authorize", h.Authorize)
	return f
}

// authorize issues one authorize request carrying the SSO cookie and returns the
// parsed Location the handler redirected to.
func (f *nonceFixture) authorize(t *testing.T, nonce string) (*url.URL, int) {
	t.Helper()

	// A real S256 challenge. The client defaults to require_pkce = true, so a
	// request without one is rejected before the nonce is ever considered — and
	// this test would then pass while proving nothing.
	sum := sha256.Sum256([]byte("verifier-" + uniqueSuffix()))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	q := url.Values{}
	q.Set("client_id", f.clientID)
	q.Set("redirect_uri", f.redirectURI)
	q.Set("response_type", "code")
	q.Set("state", "state-"+uniqueSuffix())
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	if nonce != "" {
		q.Set("nonce", nonce)
	}

	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
	req.AddCookie(f.cookie)
	rec := httptest.NewRecorder()
	f.echo.ServeHTTP(rec, req)

	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location %q: %v", rec.Header().Get("Location"), err)
	}
	return loc, rec.Code
}

func TestAuthorize_ReplayedNonceIsRefused(t *testing.T) {
	f := newNonceFixture(t)
	nonce := "route-replay-" + uniqueSuffix()

	// First use: a code, as normal.
	loc, status := f.authorize(t, nonce)
	if status != http.StatusFound {
		t.Fatalf("first request: status = %d, want 302", status)
	}
	if loc.Query().Get("code") == "" {
		t.Fatalf("first request: no code in %s", loc)
	}

	// Second use of the same nonce: refused, and refused by redirect to the
	// registered URI rather than by an HTML page, because the client is known
	// good at this point (RFC 6749 §4.1.2.1).
	loc, status = f.authorize(t, nonce)
	if status != http.StatusFound {
		t.Fatalf("replay: status = %d, want 302", status)
	}
	if got := loc.Query().Get("code"); got != "" {
		t.Fatalf("replay: a code was issued (%q) — the nonce was not burned", got)
	}
	if got := loc.Query().Get("error"); got != "invalid_request" {
		t.Fatalf("replay: error = %q, want invalid_request", got)
	}
	if desc := loc.Query().Get("error_description"); !strings.Contains(desc, "nonce") {
		t.Fatalf("replay: error_description = %q, want it to name the nonce", desc)
	}

	// A fresh nonce still works. This is the assertion that separates "the nonce
	// was spent" from "the session or the client was broken by the rejection" —
	// without it, a handler that simply failed every request after the first
	// would pass everything above.
	loc, status = f.authorize(t, "route-replay-fresh-"+uniqueSuffix())
	if status != http.StatusFound {
		t.Fatalf("fresh nonce: status = %d, want 302", status)
	}
	if loc.Query().Get("code") == "" {
		t.Fatalf("fresh nonce: no code in %s — the burn outlived its own request", loc)
	}
}

func TestAuthorize_RequestsWithoutANonceAreNotTreatedAsReplays(t *testing.T) {
	f := newNonceFixture(t)

	// nonce is OPTIONAL in the authorization-code flow (OIDC Core §3.1.2.1), and
	// plain OAuth 2.0 clients send none at all. Repeated code issuance for such a
	// client must keep working — an implementation that hashed and stored the
	// empty string would break every non-OIDC client on its second sign-in.
	for i := 0; i < 3; i++ {
		loc, status := f.authorize(t, "")
		if status != http.StatusFound {
			t.Fatalf("request %d: status = %d, want 302", i, status)
		}
		if loc.Query().Get("code") == "" {
			t.Fatalf("request %d: no code in %s", i, loc)
		}
		if got := loc.Query().Get("error"); got != "" {
			t.Fatalf("request %d: unexpected error %q", i, got)
		}
	}
}

func TestAuthorize_ReplayedNonceEchoesStateAndKeepsTheRedirectRegistered(t *testing.T) {
	f := newNonceFixture(t)
	nonce := "route-replay-state-" + uniqueSuffix()

	if _, status := f.authorize(t, nonce); status != http.StatusFound {
		t.Fatalf("first request: status = %d, want 302", status)
	}
	loc, _ := f.authorize(t, nonce)

	// The rejection must land on the registered redirect_uri and nowhere else. An
	// error reported to an unvalidated target is the open redirect this handler's
	// phase ordering exists to prevent, and a new error branch is exactly where
	// that ordering gets broken.
	if got, want := loc.Scheme+"://"+loc.Host+loc.Path, f.redirectURI; got != want {
		t.Fatalf("replay redirected to %q, want %q", got, want)
	}
	// state is echoed so the client can match the failure to the request it
	// started; without it a client cannot clear the pending authorization.
	if loc.Query().Get("state") == "" {
		t.Fatalf("replay: state was not echoed (%s)", loc)
	}
}
