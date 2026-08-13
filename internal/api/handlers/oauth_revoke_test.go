package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
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
// Issue #6 · POST /oauth/revoke — client authentication (RFC 7009 §2.1).
//
// These are the regression tests for the first blocker on PR #107. The handler
// used to read:
//
//	if clientID != "" {
//	    ... authenticate ...
//	}
//	h.authSvc.Logout(ctx, token)
//
// so omitting client_id skipped authentication entirely and anyone who had
// intercepted a refresh token could invalidate it from the public internet with
// no credential at all. Revocation is destructive, so the bar to reach it must be
// the same bar as the one to mint a token.
//
// Every assertion below checks the DATABASE, not just the status code. The status
// is deliberately uninformative — RFC 7009 §2.2 requires 200 for an unknown
// token so the endpoint cannot become an oracle — which means "did it return 200"
// says nothing about whether the token survived. Only the row does.
// ---------------------------------------------------------------------------

type revokeFixture struct {
	handler *OAuthTokenHandler
	pool    *pgxpool.Pool
	ctx     context.Context

	tenantID     int64
	userID       int64
	clientID     string
	clientSecret string

	// otherTenantID / otherClient are a second tenant with its own client, used
	// for the cross-tenant case.
	otherTenantID     int64
	otherClientID     string
	otherClientSecret string
}

func newRevokeFixture(t *testing.T) *revokeFixture {
	t.Helper()

	pool := testhelper.NewTestDB(t)
	testhelper.CleanupTables(t, pool)

	ctx := context.Background()
	logger := testhelper.TestLogger()
	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}

	f := &revokeFixture{pool: pool, ctx: ctx}
	if err := pool.QueryRow(ctx,
		`SELECT id FROM tenants WHERE slug = 'emc' AND deleted_at IS NULL`).Scan(&f.tenantID); err != nil {
		t.Fatalf("fetch seed tenant: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`SELECT id FROM users WHERE email = 'admin@emc.local' AND deleted_at IS NULL`).Scan(&f.userID); err != nil {
		t.Fatalf("fetch seed user: %v", err)
	}

	// A second tenant, so "another tenant's client" is a real row rather than a
	// hypothetical.
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenants (name, slug, jwt_secret, is_active)
		VALUES ($1, $2, 'test-secret', true) RETURNING id
	`, "Other Co", "other-"+uniqueSuffix()).Scan(&f.otherTenantID); err != nil {
		t.Fatalf("create second tenant: %v", err)
	}

	appSvc := auth.NewApplicationService(pool, logger)
	app, err := appSvc.CreateApplicationWithOptions(ctx, f.tenantID,
		"revoke-fixture-"+uniqueSuffix(), "web", nil,
		auth.AppUpdate{RedirectURIs: []string{"https://app.test/cb"}})
	if err != nil {
		t.Fatalf("CreateApplicationWithOptions: %v", err)
	}
	f.clientID, f.clientSecret = app.ClientID, app.ClientSecret

	other, err := appSvc.CreateApplicationWithOptions(ctx, f.otherTenantID,
		"revoke-other-"+uniqueSuffix(), "web", nil,
		auth.AppUpdate{RedirectURIs: []string{"https://other.test/cb"}})
	if err != nil {
		t.Fatalf("CreateApplicationWithOptions (other tenant): %v", err)
	}
	f.otherClientID, f.otherClientSecret = other.ClientID, other.ClientSecret

	// jwtSvc is not reached by Revoke — the endpoint verifies a stored hash and
	// signs nothing — so it is left nil deliberately rather than stood up.
	authSvc := auth.NewAuthService(pool, nil, logger)
	f.handler = NewOAuthTokenHandler(
		auth.NewAuthorizationServer(pool, logger), authSvc, nil, appSvc, nil, logger)
	return f
}

func uniqueSuffix() string { return strconv.FormatInt(time.Now().UnixNano(), 10) }

// issueRefreshToken writes a live refresh token for the given tenant and returns
// the raw value. Written directly rather than through a login so the test does
// not depend on the whole login path to assert one thing about revocation.
func (f *revokeFixture) issueRefreshToken(t *testing.T, tenantID int64) string {
	t.Helper()
	raw, err := auth.GenerateRefreshToken()
	if err != nil {
		t.Fatalf("GenerateRefreshToken: %v", err)
	}
	userID := f.userID
	if tenantID != f.tenantID {
		// A refresh token references a user in its own tenant.
		if err := f.pool.QueryRow(f.ctx, `
			INSERT INTO users (tenant_id, email, first_name, last_name, is_active, email_verified)
			VALUES ($1, $2, 'Other', 'User', true, true) RETURNING id
		`, tenantID, "other-"+uniqueSuffix()+"@test.local").Scan(&userID); err != nil {
			t.Fatalf("create user in second tenant: %v", err)
		}
	}
	if _, err := f.pool.Exec(f.ctx, `
		INSERT INTO refresh_tokens (user_id, tenant_id, token_hash, expires_at, session_family_id)
		VALUES ($1, $2, $3, NOW() + INTERVAL '1 day', 1)
	`, userID, tenantID, auth.HashToken(raw)); err != nil {
		t.Fatalf("insert refresh token: %v", err)
	}
	return raw
}

// isRevoked reports whether the token's row has been revoked. A missing row is
// reported as revoked=false so a test cannot pass by accidentally deleting it.
func (f *revokeFixture) isRevoked(t *testing.T, raw string) bool {
	t.Helper()
	var revoked *time.Time
	err := f.pool.QueryRow(f.ctx,
		`SELECT revoked_at FROM refresh_tokens WHERE token_hash = $1`,
		auth.HashToken(raw)).Scan(&revoked)
	if err != nil {
		t.Fatalf("read refresh token row: %v", err)
	}
	return revoked != nil
}

// postRevoke calls the handler with a form body.
func (f *revokeFixture) postRevoke(t *testing.T, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/oauth/revoke", strings.NewReader(form.Encode()))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	rec := httptest.NewRecorder()
	c := echo.New().NewContext(req, rec)
	if err := f.handler.Revoke(c); err != nil {
		t.Fatalf("Revoke returned an error: %v", err)
	}
	return rec
}

func TestRevoke_RequiresClientAuthentication(t *testing.T) {
	// THE blocker. No client_id at all: the request must be refused, and — the
	// part that actually matters — the token must survive.
	f := newRevokeFixture(t)
	token := f.issueRefreshToken(t, f.tenantID)

	rec := f.postRevoke(t, url.Values{"token": {token}})

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 — an unauthenticated revocation must be refused", rec.Code)
	}
	if f.isRevoked(t, token) {
		t.Fatal("an unauthenticated caller revoked a refresh token — RFC 7009 §2.1 requires " +
			"client authentication at the revocation endpoint")
	}
}

func TestRevoke_RejectsWrongClientSecret(t *testing.T) {
	f := newRevokeFixture(t)
	token := f.issueRefreshToken(t, f.tenantID)

	rec := f.postRevoke(t, url.Values{
		"token":         {token},
		"client_id":     {f.clientID},
		"client_secret": {"not-the-secret"},
	})

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	if f.isRevoked(t, token) {
		t.Fatal("a wrong client_secret still revoked the token")
	}
}

func TestRevoke_RejectsUnknownClient(t *testing.T) {
	f := newRevokeFixture(t)
	token := f.issueRefreshToken(t, f.tenantID)

	rec := f.postRevoke(t, url.Values{
		"token":     {token},
		"client_id": {"no-such-client"},
	})

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	if f.isRevoked(t, token) {
		t.Fatal("an unknown client_id still revoked the token")
	}
}

func TestRevoke_AuthenticatedClientRevokes(t *testing.T) {
	// The happy path, so the tightened check cannot pass by refusing everything.
	f := newRevokeFixture(t)
	token := f.issueRefreshToken(t, f.tenantID)

	rec := f.postRevoke(t, url.Values{
		"token":         {token},
		"client_id":     {f.clientID},
		"client_secret": {f.clientSecret},
	})

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if !f.isRevoked(t, token) {
		t.Fatal("an authenticated client's revocation did not take effect")
	}
}

func TestRevoke_AuthenticatedClientCannotRevokeAnotherTenantsToken(t *testing.T) {
	// Client authentication alone is not authority over any token that exists.
	// The UPDATE is scoped by tenant_id, so a client in tenant B holding a token
	// string from tenant A cannot act on it.
	//
	// The response is still 200: telling the caller "that token exists but is not
	// yours" would restore exactly the oracle §2.2 forbids.
	f := newRevokeFixture(t)
	token := f.issueRefreshToken(t, f.otherTenantID)

	rec := f.postRevoke(t, url.Values{
		"token":         {token},
		"client_id":     {f.clientID},
		"client_secret": {f.clientSecret},
	})

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (no oracle, even on refusal)", rec.Code)
	}
	if f.isRevoked(t, token) {
		t.Fatal("a client in one tenant revoked a refresh token belonging to another — " +
			"the tenant isolation boundary was crossed")
	}
}

func TestRevoke_UnknownTokenIsNotAnOracle(t *testing.T) {
	// RFC 7009 §2.2: an unknown token gets the same 200 a real one does.
	f := newRevokeFixture(t)

	rec := f.postRevoke(t, url.Values{
		"token":         {"a-string-that-was-never-a-token"},
		"client_id":     {f.clientID},
		"client_secret": {f.clientSecret},
	})

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 for an unknown token", rec.Code)
	}
}

func TestRevoke_ClientAuthIsCheckedBeforeTheTokenIsRead(t *testing.T) {
	// Ordering, asserted directly: with no client_id and no token, the answer must
	// still be 401 rather than the 200 an empty token parameter would otherwise
	// produce. If authentication were checked after the token, a caller could
	// probe the endpoint's behaviour without credentials.
	f := newRevokeFixture(t)

	rec := f.postRevoke(t, url.Values{})

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 — client authentication must be checked first", rec.Code)
	}
}
