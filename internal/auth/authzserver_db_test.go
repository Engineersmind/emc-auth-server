package auth_test

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/store"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// authzFixture is a real database with one tenant, one registered client and
// one user, ready to issue and redeem authorization codes.
type authzFixture struct {
	svc      *auth.AuthorizationServer
	appSvc   *auth.ApplicationService
	ctx      context.Context
	tenantID int64
	userID   int64
	clientID string
	verifier string
	chal     string
}

func newAuthzFixture(t *testing.T) *authzFixture {
	t.Helper()
	pool := testhelper.NewTestDB(t)
	testhelper.CleanupTables(t, pool)
	logger := testhelper.TestLogger()
	ctx := context.Background()

	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}
	var tenantID int64
	if err := pool.QueryRow(ctx,
		`SELECT id FROM tenants WHERE slug = 'emc' AND deleted_at IS NULL`).Scan(&tenantID); err != nil {
		t.Fatalf("fetch seed tenant: %v", err)
	}

	appSvc := auth.NewApplicationService(pool, logger)
	app, err := appSvc.CreateApplicationWithOptions(ctx, tenantID,
		"authz-fixture-"+strconv.FormatInt(time.Now().UnixNano(), 10), "web",
		[]string{"openid", "profile", "email"},
		auth.AppUpdate{RedirectURIs: []string{"https://app.test/cb"}})
	if err != nil {
		t.Fatalf("CreateApplicationWithOptions: %v", err)
	}

	var userID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO users (tenant_id, email, first_name, last_name, is_active, email_verified)
		VALUES ($1, $2, 'Authz', 'User', true, true)
		RETURNING id
	`, tenantID, "authz-"+strconv.FormatInt(time.Now().UnixNano(), 10)+"@test.local").Scan(&userID); err != nil {
		t.Fatalf("create user: %v", err)
	}

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	return &authzFixture{
		svc:      auth.NewAuthorizationServer(pool, logger),
		appSvc:   appSvc,
		ctx:      ctx,
		tenantID: tenantID,
		userID:   userID,
		clientID: app.ClientID,
		verifier: verifier,
		chal:     auth.DeriveS256Challenge(verifier),
	}
}

func (f *authzFixture) issue(t *testing.T) string {
	t.Helper()
	code, err := f.svc.IssueAuthorizationCode(f.ctx, auth.IssueAuthorizationCodeParams{
		TenantID:      f.tenantID,
		ClientID:      f.clientID,
		UserID:        f.userID,
		RedirectURI:   "https://app.test/cb",
		Scopes:        []string{"openid", "email"},
		CodeChallenge: f.chal,
		Nonce:         "n-test",
	})
	if err != nil {
		t.Fatalf("IssueAuthorizationCode: %v", err)
	}
	return code
}

func TestAuthorizationCode_RoundTrip(t *testing.T) {
	f := newAuthzFixture(t)
	code := f.issue(t)

	got, err := f.svc.RedeemAuthorizationCode(f.ctx, f.clientID, code, "https://app.test/cb", f.verifier)
	if err != nil {
		t.Fatalf("RedeemAuthorizationCode: %v", err)
	}
	if got.UserID != f.userID || got.TenantID != f.tenantID {
		t.Errorf("redeemed = user %d tenant %d, want %d/%d", got.UserID, got.TenantID, f.userID, f.tenantID)
	}
	if got.Nonce != "n-test" {
		t.Errorf("Nonce = %q, want the value bound at issue time", got.Nonce)
	}
	if len(got.Scopes) != 2 {
		t.Errorf("Scopes = %v, want the 2 bound at issue time", got.Scopes)
	}
	if got.AuthTime.IsZero() {
		t.Error("AuthTime is zero — the ID token's auth_time claim would be missing")
	}
}

func TestAuthorizationCode_NotStoredInPlaintext(t *testing.T) {
	// CLAUDE.md non-negotiable 1: no raw token is ever persisted. A database
	// dump must not yield anything redeemable.
	f := newAuthzFixture(t)
	code := f.issue(t)

	pool := testhelper.NewTestDB(t)
	var exists bool
	if err := pool.QueryRow(f.ctx,
		`SELECT EXISTS (SELECT 1 FROM oauth_authorization_codes WHERE code_hash = $1)`,
		code).Scan(&exists); err != nil {
		t.Fatalf("query: %v", err)
	}
	if exists {
		t.Fatal("the raw authorization code is stored in code_hash — it must be SHA-256 hashed")
	}
	if err := pool.QueryRow(f.ctx,
		`SELECT EXISTS (SELECT 1 FROM oauth_authorization_codes WHERE code_hash = $1)`,
		auth.HashToken(code)).Scan(&exists); err != nil {
		t.Fatalf("query: %v", err)
	}
	if !exists {
		t.Error("no row found for the hashed code")
	}
}

func TestAuthorizationCode_SingleUse(t *testing.T) {
	f := newAuthzFixture(t)
	code := f.issue(t)

	if _, err := f.svc.RedeemAuthorizationCode(f.ctx, f.clientID, code, "https://app.test/cb", f.verifier); err != nil {
		t.Fatalf("first redemption failed: %v", err)
	}
	_, err := f.svc.RedeemAuthorizationCode(f.ctx, f.clientID, code, "https://app.test/cb", f.verifier)
	if !errors.Is(err, auth.ErrAuthorizationCodeReplayed) {
		t.Fatalf("second redemption error = %v, want ErrAuthorizationCodeReplayed", err)
	}
}

func TestAuthorizationCode_WrongVerifierBurnsTheCode(t *testing.T) {
	// PKCE is verified AFTER consumption on purpose. A code presented with the
	// wrong verifier has been handled by someone who should not have it;
	// leaving it live would allow the verifier to be brute-forced against a
	// code that stays valid for its full lifetime.
	f := newAuthzFixture(t)
	code := f.issue(t)

	wrong := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if _, err := f.svc.RedeemAuthorizationCode(f.ctx, f.clientID, code, "", wrong); !errors.Is(err, auth.ErrInvalidCodeVerifier) {
		t.Fatalf("wrong verifier error = %v, want ErrInvalidCodeVerifier", err)
	}
	// Now the CORRECT verifier must also fail — the code is gone.
	_, err := f.svc.RedeemAuthorizationCode(f.ctx, f.clientID, code, "", f.verifier)
	if err == nil {
		t.Fatal("a code presented with a wrong verifier stayed redeemable — it must be burned")
	}
}

func TestAuthorizationCode_BoundToClient(t *testing.T) {
	f := newAuthzFixture(t)
	code := f.issue(t)

	other, err := f.appSvc.CreateApplicationWithOptions(f.ctx, f.tenantID,
		"other-client-"+strconv.FormatInt(time.Now().UnixNano(), 10), "web", nil,
		auth.AppUpdate{RedirectURIs: []string{"https://other.test/cb"}})
	if err != nil {
		t.Fatalf("create second client: %v", err)
	}

	if _, err := f.svc.RedeemAuthorizationCode(f.ctx, other.ClientID, code, "", f.verifier); err == nil {
		t.Fatal("client B redeemed client A's authorization code")
	}
	// Still redeemable by its real owner — the rejection above must not have
	// consumed it.
	if _, err := f.svc.RedeemAuthorizationCode(f.ctx, f.clientID, code, "", f.verifier); err != nil {
		t.Errorf("owner could not redeem after a foreign client's attempt: %v", err)
	}
}

func TestAuthorizationCode_BoundToRedirectURI(t *testing.T) {
	f := newAuthzFixture(t)
	code := f.issue(t)

	_, err := f.svc.RedeemAuthorizationCode(f.ctx, f.clientID, code, "https://evil.test/cb", f.verifier)
	if !errors.Is(err, auth.ErrInvalidAuthorizationCode) {
		t.Fatalf("mismatched redirect_uri error = %v, want ErrInvalidAuthorizationCode", err)
	}
}

func TestAuthorizationCode_Expired(t *testing.T) {
	f := newAuthzFixture(t)
	code := f.issue(t)

	pool := testhelper.NewTestDB(t)
	if _, err := pool.Exec(f.ctx,
		`UPDATE oauth_authorization_codes SET expires_at = NOW() - INTERVAL '1 second' WHERE code_hash = $1`,
		auth.HashToken(code)); err != nil {
		t.Fatalf("expire code: %v", err)
	}
	if _, err := f.svc.RedeemAuthorizationCode(f.ctx, f.clientID, code, "", f.verifier); err == nil {
		t.Fatal("an expired authorization code was redeemed")
	}
}

// TestAuthorizationCode_LoginCodeCannotBeRedeemedHere is the trap described in
// migration 00067, checked from this side.
//
// oauth_authorization_codes holds two different credentials. A login_code has
// no code_challenge and is redeemable with the public client_id alone. If the
// token endpoint could consume one, an attacker holding a login code would get
// a token pair without ever presenting a verifier.
func TestAuthorizationCode_LoginCodeCannotBeRedeemedHere(t *testing.T) {
	f := newAuthzFixture(t)
	pool := testhelper.NewTestDB(t)

	raw, err := auth.GenerateRefreshToken()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	// A login_code row exactly as createLoginCode writes it.
	if _, err := pool.Exec(f.ctx, `
		INSERT INTO oauth_authorization_codes
		    (tenant_id, client_id, user_id, code_hash, redirect_uri, scopes, grant_kind, expires_at)
		VALUES ($1, $2, $3, $4, $5, '{}', $6, NOW() + INTERVAL '60 seconds')
	`, f.tenantID, f.clientID, f.userID, auth.HashToken(raw), "https://app.test/cb",
		auth.GrantKindLoginCode); err != nil {
		t.Fatalf("insert login_code: %v", err)
	}

	if _, err := f.svc.RedeemAuthorizationCode(f.ctx, f.clientID, raw, "", f.verifier); err == nil {
		t.Fatal("SECURITY: /oauth/token redeemed a login_code — the grant_kind filter is missing")
	}

	// And the login_code must survive, because its own endpoint still needs it.
	var used *time.Time
	if err := pool.QueryRow(f.ctx,
		`SELECT used_at FROM oauth_authorization_codes WHERE code_hash = $1`,
		auth.HashToken(raw)).Scan(&used); err != nil {
		t.Fatalf("read login_code: %v", err)
	}
	if used != nil {
		t.Error("the rejected login_code was consumed — a failed attempt at the wrong endpoint must not burn it")
	}
}

// TestExchangeLoginCode_CannotRedeemAuthorizationCode is the same trap from the
// other side, and it is the dangerous direction: /auth/oauth/exchange performs
// NO PKCE check at all, so if it accepted an authorization_code the verifier
// would be bypassable entirely.
func TestExchangeLoginCode_CannotRedeemAuthorizationCode(t *testing.T) {
	f := newAuthzFixture(t)
	pool := testhelper.NewTestDB(t)

	code := f.issue(t)

	// Query the way ExchangeLoginCode does — matching its exact predicate.
	var tenantID, userID int64
	err := pool.QueryRow(f.ctx, `
		UPDATE oauth_authorization_codes
		SET    used_at = NOW()
		WHERE  code_hash = $1 AND client_id = $2
		  AND  grant_kind = $3
		  AND  used_at IS NULL AND expires_at > NOW()
		RETURNING tenant_id, user_id
	`, auth.HashToken(code), f.clientID, auth.GrantKindLoginCode).Scan(&tenantID, &userID)
	if err == nil {
		t.Fatal("SECURITY: the login-code exchange consumed a PKCE-protected authorization code")
	}

	// The authorization code must still be redeemable at its own endpoint.
	if _, err := f.svc.RedeemAuthorizationCode(f.ctx, f.clientID, code, "", f.verifier); err != nil {
		t.Errorf("authorization code was damaged by the login-code query: %v", err)
	}
}

func TestLookupClient_ReportsConfidentiality(t *testing.T) {
	f := newAuthzFixture(t)

	client, err := f.svc.LookupClient(f.ctx, f.clientID)
	if err != nil {
		t.Fatalf("LookupClient: %v", err)
	}
	if !client.Confidential {
		t.Error("a client created with a secret must report Confidential = true")
	}
	if !client.RequirePKCE {
		t.Error("require_pkce must default to true")
	}
	if !client.FirstParty {
		t.Error("first_party must default to true")
	}
	if len(client.RedirectURIs) != 1 || client.RedirectURIs[0] != "https://app.test/cb" {
		t.Errorf("RedirectURIs = %v, want the registered value", client.RedirectURIs)
	}

	if _, err := f.svc.LookupClient(f.ctx, "app_does_not_exist"); !errors.Is(err, auth.ErrClientNotFound) {
		t.Errorf("unknown client_id error = %v, want ErrClientNotFound", err)
	}
}

func TestValidateScopes_AcceptsOIDCAndPermissionScopes(t *testing.T) {
	// The bug this closes: migration 00032 sets oauth_clients.scopes DEFAULT to
	// {openid,profile,email}, and validateScopes rejected every one of them —
	// the column's own default was unwritable through the API.
	f := newAuthzFixture(t)

	for _, scopes := range [][]string{
		{"openid", "profile", "email"},
		{"openid", "orders:read"},
		{"offline_access"},
	} {
		name := "scope-ok-" + strconv.FormatInt(time.Now().UnixNano(), 10)
		if _, err := f.appSvc.CreateApplication(f.ctx, f.tenantID, name, "web", scopes); err != nil {
			t.Errorf("CreateApplication(%v) = %v, want success", scopes, err)
		}
	}

	for _, scopes := range [][]string{
		{"no-colon"},
		{"prof1le"},
		{":action-only"},
	} {
		name := "scope-bad-" + strconv.FormatInt(time.Now().UnixNano(), 10)
		if _, err := f.appSvc.CreateApplication(f.ctx, f.tenantID, name, "web", scopes); !errors.Is(err, auth.ErrInvalidScope) {
			t.Errorf("CreateApplication(%v) error = %v, want ErrInvalidScope", scopes, err)
		}
	}
}

func TestCreateApplication_RejectsBadRedirectURIs(t *testing.T) {
	f := newAuthzFixture(t)

	for _, uris := range [][]string{
		{"not-a-url"},
		{"ftp://app.test/cb"},
		{"https://app.test/cb#fragment"},
		{"/relative/path"},
	} {
		name := "redir-bad-" + strconv.FormatInt(time.Now().UnixNano(), 10)
		_, err := f.appSvc.CreateApplicationWithOptions(f.ctx, f.tenantID, name, "web", nil,
			auth.AppUpdate{RedirectURIs: uris})
		if !errors.Is(err, auth.ErrInvalidClientRedirectURI) {
			t.Errorf("CreateApplicationWithOptions(%v) error = %v, want ErrInvalidClientRedirectURI", uris, err)
		}
	}
}
