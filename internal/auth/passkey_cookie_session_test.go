package auth_test

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// Issue #116, item 1 — the passkey half of the orphaned cookie-session fix.
//
// POST /auth/passkey/session verified the assertion, minted a token pair, and
// only THEN noticed the identity was application-scoped — returning 400 and
// setting no cookies, which left a live session nobody held. Worse, the new
// session carried the freshest last_seen_at, so enforceSessionCap (which runs
// inside the minting transaction) ranked it first, kept it, and evicted one of
// the user's genuine sessions as cap_evicted. A retrying client therefore signed
// the user out of another device behind a response that read as a clean refusal.
//
// The handler-level tests for the password path live in
// internal/api/handlers/cookie_session_orphan_test.go.

// appScopedPasskeyUser creates a user belonging to an application and registers
// a passkey for them.
//
// The AppID on a WebAuthnIdentity comes from users.application_id (see the
// credential-resolution query in webauthn.go), not from the request — which is
// exactly why the handler cannot pre-check this the way SessionLogin can: the
// account is not known until the assertion verifies.
func appScopedPasskeyUser(t *testing.T, f *passkeyFixture, dev *virtualAuthenticator) (int64, int64, []byte) {
	t.Helper()

	appSvc := auth.NewApplicationService(f.pool, testhelper.TestLogger())
	app, err := appSvc.CreateApplication(f.ctx, f.tenantID,
		fmt.Sprintf("passkey-app-%d", time.Now().UnixNano()), "web", nil)
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}
	appRowID, err := strconv.ParseInt(app.ID, 10, 64)
	if err != nil {
		t.Fatalf("parse application id %q: %v", app.ID, err)
	}

	email := fmt.Sprintf("app-passkey-%d@emc.local", time.Now().UnixNano())
	var userID int64
	if err := f.pool.QueryRow(f.ctx, `
		INSERT INTO users (tenant_id, application_id, email, is_active, email_verified)
		VALUES ($1, $2, $3, true, true) RETURNING id
	`, f.tenantID, appRowID, email).Scan(&userID); err != nil {
		t.Fatalf("insert app-scoped user: %v", err)
	}

	creation, token, err := f.svc.RegisterBegin(f.ctx, userID, f.tenantID, email, "", testOrigin)
	if err != nil {
		t.Fatalf("RegisterBegin(app-scoped user): %v", err)
	}
	req := dev.AttestationRequest(t, testRPID, testOrigin, creation.Response.Challenge.String())
	if _, err := f.svc.RegisterComplete(f.ctx, userID, f.tenantID, email, token, "App device", req); err != nil {
		t.Fatalf("RegisterComplete(app-scoped user): %v", err)
	}

	var handle []byte
	if err := f.pool.QueryRow(f.ctx,
		`SELECT handle FROM webauthn_user_handles WHERE user_id = $1`, userID).Scan(&handle); err != nil {
		t.Fatalf("read app-scoped user handle: %v", err)
	}
	return userID, appRowID, handle
}

// TestLoginWebAuthnForCookieSession_RefusesBeforeMinting is item 1's passkey
// half.
//
// The ticket assumed this rejection could not precede token issuance, because
// the account is only known once the assertion verifies. True at the handler,
// false in the service: LoginComplete returns a fully resolved identity —
// AppID included — and issueTokenPair is the next statement. So the refusal goes
// between them, and nothing is ever minted.
func TestLoginWebAuthnForCookieSession_RefusesBeforeMinting(t *testing.T) {
	f := newPasskeyFixture(t)
	f.allowPasskeys(t, true)
	dev := newVirtualAuthenticator(t)

	userID, _, handle := appScopedPasskeyUser(t, f, dev)

	assertion, token, err := f.svc.LoginBegin(f.ctx, testOrigin)
	if err != nil {
		t.Fatalf("LoginBegin: %v", err)
	}
	req := dev.AssertionRequest(t, testRPID, testOrigin, assertion.Response.Challenge.String(), handle)

	result, id, err := f.authSvc.LoginWebAuthnForCookieSession(f.ctx, token, req)
	if !errors.Is(err, auth.ErrCookieSessionNotAvailable) {
		t.Fatalf("error = %v, want ErrCookieSessionNotAvailable", err)
	}
	if result != nil {
		t.Error("a token pair was returned alongside the refusal — nothing may be minted")
	}
	// The identity comes back with the error on purpose: the assertion DID
	// verify, so the account and the passkey are known and the refusal can be
	// audited against them instead of as an anonymous failure.
	if id == nil {
		t.Fatal("identity = nil, want the verified identity so the refusal can be audited")
	}
	if id.UserID != userID {
		t.Errorf("identity user = %d, want %d", id.UserID, userID)
	}
	if id.CredentialLabel != "App device" {
		t.Errorf("credential label = %q, want %q — the audit row needs to name the device", id.CredentialLabel, "App device")
	}

	var sessions int
	if err := f.pool.QueryRow(f.ctx,
		`SELECT count(*) FROM user_sessions WHERE user_id = $1`, userID).Scan(&sessions); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if sessions != 0 {
		t.Errorf("user_sessions rows = %d, want 0 — the refusal happened after minting", sessions)
	}

	var tokens int
	if err := f.pool.QueryRow(f.ctx,
		`SELECT count(*) FROM refresh_tokens WHERE user_id = $1`, userID).Scan(&tokens); err != nil {
		t.Fatalf("count refresh tokens: %v", err)
	}
	if tokens != 0 {
		t.Errorf("refresh_tokens rows = %d, want 0 — the refusal happened after minting", tokens)
	}
}

// TestLoginWebAuthnForCookieSession_AdvancesSignCount pins a side effect that
// must SURVIVE the refusal.
//
// The assertion was genuine, so the credential's counter has to move. Rolling it
// back — or refusing before verification to avoid the write — would make the
// user's next legitimate sign-in look like a replayed assertion and trip clone
// detection, which revokes the credential and every session the account has.
func TestLoginWebAuthnForCookieSession_AdvancesSignCount(t *testing.T) {
	f := newPasskeyFixture(t)
	f.allowPasskeys(t, true)
	dev := newVirtualAuthenticator(t)

	userID, _, handle := appScopedPasskeyUser(t, f, dev)

	var before int64
	var usedBefore *time.Time
	if err := f.pool.QueryRow(f.ctx,
		`SELECT sign_count, last_used_at FROM webauthn_credentials WHERE user_id = $1`,
		userID).Scan(&before, &usedBefore); err != nil {
		t.Fatalf("read credential usage before: %v", err)
	}
	if usedBefore != nil {
		t.Fatalf("last_used_at was already set after registration — the fixture cannot show the write")
	}

	// The device is made to report a non-zero counter, because the default is
	// zero and stays zero: that is what real synced passkeys send, which is why
	// counter-based clone detection is inert for most of them. Forcing it here is
	// what makes the persisted value observable at all.
	dev.signCount = 7

	assertion, token, err := f.svc.LoginBegin(f.ctx, testOrigin)
	if err != nil {
		t.Fatalf("LoginBegin: %v", err)
	}
	req := dev.AssertionRequest(t, testRPID, testOrigin, assertion.Response.Challenge.String(), handle)
	if _, _, err := f.authSvc.LoginWebAuthnForCookieSession(f.ctx, token, req); !errors.Is(err, auth.ErrCookieSessionNotAvailable) {
		t.Fatalf("error = %v, want ErrCookieSessionNotAvailable", err)
	}

	var after int64
	var usedAfter *time.Time
	if err := f.pool.QueryRow(f.ctx,
		`SELECT sign_count, last_used_at FROM webauthn_credentials WHERE user_id = $1`,
		userID).Scan(&after, &usedAfter); err != nil {
		t.Fatalf("read credential usage after: %v", err)
	}
	if after != 7 {
		t.Errorf("sign_count = %d, want 7 — the counter must advance even when the session is refused, or the next real assertion reads as a regression and trips clone detection", after)
	}
	if usedAfter == nil {
		t.Error("last_used_at is still null — the credential-usage write did not survive the refusal")
	}
}

// TestLoginWebAuthn_TenantLevelUnaffected is the other direction: the ordinary
// bearer-token endpoint keeps issuing tokens for tenant-level identities, and the
// new entry point does too. A refusal keyed on AppID is only correct if it is
// silent for everybody who must keep working.
func TestLoginWebAuthn_TenantLevelUnaffected(t *testing.T) {
	f := newPasskeyFixture(t)
	f.allowPasskeys(t, true)
	dev := newVirtualAuthenticator(t)
	f.register(t, dev, "Portal laptop")

	for _, tc := range []struct {
		name string
		call func(token string, req *http.Request) (*auth.AuthResult, *auth.WebAuthnIdentity, error)
	}{
		{"bearer endpoint", func(token string, req *http.Request) (*auth.AuthResult, *auth.WebAuthnIdentity, error) {
			return f.authSvc.LoginWebAuthn(f.ctx, token, req)
		}},
		{"cookie endpoint", func(token string, req *http.Request) (*auth.AuthResult, *auth.WebAuthnIdentity, error) {
			return f.authSvc.LoginWebAuthnForCookieSession(f.ctx, token, req)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertion, token, err := f.svc.LoginBegin(f.ctx, testOrigin)
			if err != nil {
				t.Fatalf("LoginBegin: %v", err)
			}
			req := dev.AssertionRequest(t, testRPID, testOrigin, assertion.Response.Challenge.String(), f.userHandle(t))
			result, id, err := tc.call(token, req)
			if err != nil {
				t.Fatalf("login: %v", err)
			}
			if result == nil || result.AccessToken == "" {
				t.Fatal("no access token issued for a tenant-level identity")
			}
			if id == nil || id.UserID != f.userID {
				t.Fatal("identity did not resolve to the fixture user")
			}
		})
	}
}
