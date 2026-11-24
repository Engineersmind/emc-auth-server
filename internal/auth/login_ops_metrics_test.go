package auth_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/metrics"
)

// Issue #226 — emc_auth_operations_total{operation,outcome} wiring checks for
// the login paths that need service-level fixtures (Redis policy state, a real
// WebAuthn ceremony). The plain password paths are covered through the HTTP
// handlers in internal/api/handlers/issue226_metrics_test.go.
//
// All assertions are DELTAS: the counters are global and other tests in this
// package exercise the same functions, so reading an absolute value would make
// the outcome depend on execution order.

func loginOpCount(t *testing.T, operation, outcome string) float64 {
	t.Helper()
	return testutil.ToFloat64(metrics.AuthOperations.WithLabelValues(operation, outcome))
}

func TestLoginOps_MagicLinkFailureAndSuccess(t *testing.T) {
	f := newMFAFixture(t)
	app, appID := f.createApp(t, "magic-ops")
	email := uniqueEmail("magic-ops")
	f.registerAppUser(t, app, email, "Password123!")
	f.enableMagicLink(t, appID)

	before := loginOpCount(t, "login_magic_link", "failure")
	if _, err := f.authSvc.VerifyMagicLink(f.ctx, app.ClientID, app.ClientSecret,
		"not-a-real-magic-link-token"); !errors.Is(err, auth.ErrInvalidMagicLink) {
		t.Fatalf("VerifyMagicLink(bogus) error = %v, want ErrInvalidMagicLink", err)
	}
	if got := loginOpCount(t, "login_magic_link", "failure") - before; got != 1 {
		t.Errorf("login_magic_link/failure delta = %v, want 1", got)
	}

	if err := f.authSvc.RequestMagicLink(f.ctx, app.ClientID, app.ClientSecret, email); err != nil {
		t.Fatalf("RequestMagicLink: %v", err)
	}
	token := tokenFromLink(t, f.mail.lastLink(t).Link)

	before = loginOpCount(t, "login_magic_link", "success")
	result, err := f.authSvc.VerifyMagicLink(f.ctx, app.ClientID, app.ClientSecret, token)
	if err != nil {
		t.Fatalf("VerifyMagicLink: %v", err)
	}
	if result == nil || result.Token == nil {
		t.Fatalf("VerifyMagicLink = %+v, want tokens", result)
	}
	if got := loginOpCount(t, "login_magic_link", "success") - before; got != 1 {
		t.Errorf("login_magic_link/success delta = %v, want 1", got)
	}
}

func TestLoginOps_PasswordlessFailureAndSuccess(t *testing.T) {
	f := newPWFixture(t)
	app, appID := f.createApp(t, "pw-ops")
	f.enable(t, appID, true)
	email := uniqueEmail("pw-ops")

	chID, code := f.startAndCode(t, app, email)

	before := loginOpCount(t, "login_passwordless", "failure")
	if _, _, err := f.verify(app, chID, wrongCode(code)); err == nil {
		t.Fatal("verify with wrong code succeeded, want ErrPasswordlessInvalidCode")
	}
	if got := loginOpCount(t, "login_passwordless", "failure") - before; got != 1 {
		t.Errorf("login_passwordless/failure delta = %v, want 1", got)
	}

	chID2, code2 := f.startAndCode(t, app, email)

	before = loginOpCount(t, "login_passwordless", "success")
	res, _, err := f.verify(app, chID2, code2)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res == nil || res.Token == nil {
		t.Fatalf("verify = %+v, want tokens", res)
	}
	if got := loginOpCount(t, "login_passwordless", "success") - before; got != 1 {
		t.Errorf("login_passwordless/success delta = %v, want 1", got)
	}
}

func TestLoginOps_PasskeyFailureAndSuccess(t *testing.T) {
	f := newPasskeyFixture(t)
	f.allowPasskeys(t, false)
	dev := newVirtualAuthenticator(t)
	f.register(t, dev, "ops device")

	// A valid-protocol assertion signed by a different, unregistered key.
	forged := newVirtualAuthenticator(t)
	assertion, token, err := f.svc.LoginBegin(f.ctx, testOrigin)
	if err != nil {
		t.Fatalf("LoginBegin: %v", err)
	}
	badReq := forged.AssertionRequest(t, testRPID, testOrigin,
		assertion.Response.Challenge.String(), f.userHandle(t))

	before := loginOpCount(t, "login_passkey", "failure")
	if _, _, err := f.authSvc.LoginWebAuthn(f.ctx, token, badReq); err == nil {
		t.Fatal("LoginWebAuthn with an unregistered key succeeded")
	}
	if got := loginOpCount(t, "login_passkey", "failure") - before; got != 1 {
		t.Errorf("login_passkey/failure delta = %v, want 1", got)
	}

	assertion, token, err = f.svc.LoginBegin(f.ctx, testOrigin)
	if err != nil {
		t.Fatalf("LoginBegin: %v", err)
	}
	req := dev.AssertionRequest(t, testRPID, testOrigin,
		assertion.Response.Challenge.String(), f.userHandle(t))

	before = loginOpCount(t, "login_passkey", "success")
	result, _, err := f.authSvc.LoginWebAuthn(f.ctx, token, req)
	if err != nil {
		t.Fatalf("LoginWebAuthn: %v", err)
	}
	if result == nil || result.AccessToken == "" {
		t.Fatalf("LoginWebAuthn = %+v, want tokens", result)
	}
	if got := loginOpCount(t, "login_passkey", "success") - before; got != 1 {
		t.Errorf("login_passkey/success delta = %v, want 1", got)
	}
}

// ---------------------------------------------------------------------------
// Not-counted paths: refusals made before any presented credential could be
// compared (#226). Each asserts BOTH outcomes moved by zero.
// ---------------------------------------------------------------------------

// A passwordless verify refused because the application's policy disables
// EmailOTP never compared a code — it is not an attempt.
func TestLoginOps_PasswordlessPolicyDisabledIsNotAnAttempt(t *testing.T) {
	f := newPWFixture(t)
	app, _ := f.createApp(t, "ops-pw-off")
	// Deliberately NOT calling f.enable: the refusal happens at the policy
	// check, before a code could be compared.

	sBefore, fBefore := loginOpCounts(t, "login_passwordless")
	_, _, err := f.verify(app, strings.Repeat("0", 64), "123456")
	if !errors.Is(err, auth.ErrPasswordlessInvalidCode) {
		t.Fatalf("verify with EmailOTP disabled = %v, want invalid_or_expired_code", err)
	}
	assertNoLoginOpDelta(t, "login_passwordless", sBefore, fBefore)
}

// A verify refused by the per-address failure block never compared the code it
// carried — it is not an attempt. The wrong guesses that spent the budget ARE
// failures, so only the blocked call itself is asserted.
func TestLoginOps_PasswordlessThrottledAddressIsNotAnAttempt(t *testing.T) {
	f := newPWFixture(t)
	app, appID := f.createApp(t, "ops-pw-block")
	f.enable(t, appID, true)
	f.setPolicy(t, appID, func(r *auth.PasswordlessPolicyRow) { r.StartsPerHour = ref(10) })
	email := uniqueEmail("ops-pw-block")

	// Spend the failure budget exactly the way
	// TestPasswordless_FailureBudgetBlocksAddress does.
	var chID, code string
	for round := 0; round < 4; round++ { // 3 wrong guesses x 4 rounds crosses 10
		chID, code = f.startAndCode(t, app, email)
		for g := 0; g < 3; g++ {
			f.verify(app, chID, wrongCode(code)) //nolint:errcheck
		}
	}
	chID, code = f.startAndCode(t, app, email)

	sBefore, fBefore := loginOpCounts(t, "login_passwordless")
	if _, _, err := f.verify(app, chID, code); !errors.Is(err, auth.ErrPasswordlessInvalidCode) {
		t.Fatalf("verify while blocked = %v, want invalid_or_expired_code", err)
	}
	assertNoLoginOpDelta(t, "login_passwordless", sBefore, fBefore)
}

// A passkey login body that cannot be parsed into an assertion is refused
// before any credential is compared — not an attempt. The error must still be
// indistinguishable from a real verification failure to the caller.
func TestLoginOps_PasskeyMalformedAssertionIsNotAnAttempt(t *testing.T) {
	f := newPasskeyFixture(t)
	f.allowPasskeys(t, true)

	// A real ceremony token, then a body that is not an assertion.
	_, token, err := f.svc.LoginBegin(f.ctx, testOrigin)
	if err != nil {
		t.Fatalf("LoginBegin: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/login/complete", strings.NewReader("this is not an assertion"))
	req.Header.Set("Content-Type", "application/json")

	sBefore, fBefore := loginOpCounts(t, "login_passkey")
	_, _, err = f.authSvc.LoginWebAuthn(f.ctx, token, req)
	if !errors.Is(err, auth.ErrWebAuthnVerification) {
		t.Fatalf("LoginWebAuthn = %v, want ErrWebAuthnVerification", err)
	}
	assertNoLoginOpDelta(t, "login_passkey", sBefore, fBefore)
}

// ---------------------------------------------------------------------------
// Verified anchors: a credential that was proven counts as success whatever
// happened after (#226). Each asserts success +1 and failure +0.
// ---------------------------------------------------------------------------

func assertLoginOpSuccess(t *testing.T, operation string, beforeS, beforeF float64) {
	t.Helper()
	s, f := loginOpCounts(t, operation)
	if d := s - beforeS; d != 1 {
		t.Errorf("%s/success delta = %v, want 1", operation, d)
	}
	if d := f - beforeF; d != 0 {
		t.Errorf("%s/failure delta = %v, want 0", operation, d)
	}
}

// A correct password refused at role scoping verified first — the refusal is
// after the anchor, so it counts as success, not failure.
func TestLoginOps_PasswordVerifiedThenRoleRefusedCountsSuccess(t *testing.T) {
	f := newMFAFixture(t)
	app, _ := f.createApp(t, "ops-role-refused")
	email := uniqueEmail("ops-role")
	f.registerAppUser(t, app, email, "Password123!")

	sBefore, fBefore := loginOpCounts(t, "login_password")
	_, err := f.authSvc.Login(f.ctx, auth.LoginInput{
		ClientID: app.ClientID, ClientSecret: app.ClientSecret,
		Email: email, Password: "Password123!",
		Roles: []string{"no-such-role"},
	})
	if err == nil {
		t.Fatal("login scoped to an unheld role returned nil error")
	}
	assertLoginOpSuccess(t, "login_password", sBefore, fBefore)
}

// A correct code refused at role scoping verified first — same rule, reached
// through completePasswordlessLogin rather than Login.
func TestLoginOps_PasswordlessVerifiedThenRoleRefusedCountsSuccess(t *testing.T) {
	f := newPWFixture(t)
	app, appID := f.createApp(t, "ops-pw-role")
	f.enable(t, appID, false)
	email := uniqueEmail("ops-pw-role")
	f.registerAppUser(t, app, email, "Password123!")

	chID, code := f.startAndCode(t, app, email)
	sBefore, fBefore := loginOpCounts(t, "login_passwordless")
	_, _, err := f.authSvc.PasswordlessVerify(f.ctx, auth.PasswordlessVerifyInput{
		ClientID: app.ClientID, ClientSecret: app.ClientSecret,
		ChallengeID: chID, Code: code,
		Roles: []string{"no-such-role"},
	})
	if !errors.Is(err, auth.ErrPasswordlessInvalidCode) {
		t.Fatalf("verify with an unheld role = %v, want invalid_or_expired_code", err)
	}
	assertLoginOpSuccess(t, "login_passwordless", sBefore, fBefore)
}

// An application-scoped passkey on the cookie-session endpoint verifies, then
// is refused — the handler itself calls that "not an authentication failure".
// Same setup as TestLoginWebAuthnForCookieSession_RefusesBeforeMinting.
func TestLoginOps_PasskeyCookieSessionRefusalCountsSuccess(t *testing.T) {
	f := newPasskeyFixture(t)
	f.allowPasskeys(t, true)
	dev := newVirtualAuthenticator(t)

	_, _, handle := appScopedPasskeyUser(t, f, dev)

	assertion, token, err := f.svc.LoginBegin(f.ctx, testOrigin)
	if err != nil {
		t.Fatalf("LoginBegin: %v", err)
	}
	req := dev.AssertionRequest(t, testRPID, testOrigin, assertion.Response.Challenge.String(), handle)

	sBefore, fBefore := loginOpCounts(t, "login_passkey")
	_, _, err = f.authSvc.LoginWebAuthnForCookieSession(f.ctx, token, req)
	if !errors.Is(err, auth.ErrCookieSessionNotAvailable) {
		t.Fatalf("error = %v, want ErrCookieSessionNotAvailable", err)
	}
	assertLoginOpSuccess(t, "login_passkey", sBefore, fBefore)
}

// ---------------------------------------------------------------------------
// Post-commit revocation counting (#226): an eviction written inside a
// transaction that then rolls back must move neither counter — the rollback
// undoes the revocation, so counting inside the transaction would report
// sessions that were never actually revoked.
// ---------------------------------------------------------------------------

func TestEnforceSessionCap_DoesNotCountBeforeCommit(t *testing.T) {
	f := newMFAFixture(t)
	app, _ := f.createApp(t, "ops-cap")
	email := uniqueEmail("ops-cap")
	userID := f.registerAppUser(t, app, email, "Password123!")

	// Two live sessions, so evicting down to one below has something to evict.
	for i := 0; i < 2; i++ {
		if _, err := f.appLogin(t, app, email, "Password123!"); err != nil {
			t.Fatalf("login %d: %v", i, err)
		}
	}

	const reason = auth.RevokeReasonCapEvicted
	sBefore := testutil.ToFloat64(metrics.SessionRevocations.WithLabelValues(reason))
	tBefore := testutil.ToFloat64(metrics.TokensRevoked.WithLabelValues(reason))

	tx, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	evicted, err := auth.ExportedEnforceSessionCap(f.ctx, tx, userID, f.tenantID, 1)
	if err != nil {
		tx.Rollback(f.ctx) //nolint:errcheck
		t.Fatalf("ExportedEnforceSessionCap: %v", err)
	}
	if len(evicted) != 1 {
		tx.Rollback(f.ctx) //nolint:errcheck
		t.Fatalf("evicted = %v, want exactly 1 session", evicted)
	}
	if err := tx.Rollback(f.ctx); err != nil {
		t.Fatalf("rollback: %v", err)
	}

	if d := testutil.ToFloat64(metrics.SessionRevocations.WithLabelValues(reason)) - sBefore; d != 0 {
		t.Errorf("session_revocations{cap_evicted} delta = %v, want 0 — counted inside a transaction that rolled back", d)
	}
	if d := testutil.ToFloat64(metrics.TokensRevoked.WithLabelValues(reason)) - tBefore; d != 0 {
		t.Errorf("tokens_revoked{cap_evicted} delta = %v, want 0 — counted inside a transaction that rolled back", d)
	}
}
