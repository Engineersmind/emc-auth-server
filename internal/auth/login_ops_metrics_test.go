package auth_test

import (
	"errors"
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
