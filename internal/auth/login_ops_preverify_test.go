package auth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/rs/zerolog"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/metrics"
)

// No-DB regression tests for the login_* outcome rule (#226): a request the
// method refused before it could compare any presented credential is not a
// login attempt and must move neither counter. These paths need no database —
// each returns before the first query — so they run everywhere.
//
// Counter assertions are DELTAS, matching issue226_metrics_test.go: other
// tests share the global registry, so absolute values mean nothing.

func loginOpCounts(t *testing.T, operation string) (success, failure float64) {
	t.Helper()
	return testutil.ToFloat64(metrics.AuthOperations.WithLabelValues(operation, "success")),
		testutil.ToFloat64(metrics.AuthOperations.WithLabelValues(operation, "failure"))
}

func assertNoLoginOpDelta(t *testing.T, operation string, beforeS, beforeF float64) {
	t.Helper()
	s, f := loginOpCounts(t, operation)
	if d := s - beforeS; d != 0 {
		t.Errorf("%s/success delta = %v, want 0", operation, d)
	}
	if d := f - beforeF; d != 0 {
		t.Errorf("%s/failure delta = %v, want 0", operation, d)
	}
}

// An app-authenticated login on a service with no application service is
// refused by authenticateApp before any user credential is touched — client
// misconfiguration, not an attempt.
func TestLoginOps_AppServiceMissingIsNotAnAttempt(t *testing.T) {
	svc := auth.NewAuthService(nil, nil, zerolog.Nop())

	sBefore, fBefore := loginOpCounts(t, "login_password")
	_, err := svc.Login(context.Background(), auth.LoginInput{
		ClientID: "missing-app", ClientSecret: "secret",
		Email: "user@example.com", Password: "any",
	})
	if err == nil {
		t.Fatal("Login with no application service returned nil error")
	}
	assertNoLoginOpDelta(t, "login_password", sBefore, fBefore)
}

// A magic-link verify on a service with no Redis refuses before the presented
// token could be checked.
func TestLoginOps_MagicLinkWithoutRedisIsNotAnAttempt(t *testing.T) {
	svc := auth.NewAuthService(nil, nil, zerolog.Nop())

	sBefore, fBefore := loginOpCounts(t, "login_magic_link")
	_, err := svc.VerifyMagicLink(context.Background(), "cid", "csecret", "any-token")
	if err == nil {
		t.Fatal("VerifyMagicLink with no Redis returned nil error")
	}
	assertNoLoginOpDelta(t, "login_magic_link", sBefore, fBefore)
}

// A passwordless verify on a service with the flow unwired refuses before the
// presented code could be checked.
func TestLoginOps_PasswordlessUnavailableIsNotAnAttempt(t *testing.T) {
	svc := auth.NewAuthService(nil, nil, zerolog.Nop())

	sBefore, fBefore := loginOpCounts(t, "login_passwordless")
	_, _, err := svc.PasswordlessVerify(context.Background(), auth.PasswordlessVerifyInput{
		ClientID: "cid", ClientSecret: "csecret",
		ChallengeID: strings.Repeat("0", 64), Code: "123456",
	})
	if err == nil {
		t.Fatal("PasswordlessVerify with the flow unwired returned nil error")
	}
	assertNoLoginOpDelta(t, "login_passwordless", sBefore, fBefore)
}

// A passkey login on a service with no relying party refuses before any
// assertion is compared. Already skipped on the old implementation — kept as
// the regression guard.
func TestLoginOps_PasskeyNotConfiguredIsNotAnAttempt(t *testing.T) {
	svc := auth.NewAuthService(nil, nil, zerolog.Nop())

	sBefore, fBefore := loginOpCounts(t, "login_passkey")
	req := httptest.NewRequest(http.MethodPost, "/login/complete", strings.NewReader("x"))
	_, _, err := svc.LoginWebAuthn(context.Background(), "any-token", req)
	if err == nil {
		t.Fatal("LoginWebAuthn with no relying party returned nil error")
	}
	assertNoLoginOpDelta(t, "login_passkey", sBefore, fBefore)
}
