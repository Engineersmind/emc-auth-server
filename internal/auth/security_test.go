package auth_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/mailer"
	"github.com/engineersmind/emc-auth-server/internal/store"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// newSecurityTestServices creates a fully-wired AuthService + ResetService backed by
// real DB and Redis. Seeds the "emc" tenant so it always exists.
func newSecurityTestServices(t *testing.T) (*auth.AuthService, *auth.ResetService, func()) {
	t.Helper()

	pool := testhelper.NewTestDB(t)
	rdb := testhelper.NewTestRedis(t)
	logger := testhelper.TestLogger()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}

	jwtSvc := auth.NewJWTService(pool, "https://auth.emc.local")

	totpEncKey := os.Getenv("TOTP_ENCRYPTION_KEY")
	totpSvc, err := auth.NewTOTPService(pool, totpEncKey, logger)
	if err != nil {
		t.Fatalf("NewTOTPService: %v", err)
	}

	svc := auth.NewAuthService(pool, jwtSvc, logger).WithTOTP(totpSvc, rdb)

	resetSvc := auth.NewResetService(
		pool,
		mailer.NewMailer(mailer.MailerConfig{Env: "test", Logger: logger}),
		"http://localhost:8080",
		logger,
	)

	cleanup := func() {
		testhelper.CleanupTables(t, pool)
	}
	return svc, resetSvc, cleanup
}

// securityUniqueEmail generates a collision-free email for security tests.
func securityUniqueEmail(prefix string) string {
	return fmt.Sprintf("%s-%d@sec.test", prefix, time.Now().UnixNano())
}

// TestReplayAttack_RefreshToken proves that a rotated (revoked) refresh token
// cannot be replayed to obtain new tokens (AUTH-03 replay protection).
func TestReplayAttack_RefreshToken(t *testing.T) {
	svc, _, cleanup := newSecurityTestServices(t)
	defer cleanup()

	ctx := context.Background()
	email := securityUniqueEmail("replay")

	// Step 1: Register a user and capture the initial refresh token.
	result, err := svc.Register(ctx, auth.RegisterInput{
		TenantSlug: "emc",
		Email:      email,
		Password:   "SecPass123!",
		FirstName:  "R",
		LastName:   "T",
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	originalRefreshToken := result.RefreshToken

	// Step 2: First Refresh — rotates old token, issues a new one.
	rotated, err := svc.Refresh(ctx, originalRefreshToken)
	if err != nil {
		t.Fatalf("first Refresh: %v", err)
	}
	if rotated == nil || rotated.RefreshToken == "" {
		t.Fatal("first Refresh returned empty result")
	}
	rotatedRefreshToken := rotated.RefreshToken

	// Step 3: Replay the OLD token — must be rejected with ErrInvalidRefreshToken.
	_, err = svc.Refresh(ctx, originalRefreshToken)
	if err == nil {
		t.Fatal("replay of rotated token expected error, got nil — token rotation not enforced")
	}
	if !errors.Is(err, auth.ErrInvalidRefreshToken) {
		t.Errorf("replay error = %v; want errors.Is(err, auth.ErrInvalidRefreshToken) = true", err)
	}
	t.Logf("old token rejected with ErrInvalidRefreshToken: %v", err)

	// Step 4: The rotated token from step 2 must still be usable.
	final, err := svc.Refresh(ctx, rotatedRefreshToken)
	if err != nil {
		t.Fatalf("second Refresh with rotated token: %v", err)
	}
	if final == nil || final.AccessToken == "" {
		t.Fatal("second Refresh returned empty access token")
	}
	// Prove the new access token is distinct — rotation must issue a fresh JWT,
	// not return the same (cached) token from the previous call (M-02).
	if final.AccessToken == rotated.AccessToken {
		t.Error("second Refresh returned the same access token as the first — token not rotated")
	}
}

// TestEmailEnumeration_ForgotPassword proves that ForgotPassword returns nil
// (success) for registered, unregistered, and non-existent-tenant emails.
// This prevents email enumeration via the forgot-password endpoint (RESET-03).
func TestEmailEnumeration_ForgotPassword(t *testing.T) {
	svc, resetSvc, cleanup := newSecurityTestServices(t)
	defer cleanup()

	ctx := context.Background()
	registeredEmail := securityUniqueEmail("registered")

	// Register a real user so the "registered email" path is exercised.
	_, err := svc.Register(ctx, auth.RegisterInput{
		TenantSlug: "emc",
		Email:      registeredEmail,
		Password:   "SecPass123!",
		FirstName:  "Reg",
		LastName:   "User",
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Call 1: registered email — must return nil.
	if err := resetSvc.ForgotPassword(ctx, "emc", registeredEmail); err != nil {
		t.Errorf("ForgotPassword(registered email) = %v; want nil to prevent email enumeration", err)
	}

	// Call 2: unregistered email in a real tenant — must return nil.
	if err := resetSvc.ForgotPassword(ctx, "emc", "notregistered@sec.test"); err != nil {
		t.Errorf("ForgotPassword(unregistered email) = %v; want nil to prevent email enumeration", err)
	}

	// Call 3: non-existent tenant — must return nil (RESET-03 silent success).
	if err := resetSvc.ForgotPassword(ctx, "no-such-tenant", "any@email.com"); err != nil {
		t.Errorf("ForgotPassword(non-existent tenant) = %v; want nil to prevent email enumeration", err)
	}
}

// TestTOTPBypass_InvalidCode proves that LoginOTP rejects wrong TOTP codes and wrong
// backup codes, making TOTP bypass impossible.
func TestTOTPBypass_InvalidCode(t *testing.T) {
	if os.Getenv("DATABASE_URL") == "" {
		t.Skip("DATABASE_URL not set — skipping TOTP bypass test")
	}
	if os.Getenv("REDIS_URL") == "" {
		t.Skip("REDIS_URL not set — skipping TOTP bypass test")
	}

	pool := testhelper.NewTestDB(t)
	rdb := testhelper.NewTestRedis(t)
	logger := testhelper.TestLogger()
	ctx := context.Background()

	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}

	totpEncKey := os.Getenv("TOTP_ENCRYPTION_KEY")
	totpSvc, err := auth.NewTOTPService(pool, totpEncKey, logger)
	if err != nil {
		t.Fatalf("NewTOTPService: %v", err)
	}

	jwtSvc := auth.NewJWTService(pool, "https://auth.emc.local")
	svc := auth.NewAuthService(pool, jwtSvc, logger).WithTOTP(totpSvc, rdb)

	t.Cleanup(func() { testhelper.CleanupTables(t, pool) })

	email := securityUniqueEmail("totpbypass")

	// Register the user.
	_, err = svc.Register(ctx, auth.RegisterInput{
		TenantSlug: "emc",
		Email:      email,
		Password:   "SecPass123!",
		FirstName:  "TOTP",
		LastName:   "Bypass",
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Fetch the userID and tenantID.
	var userID, tenantID int64
	err = pool.QueryRow(ctx, `
		SELECT u.id, u.tenant_id
		FROM users u
		JOIN tenants ten ON ten.id = u.tenant_id
		WHERE u.email = $1 AND ten.slug = 'emc'
	`, email).Scan(&userID, &tenantID)
	if err != nil {
		t.Fatalf("fetch user IDs: %v", err)
	}

	// Enroll TOTP for the user.
	_, err = totpSvc.Enroll(ctx, userID, tenantID, email)
	if err != nil {
		t.Fatalf("Enroll TOTP: %v", err)
	}

	// Manually activate the secret (skips the VerifyAndActivate step in test).
	_, err = pool.Exec(ctx, `UPDATE totp_secrets SET is_active = true WHERE user_id = $1`, userID)
	if err != nil {
		t.Fatalf("activate TOTP: %v", err)
	}

	// Login — must return an OTP challenge since TOTP is now active.
	loginResult, err := svc.Login(ctx, auth.LoginInput{
		Email:    email,
		Password: "SecPass123!",
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if loginResult.OTPChallenge == nil {
		t.Fatal("Login should return OTPChallenge for user with active TOTP")
	}

	sessionToken := loginResult.OTPChallenge.OTPSessionToken

	// Attempt bypass with an obviously wrong 6-digit code.
	_, err = svc.LoginOTP(ctx, auth.LoginOTPInput{
		OTPSessionToken: sessionToken,
		Code:            "000000",
	})
	if err == nil {
		t.Fatal("LoginOTP with '000000' should return error — TOTP bypass must be impossible")
	}
	t.Logf("wrong TOTP code rejected: %v", err)

	// Re-login to get a fresh session token (OTP sessions may be single-use after failure).
	loginResult2, err := svc.Login(ctx, auth.LoginInput{
		Email:    email,
		Password: "SecPass123!",
	})
	if err != nil {
		t.Fatalf("second Login: %v", err)
	}
	if loginResult2.OTPChallenge == nil {
		t.Fatal("second Login should still return OTPChallenge")
	}

	// Attempt bypass with a fake 8-character backup code.
	_, err = svc.LoginOTP(ctx, auth.LoginOTPInput{
		OTPSessionToken: loginResult2.OTPChallenge.OTPSessionToken,
		Code:            "FAKECODE",
	})
	if err == nil {
		t.Fatal("LoginOTP with fake backup code 'FAKECODE' should return error — backup code bypass must be impossible")
	}
	t.Logf("wrong backup code rejected: %v", err)
}

// TestSQLInjection_LoginEmail proves that SQL metacharacters in the email field
// do not cause server errors (500) and do not leak DB error strings.
func TestSQLInjection_LoginEmail(t *testing.T) {
	svc, _, cleanup := newSecurityTestServices(t)
	defer cleanup()

	ctx := context.Background()

	payloads := []string{
		"' OR '1'='1",
		"admin'--",
		"\" OR \"1\"=\"1",
		"'; DROP TABLE users; --",
		"admin@emc.local' AND 1=1--",
	}

	for _, payload := range payloads {
		payload := payload // capture for subtests
		t.Run(fmt.Sprintf("payload=%q", payload), func(t *testing.T) {
			start := time.Now()
			_, err := svc.Login(ctx, auth.LoginInput{
				Email:    payload,
				Password: "anypassword",
			})
			elapsed := time.Since(start)

			// Must return an error (not a successful login).
			if err == nil {
				t.Fatalf("Login with SQL injection email %q returned nil error — injection succeeded!", payload)
			}

			// The error must NOT contain SQL error indicators.
			errStr := err.Error()
			sqlKeywords := []string{"ERROR", "syntax error", "SQLSTATE", "pq:", "pgx:"}
			for _, kw := range sqlKeywords {
				if strings.Contains(errStr, kw) {
					t.Errorf("error leaks SQL keyword %q in message: %v", kw, errStr)
				}
			}

			if elapsed > 10*time.Second {
				t.Errorf("Login with SQL injection email took %v — unexpected delay", elapsed)
			}

			t.Logf("payload %q -> error: %v (%.3fs)", payload, err, elapsed.Seconds())
		})
	}
}

// TestSQLInjection_LoginPassword proves that SQL metacharacters in the password field
// do not cause DB errors and do not leak SQL error strings. It also checks that
// time-based injections (pg_sleep) are not executed.
func TestSQLInjection_LoginPassword(t *testing.T) {
	svc, _, cleanup := newSecurityTestServices(t)
	defer cleanup()

	ctx := context.Background()

	payloads := []string{
		"' OR '1'='1",
		"' OR 1=1--",
		"'; SELECT pg_sleep(5);--",
	}

	for _, payload := range payloads {
		payload := payload // capture for subtests
		t.Run(fmt.Sprintf("payload=%q", payload), func(t *testing.T) {
			start := time.Now()
			_, err := svc.Login(ctx, auth.LoginInput{
				Email:    "admin@emc.local",
				Password: payload,
			})
			elapsed := time.Since(start)

			// Must return an error.
			if err == nil {
				t.Fatalf("Login with SQL injection password %q returned nil error — injection succeeded!", payload)
			}

			// Must NOT leak SQL error strings.
			errStr := err.Error()
			sqlKeywords := []string{"ERROR", "syntax error", "SQLSTATE", "pq:", "pgx:"}
			for _, kw := range sqlKeywords {
				if strings.Contains(errStr, kw) {
					t.Errorf("error leaks SQL keyword %q in message: %v", kw, errStr)
				}
			}

			// Must return in under 3 seconds (guards against pg_sleep time-based injection).
			if elapsed > 3*time.Second {
				t.Errorf("Login with SQL injection password took %v — possible time-based injection (pg_sleep executed)", elapsed)
			}

			t.Logf("payload %q -> error: %v (%.3fs)", payload, err, elapsed.Seconds())
		})
	}
}
