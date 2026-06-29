package auth_test

import (
	"context"
	"errors"
	"testing"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/mailer"
	"github.com/engineersmind/emc-auth-server/internal/store"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// newResetService creates a ResetService backed by a real DB.
func newResetService(t *testing.T) (*auth.ResetService, context.Context) {
	t.Helper()
	pool := testhelper.NewTestDB(t)
	testhelper.CleanupTables(t, pool)
	logger := testhelper.TestLogger()

	ctx := context.Background()
	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}

	m := mailer.NewMailer(mailer.MailerConfig{
		Env:    "development",
		Logger: logger,
	})
	svc := auth.NewResetService(pool, m, "http://localhost:8080", logger)
	return svc, ctx
}

func TestForgotPassword_UnknownEmail_Silent(t *testing.T) {
	svc, ctx := newResetService(t)

	// Unknown email in a known tenant — must return nil (no enumeration, RESET-03).
	err := svc.ForgotPassword(ctx, "emc", "nobody@nope.invalid")
	if err != nil {
		t.Errorf("ForgotPassword() expected nil for unknown email, got %v", err)
	}
}

func TestForgotPassword_UnknownTenant_Silent(t *testing.T) {
	svc, ctx := newResetService(t)

	// Unknown tenant — must also return nil (RESET-03).
	err := svc.ForgotPassword(ctx, "nonexistent-tenant", "user@example.com")
	if err != nil {
		t.Errorf("ForgotPassword() expected nil for unknown tenant, got %v", err)
	}
}

func TestForgotPassword_KnownEmail(t *testing.T) {
	pool := testhelper.NewTestDB(t)
	testhelper.CleanupTables(t, pool)
	logger := testhelper.TestLogger()
	ctx := context.Background()

	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}

	m := mailer.NewMailer(mailer.MailerConfig{Env: "development", Logger: logger})
	svc := auth.NewResetService(pool, m, "http://localhost:8080", logger)

	// admin@emc.local is seeded — should work silently.
	err := svc.ForgotPassword(ctx, "emc", "admin@emc.local")
	if err != nil {
		t.Errorf("ForgotPassword() for known email error = %v", err)
	}
}

func TestResetPassword_ValidToken(t *testing.T) {
	pool := testhelper.NewTestDB(t)
	testhelper.CleanupTables(t, pool)
	logger := testhelper.TestLogger()
	ctx := context.Background()

	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}

	m := mailer.NewMailer(mailer.MailerConfig{Env: "development", Logger: logger})
	svc := auth.NewResetService(pool, m, "http://localhost:8080", logger)

	// Register a user to get a real user_id in this tenant.
	jwtSvc := auth.NewJWTService(pool, "https://auth.emc.local")
	authSvc := auth.NewAuthService(pool, jwtSvc, logger)
	email := uniqueEmail("reset-valid")
	_, err := authSvc.Register(ctx, auth.RegisterInput{
		TenantSlug: "emc",
		Email:      email,
		Password:   "OldPassword123!",
		FirstName:  "Reset",
		LastName:   "Valid",
	})
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	// Look up user_id and tenant_id for the registered user.
	var userID, tenantID int64
	err = pool.QueryRow(ctx,
		`SELECT u.id, u.tenant_id FROM users u WHERE u.email = $1`, email,
	).Scan(&userID, &tenantID)
	if err != nil {
		t.Fatalf("lookup user: %v", err)
	}

	// Insert a known raw token directly (bypassing email dispatch).
	const rawToken = "testtoken123abc456def789"
	tokenHash := auth.HashToken(rawToken)
	_, err = pool.Exec(ctx, `
		INSERT INTO password_reset_tokens (user_id, tenant_id, token_hash, expires_at)
		VALUES ($1, $2, $3, NOW() + interval '15 minutes')
	`, userID, tenantID, tokenHash)
	if err != nil {
		t.Fatalf("insert reset token: %v", err)
	}

	// Now reset using the raw token.
	err = svc.ResetPassword(ctx, auth.ResetPasswordInput{
		RawToken:    rawToken,
		NewPassword: "NewPassword456!",
	})
	if err != nil {
		t.Errorf("ResetPassword() error = %v", err)
	}
}

func TestResetPassword_InvalidToken(t *testing.T) {
	svc, ctx := newResetService(t)

	err := svc.ResetPassword(ctx, auth.ResetPasswordInput{
		RawToken:    "completelyinvalidtoken123456789",
		NewPassword: "NewPassword456!",
	})
	if err == nil {
		t.Fatal("ResetPassword() expected error for invalid token, got nil")
	}
	if !errors.Is(err, auth.ErrInvalidResetToken) {
		t.Errorf("ResetPassword() error = %v, want auth.ErrInvalidResetToken", err)
	}
}

func TestResetPassword_ShortPassword(t *testing.T) {
	svc, ctx := newResetService(t)

	err := svc.ResetPassword(ctx, auth.ResetPasswordInput{
		RawToken:    "anytoken",
		NewPassword: "short",
	})
	if err == nil {
		t.Fatal("ResetPassword() expected error for short password, got nil")
	}
}
