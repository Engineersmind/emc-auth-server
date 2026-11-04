package auth_test

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/mailer"
	"github.com/engineersmind/emc-auth-server/internal/store"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// insertResetToken stores a known raw token for userID and returns it.
func insertResetToken(t *testing.T, ctx context.Context, pool *pgxpool.Pool, userID, tenantID int64) string {
	t.Helper()
	raw := fmt.Sprintf("scope-token-%d", time.Now().UnixNano())
	if _, err := pool.Exec(ctx, `
		INSERT INTO password_reset_tokens (user_id, tenant_id, token_hash, expires_at)
		VALUES ($1, $2, $3, NOW() + interval '15 minutes')
	`, userID, tenantID, auth.HashToken(raw)); err != nil {
		t.Fatalf("insert reset token: %v", err)
	}
	return raw
}

func tokenUsed(t *testing.T, ctx context.Context, pool *pgxpool.Pool, raw string) bool {
	t.Helper()
	var used bool
	if err := pool.QueryRow(ctx, `SELECT used_at IS NOT NULL FROM password_reset_tokens WHERE token_hash = $1`,
		auth.HashToken(raw)).Scan(&used); err != nil {
		t.Fatalf("read token: %v", err)
	}
	return used
}

// Code review (PR #174): an application backend's reset is scoped to its own
// tenant and application, so a tenant holding valid credentials cannot use its
// per-application limits to redeem — or guess — another tenant's tokens.
func TestResetPassword_ScopedToCallingApplication(t *testing.T) {
	pool := testhelper.NewTestDB(t)
	logger := testhelper.TestLogger()
	ctx := context.Background()
	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}
	svc := auth.NewResetService(pool, mailer.NewMailer(mailer.MailerConfig{Env: "development", Logger: logger}),
		"http://localhost:8080", logger)
	appSvc := auth.NewApplicationService(pool, logger)
	authSvc := auth.NewAuthService(pool, newTestJWTService(t, pool, "https://auth.emc.local"), logger).WithApplications(appSvc)

	var tenantID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM tenants WHERE slug = 'emc' AND deleted_at IS NULL`).Scan(&tenantID); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	app, err := appSvc.CreateApplication(ctx, tenantID, fmt.Sprintf("reset-scope-%d", time.Now().UnixNano()), "web", nil)
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}
	appID, _ := strconv.ParseInt(app.ID, 10, 64)
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM oauth_clients WHERE id = $1`, appID) })

	// A user of the application.
	appEmail := uniqueEmail("reset-scope-app")
	if _, err := authSvc.Register(ctx, auth.RegisterInput{
		ClientID: app.ClientID, ClientSecret: app.ClientSecret,
		Email: appEmail, Password: "OldPassword123!",
	}); err != nil {
		t.Fatalf("app Register: %v", err)
	}
	var appUserID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM users WHERE email = $1 AND application_id = $2`, appEmail, appID).Scan(&appUserID); err != nil {
		t.Fatalf("lookup app user: %v", err)
	}

	// 1. Another tenant's scope: invalid, and the token is NOT consumed.
	raw := insertResetToken(t, ctx, pool, appUserID, tenantID)
	otherTenant := tenantID + 1_000_000
	err = svc.ResetPassword(ctx, auth.ResetPasswordInput{
		RawToken: raw, NewPassword: "NewPassword456!",
		ScopeTenantID: otherTenant, ScopeApplicationID: &appID,
	})
	if !errors.Is(err, auth.ErrInvalidResetToken) {
		t.Fatalf("other tenant's scope: got %v, want ErrInvalidResetToken", err)
	}
	if tokenUsed(t, ctx, pool, raw) {
		t.Fatal("a refused cross-tenant attempt must not consume the victim's token")
	}

	// 2. Same tenant, another application: invalid too.
	otherApp := appID + 1_000_000
	if err := svc.ResetPassword(ctx, auth.ResetPasswordInput{
		RawToken: raw, NewPassword: "NewPassword456!",
		ScopeTenantID: tenantID, ScopeApplicationID: &otherApp,
	}); !errors.Is(err, auth.ErrInvalidResetToken) {
		t.Fatalf("other application's scope: got %v, want ErrInvalidResetToken", err)
	}

	// 3. The owning application redeems its own user's token.
	if err := svc.ResetPassword(ctx, auth.ResetPasswordInput{
		RawToken: raw, NewPassword: "NewPassword456!",
		ScopeTenantID: tenantID, ScopeApplicationID: &appID,
	}); err != nil {
		t.Fatalf("owning application: %v", err)
	}

	// 4. Unscoped (a browser, or a backend sending no credentials — today's
	//    behaviour) still works for any valid token.
	raw2 := insertResetToken(t, ctx, pool, appUserID, tenantID)
	if err := svc.ResetPassword(ctx, auth.ResetPasswordInput{RawToken: raw2, NewPassword: "NewerPassword789!"}); err != nil {
		t.Fatalf("unscoped: %v", err)
	}
}
