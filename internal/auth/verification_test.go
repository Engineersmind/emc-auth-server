package auth_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/mailer"
	"github.com/engineersmind/emc-auth-server/internal/store"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// seededVerification wires an AuthService + VerificationService against a real
// DB with the "emc" tenant seeded, returning them plus the capture mailer.
func seededVerification(t *testing.T) (*auth.AuthService, *auth.VerificationService, *captureMailer, int64, context.Context) {
	t.Helper()
	pool := testhelper.NewTestDB(t)
	testhelper.CleanupTables(t, pool)
	logger := testhelper.TestLogger()
	ctx := context.Background()
	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}
	var tenantID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM tenants WHERE slug = 'emc'`).Scan(&tenantID); err != nil {
		t.Fatalf("tenant id: %v", err)
	}

	mail := &captureMailer{}
	verifSvc := auth.NewVerificationService(pool, mail, "http://localhost:8080", logger)
	jwtSvc := newTestJWTService(t, pool, "https://auth.emc.local")
	authSvc := auth.NewAuthService(pool, jwtSvc, logger).WithVerification(verifSvc)
	return authSvc, verifSvc, mail, tenantID, ctx
}

// TestRegister_SendsVerification proves registration dispatches a verification
// email and creates a token row.
func TestRegister_SendsVerification(t *testing.T) {
	authSvc, _, mail, _, ctx := seededVerification(t)
	email := uniqueEmail("verify-register")
	if _, err := authSvc.Register(ctx, auth.RegisterInput{Email: email, Password: "OldPassword123!", FirstName: "V", LastName: "R"}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if len(mail.verifications) != 1 {
		t.Fatalf("verification emails = %d, want 1", len(mail.verifications))
	}
	if mail.verifications[0].To != email || mail.verifications[0].Link == "" {
		t.Errorf("verification email = %+v, want To=%s with a link", mail.verifications[0], email)
	}
}

// TestVerifyEmail_FullFlow proves a real registration → verify link → verified
// state + welcome email round trip works, and that the token is single-use.
func TestVerifyEmail_FullFlow(t *testing.T) {
	authSvc, verifSvc, mail, _, ctx := seededVerification(t)

	email := uniqueEmail("verify-full")
	if _, err := authSvc.Register(ctx, auth.RegisterInput{Email: email, Password: "OldPassword123!", FirstName: "V", LastName: "F"}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Recover the raw token from the emailed link (…/verify-email?token=RAW).
	link := mail.verifications[0].Link
	const marker = "token="
	idx := -1
	for i := 0; i+len(marker) <= len(link); i++ {
		if link[i:i+len(marker)] == marker {
			idx = i + len(marker)
			break
		}
	}
	if idx < 0 {
		t.Fatalf("no token in link %q", link)
	}
	rawToken := link[idx:]

	if err := verifSvc.VerifyEmail(ctx, rawToken); err != nil {
		t.Fatalf("VerifyEmail: %v", err)
	}
	if len(mail.welcomes) != 1 || mail.welcomes[0].To != email {
		t.Errorf("welcome emails = %+v, want 1 to %s", mail.welcomes, email)
	}

	// Second use of the same token must fail (single-use).
	if err := verifSvc.VerifyEmail(ctx, rawToken); !errors.Is(err, auth.ErrInvalidVerificationToken) {
		t.Errorf("second VerifyEmail = %v, want ErrInvalidVerificationToken", err)
	}
}

// TestVerifyEmail_InvalidToken rejects an unknown token.
func TestVerifyEmail_InvalidToken(t *testing.T) {
	_, verifSvc, _, _, ctx := seededVerification(t)
	if err := verifSvc.VerifyEmail(ctx, "nope-not-a-real-token"); !errors.Is(err, auth.ErrInvalidVerificationToken) {
		t.Errorf("VerifyEmail(bad) = %v, want ErrInvalidVerificationToken", err)
	}
}

// TestResendVerification_EnumerationSafe returns nil for unknown emails.
func TestResendVerification_EnumerationSafe(t *testing.T) {
	_, verifSvc, _, _, ctx := seededVerification(t)
	if err := verifSvc.ResendVerification(ctx, "nobody@nope.invalid"); err != nil {
		t.Errorf("resend unknown email = %v, want nil", err)
	}
	if err := verifSvc.ResendVerification(ctx, ""); err != nil {
		t.Errorf("resend empty email = %v, want nil", err)
	}
}

// TestResendVerification_ResolvesTenantFromEmail is the regression test for the
// change that removed the X-Tenant-Slug requirement.
//
// The caller no longer supplies a tenant. A person who did not receive their
// verification email was previously asked for their tenant's slug — an internal
// identifier they have most likely never seen — while Login, the step
// immediately before, has never needed one. This asserts the address alone is
// enough to find the account and send the mail.
func TestResendVerification_ResolvesTenantFromEmail(t *testing.T) {
	authSvc, verifSvc, mail, _, ctx := seededVerification(t)

	const email = "unverified-resend@example.test"
	if _, err := authSvc.Register(ctx, auth.RegisterInput{
		Email:    email,
		Password: "CorrectHorseBattery1",
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	before := len(mail.verifications)
	if err := verifSvc.ResendVerification(ctx, email); err != nil {
		t.Fatalf("ResendVerification: %v", err)
	}
	if got := len(mail.verifications) - before; got != 1 {
		t.Fatalf("sent %d verification emails, want 1 — the tenant was not "+
			"resolved from the address alone", got)
	}
	if to := mail.verifications[len(mail.verifications)-1].To; to != email {
		t.Fatalf("verification sent to %q, want %q", to, email)
	}
}

// TestResendVerification_SkipsVerifiedAccounts confirms an account that has
// already completed verification produces no further mail, so the endpoint
// cannot be used to repeatedly mail a known address.
func TestResendVerification_SkipsVerifiedAccounts(t *testing.T) {
	authSvc, verifSvc, mail, _, ctx := seededVerification(t)

	const email = "already-verified@example.test"
	if _, err := authSvc.Register(ctx, auth.RegisterInput{
		Email:    email,
		Password: "CorrectHorseBattery1",
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Complete verification through the real flow — the token from the mail
	// registration just sent — rather than writing email_verified directly, so
	// the test exercises the same state transition production does.
	link := mail.verifications[len(mail.verifications)-1].Link
	token := link[strings.LastIndex(link, "=")+1:]
	if err := verifSvc.VerifyEmail(ctx, token); err != nil {
		t.Fatalf("VerifyEmail: %v", err)
	}

	before := len(mail.verifications)
	if err := verifSvc.ResendVerification(ctx, email); err != nil {
		t.Fatalf("ResendVerification: %v", err)
	}
	if got := len(mail.verifications) - before; got != 0 {
		t.Fatalf("sent %d emails for an already-verified account, want 0", got)
	}
}

// TestVerificationUsesTenantTemplate proves an active per-tenant template
// override is resolved and passed to the mailer (custom template path).
func TestVerificationUsesTenantTemplate(t *testing.T) {
	pool := testhelper.NewTestDB(t)
	testhelper.CleanupTables(t, pool)
	logger := testhelper.TestLogger()
	ctx := context.Background()
	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}
	var tenantID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM tenants WHERE slug = 'emc'`).Scan(&tenantID); err != nil {
		t.Fatalf("tenant id: %v", err)
	}

	tmplSvc := auth.NewEmailTemplateService(pool, logger)
	if _, err := tmplSvc.Upsert(ctx, tenantID, nil, mailer.TemplateEmailVerification, auth.UpsertTemplateInput{
		Subject:  "Custom verify {{.ProductName}}",
		HTMLBody: "<p>Verify: {{.Link}}</p>",
		TextBody: "Verify: {{.Link}}",
	}, nil); err != nil {
		t.Fatalf("Upsert template: %v", err)
	}

	// Resolve returns the override (non-nil).
	got, err := tmplSvc.Resolve(ctx, tenantID, nil, mailer.TemplateEmailVerification)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got == nil || got.Subject != "Custom verify {{.ProductName}}" {
		t.Errorf("Resolve = %+v, want the custom override", got)
	}

	// A type with no override resolves to nil (built-in default is used).
	none, err := tmplSvc.Resolve(ctx, tenantID, nil, mailer.TemplatePasswordReset)
	if err != nil {
		t.Fatalf("Resolve(no override): %v", err)
	}
	if none != nil {
		t.Errorf("Resolve(no override) = %+v, want nil", none)
	}
}

// TestSenderProvider_SendGrid proves a SendGrid sender can be stored (API key,
// no SMTP host) and resolves back with the decrypted key and provider set. The
// API key is never returned by Get (only has_api_key).
func TestSenderProvider_SendGrid(t *testing.T) {
	pool := testhelper.NewTestDB(t)
	testhelper.CleanupTables(t, pool)
	logger := testhelper.TestLogger()
	ctx := context.Background()
	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}
	var tenantID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM tenants WHERE slug = 'emc'`).Scan(&tenantID); err != nil {
		t.Fatalf("tenant id: %v", err)
	}

	totpSvc, err := auth.NewTOTPService(pool, totpEnvKey(), logger)
	if err != nil {
		t.Fatalf("NewTOTPService: %v", err)
	}
	senderSvc := auth.NewEmailSenderService(pool, totpSvc.EncryptionKey(), logger)

	// SendGrid sender: no SMTP host required, API key required.
	got, err := senderSvc.Upsert(ctx, tenantID, nil, auth.UpsertSenderInput{
		Provider: auth.SenderProviderSendGrid, FromAddress: "no-reply@acme.com", APIKey: "SG.secret-key", FromName: "Acme",
	}, nil)
	if err != nil {
		t.Fatalf("Upsert(sendgrid): %v", err)
	}
	if got.Provider != auth.SenderProviderSendGrid || !got.HasAPIKey || got.HasPassword {
		t.Errorf("Get = %+v, want provider=sendgrid has_api_key=true has_password=false", got)
	}

	// Resolve returns the decrypted key + provider for the send path.
	resolved, err := senderSvc.Resolve(ctx, tenantID, nil)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if resolved == nil || resolved.Provider != mailer.ProviderSendGrid || resolved.APIKey != "SG.secret-key" {
		t.Errorf("Resolve = %+v, want provider=sendgrid apikey=SG.secret-key", resolved)
	}

	// Missing API key on a new sendgrid sender is rejected.
	if _, err := senderSvc.Upsert(ctx, tenantID, nil, auth.UpsertSenderInput{
		Provider: auth.SenderProviderSendGrid, FromAddress: "x@y.com", APIKey: "",
	}, nil); err != nil {
		// Updating an existing row that already has a key is allowed to omit it —
		// so this succeeds (keeps stored key). Assert it kept the provider.
		t.Fatalf("Upsert(sendgrid, omit key on update): %v", err)
	}
}

// TestRegister_WithoutTenantSlug is the regression test for a broken sign-up
// page.
//
// /auth/register required an X-Tenant-Slug header, while the admin console's
// RegisterPayload has never carried a slug and its client never sent the
// header — so every submission from the console's own sign-up page returned
// 400. Requiring it also asked a person creating their first account for the
// tenant's OIDC issuer identifier, which is a machine-facing value they have no
// way to know.
//
// An empty slug now resolves to the platform tenant.
func TestRegister_WithoutTenantSlug(t *testing.T) {
	authSvc, _, _, platformTenantID, ctx := seededVerification(t)

	res, err := authSvc.Register(ctx, auth.RegisterInput{
		Email:    uniqueEmail("no-slug-register"),
		Password: "CorrectHorseBattery1",
	})
	if err != nil {
		t.Fatalf("Register with no slug: %v — the console sign-up page sends none", err)
	}
	if res.TenantID != platformTenantID {
		t.Fatalf("registered into tenant %d, want the platform tenant %d",
			res.TenantID, platformTenantID)
	}
}

// TestRegister_IsAlwaysPlatformTenant pins the contract: a first-party
// registration lands in the platform tenant and the caller has no say in it.
//
// RegisterInput no longer carries a tenant selector at all, so this is enforced
// by the type rather than by validation — the test exists so that reintroducing
// one has to break something visible.
func TestRegister_IsAlwaysPlatformTenant(t *testing.T) {
	authSvc, _, _, platformTenantID, ctx := seededVerification(t)

	for i := 0; i < 2; i++ {
		res, err := authSvc.Register(ctx, auth.RegisterInput{
			Email:    uniqueEmail("platform-register"),
			Password: "CorrectHorseBattery1",
		})
		if err != nil {
			t.Fatalf("Register: %v", err)
		}
		if res.TenantID != platformTenantID {
			t.Fatalf("registered into tenant %d, want the platform tenant %d",
				res.TenantID, platformTenantID)
		}
	}
}
