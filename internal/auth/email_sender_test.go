package auth_test

import (
	"errors"
	"testing"

	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// TestEmailSender_PriorityResolution proves the sender chain: application
// override → tenant-level sender → nil (global), including deactivation and
// deletion fallbacks.
func TestEmailSender_PriorityResolution(t *testing.T) {
	f := newMFAFixture(t)
	_, appA := f.createApp(t, "sender-app-a")
	_, appB := f.createApp(t, "sender-app-b")

	// Nothing configured → nil = global sender.
	sender, err := f.senderSvc.Resolve(f.ctx, f.tenantID, &appA)
	if err != nil || sender != nil {
		t.Fatalf("Resolve(no rows) = %v, %v — want nil, nil (global)", sender, err)
	}

	// Validation: missing/invalid from_address rejected.
	if _, err := f.senderSvc.Upsert(f.ctx, f.tenantID, nil, auth.UpsertSenderInput{SMTPHost: "smtp.acme.com"}, nil); !errors.Is(err, auth.ErrInvalidSender) {
		t.Errorf("Upsert(no from) error = %v, want ErrInvalidSender", err)
	}
	if _, err := f.senderSvc.Upsert(f.ctx, f.tenantID, nil, auth.UpsertSenderInput{FromAddress: "not-an-email", SMTPHost: "smtp.acme.com"}, nil); !errors.Is(err, auth.ErrInvalidSender) {
		t.Errorf("Upsert(bad from) error = %v, want ErrInvalidSender", err)
	}

	// Tenant-level sender → used by every app of the tenant.
	if _, err := f.senderSvc.Upsert(f.ctx, f.tenantID, nil, auth.UpsertSenderInput{
		FromAddress: "no-reply@acme.com", SMTPHost: "smtp.acme.com", SMTPPort: 587,
		SMTPUsername: "acme", SMTPPassword: "tenant-secret",
	}, nil); err != nil {
		t.Fatalf("Upsert(tenant): %v", err)
	}
	sender, err = f.senderSvc.Resolve(f.ctx, f.tenantID, &appA)
	if err != nil || sender == nil || sender.From != "no-reply@acme.com" {
		t.Fatalf("Resolve(app A, tenant sender) = %+v, %v — want tenant sender", sender, err)
	}
	if sender.Password != "tenant-secret" {
		t.Errorf("resolved password = %q, want decrypted plaintext", sender.Password)
	}

	// Application override wins for THAT app only.
	if _, err := f.senderSvc.Upsert(f.ctx, f.tenantID, &appA, auth.UpsertSenderInput{
		FromAddress: "codes@app-a.acme.com", SMTPHost: "smtp.app-a.acme.com",
	}, nil); err != nil {
		t.Fatalf("Upsert(app A): %v", err)
	}
	if s, _ := f.senderSvc.Resolve(f.ctx, f.tenantID, &appA); s == nil || s.From != "codes@app-a.acme.com" {
		t.Errorf("Resolve(app A) = %+v, want application override", s)
	}
	if s, _ := f.senderSvc.Resolve(f.ctx, f.tenantID, &appB); s == nil || s.From != "no-reply@acme.com" {
		t.Errorf("Resolve(app B) = %+v, want tenant sender (no override for B)", s)
	}
	if s, _ := f.senderSvc.Resolve(f.ctx, f.tenantID, nil); s == nil || s.From != "no-reply@acme.com" {
		t.Errorf("Resolve(tenant-level) = %+v, want tenant sender", s)
	}

	// Deactivating the app override falls back to the tenant sender.
	inactive := false
	if _, err := f.senderSvc.Upsert(f.ctx, f.tenantID, &appA, auth.UpsertSenderInput{
		FromAddress: "codes@app-a.acme.com", SMTPHost: "smtp.app-a.acme.com", IsActive: &inactive,
	}, nil); err != nil {
		t.Fatalf("Upsert(deactivate app A): %v", err)
	}
	if s, _ := f.senderSvc.Resolve(f.ctx, f.tenantID, &appA); s == nil || s.From != "no-reply@acme.com" {
		t.Errorf("Resolve(app A, override inactive) = %+v, want tenant sender", s)
	}

	// Get never exposes the password; empty password on update keeps it.
	got, err := f.senderSvc.Get(f.ctx, f.tenantID, nil)
	if err != nil {
		t.Fatalf("Get(tenant): %v", err)
	}
	if !got.HasPassword {
		t.Error("Get(tenant).HasPassword = false, want true")
	}
	if _, err := f.senderSvc.Upsert(f.ctx, f.tenantID, nil, auth.UpsertSenderInput{
		FromAddress: "no-reply@acme.com", SMTPHost: "smtp2.acme.com",
	}, nil); err != nil {
		t.Fatalf("Upsert(tenant, keep password): %v", err)
	}
	if s, _ := f.senderSvc.Resolve(f.ctx, f.tenantID, nil); s == nil || s.Password != "tenant-secret" || s.Host != "smtp2.acme.com" {
		t.Errorf("Resolve after password-preserving update = %+v, want kept password + new host", s)
	}

	// Deleting the tenant sender ends the chain → global.
	if err := f.senderSvc.Delete(f.ctx, f.tenantID, nil); err != nil {
		t.Fatalf("Delete(tenant): %v", err)
	}
	if err := f.senderSvc.Delete(f.ctx, f.tenantID, nil); !errors.Is(err, auth.ErrSenderNotFound) {
		t.Errorf("second Delete error = %v, want ErrSenderNotFound", err)
	}
	if s, _ := f.senderSvc.Resolve(f.ctx, f.tenantID, &appB); s != nil {
		t.Errorf("Resolve(app B, all deleted) = %+v, want nil (global)", s)
	}
}

// TestEmailSender_BrandingRoundTrip proves the branding + TLS fields persist
// through Upsert and come back on both Get and Resolve.
func TestEmailSender_BrandingRoundTrip(t *testing.T) {
	f := newMFAFixture(t)

	if _, err := f.senderSvc.Upsert(f.ctx, f.tenantID, nil, auth.UpsertSenderInput{
		FromAddress:   "no-reply@acme.com",
		SMTPHost:      "smtp.acme.com",
		SMTPPort:      465,
		TLSMode:       "ssl",
		FromName:      "Acme Security",
		ReplyTo:       "support@acme.com",
		ProductName:   "Acme Cloud",
		LogoURL:       "https://acme.com/logo.png",
		SubjectPrefix: "[Acme]",
	}, nil); err != nil {
		t.Fatalf("Upsert(branding): %v", err)
	}

	got, err := f.senderSvc.Get(f.ctx, f.tenantID, nil)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.FromName != "Acme Security" || got.ReplyTo != "support@acme.com" ||
		got.ProductName != "Acme Cloud" || got.LogoURL != "https://acme.com/logo.png" ||
		got.SubjectPrefix != "[Acme]" || got.TLSMode != "ssl" {
		t.Errorf("Get branding = %+v, want the values just set", got)
	}

	sender, err := f.senderSvc.Resolve(f.ctx, f.tenantID, nil)
	if err != nil || sender == nil {
		t.Fatalf("Resolve: %+v, %v", sender, err)
	}
	if sender.FromName != "Acme Security" || sender.ReplyTo != "support@acme.com" ||
		sender.ProductName != "Acme Cloud" || sender.LogoURL != "https://acme.com/logo.png" ||
		sender.SubjectPrefix != "[Acme]" || sender.TLSMode != "ssl" {
		t.Errorf("Resolve branding = %+v, want the values just set", sender)
	}
}

// TestEmailMFA_CodesUseResolvedSender proves MFA code emails actually go out
// via the priority-resolved sender.
func TestEmailMFA_CodesUseResolvedSender(t *testing.T) {
	f := newMFAFixture(t)
	app, appID := f.createApp(t, "sender-mfa-app")
	email := uniqueEmail("sender-mfa")
	userID := f.registerAppUser(t, app, email, "Password123!")

	if err := f.totpSvc.SetAppMFAPolicy(f.ctx, f.tenantID, appID, auth.MFAModeOptional, []string{auth.MFAMethodEmail}, nil); err != nil {
		t.Fatalf("SetAppMFAPolicy: %v", err)
	}

	// No sender rows → global (nil override).
	if err := f.emailSvc.BeginEnrollment(f.ctx, userID, f.tenantID, email); err != nil {
		t.Fatalf("BeginEnrollment: %v", err)
	}
	if s := f.mail.lastSender(t); s != nil {
		t.Errorf("enrollment email sender = %+v, want nil (global)", s)
	}
	if err := f.emailSvc.ActivateEnrollment(f.ctx, userID, f.mail.lastCode(t).Code); err != nil {
		t.Fatalf("ActivateEnrollment: %v", err)
	}

	// Tenant sender configured → login challenge code goes out via it.
	if _, err := f.senderSvc.Upsert(f.ctx, f.tenantID, nil, auth.UpsertSenderInput{
		FromAddress: "no-reply@acme.com", SMTPHost: "smtp.acme.com",
	}, nil); err != nil {
		t.Fatalf("Upsert(tenant): %v", err)
	}
	if _, err := f.appLogin(t, app, email, "Password123!"); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if s := f.mail.lastSender(t); s == nil || s.From != "no-reply@acme.com" {
		t.Errorf("login code sender = %+v, want tenant sender", s)
	}

	// Application override configured → it wins.
	if _, err := f.senderSvc.Upsert(f.ctx, f.tenantID, &appID, auth.UpsertSenderInput{
		FromAddress: "codes@sender-mfa-app.acme.com", SMTPHost: "smtp.app.acme.com",
	}, nil); err != nil {
		t.Fatalf("Upsert(app): %v", err)
	}
	if _, err := f.appLogin(t, app, email, "Password123!"); err != nil {
		t.Fatalf("second Login: %v", err)
	}
	if s := f.mail.lastSender(t); s == nil || s.From != "codes@sender-mfa-app.acme.com" {
		t.Errorf("login code sender = %+v, want application override", s)
	}
}
