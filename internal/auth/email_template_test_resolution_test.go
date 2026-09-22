package auth_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/mailer"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// ---------------------------------------------------------------------------
// Status governs real sends; a test send always shows the saved template.
//
// The reported defect: an admin saved a template on an application, clicked
// "Send test", and received the built-in default instead of their own content.
//
// The cause was one filter serving two different questions. Resolve applied
// `is_active = true` to every lookup, and every new application is seeded with
// its templates DISABLED because mail is opt-in (migration 00073). So the state
// an admin is in while writing a template — saved, not yet enabled — was
// exactly the state in which the test send ignored it. Testing before enabling
// is the normal order of work, which made the feature unusable for its purpose.
//
// The rule these tests pin:
//
//   - real sends       → Status decides whether users get the email
//   - test sends       → always render the saved template, Status or not
//   - nothing saved    → the built-in default, in both cases
//
// IsTypeEnabled is untouched, so a disabled template stays disabled for users.
// ---------------------------------------------------------------------------

// newTemplateFixture returns a tenant + application with the usual opt-in
// seeding (every type present, inactive, empty bodies).
func newTemplateFixture(t *testing.T, slug string) (*auth.EmailTemplateService, int64, int64, context.Context) {
	t.Helper()
	pool := testhelper.NewTestDB(t)
	testhelper.CleanupTables(t, pool)
	ctx := context.Background()
	logger := testhelper.TestLogger()

	var tenantID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenants (name, slug, jwt_secret, is_active)
		VALUES ('Test Resolution', $1, 'secret-test-resolution', true) RETURNING id
	`, fmt.Sprintf("%s-%d", slug, time.Now().UnixNano())).Scan(&tenantID); err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	app, err := auth.NewApplicationService(pool, logger).
		CreateApplication(ctx, tenantID, slug+"-app", "spa", nil)
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}

	return auth.NewEmailTemplateService(pool, logger), tenantID, parseInt64(t, app.ID), ctx
}

// TestSendTest_UsesASavedButDisabledTemplate is the reported bug.
func TestSendTest_UsesASavedButDisabledTemplate(t *testing.T) {
	svc, tenantID, appID, ctx := newTemplateFixture(t, "disabled-save")

	// Save content while the template is still disabled — what an admin does
	// when writing a template they have not switched on yet.
	disabled := false
	if _, err := svc.Upsert(ctx, tenantID, &appID, mailer.TemplateEmailVerification, auth.UpsertTemplateInput{
		Subject:  "My own subject",
		HTMLBody: "<p>My own body</p>",
		TextBody: "My own body",
		IsActive: &disabled,
	}, nil); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	// The test send must show it.
	got := svc.ResolveTemplateForTest(ctx, tenantID, &appID, mailer.TemplateEmailVerification)
	if got == nil {
		t.Fatal("test resolution returned the built-in default — the admin cannot check their own template before enabling it")
	}
	if got.Subject != "My own subject" {
		t.Errorf("test subject = %q, want the saved one", got.Subject)
	}

	// A REAL send must still be suppressed: Status means what it says.
	if svc.IsTypeEnabled(ctx, tenantID, &appID, mailer.TemplateEmailVerification) {
		t.Error("a disabled template reports as enabled for real sends — users would receive an email the operator switched off")
	}
	// And the real-send resolution keeps honouring is_active.
	if real := svc.ResolveTemplate(ctx, tenantID, &appID, mailer.TemplateEmailVerification); real != nil {
		t.Error("the real-send path resolved a disabled template; only the test path may ignore Status")
	}
}

// TestSendTest_UsesASavedEnabledTemplate is the other half: once enabled, both
// paths agree. A fix that only worked while disabled would be its own bug.
func TestSendTest_UsesASavedEnabledTemplate(t *testing.T) {
	svc, tenantID, appID, ctx := newTemplateFixture(t, "enabled-save")

	active := true
	if _, err := svc.Upsert(ctx, tenantID, &appID, mailer.TemplateWelcome, auth.UpsertTemplateInput{
		Subject:  "Welcome aboard",
		HTMLBody: "<p>Glad you are here</p>",
		TextBody: "Glad you are here",
		IsActive: &active,
	}, nil); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	for name, got := range map[string]*mailer.Template{
		"test": svc.ResolveTemplateForTest(ctx, tenantID, &appID, mailer.TemplateWelcome),
		"real": svc.ResolveTemplate(ctx, tenantID, &appID, mailer.TemplateWelcome),
	} {
		if got == nil {
			t.Fatalf("%s resolution returned the built-in default for an enabled saved template", name)
		}
		if got.Subject != "Welcome aboard" {
			t.Errorf("%s subject = %q, want the saved one", name, got.Subject)
		}
	}
}

// TestSendTest_FallsBackToTheBuiltInWhenNothingIsSaved covers "if no template
// is set, send the default" — and specifically that the OPT-IN PLACEHOLDER does
// not count as a saved template.
//
// This is the failure the empty-body guard in resolve() prevents. A new
// application has a row per type: is_active = false with empty bodies. Once the
// test path stopped filtering on is_active, that row became a match — and a
// test send would have delivered a blank message rather than the built-in
// default. Nil here means "use the built-in", so nil is the correct answer.
func TestSendTest_FallsBackToTheBuiltInWhenNothingIsSaved(t *testing.T) {
	svc, tenantID, appID, ctx := newTemplateFixture(t, "never-saved")

	for _, tt := range []mailer.TemplateType{
		mailer.TemplateEmailVerification,
		mailer.TemplateWelcome,
		mailer.TemplatePasswordReset,
	} {
		if got := svc.ResolveTemplateForTest(ctx, tenantID, &appID, tt); got != nil {
			t.Errorf("%s resolved a seeded placeholder (subject=%q, html=%q) — a test send would deliver a blank email instead of the built-in default",
				tt, got.Subject, got.HTML)
		}
	}
}

// TestSendTest_PrefersTheApplicationTemplateOverTheTenants pins precedence,
// which must not change just because is_active is ignored: the application's
// own template still wins over the tenant's.
func TestSendTest_PrefersTheApplicationTemplateOverTheTenants(t *testing.T) {
	svc, tenantID, appID, ctx := newTemplateFixture(t, "precedence")

	active := true
	disabled := false

	// Tenant-wide template, enabled.
	if _, err := svc.Upsert(ctx, tenantID, nil, mailer.TemplateMagicLink, auth.UpsertTemplateInput{
		Subject: "Tenant subject", HTMLBody: "<p>tenant</p>", TextBody: "tenant", IsActive: &active,
	}, nil); err != nil {
		t.Fatalf("Upsert tenant: %v", err)
	}
	// Application template, disabled — still the more specific scope.
	if _, err := svc.Upsert(ctx, tenantID, &appID, mailer.TemplateMagicLink, auth.UpsertTemplateInput{
		Subject: "App subject", HTMLBody: "<p>app</p>", TextBody: "app", IsActive: &disabled,
	}, nil); err != nil {
		t.Fatalf("Upsert app: %v", err)
	}

	got := svc.ResolveTemplateForTest(ctx, tenantID, &appID, mailer.TemplateMagicLink)
	if got == nil {
		t.Fatal("test resolution returned the built-in default")
	}
	if got.Subject != "App subject" {
		t.Errorf("test resolved %q, want the application's own template — ignoring is_active must not change scope precedence", got.Subject)
	}

	// The real send skips the disabled application row and uses the tenant's.
	real := svc.ResolveTemplate(ctx, tenantID, &appID, mailer.TemplateMagicLink)
	if real == nil || real.Subject != "Tenant subject" {
		t.Errorf("real send resolved %v, want the enabled tenant template", real)
	}
}

// A tenant-scoped test send (no application) must behave the same way.
func TestSendTest_UsesASavedButDisabledTenantTemplate(t *testing.T) {
	svc, tenantID, _, ctx := newTemplateFixture(t, "tenant-disabled")

	disabled := false
	if _, err := svc.Upsert(ctx, tenantID, nil, mailer.TemplateMFACode, auth.UpsertTemplateInput{
		Subject: "Tenant MFA", HTMLBody: "<p>code</p>", TextBody: "code", IsActive: &disabled,
	}, nil); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	got := svc.ResolveTemplateForTest(ctx, tenantID, nil, mailer.TemplateMFACode)
	if got == nil || got.Subject != "Tenant MFA" {
		t.Fatalf("tenant test resolution = %v, want the saved tenant template", got)
	}
	if real := svc.ResolveTemplate(ctx, tenantID, nil, mailer.TemplateMFACode); real != nil {
		t.Error("the real-send path resolved a disabled tenant template")
	}
}
