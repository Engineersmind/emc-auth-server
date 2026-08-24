package auth_test

import (
	"context"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/mailer"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// ---------------------------------------------------------------------------
// Email delivery is opt-in per application (migration 00073).
//
// A new application used to inherit every built-in template as ENABLED, because
// email_templates holds only overrides and absence means "send the built-in
// default" (00060). Creating an application therefore switched on thirteen kinds
// of outbound mail — verification, reset, MFA codes, invitations — before anyone
// had configured a sender or asked for any of it.
//
// CreateApplication now seeds a suppression row per type: is_active = false with
// EMPTY bodies. Empty is the load-bearing detail — see the assertions below.
// ---------------------------------------------------------------------------

func TestCreateApplication_SeedsEveryTemplateDisabled(t *testing.T) {
	pool := testhelper.NewTestDB(t)
	testhelper.CleanupTables(t, pool)
	ctx := context.Background()
	logger := testhelper.TestLogger()

	var tenantID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenants (name, slug, jwt_secret, is_active)
		VALUES ('Opt-in Mail', $1, 'secret-optin-templates', true) RETURNING id
	`, fmt.Sprintf("optin-%d", time.Now().UnixNano())).Scan(&tenantID); err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	svc := auth.NewApplicationService(pool, logger)
	app, err := svc.CreateApplication(ctx, tenantID, "fresh-app", "spa", nil)
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}
	appID := parseInt64(t, app.ID)

	// One suppression row per customizable type, all inactive.
	var total, active int
	if err = pool.QueryRow(ctx, `
		SELECT COUNT(*), COUNT(*) FILTER (WHERE is_active)
		FROM email_templates WHERE application_id = $1
	`, appID).Scan(&total, &active); err != nil {
		t.Fatalf("count templates: %v", err)
	}
	if total != len(mailer.AllTemplateTypes) {
		t.Errorf("seeded %d rows, want %d (one per customizable type)", total, len(mailer.AllTemplateTypes))
	}
	if active != 0 {
		t.Errorf("%d template(s) are active on a new application, want 0 — mail is opt-in", active)
	}

	// The bodies must be EMPTY, not a copy of the built-in default. A copy would
	// fork the template: frozen at today's wording, never receiving later
	// improvements — the trap the admin UI warns about when disabling a default.
	var nonEmpty int
	if err = pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM email_templates
		WHERE application_id = $1 AND (subject <> '' OR html_body <> '')
	`, appID).Scan(&nonEmpty); err != nil {
		t.Fatalf("count non-empty bodies: %v", err)
	}
	if nonEmpty != 0 {
		t.Errorf("%d seeded row(s) carry content; suppression rows must be empty so the maintained default still applies once enabled", nonEmpty)
	}
}

// TestCreateApplication_SuppressionStopsTheSend is the behaviour the operator
// actually asked for: a new app sends no verification mail until they turn it on.
func TestCreateApplication_SuppressionStopsTheSend(t *testing.T) {
	pool := testhelper.NewTestDB(t)
	testhelper.CleanupTables(t, pool)
	ctx := context.Background()
	logger := testhelper.TestLogger()

	var tenantID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenants (name, slug, jwt_secret, is_active)
		VALUES ('Suppressed', $1, 'secret-suppressed', true) RETURNING id
	`, fmt.Sprintf("suppressed-%d", time.Now().UnixNano())).Scan(&tenantID); err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	app, err := auth.NewApplicationService(pool, logger).
		CreateApplication(ctx, tenantID, "quiet-app", "spa", nil)
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}
	appID := parseInt64(t, app.ID)

	tmplSvc := auth.NewEmailTemplateService(pool, logger)

	// Verification is suppressed for the application...
	if tmplSvc.IsTypeEnabled(ctx, tenantID, &appID, mailer.TemplateEmailVerification) {
		t.Error("email verification is enabled on a new application; no mail should be sent until an operator enables it")
	}
	// ...and so is every other type.
	for _, tt := range mailer.AllTemplateTypes {
		if tmplSvc.IsTypeEnabled(ctx, tenantID, &appID, tt) {
			t.Errorf("template %q is enabled on a new application, want disabled", tt)
		}
	}

	// The TENANT scope is untouched: suppression is per application, so a tenant
	// that had configured its own templates keeps them.
	if !tmplSvc.IsTypeEnabled(ctx, tenantID, nil, mailer.TemplateEmailVerification) {
		t.Error("tenant-level verification became disabled; seeding must be scoped to the new application only")
	}
}

// TestSuppressedTemplateStillShowsDefaultContent covers the editor.
//
// The suppression row has empty bodies, so a naive Get would hand the admin UI a
// blank subject and body for every template on a new application — forcing the
// operator to retype content that already exists, or to save the blank as their
// template. Get fills from the built-in default instead, and keeps IsDefault
// true so enabling without editing keeps tracking upstream improvements.
func TestSuppressedTemplateStillShowsDefaultContent(t *testing.T) {
	pool := testhelper.NewTestDB(t)
	testhelper.CleanupTables(t, pool)
	ctx := context.Background()
	logger := testhelper.TestLogger()

	var tenantID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenants (name, slug, jwt_secret, is_active)
		VALUES ('Editor', $1, 'secret-editor', true) RETURNING id
	`, fmt.Sprintf("editor-%d", time.Now().UnixNano())).Scan(&tenantID); err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	app, err := auth.NewApplicationService(pool, logger).
		CreateApplication(ctx, tenantID, "editor-app", "spa", nil)
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}
	appID := parseInt64(t, app.ID)

	tmplSvc := auth.NewEmailTemplateService(pool, logger)
	got, err := tmplSvc.Get(ctx, tenantID, &appID, mailer.TemplateEmailVerification)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	if got.IsActive {
		t.Error("IsActive = true; the row is a suppression marker and must read as disabled")
	}
	if got.Subject == "" || got.HTMLBody == "" {
		t.Error("editor received empty content for a suppressed template; it must fall back to the built-in default")
	}
	def, _ := mailer.BuiltinTemplate(mailer.TemplateEmailVerification)
	if got.Subject != def.Subject {
		t.Errorf("subject = %q, want the built-in default %q", got.Subject, def.Subject)
	}
	if !got.IsDefault {
		t.Error("IsDefault = false; the content is the maintained default, so the UI must not present it as a custom copy")
	}
}

// TestExistingApplicationsKeepSendingMail: the migration deliberately does not
// retro-suppress. Applications already in production are sending verification and
// reset mail, and switching that off without operator action would break live
// signup and account recovery.
func TestExistingApplicationsKeepSendingMail(t *testing.T) {
	pool := testhelper.NewTestDB(t)
	testhelper.CleanupTables(t, pool)
	ctx := context.Background()
	logger := testhelper.TestLogger()

	var tenantID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenants (name, slug, jwt_secret, is_active)
		VALUES ('Legacy', $1, 'secret-legacy', true) RETURNING id
	`, fmt.Sprintf("legacy-%d", time.Now().UnixNano())).Scan(&tenantID); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	// An application created the way they were BEFORE this change: the client row
	// alone, with no template rows.
	var legacyAppID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO oauth_clients (tenant_id, client_id, name, app_type)
		VALUES ($1, $2, 'legacy-app', 'spa') RETURNING id
	`, tenantID, fmt.Sprintf("app_legacy_%d", time.Now().UnixNano())).Scan(&legacyAppID); err != nil {
		t.Fatalf("create legacy application: %v", err)
	}

	tmplSvc := auth.NewEmailTemplateService(pool, logger)
	if !tmplSvc.IsTypeEnabled(ctx, tenantID, &legacyAppID, mailer.TemplateEmailVerification) {
		t.Error("an application with no template rows stopped sending verification mail; absence must still mean enabled")
	}
}

// parseInt64 converts an API-facing string id to the row id these assertions
// query by. Local to this file: the ids are strings on the wire and int64 in the
// schema, and every test here needs the crossing.
func parseInt64(t *testing.T, s string) int64 {
	t.Helper()
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		t.Fatalf("parse id %q: %v", s, err)
	}
	return n
}
