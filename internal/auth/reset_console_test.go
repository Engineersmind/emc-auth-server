package auth_test

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/mailer"
	"github.com/engineersmind/emc-auth-server/internal/store"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// ---------------------------------------------------------------------------
// ForgotPasswordFirstParty — the console's forgot-password (issue #179).
//
// Console administrators are first-party accounts (application_id IS NULL) and
// the console holds no client credentials, so the application-scoped
// ForgotPassword could never reach them. These pin who the cross-tenant lookup
// mails, and that each emailed token resets only its own account.
// ---------------------------------------------------------------------------

const consoleDashboardURL = "https://console.example.test"

type consoleResetEnv struct {
	pool *pgxpool.Pool
	ctx  context.Context
	svc  *auth.ResetService
	mail *captureMailer
}

func newConsoleResetEnv(t *testing.T) *consoleResetEnv {
	t.Helper()
	pool := testhelper.NewTestDB(t)
	testhelper.CleanupTables(t, pool)
	logger := testhelper.TestLogger()
	ctx := context.Background()
	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}
	mail := &captureMailer{}
	svc := auth.NewResetService(pool, mail, "http://localhost:8080", logger).WithDashboardURL(consoleDashboardURL)
	return &consoleResetEnv{pool: pool, ctx: ctx, svc: svc, mail: mail}
}

func (e *consoleResetEnv) tenant(t *testing.T, label string, active bool) int64 {
	t.Helper()
	var id int64
	slug := fmt.Sprintf("%s-%d", label, time.Now().UnixNano())
	if err := e.pool.QueryRow(e.ctx, `
		INSERT INTO tenants (name, slug, jwt_secret, is_active)
		VALUES ($1, $1, 'test-secret-not-used-for-signing', $2)
		RETURNING id
	`, slug, active).Scan(&id); err != nil {
		t.Fatalf("seed tenant %s: %v", label, err)
	}
	return id
}

func (e *consoleResetEnv) app(t *testing.T, tenantID int64) int64 {
	t.Helper()
	var id int64
	name := fmt.Sprintf("console-reset-app-%d", time.Now().UnixNano())
	if err := e.pool.QueryRow(e.ctx, `
		INSERT INTO oauth_clients
		    (tenant_id, client_id, name, redirect_uris, grant_types, scopes,
		     app_type, require_pkce, first_party)
		VALUES ($1, $2, $2, ARRAY['https://x/cb'], ARRAY['authorization_code'],
		        ARRAY['openid'], 'spa', true, true)
		RETURNING id
	`, tenantID, name).Scan(&id); err != nil {
		t.Fatalf("seed app: %v", err)
	}
	return id
}

// user creates an account with a password credential. appID nil is a
// first-party (console) account.
func (e *consoleResetEnv) user(t *testing.T, tenantID int64, appID *int64, email string, active bool) int64 {
	t.Helper()
	var id int64
	if err := e.pool.QueryRow(e.ctx, `
		INSERT INTO users (tenant_id, application_id, email, first_name, last_name, is_active, email_verified)
		VALUES ($1, $2, $3, 'C', 'R', $4, true)
		RETURNING id
	`, tenantID, appID, email, active).Scan(&id); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := e.pool.Exec(e.ctx,
		`INSERT INTO user_credentials (user_id, tenant_id, password_hash) VALUES ($1, $2, 'original-hash')`,
		id, tenantID); err != nil {
		t.Fatalf("seed credential: %v", err)
	}
	return id
}

func (e *consoleResetEnv) tenantName(t *testing.T, tenantID int64) string {
	t.Helper()
	var name string
	if err := e.pool.QueryRow(e.ctx, `SELECT name FROM tenants WHERE id = $1`, tenantID).Scan(&name); err != nil {
		t.Fatalf("read tenant name: %v", err)
	}
	return name
}

func (e *consoleResetEnv) passwordHash(t *testing.T, userID int64) string {
	t.Helper()
	var h string
	if err := e.pool.QueryRow(e.ctx, `SELECT password_hash FROM user_credentials WHERE user_id = $1`, userID).Scan(&h); err != nil {
		t.Fatalf("read credential: %v", err)
	}
	return h
}

// consoleResetToken pulls the raw token out of an emailed reset link, asserting the
// link opens the console page rather than the API path (GHSA-2267-r48x-9fh2).
func consoleResetToken(t *testing.T, link string) string {
	t.Helper()
	if !strings.HasPrefix(link, consoleDashboardURL+"/reset-password?token=") {
		t.Fatalf("reset link = %q, want %s/reset-password?token=…", link, consoleDashboardURL)
	}
	u, err := url.Parse(link)
	if err != nil {
		t.Fatalf("parse reset link: %v", err)
	}
	return u.Query().Get("token")
}

func TestForgotPasswordFirstParty_OneEmailPerAccount_EachTokenResetsOnlyItsOwn(t *testing.T) {
	e := newConsoleResetEnv(t)
	tenantA := e.tenant(t, "console-a", true)
	tenantB := e.tenant(t, "console-b", true)
	email := uniqueEmail("console-two-tenants")
	userA := e.user(t, tenantA, nil, email, true)
	userB := e.user(t, tenantB, nil, email, true)

	// Case and padding normalise, as on every other email path.
	issued, err := e.svc.ForgotPasswordFirstParty(e.ctx, "  "+strings.ToUpper(email)+" ")
	if err != nil {
		t.Fatalf("ForgotPasswordFirstParty: %v", err)
	}
	if len(issued) != 2 || issued[0] != min(tenantA, tenantB) || issued[1] != max(tenantA, tenantB) {
		t.Errorf("issued tenants = %v, want both %d and %d", issued, tenantA, tenantB)
	}
	if len(e.mail.resets) != 2 {
		t.Fatalf("reset emails sent = %d, want one per account (2)", len(e.mail.resets))
	}
	// Each email names its own tenant, or the recipient cannot tell which link
	// resets which account. The emails are in tenant-id order.
	wantNames := []string{e.tenantName(t, min(tenantA, tenantB)), e.tenantName(t, max(tenantA, tenantB))}
	for i, r := range e.mail.resets {
		if r.To != email {
			t.Errorf("reset email To = %q, want %q", r.To, email)
		}
		if r.TenantName != wantNames[i] {
			t.Errorf("email %d TenantName = %q, want %q", i+1, r.TenantName, wantNames[i])
		}
	}

	// The emails are in tenant-id order; map each token to the account it names
	// by redeeming it and seeing which credential changed.
	first := consoleResetToken(t, e.mail.resets[0].ResetLink)
	second := consoleResetToken(t, e.mail.resets[1].ResetLink)
	if first == second {
		t.Fatal("both emails carry the same token; each account must get its own")
	}

	// Redeemed unscoped, exactly as a browser calls POST /auth/reset-password.
	if err := e.svc.ResetPassword(e.ctx, auth.ResetPasswordInput{RawToken: first, NewPassword: "Brand-New-Passw0rd!"}); err != nil {
		t.Fatalf("ResetPassword(first token): %v", err)
	}
	firstUser, otherUser := userA, userB
	if tenantB < tenantA {
		firstUser, otherUser = userB, userA
	}
	if e.passwordHash(t, firstUser) == "original-hash" {
		t.Error("first token did not reset its own account")
	}
	if e.passwordHash(t, otherUser) != "original-hash" {
		t.Error("first token changed the OTHER tenant's account; a token must reset exactly one account")
	}

	if err := e.svc.ResetPassword(e.ctx, auth.ResetPasswordInput{RawToken: second, NewPassword: "Another-New-Passw0rd!"}); err != nil {
		t.Fatalf("ResetPassword(second token): %v", err)
	}
	if e.passwordHash(t, otherUser) == "original-hash" {
		t.Error("second token did not reset its own account")
	}
}

func TestForgotPasswordFirstParty_SendsNothingForAccountsItMustNotReach(t *testing.T) {
	e := newConsoleResetEnv(t)
	tenant := e.tenant(t, "console-none", true)
	inactiveTenant := e.tenant(t, "console-off", false)
	appID := e.app(t, tenant)

	appOnly := uniqueEmail("console-app-only")
	e.user(t, tenant, &appID, appOnly, true)

	inactive := uniqueEmail("console-inactive")
	e.user(t, tenant, nil, inactive, false)

	deleted := uniqueEmail("console-deleted")
	deletedID := e.user(t, tenant, nil, deleted, true)
	if _, err := e.pool.Exec(e.ctx, `UPDATE users SET deleted_at = NOW() WHERE id = $1`, deletedID); err != nil {
		t.Fatalf("soft-delete user: %v", err)
	}

	inTenantOff := uniqueEmail("console-tenant-off")
	e.user(t, inactiveTenant, nil, inTenantOff, true)

	for name, email := range map[string]string{
		"unknown email":              uniqueEmail("console-nobody"),
		"application-scoped only":    appOnly,
		"inactive account":           inactive,
		"soft-deleted account":       deleted,
		"account in inactive tenant": inTenantOff,
	} {
		t.Run(name, func(t *testing.T) {
			before := len(e.mail.resets)
			issued, err := e.svc.ForgotPasswordFirstParty(e.ctx, email)
			if err != nil {
				t.Fatalf("ForgotPasswordFirstParty: %v, want nil (RESET-03)", err)
			}
			if len(issued) != 0 {
				t.Errorf("issued = %v, want none", issued)
			}
			if got := len(e.mail.resets) - before; got != 0 {
				t.Errorf("reset emails sent = %d, want 0", got)
			}
		})
	}
}

func TestForgotPasswordFirstParty_CapsTheFanOut(t *testing.T) {
	e := newConsoleResetEnv(t)
	email := uniqueEmail("console-fanout")
	for i := 0; i < auth.MaxConsoleResetFanOut+2; i++ {
		e.user(t, e.tenant(t, fmt.Sprintf("console-fan-%d", i), true), nil, email, true)
	}

	issued, err := e.svc.ForgotPasswordFirstParty(e.ctx, email)
	if err != nil {
		t.Fatalf("ForgotPasswordFirstParty: %v", err)
	}
	if len(issued) != auth.MaxConsoleResetFanOut {
		t.Errorf("issued = %d tokens, want the cap (%d)", len(issued), auth.MaxConsoleResetFanOut)
	}
	if len(e.mail.resets) != auth.MaxConsoleResetFanOut {
		t.Errorf("reset emails sent = %d, want the cap (%d)", len(e.mail.resets), auth.MaxConsoleResetFanOut)
	}
}

// failingResetMailer refuses every reset email, as SendGrid does when the
// server reaches it without logging in (550 "Unauthenticated senders not
// allowed") - which is how this case was found.
type failingResetMailer struct{ captureMailer }

func (m *failingResetMailer) SendReset(context.Context, *mailer.SMTPConfig, *mailer.Template, mailer.ResetEmail) error {
	return errors.New("550 Unauthenticated senders not allowed")
}

// TestForgotPasswordFirstParty_FailedSendIsStillReportedIssued pins that a
// stored token is reported - and so audited - even when its email could not be
// sent. The token is live and redeemable; leaving it out of the audit trail
// would hide a credential that exists.
func TestForgotPasswordFirstParty_FailedSendIsStillReportedIssued(t *testing.T) {
	e := newConsoleResetEnv(t)
	tenant := e.tenant(t, "console-sendfail", true)
	email := uniqueEmail("console-sendfail")
	userID := e.user(t, tenant, nil, email, true)
	svc := auth.NewResetService(e.pool, &failingResetMailer{}, "http://localhost:8080", testhelper.TestLogger()).
		WithDashboardURL(consoleDashboardURL)

	issued, err := svc.ForgotPasswordFirstParty(e.ctx, email)
	if err != nil {
		t.Fatalf("ForgotPasswordFirstParty: %v, want nil (RESET-03)", err)
	}
	if len(issued) != 1 || issued[0] != tenant {
		t.Errorf("issued = %v, want [%d]: the token was stored, so it must be audited", issued, tenant)
	}
	var tokens int
	if err := e.pool.QueryRow(e.ctx, `SELECT count(*) FROM password_reset_tokens WHERE user_id = $1`, userID).Scan(&tokens); err != nil {
		t.Fatalf("count tokens: %v", err)
	}
	if tokens != 1 {
		t.Errorf("stored tokens = %d, want 1", tokens)
	}
}

// TestForgotPasswordFirstParty_CooldownBoundsMailPerAccount pins that a request
// inside ConsoleResetCooldown mails no account that was just mailed. The
// per-email rate limit counts requests, and one request mails every account the
// address owns, so without the cooldown the inbox would get one email per
// account per allowed request.
func TestForgotPasswordFirstParty_CooldownBoundsMailPerAccount(t *testing.T) {
	e := newConsoleResetEnv(t)
	email := uniqueEmail("console-cooldown")
	userA := e.user(t, e.tenant(t, "console-cool-a", true), nil, email, true)
	e.user(t, e.tenant(t, "console-cool-b", true), nil, email, true)

	if issued, err := e.svc.ForgotPasswordFirstParty(e.ctx, email); err != nil || len(issued) != 2 {
		t.Fatalf("first request: issued %v, err %v; want both accounts", issued, err)
	}
	if issued, err := e.svc.ForgotPasswordFirstParty(e.ctx, email); err != nil || len(issued) != 0 {
		t.Fatalf("request inside the cooldown: issued %v, err %v; want none", issued, err)
	}
	if len(e.mail.resets) != 2 {
		t.Fatalf("reset emails sent = %d, want 2 (none for the second request)", len(e.mail.resets))
	}

	// The cooldown is per account: once account A's token is older than the
	// window, A is mailed again and B, still inside it, is not.
	if _, err := e.pool.Exec(e.ctx,
		`UPDATE password_reset_tokens SET created_at = NOW() - $2 * INTERVAL '1 second' WHERE user_id = $1`,
		userA, int64(2*auth.ConsoleResetCooldown/time.Second)); err != nil {
		t.Fatalf("age token: %v", err)
	}
	issued, err := e.svc.ForgotPasswordFirstParty(e.ctx, email)
	if err != nil || len(issued) != 1 {
		t.Fatalf("after A's cooldown: issued %v, err %v; want exactly account A", issued, err)
	}
}

// templateCaptureMailer records the template each reset email was sent with.
type templateCaptureMailer struct {
	captureMailer
	templates []*mailer.Template
}

func (m *templateCaptureMailer) SendReset(ctx context.Context, sender *mailer.SMTPConfig, tmpl *mailer.Template, e mailer.ResetEmail) error {
	m.templates = append(m.templates, tmpl)
	return m.captureMailer.SendReset(ctx, sender, tmpl, e)
}

// TestForgotPasswordFirstParty_IgnoresTenantTemplateSettings pins that a
// tenant's password_reset template settings do not reach platform console
// accounts. A tenant that turns the template off because its applications send
// their own reset email must not lock its console administrators out of reset,
// and a tenant's branding must not be put on a platform email.
func TestForgotPasswordFirstParty_IgnoresTenantTemplateSettings(t *testing.T) {
	e := newConsoleResetEnv(t)
	tenant := e.tenant(t, "console-tmpl", true)
	email := uniqueEmail("console-tmpl")
	e.user(t, tenant, nil, email, true)
	for _, active := range []bool{false, true} {
		if _, err := e.pool.Exec(e.ctx, `
			INSERT INTO email_templates (tenant_id, template_type, subject, html_body, is_active)
			VALUES ($1, 'password_reset', 'Tenant subject', '<p>tenant body</p>', $2)
			ON CONFLICT (tenant_id, template_type) WHERE application_id IS NULL
			DO UPDATE SET is_active = EXCLUDED.is_active
		`, tenant, active); err != nil {
			t.Fatalf("store tenant template: %v", err)
		}
		mail := &templateCaptureMailer{}
		svc := auth.NewResetService(e.pool, mail, "http://localhost:8080", testhelper.TestLogger()).
			WithDashboardURL(consoleDashboardURL).
			WithTemplates(auth.NewEmailTemplateService(e.pool, testhelper.TestLogger()))
		if _, err := e.pool.Exec(e.ctx, `DELETE FROM password_reset_tokens WHERE tenant_id = $1`, tenant); err != nil {
			t.Fatalf("clear cooldown: %v", err)
		}

		issued, err := svc.ForgotPasswordFirstParty(e.ctx, email)
		if err != nil || len(issued) != 1 {
			t.Fatalf("tenant template active=%v: issued %v, err %v; want the console account mailed", active, issued, err)
		}
		if len(mail.templates) != 1 || mail.templates[0] != nil {
			t.Errorf("tenant template active=%v: sent with %v, want the built-in platform template (nil)", active, mail.templates)
		}
	}
}
