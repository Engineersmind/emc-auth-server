package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/engineersmind/emc-auth-server/internal/admin"
	"github.com/engineersmind/emc-auth-server/internal/audit"
	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/mailer"
	"github.com/engineersmind/emc-auth-server/internal/store"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// Handler-level coverage for the test-send endpoint. Every finding in the PR #91
// review lived here — the 409 guard, allow_inherited, recipient normalization,
// the external-recipient content restriction — and none of it had a test. The
// 409 and validation paths return before SendTest is ever called, so they need
// no live provider.

// recordingMailer captures what SendTest was asked to deliver.
type recordingMailer struct {
	calls []struct {
		Sender *mailer.SMTPConfig
		Tmpl   *mailer.Template
		Type   mailer.TemplateType
		To     string
	}
	err error
}

func (m *recordingMailer) SendVerification(context.Context, *mailer.SMTPConfig, *mailer.Template, mailer.VerificationEmail) error {
	return nil
}
func (m *recordingMailer) SendReset(context.Context, *mailer.SMTPConfig, *mailer.Template, mailer.ResetEmail) error {
	return nil
}
func (m *recordingMailer) SendWelcome(context.Context, *mailer.SMTPConfig, *mailer.Template, mailer.WelcomeEmail) error {
	return nil
}
func (m *recordingMailer) SendMFACode(context.Context, *mailer.SMTPConfig, *mailer.Template, mailer.MFACodeEmail) error {
	return nil
}
func (m *recordingMailer) SendMagicLink(context.Context, *mailer.SMTPConfig, *mailer.Template, mailer.MagicLinkEmail) error {
	return nil
}
func (m *recordingMailer) SendPasswordChanged(context.Context, *mailer.SMTPConfig, *mailer.Template, mailer.PasswordChangedEmail) error {
	return nil
}
func (m *recordingMailer) SendInvitation(context.Context, *mailer.SMTPConfig, *mailer.Template, mailer.InvitationEmail) error {
	return nil
}
func (m *recordingMailer) SendChangeEmail(context.Context, *mailer.SMTPConfig, *mailer.Template, mailer.ChangeEmailEmail) error {
	return nil
}
func (m *recordingMailer) SendBlockedAccount(context.Context, *mailer.SMTPConfig, *mailer.Template, mailer.BlockedAccountEmail) error {
	return nil
}
func (m *recordingMailer) SendPasswordBreach(context.Context, *mailer.SMTPConfig, *mailer.Template, mailer.PasswordBreachEmail) error {
	return nil
}
func (m *recordingMailer) GlobalProvider() string { return "sendgrid" }

func (m *recordingMailer) SendTest(_ context.Context, sender *mailer.SMTPConfig, tmpl *mailer.Template, tt mailer.TemplateType, to string) error {
	m.calls = append(m.calls, struct {
		Sender *mailer.SMTPConfig
		Tmpl   *mailer.Template
		Type   mailer.TemplateType
		To     string
	}{sender, tmpl, tt, to})
	return m.err
}

var errProviderRawDetail = errors.New(`smtp send: dial tcp smtp.internal.example:587: auth user apikey failed`)

type testSendEnv struct {
	h        *AdminHandler
	mail     *recordingMailer
	tenantID int64
	appRowID int64
	claims   *auth.Claims
	svc      *auth.EmailSenderService
	ctx      context.Context
}

func newTestSendEnv(t *testing.T) *testSendEnv {
	t.Helper()
	pool := testhelper.NewTestDB(t)
	logger := testhelper.TestLogger()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)

	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}
	t.Cleanup(func() { testhelper.CleanupTables(t, pool) })

	var tenantID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM tenants WHERE slug = 'emc'`).Scan(&tenantID); err != nil {
		t.Fatalf("tenant id: %v", err)
	}
	var appRowID int64
	err := pool.QueryRow(ctx, `
		INSERT INTO oauth_clients (tenant_id, name, app_type, client_id, scopes)
		VALUES ($1, 'Test Send App', 'web', 'test_send_client', '{}')
		RETURNING id
	`, tenantID).Scan(&appRowID)
	if err != nil {
		t.Fatalf("seed application: %v", err)
	}

	// The sender service reuses the TOTP encryption key; a fixed all-zero dev
	// key keeps these tests independent of the environment.
	totpSvc, err := auth.NewTOTPService(pool, strings.Repeat("0", 64), logger)
	if err != nil {
		t.Fatalf("NewTOTPService: %v", err)
	}
	senderSvc := auth.NewEmailSenderService(pool, totpSvc.EncryptionKey(), logger)
	rec := &recordingMailer{}

	// A real audit logger is required: the success path audits, and a nil
	// *audit.Logger nil-pointer dereferences inside Log(). Drained on cleanup so
	// events are flushed before the tables are truncated.
	auditLog := audit.New(pool, logger, audit.WithFlushInterval(20*time.Millisecond))
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer ccancel()
		_ = auditLog.Close(cctx)
	})

	// WithApplications is required, not optional: the app-scoped routes go
	// through emailSenderScope → applicationOwnedByTenant → appSvc, which nil
	// pointer dereferences when unset.
	h := NewAdminHandler(admin.New(pool, nil, logger), auditLog, logger).
		WithApplications(auth.NewApplicationService(pool, logger)).
		WithEmailSenders(senderSvc).
		WithMailer(rec)

	return &testSendEnv{
		h:        h,
		mail:     rec,
		tenantID: tenantID,
		appRowID: appRowID,
		claims: &auth.Claims{
			UserID:   "1",
			TenantID: strconv.FormatInt(tenantID, 10),
			Email:    "owner@emc.local",
		},
		svc: senderSvc,
		ctx: ctx,
	}
}

// post drives SendTestEmail with the given body against either the application
// scope (appScoped=true) or the tenant scope.
func (e *testSendEnv) post(t *testing.T, body string, appScoped bool) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	ec := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := ec.NewContext(req, rec)
	c.Set("user", e.claims)

	names := []string{"tid"}
	vals := []string{strconv.FormatInt(e.tenantID, 10)}
	if appScoped {
		names = append(names, "appID")
		vals = append(vals, strconv.FormatInt(e.appRowID, 10))
	}
	c.SetParamNames(names...)
	c.SetParamValues(vals...)

	if err := e.h.SendTestEmail(c); err != nil {
		t.Fatalf("SendTestEmail: %v", err)
	}
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out
}

func (e *testSendEnv) configureSender(t *testing.T, appRowID *int64, key string, active bool) {
	t.Helper()
	if _, err := e.svc.Upsert(e.ctx, e.tenantID, appRowID, auth.UpsertSenderInput{
		Provider:    auth.SenderProviderSendGrid,
		FromAddress: "no-reply@acme.com",
		APIKey:      key,
		IsActive:    &active,
	}, nil); err != nil {
		t.Fatalf("Upsert sender: %v", err)
	}
}

// ─── The 409 guard ──────────────────────────────────────────────────────────

func TestSendTest409WhenApplicationHasNoSenderOfItsOwn(t *testing.T) {
	e := newTestSendEnv(t)
	e.configureSender(t, nil, "SG.tenant-key", true) // tenant only

	rec, body := e.post(t, `{}`, true)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body = %v", rec.Code, body)
	}
	if len(e.mail.calls) != 0 {
		t.Error("the send happened despite the 409 — the guard must return before SendTest")
	}
	if got, _ := body["scope"].(string); got != auth.SenderScopeTenant {
		t.Errorf("scope = %q, want %q", got, auth.SenderScopeTenant)
	}
}

func TestSendTestAllowInheritedOptsOutOfThe409(t *testing.T) {
	e := newTestSendEnv(t)
	e.configureSender(t, nil, "SG.tenant-key", true)

	rec, body := e.post(t, `{"allow_inherited":true}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %v", rec.Code, body)
	}
	if len(e.mail.calls) != 1 {
		t.Fatalf("SendTest called %d times, want 1", len(e.mail.calls))
	}
	if got, _ := body["scope"].(string); got != auth.SenderScopeTenant {
		t.Errorf("scope = %q, want the honest %q", got, auth.SenderScopeTenant)
	}
}

// The regression the review caught: a tenant-addressed test on a stock install
// (provider via env vars, no sender row) must NOT 409 — tenant → global is the
// documented default, not a fall-through.
func TestSendTestTenantScopeDoesNotRequireASenderRow(t *testing.T) {
	e := newTestSendEnv(t)

	rec, body := e.post(t, `{}`, false)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for a stock single-tenant install; body = %v", rec.Code, body)
	}
	if got, _ := body["scope"].(string); got != auth.SenderScopeGlobal {
		t.Errorf("scope = %q, want %q", got, auth.SenderScopeGlobal)
	}
}

// An inactive application row must not satisfy the guard — this is the handler
// half of the is_active divergence bug.
func TestSendTest409WhenApplicationSenderIsInactive(t *testing.T) {
	e := newTestSendEnv(t)
	e.configureSender(t, nil, "SG.tenant-key", true)
	e.configureSender(t, &e.appRowID, "SG.app-key", false) // present but off

	rec, body := e.post(t, `{}`, true)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 for an inactive app sender; body = %v", rec.Code, body)
	}
	if len(e.mail.calls) != 0 {
		t.Error("sent on inherited credentials while addressed to the application")
	}
}

func TestSendTestSucceedsOnTheApplicationsOwnSender(t *testing.T) {
	e := newTestSendEnv(t)
	e.configureSender(t, &e.appRowID, "SG.app-key", true)

	rec, body := e.post(t, `{}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %v", rec.Code, body)
	}
	if got, _ := body["scope"].(string); got != auth.SenderScopeApplication {
		t.Errorf("scope = %q, want %q", got, auth.SenderScopeApplication)
	}
	if e.mail.calls[0].Sender == nil || e.mail.calls[0].Sender.APIKey != "SG.app-key" {
		t.Error("sent with credentials that are not the application's own")
	}
}

// ─── Recipient handling ─────────────────────────────────────────────────────

func TestSendTestDefaultsRecipientToTheCaller(t *testing.T) {
	e := newTestSendEnv(t)
	rec, _ := e.post(t, `{}`, false)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if e.mail.calls[0].To != "owner@emc.local" {
		t.Errorf("recipient = %q, want the caller's own address", e.mail.calls[0].To)
	}
}

// ParseAddress accepts a display name; carrying that form onward would put
// attacker-chosen text into the SMTP envelope, the provider payload, the JSON
// response and the audit record.
func TestSendTestNormalizesADisplayNameRecipient(t *testing.T) {
	e := newTestSendEnv(t)
	rec, body := e.post(t, `{"to":"\"Verify Your Account\" <attacker@evil.example>"}`, false)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %v", rec.Code, body)
	}
	if got := e.mail.calls[0].To; got != "attacker@evil.example" {
		t.Errorf("recipient = %q, want the bare parsed address", got)
	}
	if got, _ := body["to"].(string); got != "attacker@evil.example" {
		t.Errorf("response to = %q, want the bare parsed address", got)
	}
}

func TestSendTestRejectsAnInvalidRecipient(t *testing.T) {
	e := newTestSendEnv(t)
	rec, _ := e.post(t, `{"to":"not-an-email"}`, false)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if len(e.mail.calls) != 0 {
		t.Error("sent despite an invalid recipient")
	}
}

// ─── External recipients get built-in content only ──────────────────────────

// The security fix from the review: template bodies are editable at this same
// permission level, so an arbitrary recipient plus an arbitrary template would
// make this a phishing relay from a verified sender identity.
func TestSendTestForcesTheDiagnosticTemplateForExternalRecipients(t *testing.T) {
	e := newTestSendEnv(t)

	rec, body := e.post(t, `{"to":"victim@elsewhere.example","template_type":"welcome"}`, false)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %v", rec.Code, body)
	}
	call := e.mail.calls[0]
	if call.Type != mailer.TemplateProviderTest {
		t.Errorf("template = %q for an external recipient, want %q — attacker-authored content must not reach third parties", call.Type, mailer.TemplateProviderTest)
	}
	if call.Tmpl != nil {
		t.Error("a per-scope template override was resolved for an external recipient")
	}
	if got, _ := body["template"].(string); got != string(mailer.TemplateProviderTest) {
		t.Errorf("response template = %q, want the diagnostic template", got)
	}
}

// Sending a real template to yourself stays available — that is the preview use
// case, and it reaches nobody else.
func TestSendTestKeepsRealTemplatesForSelfSends(t *testing.T) {
	e := newTestSendEnv(t)

	rec, _ := e.post(t, `{"to":"owner@emc.local","template_type":"welcome"}`, false)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := e.mail.calls[0].Type; got != mailer.TemplateWelcome {
		t.Errorf("template = %q for a self-send, want %q", got, mailer.TemplateWelcome)
	}
}

func TestSendTestRejectsAnUnknownTemplateType(t *testing.T) {
	e := newTestSendEnv(t)
	rec, _ := e.post(t, `{"template_type":"no-such-thing"}`, false)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// ─── Provider failure mapping ───────────────────────────────────────────────

func TestSendTestMapsCredentialRejectionToAnActionableMessage(t *testing.T) {
	e := newTestSendEnv(t)
	e.mail.err = mailer.ErrProviderAuth

	rec, body := e.post(t, `{}`, false)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
	msg, _ := body["error"].(string)
	if !strings.Contains(msg, "credentials") {
		t.Errorf("error = %q, want it to name the credentials", msg)
	}
}

func TestSendTestMapsSenderRejectionToAnActionableMessage(t *testing.T) {
	e := newTestSendEnv(t)
	e.mail.err = mailer.ErrProviderSender

	_, body := e.post(t, `{}`, false)
	msg, _ := body["error"].(string)
	if !strings.Contains(msg, "From address") {
		t.Errorf("error = %q, want it to name the From address", msg)
	}
}

// Unclassified failures must not leak the upstream body — go-mail error text can
// carry the SMTP host, port and username.
func TestSendTestDoesNotEchoRawProviderErrors(t *testing.T) {
	e := newTestSendEnv(t)
	e.mail.err = errProviderRawDetail

	_, body := e.post(t, `{}`, false)
	msg, _ := body["error"].(string)
	if strings.Contains(msg, "smtp.internal.example") || strings.Contains(msg, "apikey") {
		t.Errorf("error leaked upstream detail: %q", msg)
	}
	if !strings.Contains(msg, "see server logs") {
		t.Errorf("error = %q, want the generic message", msg)
	}
}

// A service token carries no email, so ownEmail is "" and ANY supplied
// recipient must count as external. Documented explicitly (PR #91 FLAG-1)
// because the alternative reading — empty ownEmail matching an empty-ish
// recipient, or a refactor treating "" as "self" — would silently reopen the
// arbitrary-content path for exactly the least attributable caller.
func TestSendTestTreatsAnyRecipientAsExternalForATokenWithNoEmail(t *testing.T) {
	e := newTestSendEnv(t)
	e.claims.Email = "" // service token: client_id in UserID, no email claim

	rec, body := e.post(t, `{"to":"someone@elsewhere.example","template_type":"welcome"}`, false)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %v", rec.Code, body)
	}
	call := e.mail.calls[0]
	if call.Type != mailer.TemplateProviderTest {
		t.Errorf("template = %q, want %q — an email-less caller must never be able to send a real template outward", call.Type, mailer.TemplateProviderTest)
	}
	if call.Tmpl != nil {
		t.Error("a per-scope override was resolved for an email-less caller")
	}
}

// The mirror case: with no email claim there is no self-send, so omitting the
// recipient has nothing to fall back to and must 400 rather than attempt a
// send to "".
func TestSendTestRejectsOmittedRecipientWhenCallerHasNoEmail(t *testing.T) {
	e := newTestSendEnv(t)
	e.claims.Email = ""

	rec, _ := e.post(t, `{}`, false)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if len(e.mail.calls) != 0 {
		t.Error("attempted a send with no resolvable recipient")
	}
}
