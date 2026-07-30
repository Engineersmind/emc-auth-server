package mailer

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

// ─── Provider failure classification ────────────────────────────────────────
//
// An admin pressing "send test" can act on exactly two failures: bad
// credentials and an unverified From address. Everything else is noise to them.
// These tests pin the classification so the API keeps saying WHICH one it is
// instead of regressing to echoing a raw upstream body.

// sendGridStub serves one canned response from a fake SendGrid endpoint.
func sendGridStub(t *testing.T, status int, body string) *sendGridTransport {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return &sendGridTransport{
		apiKey:     "SG.test-key",
		endpoint:   srv.URL,
		httpClient: srv.Client(),
		logger:     zerolog.Nop(),
	}
}

func testMessage() outMessage {
	return outMessage{
		From:    "sender@example.com",
		To:      "admin@example.com",
		Subject: "Test",
		HTML:    "<p>hi</p>",
		Text:    "hi",
	}
}

func TestSendGridClassifiesCredentialRejection(t *testing.T) {
	// The exact body the live API returned for the revoked key that prompted
	// this work.
	tr := sendGridStub(t, http.StatusUnauthorized,
		`{"errors":[{"message":"The provided authorization grant is invalid, expired, or revoked","field":null,"help":null}]}`)

	err := tr.send(context.Background(), testMessage())
	if !errors.Is(err, ErrProviderAuth) {
		t.Fatalf("error = %v, want ErrProviderAuth", err)
	}
	if errors.Is(err, ErrProviderSender) {
		t.Error("a 401 was also classified as a sender-identity problem")
	}
}

func TestSendGridClassifiesUnverifiedSender(t *testing.T) {
	tr := sendGridStub(t, http.StatusForbidden,
		`{"errors":[{"message":"The from address does not match a verified Sender Identity","field":"from","help":null}]}`)

	err := tr.send(context.Background(), testMessage())
	if !errors.Is(err, ErrProviderSender) {
		t.Fatalf("error = %v, want ErrProviderSender", err)
	}
	if errors.Is(err, ErrProviderAuth) {
		t.Error("an unverified sender was also classified as a credential problem — the two have different fixes")
	}
}

// A 403 that is NOT about the sender is an under-scoped key, which is a
// credential problem the admin fixes in the same place as a bad key.
func TestSendGridClassifiesUnderScopedKeyAsAuth(t *testing.T) {
	tr := sendGridStub(t, http.StatusForbidden,
		`{"errors":[{"message":"access forbidden","field":null,"help":null}]}`)

	err := tr.send(context.Background(), testMessage())
	if !errors.Is(err, ErrProviderAuth) {
		t.Fatalf("error = %v, want ErrProviderAuth", err)
	}
}

// Failures the admin cannot act on must NOT be dressed up as credential
// problems — sending them to "check your API key" wastes the one clue they had.
func TestSendGridDoesNotMisclassifyOtherFailures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"bad request", http.StatusBadRequest, `{"errors":[{"message":"Invalid type. Expected: string"}]}`},
		{"rate limited", http.StatusTooManyRequests, `{"errors":[{"message":"too many requests"}]}`},
		{"provider outage", http.StatusServiceUnavailable, `service unavailable`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr := sendGridStub(t, tc.status, tc.body)
			err := tr.send(context.Background(), testMessage())
			if err == nil {
				t.Fatal("expected an error")
			}
			if errors.Is(err, ErrProviderAuth) || errors.Is(err, ErrProviderSender) {
				t.Errorf("status %d misclassified as a credential/sender problem: %v", tc.status, err)
			}
		})
	}
}

// ─── Credential trimming ────────────────────────────────────────────────────

// A key pasted with a trailing newline is the single most common cause of an
// otherwise inexplicable 401: the whitespace is invisible everywhere except in
// the Authorization header. Trimming happens at the transport boundary so both
// the global config and per-scope senders are covered.
func TestPickTransportTrimsCredentials(t *testing.T) {
	sg := pickTransport(&SMTPConfig{
		Provider: " sendgrid\n",
		APIKey:   "  SG.pasted-with-whitespace\n",
	}, zerolog.Nop())

	sgTr, ok := sg.(*sendGridTransport)
	if !ok {
		t.Fatalf("provider %q with surrounding whitespace did not resolve to the SendGrid transport (got %T)", " sendgrid\n", sg)
	}
	if sgTr.apiKey != "SG.pasted-with-whitespace" {
		t.Errorf("apiKey = %q, want it trimmed", sgTr.apiKey)
	}

	smtpTr, ok := pickTransport(&SMTPConfig{
		Provider: "smtp",
		Host:     " smtp.example.com ",
		Username: " apikey\n",
		Password: "\tsecret \n",
	}, zerolog.Nop()).(*smtpTransport)
	if !ok {
		t.Fatal("expected an smtpTransport")
	}
	if smtpTr.host != "smtp.example.com" || smtpTr.username != "apikey" || smtpTr.password != "secret" {
		t.Errorf("host=%q username=%q password=%q — all should be trimmed", smtpTr.host, smtpTr.username, smtpTr.password)
	}
}

func TestNewMailerTrimsGlobalCredentials(t *testing.T) {
	built, ok := NewMailer(MailerConfig{
		Provider:       "sendgrid",
		SendGridAPIKey: "  SG.env-with-trailing-newline\n",
		EmailFrom:      "sender@example.com",
		Logger:         zerolog.Nop(),
	}).(*mailerImpl)
	if !ok {
		t.Fatal("NewMailer did not return a *mailerImpl")
	}

	tr, ok := built.globalTr.(*sendGridTransport)
	if !ok {
		t.Fatalf("global transport = %T, want *sendGridTransport", built.globalTr)
	}
	if tr.apiKey != "SG.env-with-trailing-newline" {
		t.Errorf("global apiKey = %q, want it trimmed", tr.apiKey)
	}
}

// GlobalProvider must report "dev" rather than "" when nothing is configured:
// a test that "succeeds" without transmitting anything is the most confusing
// possible result, so the response has to name it.
func TestGlobalProviderNamesTheDevTransport(t *testing.T) {
	m := NewMailer(MailerConfig{EmailFrom: "sender@example.com", Logger: zerolog.Nop()})
	if got := m.GlobalProvider(); got != "dev" {
		t.Errorf("GlobalProvider() = %q with nothing configured, want %q", got, "dev")
	}

	sg := NewMailer(MailerConfig{
		Provider:       "sendgrid",
		SendGridAPIKey: "SG.key",
		EmailFrom:      "sender@example.com",
		Logger:         zerolog.Nop(),
	})
	if got := sg.GlobalProvider(); got != ProviderSendGrid {
		t.Errorf("GlobalProvider() = %q, want %q", got, ProviderSendGrid)
	}
}

// ─── Diagnostic test template ───────────────────────────────────────────────
//
// The admin "send test" action used to render email_verification, so the
// recipient received a genuine-looking "Verify your email address" message
// containing a dead sample link. That is worse than useless: it trains people
// to click verification links that go nowhere, and an admin checking their
// inbox cannot distinguish a configuration test from a real verification bug.

// sendTestVia runs SendTest against the capturing mailer from
// templates_flows_test.go, so the rendered message can be inspected with no
// network involved.
func sendTestVia(t *testing.T, tt TemplateType) outMessage {
	t.Helper()
	m, tr := newCapturingMailer()
	if err := m.SendTest(context.Background(), nil, nil, tt, "admin@example.com"); err != nil {
		t.Fatalf("SendTest(%q): %v", tt, err)
	}
	if len(tr.msgs) != 1 {
		t.Fatalf("captured %d messages, want 1", len(tr.msgs))
	}
	return tr.msgs[0]
}

func TestProviderTestTemplateAnnouncesItselfAsATest(t *testing.T) {
	msg := sendTestVia(t, TemplateProviderTest)

	if msg.Subject != "Test email" {
		t.Errorf("subject = %q, want %q", msg.Subject, "Test email")
	}
	// The failure this guards: a recipient being asked to verify an address.
	for _, banned := range []string{"Verify", "verify", "Confirm your email"} {
		if strings.Contains(msg.HTML, banned) || strings.Contains(msg.Text, banned) {
			t.Errorf("diagnostic email contains %q — it must not read as a verification email", banned)
		}
	}
	// No call to action at all: a dead sample link is the thing that made the
	// old behaviour actively misleading.
	if strings.Contains(msg.HTML, "SAMPLE_TOKEN") || strings.Contains(msg.Text, "SAMPLE_TOKEN") {
		t.Error("diagnostic email contains a sample action link — it should have no link")
	}
	if !strings.Contains(msg.Text, "test message") {
		t.Errorf("diagnostic email does not describe itself as a test:\n%s", msg.Text)
	}
	// Branding still applies, so it looks like it came from the product.
	if !strings.Contains(msg.Text, defaultProductName) {
		t.Errorf("diagnostic email missing product branding:\n%s", msg.Text)
	}
}

// An unrecognised template type must degrade to the diagnostic email, never to
// a real account email — the old fallback was email_verification.
func TestSendTestFallsBackToTheDiagnosticTemplate(t *testing.T) {
	msg := sendTestVia(t, TemplateType("no-such-template"))

	if msg.Subject != "Test email" {
		t.Errorf("subject = %q for an unknown type, want the diagnostic %q", msg.Subject, "Test email")
	}
}

// A real template type still renders that template — the Templates screen
// depends on it to preview actual content.
func TestSendTestStillRendersARequestedRealTemplate(t *testing.T) {
	msg := sendTestVia(t, TemplateWelcome)

	if msg.Subject == "Test email" {
		t.Error("an explicitly requested template was replaced by the diagnostic email")
	}
}

// The diagnostic type must stay out of the customizable set, or it shows up in
// the template editor and becomes overridable — at which point "send test" can
// be made to say anything.
func TestProviderTestTemplateIsNotCustomizable(t *testing.T) {
	if ValidTemplateType(TemplateProviderTest) {
		t.Error("TemplateProviderTest is in AllTemplateTypes — it would appear in the template editor and be overridable")
	}
	for _, tt := range AllTemplateTypes {
		if tt == TemplateProviderTest {
			t.Fatal("TemplateProviderTest listed in AllTemplateTypes")
		}
	}
	// It must still have a built-in, or every test send fails at dispatch.
	if _, ok := builtinTemplates[TemplateProviderTest]; !ok {
		t.Error("TemplateProviderTest has no built-in template")
	}
}
