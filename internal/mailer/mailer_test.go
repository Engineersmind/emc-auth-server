package mailer

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

// newTestLogger returns a discard logger for tests.
func newTestLogger() zerolog.Logger {
	return zerolog.New(zerolog.NewTestWriter(nil)).Level(zerolog.Disabled)
}

// globalTransport reaches into the concrete mailer to inspect which transport
// the global provider resolved to.
func globalTransport(t *testing.T, m Mailer) transport {
	t.Helper()
	mi, ok := m.(*mailerImpl)
	if !ok {
		t.Fatalf("NewMailer returned %T, want *mailerImpl", m)
	}
	return mi.globalTr
}

// TestNewMailer_SelectsTransport proves provider inference: SendGrid key →
// sendgrid, else SMTP host → smtp, else log-only dev transport (any Env).
func TestNewMailer_SelectsTransport(t *testing.T) {
	logger := zerolog.Nop()

	if _, ok := globalTransport(t, NewMailer(MailerConfig{Env: "development", Logger: logger})).(*devTransport); !ok {
		t.Error("no provider should yield devTransport (development)")
	}
	if _, ok := globalTransport(t, NewMailer(MailerConfig{Env: "production", Logger: logger})).(*devTransport); !ok {
		t.Error("no provider should yield devTransport (production)")
	}
	if _, ok := globalTransport(t, NewMailer(MailerConfig{SMTPHost: "smtp.example.com", Logger: logger})).(*smtpTransport); !ok {
		t.Error("SMTP host should yield smtpTransport")
	}
	if _, ok := globalTransport(t, NewMailer(MailerConfig{SendGridAPIKey: "SG.x", Logger: logger})).(*sendGridTransport); !ok {
		t.Error("SendGrid key should yield sendGridTransport")
	}
	// Explicit provider wins over inference.
	if _, ok := globalTransport(t, NewMailer(MailerConfig{Provider: "smtp", SMTPHost: "h", SendGridAPIKey: "SG.x", Logger: logger})).(*smtpTransport); !ok {
		t.Error("explicit Provider=smtp should override SendGrid inference")
	}
}

// TestBranding_Defaults proves an unset sender yields the default product name
// and no prefix, while a configured sender's branding flows into subject + body.
func TestBranding_Defaults(t *testing.T) {
	b := brandingFrom(nil)
	if b.ProductName != defaultProductName {
		t.Errorf("default ProductName = %q, want %q", b.ProductName, defaultProductName)
	}
	if got := b.subjectWith("Password Reset Request"); got != "Password Reset Request" {
		t.Errorf("subject with no prefix = %q, want unchanged", got)
	}

	b = brandingFrom(&SMTPConfig{ProductName: "Acme Cloud", LogoURL: "https://acme/logo.png", SubjectPrefix: "[Acme]"})
	if got := b.subjectWith("Password Reset Request"); got != "[Acme] Password Reset Request" {
		t.Errorf("prefixed subject = %q, want %q", got, "[Acme] Password Reset Request")
	}

	// Render the built-in reset template with this branding + a link.
	tmpl, _ := BuiltinTemplate(TemplatePasswordReset)
	out, err := tmpl.render(TemplateData{ProductName: b.ProductName, LogoURL: b.LogoURL, Link: "https://acme/reset?token=x", TTLMinutes: 15})
	if err != nil {
		t.Fatalf("render reset: %v", err)
	}
	if !strings.Contains(out.Text, "Acme Cloud") || !strings.Contains(out.Text, "https://acme/reset?token=x") {
		t.Errorf("text body missing product name or link:\n%s", out.Text)
	}
	if !strings.Contains(out.HTML, "https://acme/logo.png") || !strings.Contains(out.HTML, "Acme Cloud") {
		t.Errorf("html body missing logo or product name:\n%s", out.HTML)
	}

	// The MFA code must render in a body block (never the subject).
	mfa, _ := BuiltinTemplate(TemplateMFACode)
	mout, err := mfa.render(TemplateData{ProductName: b.ProductName, Code: "482913", AppName: "Acme", TTLMinutes: 5})
	if err != nil {
		t.Fatalf("render mfa: %v", err)
	}
	if !strings.Contains(mout.Text, "482913") {
		t.Error("MFA text body missing the code")
	}
	if strings.Contains(mout.Subject, "482913") {
		t.Error("MFA code must never appear in the subject")
	}
}

// TestBuiltinTemplates_AllRender ensures every registered type has a built-in
// default that parses and executes.
func TestBuiltinTemplates_AllRender(t *testing.T) {
	data := TemplateData{ProductName: "P", AppName: "App", Link: "https://x/y", Code: "123456", TTLMinutes: 10, Name: "Sam"}
	for _, tt := range AllTemplateTypes {
		tmpl, ok := BuiltinTemplate(tt)
		if !ok {
			t.Errorf("%s: no built-in template", tt)
			continue
		}
		if err := tmpl.Validate(); err != nil {
			t.Errorf("%s: validate: %v", tt, err)
		}
		if _, err := tmpl.render(data); err != nil {
			t.Errorf("%s: render: %v", tt, err)
		}
	}
}

// TestDevMailer_NeverErrors confirms the log-only mailer satisfies every send
// method without touching the network.
func TestDevMailer_NeverErrors(t *testing.T) {
	m := NewMailer(MailerConfig{Logger: newTestLogger()})
	ctx := context.Background()

	if err := m.SendReset(ctx, nil, nil, ResetEmail{To: "u@example.com", ResetLink: "https://x/y"}); err != nil {
		t.Errorf("SendReset: %v", err)
	}
	if err := m.SendMFACode(ctx, nil, nil, MFACodeEmail{To: "u@example.com", Code: "123456", TTLMinutes: 10}); err != nil {
		t.Errorf("SendMFACode: %v", err)
	}
	// A per-scope sender override is honored via its own transport even when the
	// global mailer is dev; a SendGrid override is exercised in TestSendGridTransport.
	if err := m.SendMagicLink(ctx, nil, nil, MagicLinkEmail{To: "u@example.com", Link: "https://x/?token=t", TTLMinutes: 15}); err != nil {
		t.Errorf("SendMagicLink: %v", err)
	}
	if err := m.SendVerification(ctx, nil, nil, VerificationEmail{To: "u@example.com", Link: "https://x/verify?token=t", TTLMinutes: 30}); err != nil {
		t.Errorf("SendVerification: %v", err)
	}
	if err := m.SendWelcome(ctx, nil, nil, WelcomeEmail{To: "u@example.com", Name: "Sam"}); err != nil {
		t.Errorf("SendWelcome: %v", err)
	}
	if err := m.SendPasswordChanged(ctx, nil, nil, PasswordChangedEmail{To: "u@example.com"}); err != nil {
		t.Errorf("SendPasswordChanged: %v", err)
	}
}

// TestCustomTemplate_FallsBackToBuiltin proves a syntactically-broken custom
// template does not block the send: the built-in default renders instead.
func TestCustomTemplate_FallsBackToBuiltin(t *testing.T) {
	m := NewMailer(MailerConfig{Logger: newTestLogger()})
	broken := &Template{Subject: "{{.Nope", HTML: "{{.AlsoBroken", Text: "x"}
	if err := m.SendReset(context.Background(), nil, broken, ResetEmail{To: "u@example.com", ResetLink: "https://x/y"}); err != nil {
		t.Errorf("broken custom template should fall back, got: %v", err)
	}
}

// TestSendGridTransport asserts the Web API request shape and error mapping.
func TestSendGridTransport(t *testing.T) {
	var gotAuth, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		b := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(b)
		gotBody = string(b)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	tr := &sendGridTransport{apiKey: "SG.test", endpoint: srv.URL, httpClient: srv.Client(), logger: newTestLogger()}
	err := tr.send(context.Background(), outMessage{
		From: "no-reply@x.com", FromName: "X", To: "u@example.com",
		Subject: "Hi", HTML: "<p>hi</p>", Text: "hi",
	})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if gotAuth != "Bearer SG.test" {
		t.Errorf("auth header = %q", gotAuth)
	}
	var parsed sgMail
	if err := json.Unmarshal([]byte(gotBody), &parsed); err != nil {
		t.Fatalf("body not valid sgMail json: %v (%s)", err, gotBody)
	}
	if parsed.From.Email != "no-reply@x.com" || len(parsed.Personalizations) != 1 || parsed.Personalizations[0].To[0].Email != "u@example.com" {
		t.Errorf("unexpected payload: %+v", parsed)
	}
	if len(parsed.Content) != 2 || parsed.Content[0].Type != "text/plain" {
		t.Errorf("content must be text/plain then text/html: %+v", parsed.Content)
	}
}

// TestSendGridTransport_ErrorStatus maps a non-2xx to an error.
func TestSendGridTransport_ErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"errors":[{"message":"bad key"}]}`))
	}))
	defer srv.Close()

	tr := &sendGridTransport{apiKey: "SG.bad", endpoint: srv.URL, httpClient: srv.Client(), logger: newTestLogger()}
	err := tr.send(context.Background(), outMessage{From: "a@b.com", To: "u@example.com", Subject: "s", HTML: "h", Text: "t"})
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Errorf("want 401 error, got: %v", err)
	}
}

// TestTLSFor covers TLS-mode selection: explicit override wins, otherwise the
// port decides (465 = implicit TLS, everything else = mandatory STARTTLS).
func TestTLSFor(t *testing.T) {
	cases := []struct {
		port     int
		override string
		wantSSL  bool
	}{
		{587, "", false},
		{465, "", true},
		{2525, "", false},
		{587, "ssl", true},
		{465, "starttls", false},
		{25, "none", false},
		{587, "opportunistic", false},
	}
	for _, c := range cases {
		ssl, _ := tlsFor(c.port, c.override)
		if ssl != c.wantSSL {
			t.Errorf("tlsFor(%d, %q) ssl = %v, want %v", c.port, c.override, ssl, c.wantSSL)
		}
	}
}

// TestSMTPTransport_LiveSend performs a real SMTP send through go-mail against a
// catcher (e.g. Mailpit) and asserts delivery via its HTTP API. Skipped unless
// SMTP_TEST_HOST is set.
//
//	docker run -d --name mailpit -p 1025:1025 -p 8025:8025 axllent/mailpit
//	SMTP_TEST_HOST=localhost SMTP_TEST_PORT=1025 SMTP_TEST_TLS=none \
//	  MAILPIT_API=http://localhost:8025 go test ./internal/mailer -run LiveSend -v
func TestSMTPTransport_LiveSend(t *testing.T) {
	host := os.Getenv("SMTP_TEST_HOST")
	if host == "" {
		t.Skip("SMTP_TEST_HOST not set; skipping live SMTP send")
	}
	port := 1025
	if p := os.Getenv("SMTP_TEST_PORT"); p != "" {
		if _, err := parseInt(p, &port); err != nil {
			t.Fatalf("bad SMTP_TEST_PORT %q: %v", p, err)
		}
	}
	from := "auth@emc.local"
	if f := os.Getenv("SMTP_TEST_FROM"); f != "" {
		from = f
	}
	m := &mailerImpl{
		logger: newTestLogger(),
		global: SMTPConfig{From: from, Provider: ProviderSMTP},
		globalTr: &smtpTransport{
			host:     host,
			port:     port,
			username: os.Getenv("SMTP_TEST_USERNAME"),
			password: os.Getenv("SMTP_TEST_PASSWORD"),
			tlsMode:  os.Getenv("SMTP_TEST_TLS"),
			logger:   newTestLogger(),
		},
	}

	to := "recipient@emc.local"
	if tt := os.Getenv("SMTP_TEST_TO"); tt != "" {
		to = tt
	}
	link := "http://localhost:4000/?token=live-send-token"
	if err := m.SendMagicLink(context.Background(), nil, nil, MagicLinkEmail{
		To: to, Link: link, AppName: "EMC Live Test", TTLMinutes: 15,
	}); err != nil {
		t.Fatalf("SendMagicLink to catcher: %v", err)
	}

	apiBase := os.Getenv("MAILPIT_API")
	if apiBase == "" {
		return
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, apiBase+"/api/v1/messages", nil) //nolint:gosec // test-only local Mailpit API
		if err != nil {
			t.Fatalf("mailpit api request: %v", err)
		}
		resp, err := http.DefaultClient.Do(req) //nolint:gosec // test-only local Mailpit API
		if err != nil {
			t.Fatalf("mailpit api: %v", err)
		}
		var out struct {
			Messages []struct {
				To      []struct{ Address string } `json:"To"`
				Subject string                     `json:"Subject"`
			} `json:"messages"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&out)
		_ = resp.Body.Close()
		for _, msg := range out.Messages {
			if strings.Contains(msg.Subject, "Sign in to EMC Live Test") {
				for _, r := range msg.To {
					if r.Address == to {
						return
					}
				}
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("message not found in Mailpit within timeout")
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// parseInt is a tiny strconv.Atoi wrapper that writes into dst.
func parseInt(s string, dst *int) (int, error) {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, &parseErr{s}
		}
		n = n*10 + int(r-'0')
	}
	*dst = n
	return n, nil
}

type parseErr struct{ s string }

func (e *parseErr) Error() string { return "not an integer: " + e.s }
