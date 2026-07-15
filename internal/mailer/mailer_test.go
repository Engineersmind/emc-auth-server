package mailer

import (
	"context"
	"encoding/json"
	"net/http"
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

// TestNewMailer_SelectsImplementation proves the selection contract is driven
// by SMTP_HOST, not ENV: a configured host sends via SMTP in any environment,
// and an empty host logs to the console (with a warning only in production).
func TestNewMailer_SelectsImplementation(t *testing.T) {
	logger := zerolog.Nop()

	if _, ok := NewMailer(MailerConfig{Env: "development", Logger: logger}).(*DevMailer); !ok {
		t.Error("no SMTP_HOST should yield a DevMailer (development)")
	}
	if _, ok := NewMailer(MailerConfig{Env: "production", Logger: logger}).(*DevMailer); !ok {
		t.Error("no SMTP_HOST should yield a DevMailer (production)")
	}
	if _, ok := NewMailer(MailerConfig{Env: "development", SMTPHost: "smtp.example.com", Logger: logger}).(*SMTPMailer); !ok {
		t.Error("SMTP_HOST set should yield an SMTPMailer even in development")
	}
	if _, ok := NewMailer(MailerConfig{Env: "production", SMTPHost: "smtp.example.com", Logger: logger}).(*SMTPMailer); !ok {
		t.Error("SMTP_HOST set should yield an SMTPMailer (production)")
	}
}

// TestDevMailer_NeverErrors confirms the log-only mailer satisfies every
// interface method without touching the network.
func TestDevMailer_NeverErrors(t *testing.T) {
	m := &DevMailer{logger: newTestLogger()}
	ctx := context.Background()

	if err := m.SendReset(ctx, ResetEmail{To: "u@example.com", ResetLink: "https://x/y"}); err != nil {
		t.Errorf("SendReset: %v", err)
	}
	if err := m.SendMFACode(ctx, MFACodeEmail{To: "u@example.com", Code: "123456", TTLMinutes: 10}); err != nil {
		t.Errorf("SendMFACode: %v", err)
	}
	if err := m.SendMFACodeFrom(ctx, &SMTPConfig{From: "app@example.com"}, MFACodeEmail{To: "u@example.com", Code: "123456"}); err != nil {
		t.Errorf("SendMFACodeFrom: %v", err)
	}
	if err := m.SendMagicLink(ctx, nil, MagicLinkEmail{To: "u@example.com", Link: "https://x/?token=t", TTLMinutes: 15}); err != nil {
		t.Errorf("SendMagicLink: %v", err)
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

// TestSMTPMailer_LiveSend performs a real SMTP send through go-mail against a
// catcher (e.g. Mailpit) and asserts delivery via its HTTP API. It is skipped
// unless SMTP_TEST_HOST is set, matching the repo's DB/Redis-gated tests.
//
//	docker run -d --name mailpit -p 1025:1025 -p 8025:8025 axllent/mailpit
//	SMTP_TEST_HOST=localhost SMTP_TEST_PORT=1025 SMTP_TEST_TLS=none \
//	  MAILPIT_API=http://localhost:8025 go test ./internal/mailer -run LiveSend -v
func TestSMTPMailer_LiveSend(t *testing.T) {
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
	m := &SMTPMailer{
		host:     host,
		port:     port,
		from:     from,
		username: os.Getenv("SMTP_TEST_USERNAME"), // set for authenticated relays (Gmail, etc.)
		password: os.Getenv("SMTP_TEST_PASSWORD"),
		tlsMode:  os.Getenv("SMTP_TEST_TLS"), // "none" for a plaintext catcher
		logger:   newTestLogger(),
	}

	to := "recipient@emc.local"
	if t := os.Getenv("SMTP_TEST_TO"); t != "" {
		to = t
	}
	link := "http://localhost:4000/?token=live-send-token"
	if err := m.SendMagicLink(context.Background(), nil, MagicLinkEmail{
		To: to, Link: link, AppName: "EMC Live Test", TTLMinutes: 15,
	}); err != nil {
		t.Fatalf("SendMagicLink to catcher: %v", err)
	}

	apiBase := os.Getenv("MAILPIT_API")
	if apiBase == "" {
		return // send succeeded; no API to assert delivery against
	}

	// Poll the Mailpit API until the message shows up.
	deadline := time.Now().Add(5 * time.Second)
	for {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, apiBase+"/api/v1/messages", nil) //nolint:gosec // test-only call to a local Mailpit API from an env-supplied base URL
		if err != nil {
			t.Fatalf("mailpit api request: %v", err)
		}
		resp, err := http.DefaultClient.Do(req) //nolint:gosec // test-only call to a local Mailpit API from an env-supplied base URL
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
						return // delivered and captured
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

// parseInt is a tiny strconv.Atoi wrapper that writes into dst; kept local to
// avoid widening imports in the non-live tests.
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
