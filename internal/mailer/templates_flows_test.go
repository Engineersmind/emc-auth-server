package mailer

import (
	"context"
	"strings"
	"testing"
)

// TestBlockedAccountTemplate_ReasonVariants proves the one blocked_account
// template renders three distinct messages, and — most importantly — that the
// call to action matches the event: only an automatic lockout offers to unblock.
func TestBlockedAccountTemplate_ReasonVariants(t *testing.T) {
	tmpl, ok := BuiltinTemplate(TemplateBlockedAccount)
	if !ok {
		t.Fatal("no built-in blocked_account template")
	}

	cases := []struct {
		reason      string
		wantCTA     string
		wantInBody  string
		rejectInCTA string
	}{
		{
			reason:      BlockReasonFailedAttempts,
			wantCTA:     "Unblock account",
			wantInBody:  "too many failed sign-in attempts",
			rejectInCTA: "Reset password",
		},
		{
			reason:      BlockReasonAdmin,
			wantCTA:     "Reset password",
			wantInBody:  "administrator has blocked",
			rejectInCTA: "Unblock account",
		},
		{
			reason:      BlockReasonSuspiciousLogin,
			wantCTA:     "Change password",
			wantInBody:  "has not been blocked",
			rejectInCTA: "Unblock account",
		},
	}

	for _, tc := range cases {
		t.Run(tc.reason, func(t *testing.T) {
			out, err := tmpl.render(TemplateData{
				ProductName: "P", Link: "https://x/action?token=t", Reason: tc.reason, TTLMinutes: 60,
			})
			if err != nil {
				t.Fatalf("render: %v", err)
			}
			if !strings.Contains(out.HTML, tc.wantCTA) {
				t.Errorf("HTML missing CTA %q:\n%s", tc.wantCTA, out.HTML)
			}
			if strings.Contains(out.HTML, tc.rejectInCTA) {
				t.Errorf("HTML must not offer %q for reason %s", tc.rejectInCTA, tc.reason)
			}
			if !strings.Contains(out.HTML, tc.wantInBody) {
				t.Errorf("HTML missing %q:\n%s", tc.wantInBody, out.HTML)
			}
			if !strings.Contains(out.Text, "https://x/action?token=t") {
				t.Errorf("text body missing the action link:\n%s", out.Text)
			}
		})
	}

	// The suspicious-login variant must not claim the account was blocked — that
	// would send users chasing a lockout that never happened.
	alert, err := tmpl.render(TemplateData{ProductName: "P", Reason: BlockReasonSuspiciousLogin})
	if err != nil {
		t.Fatalf("render alert: %v", err)
	}
	if strings.Contains(alert.Subject, "blocked") {
		t.Errorf("suspicious-login subject claims a block: %q", alert.Subject)
	}
}

// captureTransport records the message a send produced instead of delivering it.
type captureTransport struct{ msgs []outMessage }

func (c *captureTransport) send(_ context.Context, m outMessage) error {
	c.msgs = append(c.msgs, m)
	return nil
}

// newCapturingMailer returns a mailer whose global transport records messages.
func newCapturingMailer() (*mailerImpl, *captureTransport) {
	tr := &captureTransport{}
	return &mailerImpl{
		global:   SMTPConfig{From: "no-reply@emc.local"},
		globalTr: tr,
		logger:   newTestLogger(),
	}, tr
}

// TestSendReset_UsesCallerTTL proves the reset body states the TTL the caller
// passed, rather than a hardcoded window that could contradict the real token
// expiry — and that an unset value still renders a sane default.
func TestSendReset_UsesCallerTTL(t *testing.T) {
	m, tr := newCapturingMailer()
	ctx := context.Background()

	if err := m.SendReset(ctx, nil, nil, ResetEmail{To: "u@example.com", ResetLink: "https://x/r", TTLMinutes: 45}); err != nil {
		t.Fatalf("SendReset: %v", err)
	}
	if !strings.Contains(tr.msgs[0].Text, "45 minutes") {
		t.Errorf("body does not state the caller's 45-minute TTL:\n%s", tr.msgs[0].Text)
	}

	if err := m.SendReset(ctx, nil, nil, ResetEmail{To: "u@example.com", ResetLink: "https://x/r"}); err != nil {
		t.Fatalf("SendReset (no TTL): %v", err)
	}
	body := tr.msgs[1].Text
	if strings.Contains(body, "0 minutes") {
		t.Errorf("unset TTL rendered as 0 minutes:\n%s", body)
	}
	if !strings.Contains(body, "15 minutes") {
		t.Errorf("unset TTL did not fall back to the default:\n%s", body)
	}
}

// TestSendNewFlowEmails proves each newly wired send method renders its own
// template and reaches a transport.
func TestSendNewFlowEmails(t *testing.T) {
	m, tr := newCapturingMailer()
	ctx := context.Background()

	if err := m.SendInvitation(ctx, nil, nil, InvitationEmail{
		To: "u@example.com", Link: "https://x/invite?token=t", InviterName: "Jordan", TTLMinutes: 4320,
	}); err != nil {
		t.Fatalf("SendInvitation: %v", err)
	}
	if err := m.SendChangeEmail(ctx, nil, nil, ChangeEmailEmail{
		To: "new@example.com", Link: "https://x/confirm?token=t", TTLMinutes: 60,
	}); err != nil {
		t.Fatalf("SendChangeEmail: %v", err)
	}
	if err := m.SendBlockedAccount(ctx, nil, nil, BlockedAccountEmail{
		To: "u@example.com", Link: "https://x/unblock?token=t", Reason: BlockReasonFailedAttempts, TTLMinutes: 60,
	}); err != nil {
		t.Fatalf("SendBlockedAccount: %v", err)
	}
	if err := m.SendPasswordBreach(ctx, nil, nil, PasswordBreachEmail{
		To: "u@example.com", Link: "https://x/forgot",
	}); err != nil {
		t.Fatalf("SendPasswordBreach: %v", err)
	}

	if len(tr.msgs) != 4 {
		t.Fatalf("messages = %d, want 4", len(tr.msgs))
	}
	wants := []string{"Jordan", "https://x/confirm?token=t", "https://x/unblock?token=t", "https://x/forgot"}
	for i, want := range wants {
		if !strings.Contains(tr.msgs[i].Text, want) && !strings.Contains(tr.msgs[i].HTML, want) {
			t.Errorf("message %d missing %q", i, want)
		}
		if tr.msgs[i].Subject == "" {
			t.Errorf("message %d has an empty subject", i)
		}
	}
}
