package testhelper

import (
	"context"
	"sync"

	"github.com/engineersmind/emc-auth-server/internal/mailer"
)

// RecordingMailer is a mailer.Mailer that records what it was asked to send
// instead of sending it.
//
// It lives here, in one place, on purpose. Several packages previously each
// carried their own hand-written double of this interface, and every method
// added to mailer.Mailer had to be added to all of them. A miss does not break
// `go build` — the doubles are test-only — so it surfaces as a vet failure or
// not at all until the package is next compiled. One implementation means one
// place to update.
//
// Every method is safe for concurrent use: the notification pipeline sends from
// its own goroutine, so a test that asserts on what arrived is reading while
// the writer may still be writing.
type RecordingMailer struct {
	mu          sync.Mutex
	invitations []mailer.InvitationEmail
	activity    []mailer.AdminActivityEmail
	access      []mailer.AccessChangedEmail

	// SendInvitationErr, when non-nil, is returned by SendInvitation instead of
	// recording it. For exercising the paths that must report an undelivered
	// invitation rather than swallow it.
	SendInvitationErr error
}

// Invitations returns a copy of the invitations sent so far.
func (m *RecordingMailer) Invitations() []mailer.InvitationEmail {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]mailer.InvitationEmail(nil), m.invitations...)
}

// Activity returns a copy of the admin-activity notices sent so far.
func (m *RecordingMailer) Activity() []mailer.AdminActivityEmail {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]mailer.AdminActivityEmail(nil), m.activity...)
}

// AccessChanges returns a copy of the access-changed notices sent so far.
func (m *RecordingMailer) AccessChanges() []mailer.AccessChangedEmail {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]mailer.AccessChangedEmail(nil), m.access...)
}

// Reset discards everything recorded so far, so one fixture can be reused
// across sub-tests without them observing each other's mail.
func (m *RecordingMailer) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.invitations, m.activity, m.access = nil, nil, nil
}

func (m *RecordingMailer) SendInvitation(_ context.Context, _ *mailer.SMTPConfig, _ *mailer.Template, e mailer.InvitationEmail) error {
	if m.SendInvitationErr != nil {
		return m.SendInvitationErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.invitations = append(m.invitations, e)
	return nil
}

func (m *RecordingMailer) SendAdminActivity(_ context.Context, _ *mailer.SMTPConfig, _ *mailer.Template, e mailer.AdminActivityEmail) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.activity = append(m.activity, e)
	return nil
}

func (m *RecordingMailer) SendAccessChanged(_ context.Context, _ *mailer.SMTPConfig, _ *mailer.Template, e mailer.AccessChangedEmail) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.access = append(m.access, e)
	return nil
}

// The remainder are accepted and discarded. Add recording to one only when a
// test actually asserts on it.

func (m *RecordingMailer) SendReset(context.Context, *mailer.SMTPConfig, *mailer.Template, mailer.ResetEmail) error {
	return nil
}

func (m *RecordingMailer) SendMFACode(context.Context, *mailer.SMTPConfig, *mailer.Template, mailer.MFACodeEmail) error {
	return nil
}

func (m *RecordingMailer) SendMagicLink(context.Context, *mailer.SMTPConfig, *mailer.Template, mailer.MagicLinkEmail) error {
	return nil
}

func (m *RecordingMailer) SendVerification(context.Context, *mailer.SMTPConfig, *mailer.Template, mailer.VerificationEmail) error {
	return nil
}

func (m *RecordingMailer) SendWelcome(context.Context, *mailer.SMTPConfig, *mailer.Template, mailer.WelcomeEmail) error {
	return nil
}

func (m *RecordingMailer) SendPasswordChanged(context.Context, *mailer.SMTPConfig, *mailer.Template, mailer.PasswordChangedEmail) error {
	return nil
}

func (m *RecordingMailer) SendChangeEmail(context.Context, *mailer.SMTPConfig, *mailer.Template, mailer.ChangeEmailEmail) error {
	return nil
}

func (m *RecordingMailer) SendBlockedAccount(context.Context, *mailer.SMTPConfig, *mailer.Template, mailer.BlockedAccountEmail) error {
	return nil
}

func (m *RecordingMailer) SendPasswordBreach(context.Context, *mailer.SMTPConfig, *mailer.Template, mailer.PasswordBreachEmail) error {
	return nil
}

func (m *RecordingMailer) SendTest(context.Context, *mailer.SMTPConfig, *mailer.Template, mailer.TemplateType, string) error {
	return nil
}

// GlobalProvider reports "dev": nothing here transmits.
func (m *RecordingMailer) GlobalProvider() string { return "dev" }

// Compile-time proof that this stays a complete mailer.Mailer. This is the
// assertion that turns a newly added interface method into a build failure in
// one file rather than a silent gap in several.
var _ mailer.Mailer = (*RecordingMailer)(nil)
