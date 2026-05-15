// Package mailer provides email dispatch for the emc-auth-server.
// In development (ENV=development), all emails are logged to the zerolog logger
// at INFO level. In production, emails are sent via SMTP (net/smtp).
package mailer

import (
	"context"
	"fmt"
	"net/smtp"

	"github.com/rs/zerolog"
)

// ResetEmail is the data needed to send a password reset email.
type ResetEmail struct {
	// To is the recipient email address.
	To string
	// ResetLink is the full URL the user clicks to reset their password.
	// Example: "https://auth.emc.local/reset-password?token=<raw_token>"
	ResetLink string
	// TenantSlug is the tenant the user belongs to (for personalisation/logging).
	TenantSlug string
}

// Mailer is the interface for sending transactional emails.
// Replace DevMailer with SMTPMailer (or any other implementation) by swapping
// the concrete type passed to NewMailer — handlers use only this interface.
type Mailer interface {
	// SendReset dispatches a password reset email to the specified address.
	SendReset(ctx context.Context, email ResetEmail) error
}

// DevMailer logs emails to zerolog instead of sending them.
// Used when ENV != "production" so local development requires no SMTP setup.
type DevMailer struct {
	logger zerolog.Logger
}

// SendReset logs the reset link at INFO level.
// The full reset link is visible in server logs — sufficient for local development.
func (m *DevMailer) SendReset(ctx context.Context, email ResetEmail) error {
	m.logger.Info().
		Str("to", email.To).
		Str("tenant", email.TenantSlug).
		Str("reset_link", email.ResetLink).
		Msg("[DEV] password reset email (not sent — log only)")
	return nil
}

// SMTPMailer sends emails via an SMTP relay using net/smtp.
// Supports SMTP AUTH PLAIN over TLS (STARTTLS on port 587).
type SMTPMailer struct {
	host     string
	port     int
	from     string
	username string
	password string
	logger   zerolog.Logger
}

// SendReset sends a password reset email via SMTP.
// The message body is plain-text only (no HTML template) for Phase 2.
// Phase 6 can add an HTML template loader here.
func (m *SMTPMailer) SendReset(ctx context.Context, email ResetEmail) error {
	addr := fmt.Sprintf("%s:%d", m.host, m.port)

	subject := "Password Reset Request"
	body := fmt.Sprintf(`You requested a password reset for your account.

Click the link below to reset your password (valid for 15 minutes):

%s

If you did not request this, please ignore this email. Your password will not change.

- EMC Auth Server
`, email.ResetLink)

	msg := fmt.Sprintf(
		"From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s",
		m.from, email.To, subject, body,
	)

	var auth smtp.Auth
	if m.username != "" {
		auth = smtp.PlainAuth("", m.username, m.password, m.host)
	}

	if err := smtp.SendMail(addr, auth, m.from, []string{email.To}, []byte(msg)); err != nil {
		m.logger.Error().Err(err).Str("to", email.To).Msg("smtp send failed")
		return fmt.Errorf("smtp send: %w", err)
	}

	m.logger.Info().Str("to", email.To).Msg("password reset email sent")
	return nil
}

// MailerConfig holds the configuration for constructing a Mailer.
type MailerConfig struct {
	Env          string
	SMTPHost     string
	SMTPPort     int
	SMTPFrom     string
	SMTPUsername string
	SMTPPassword string
	Logger       zerolog.Logger
}

// NewMailer returns a DevMailer when env != "production", or SMTPMailer otherwise.
// If env == "production" but SMTPHost is empty, it falls back to DevMailer with a warning.
func NewMailer(cfg MailerConfig) Mailer {
	if cfg.Env != "production" {
		return &DevMailer{logger: cfg.Logger}
	}
	if cfg.SMTPHost == "" {
		cfg.Logger.Warn().Msg("SMTP_HOST not set in production — falling back to console mailer")
		return &DevMailer{logger: cfg.Logger}
	}
	return &SMTPMailer{
		host:     cfg.SMTPHost,
		port:     cfg.SMTPPort,
		from:     cfg.SMTPFrom,
		username: cfg.SMTPUsername,
		password: cfg.SMTPPassword,
		logger:   cfg.Logger,
	}
}
