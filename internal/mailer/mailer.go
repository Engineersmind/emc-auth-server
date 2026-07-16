// Package mailer provides email dispatch for the emc-auth-server.
// Delivery is selected by whether an SMTP host is configured, not by ENV (see
// NewMailer): with no SMTP_HOST, emails are logged to the zerolog logger at INFO
// level; with an SMTP_HOST set, emails are sent via SMTP using go-mail
// (github.com/wneessen/go-mail), which supports STARTTLS (587) and implicit
// TLS (465), SMTP AUTH negotiation, and per-send context timeouts so a slow or
// unreachable relay can never hang a login request.
package mailer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog"
	mail "github.com/wneessen/go-mail"
)

// smtpSendTimeout bounds a single dial+send even when the caller's context has
// no deadline, so a hung relay fails fast instead of blocking the request.
const smtpSendTimeout = 15 * time.Second

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

// MFACodeEmail is the data needed to send an MFA one-time-code email.
type MFACodeEmail struct {
	// To is the recipient email address.
	To string
	// Code is the one-time code (plaintext — only ever held in memory here;
	// the server stores just its hash).
	Code string
	// AppName personalises the message with the requesting application's name;
	// empty for tenant-level accounts.
	AppName string
	// TTLMinutes is how long the code stays valid, for the message text.
	TTLMinutes int
}

// SMTPConfig is a per-send sender override (white-label senders): when a
// tenant or application has its own sender configured, transactional mail is
// dispatched through that relay with that From address instead of the global
// server sender.
type SMTPConfig struct {
	From     string
	Host     string
	Port     int
	Username string
	Password string
}

// MagicLinkEmail is the data needed to send a passwordless sign-in link.
type MagicLinkEmail struct {
	// To is the recipient email address.
	To string
	// Link is the full sign-in URL (application redirect URL + token).
	Link string
	// AppName personalises the message with the requesting application's name.
	AppName string
	// TTLMinutes is how long the link stays valid, for the message text.
	TTLMinutes int
}

// Mailer is the interface for sending transactional emails.
// Replace DevMailer with SMTPMailer (or any other implementation) by swapping
// the concrete type passed to NewMailer — handlers use only this interface.
type Mailer interface {
	// SendReset dispatches a password reset email to the specified address.
	SendReset(ctx context.Context, email ResetEmail) error
	// SendMFACode dispatches a one-time MFA code email via the default sender.
	SendMFACode(ctx context.Context, email MFACodeEmail) error
	// SendMFACodeFrom dispatches a one-time MFA code email via the given
	// sender override; a nil sender behaves exactly like SendMFACode.
	SendMFACodeFrom(ctx context.Context, sender *SMTPConfig, email MFACodeEmail) error
	// SendMagicLink dispatches a passwordless sign-in link via the given
	// sender override (nil = default sender).
	SendMagicLink(ctx context.Context, sender *SMTPConfig, email MagicLinkEmail) error
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

// SendMFACode logs the one-time code at INFO level.
func (m *DevMailer) SendMFACode(ctx context.Context, email MFACodeEmail) error {
	return m.SendMFACodeFrom(ctx, nil, email)
}

// SendMFACodeFrom logs the one-time code, including which sender would have
// been used in production.
func (m *DevMailer) SendMFACodeFrom(ctx context.Context, sender *SMTPConfig, email MFACodeEmail) error {
	from := "(global sender)"
	if sender != nil {
		from = sender.From
	}
	m.logger.Info().
		Str("to", email.To).
		Str("from", from).
		Str("app", email.AppName).
		Str("code", email.Code).
		Int("ttl_minutes", email.TTLMinutes).
		Msg("[DEV] MFA code email (not sent — log only)")
	return nil
}

// SendMagicLink logs the sign-in link at INFO level.
func (m *DevMailer) SendMagicLink(ctx context.Context, sender *SMTPConfig, email MagicLinkEmail) error {
	from := "(global sender)"
	if sender != nil {
		from = sender.From
	}
	m.logger.Info().
		Str("to", email.To).
		Str("from", from).
		Str("app", email.AppName).
		Str("magic_link", email.Link).
		Int("ttl_minutes", email.TTLMinutes).
		Msg("[DEV] magic link email (not sent — log only)")
	return nil
}

// SMTPMailer sends emails via an SMTP relay using go-mail. It supports
// STARTTLS and implicit TLS, SMTP AUTH negotiation, and per-send timeouts.
type SMTPMailer struct {
	host     string
	port     int
	from     string
	username string
	password string
	// tlsMode overrides TLS selection for the global sender: "ssl", "starttls",
	// "opportunistic", or "none". Empty derives from the port (465 = implicit
	// TLS, anything else = mandatory STARTTLS).
	tlsMode string
	logger  zerolog.Logger
}

// senderParams collapses the mailer's own config with an optional per-send
// override (white-label tenant/application sender) into one set of values.
// A per-scope sender carries no explicit TLS mode, so its TLS is port-derived.
func (m *SMTPMailer) senderParams(sender *SMTPConfig) (host string, port int, from, username, password, tlsMode string) {
	if sender != nil {
		return sender.Host, sender.Port, sender.From, sender.Username, sender.Password, ""
	}
	return m.host, m.port, m.from, m.username, m.password, m.tlsMode
}

// send builds and dispatches one plain-text message, bounded by ctx and the
// client timeout. It is the single SMTP code path shared by every email type.
func (m *SMTPMailer) send(ctx context.Context, sender *SMTPConfig, to, subject, body string) error {
	host, port, from, username, password, tlsMode := m.senderParams(sender)

	msg := mail.NewMsg()
	if err := msg.From(from); err != nil {
		return fmt.Errorf("invalid from address %q: %w", from, err)
	}
	if err := msg.To(to); err != nil {
		return fmt.Errorf("invalid recipient %q: %w", to, err)
	}
	msg.Subject(subject)
	msg.SetBodyString(mail.TypeTextPlain, body)

	opts := []mail.Option{
		mail.WithPort(port),
		mail.WithTimeout(smtpSendTimeout),
	}
	if useSSL, policy := tlsFor(port, tlsMode); useSSL {
		opts = append(opts, mail.WithSSL())
	} else {
		opts = append(opts, mail.WithTLSPolicy(policy))
	}
	if username != "" {
		// AutoDiscover negotiates the strongest mechanism the relay advertises
		// (PLAIN/LOGIN/CRAM-MD5/…), which works across Gmail, SES, Brevo, etc.
		opts = append(opts,
			mail.WithSMTPAuth(mail.SMTPAuthAutoDiscover),
			mail.WithUsername(username),
			mail.WithPassword(password),
		)
	} else {
		opts = append(opts, mail.WithSMTPAuth(mail.SMTPAuthNoAuth))
	}

	client, err := mail.NewClient(host, opts...)
	if err != nil {
		return fmt.Errorf("smtp client: %w", err)
	}
	if err := client.DialAndSendWithContext(ctx, msg); err != nil {
		m.logger.Error().Err(err).Str("to", to).Str("from", from).Msg("smtp send failed")
		return fmt.Errorf("smtp send: %w", err)
	}
	return nil
}

// tlsFor selects the TLS mode: an explicit override wins, otherwise it is
// derived from the port (465 = implicit TLS, everything else = STARTTLS).
// The production default is mandatory encryption; "none"/"opportunistic" exist
// for local relays and quirky providers.
func tlsFor(port int, override string) (useSSL bool, policy mail.TLSPolicy) {
	switch strings.ToLower(override) {
	case "ssl", "tls":
		return true, mail.TLSMandatory
	case "starttls":
		return false, mail.TLSMandatory
	case "opportunistic":
		return false, mail.TLSOpportunistic
	case "none", "insecure", "plain":
		return false, mail.NoTLS
	}
	if port == 465 {
		return true, mail.TLSMandatory
	}
	return false, mail.TLSMandatory
}

// SendReset sends a password reset email via SMTP.
func (m *SMTPMailer) SendReset(ctx context.Context, email ResetEmail) error {
	subject := "Password Reset Request"
	body := fmt.Sprintf(`You requested a password reset for your account.

Click the link below to reset your password (valid for 15 minutes):

%s

If you did not request this, please ignore this email. Your password will not change.

- EMC Auth Server
`, email.ResetLink)

	if err := m.send(ctx, nil, email.To, subject, body); err != nil {
		return err
	}
	m.logger.Info().Str("to", email.To).Msg("password reset email sent")
	return nil
}

// SendMFACode sends a one-time MFA code email via the global SMTP sender.
func (m *SMTPMailer) SendMFACode(ctx context.Context, email MFACodeEmail) error {
	return m.SendMFACodeFrom(ctx, nil, email)
}

// SendMFACodeFrom sends a one-time MFA code email, dialing the override relay
// when sender is non-nil (white-label tenant/application senders) and the
// mailer's own configuration otherwise.
func (m *SMTPMailer) SendMFACodeFrom(ctx context.Context, sender *SMTPConfig, email MFACodeEmail) error {
	source := "your account"
	if email.AppName != "" {
		source = email.AppName
	}
	// The code must never appear in the subject: subjects are stored in
	// plaintext by SMTP relay logs and shown in push-notification previews
	// and inbox list views, none of which require opening the message.
	subject := "Your verification code"
	if email.AppName != "" {
		subject = fmt.Sprintf("Your %s verification code", email.AppName)
	}
	body := fmt.Sprintf(`Your one-time verification code for %s is:

    %s

It expires in %d minutes. If you did not try to sign in, secure your account
by changing your password.

- EMC Auth Server
`, source, email.Code, email.TTLMinutes)

	if err := m.send(ctx, sender, email.To, subject, body); err != nil {
		return err
	}
	m.logger.Info().Str("to", email.To).Str("app", email.AppName).Msg("MFA code email sent")
	return nil
}

// SendMagicLink sends a passwordless sign-in link via SMTP, dialing the
// override relay when sender is non-nil.
func (m *SMTPMailer) SendMagicLink(ctx context.Context, sender *SMTPConfig, email MagicLinkEmail) error {
	source := "your account"
	if email.AppName != "" {
		source = email.AppName
	}
	subject := fmt.Sprintf("Sign in to %s", source)
	body := fmt.Sprintf(`Click the link below to sign in to %s (valid for %d minutes, single use):

%s

If you did not request this, you can safely ignore this email.

- EMC Auth Server
`, source, email.TTLMinutes, email.Link)

	if err := m.send(ctx, sender, email.To, subject, body); err != nil {
		return err
	}
	m.logger.Info().Str("to", email.To).Str("app", email.AppName).Msg("magic link email sent")
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
	// SMTPTLS overrides TLS selection for the global sender: "ssl", "starttls",
	// "opportunistic", or "none". Empty derives from the port.
	SMTPTLS string
	Logger  zerolog.Logger
}

// NewMailer selects the mailer by whether an SMTP host is configured, NOT by
// environment: a configured SMTP_HOST sends real mail in any environment, and
// an empty SMTP_HOST logs to the console. This deliberately decouples email
// delivery from ENV — ENV governs the HTTPS/cookie security posture, and tying
// mail to it would force a choice between "real email" and "plain-HTTP local
// testing". In production without SMTP_HOST it warns, since that is almost
// certainly a misconfiguration.
func NewMailer(cfg MailerConfig) Mailer {
	if cfg.SMTPHost == "" {
		if cfg.Env == "production" {
			cfg.Logger.Warn().Msg("SMTP_HOST not set in production — falling back to console mailer")
		}
		return &DevMailer{logger: cfg.Logger}
	}
	return &SMTPMailer{
		host:     cfg.SMTPHost,
		port:     cfg.SMTPPort,
		from:     cfg.SMTPFrom,
		username: cfg.SMTPUsername,
		password: cfg.SMTPPassword,
		tlsMode:  cfg.SMTPTLS,
		logger:   cfg.Logger,
	}
}
