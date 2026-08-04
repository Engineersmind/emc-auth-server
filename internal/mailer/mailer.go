// Package mailer provides multi-provider email dispatch for emc-auth-server.
//
// Three layers cooperate:
//
//   - Transport (provider.go): how a message is delivered — SMTP relay
//     (go-mail), SendGrid Web API v3, or a log-only dev transport.
//   - Templates (templates.go): what a message says — a built-in default per
//     TemplateType that a tenant/application may override in the DB.
//   - Orchestration (this file): every Send* method resolves branding, renders
//     the template (custom override or built-in fallback), and dispatches via
//     the selected transport.
//
// Every send accepts an optional per-scope *SMTPConfig (white-label senders):
// it carries the provider choice + credentials AND branding. A nil sender uses
// the global server sender/provider. Every send also accepts an optional
// *Template override; nil uses the built-in default for that type. A broken
// custom template falls back to the built-in default so a bad template can
// never block a login-critical email.
package mailer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog"
	mail "github.com/wneessen/go-mail"
)

// smtpSendTimeout bounds a single dial+send / HTTP call even when the caller's
// context has no deadline, so a hung relay or API fails fast.
const smtpSendTimeout = 15 * time.Second

// defaultProductName is the branding used when no per-scope product name is set.
const defaultProductName = "EMC Auth"

// SMTPConfig is a per-send sender override (white-label senders): when a tenant
// or application has its own sender configured, mail is dispatched through that
// provider with that From address and branding instead of the global sender.
//
// Named SMTPConfig for backward compatibility; it now also carries SendGrid
// (Provider="sendgrid", APIKey=...) settings. SenderConfig is an alias.
type SMTPConfig struct {
	// Provider selects the transport: "smtp" (default) or "sendgrid".
	Provider string

	// SMTP relay credentials (Provider="smtp").
	From     string
	Host     string
	Port     int
	Username string
	Password string
	// TLSMode pins the SMTP TLS mode ("ssl","starttls","opportunistic","none");
	// empty derives from the port.
	TLSMode string

	// APIKey is the SendGrid API key (Provider="sendgrid").
	APIKey string

	// Branding (all optional; empty falls back to sensible defaults).
	FromName      string // display name on the From header
	ReplyTo       string // Reply-To address
	ProductName   string // shown in body + sign-off (default "EMC Auth")
	LogoURL       string // logo image shown at the top of the HTML body
	SubjectPrefix string // prepended to every subject, e.g. "[Acme]"
}

// SenderConfig is the preferred name for a per-scope sender override.
type SenderConfig = SMTPConfig

// ---------------------------------------------------------------------------
// Email data types — one per template; carry the recipient + variables.
// ---------------------------------------------------------------------------

// ResetEmail is a password reset email.
type ResetEmail struct {
	To         string
	ResetLink  string
	TenantSlug string
	// TTLMinutes is the link's validity window as stated in the body. Zero falls
	// back to defaultResetTTLMinutes so an unset value never renders "0 minutes".
	TTLMinutes int
}

// MFACodeEmail is a one-time MFA code email.
type MFACodeEmail struct {
	To         string
	Code       string
	AppName    string
	TTLMinutes int
}

// MagicLinkEmail is a passwordless sign-in link.
type MagicLinkEmail struct {
	To         string
	Link       string
	AppName    string
	TTLMinutes int
}

// VerificationEmail confirms ownership of an email address.
type VerificationEmail struct {
	To         string
	Link       string
	AppName    string
	TTLMinutes int
}

// WelcomeEmail greets a user after verification.
type WelcomeEmail struct {
	To      string
	Name    string
	AppName string
}

// PasswordChangedEmail confirms a password change.
type PasswordChangedEmail struct {
	To string
}

// InvitationEmail invites a user to claim an admin-created account.
type InvitationEmail struct {
	To          string
	Link        string
	AppName     string
	InviterName string
	Name        string
	TTLMinutes  int
}

// ChangeEmailEmail carries either half of the email-change flow, selected by
// Reason:
//
//	"" (default)     — the confirmation link, delivered to the NEW address, which
//	                   is the pending one being proven.
//	"email_changed"  — the after-the-fact security notice, delivered to the OLD
//	                   address once the change has applied. No action link; it
//	                   points at password reset so a user who did not ask for the
//	                   change can react. NewEmail names the address now on file.
type ChangeEmailEmail struct {
	To         string
	Link       string
	AppName    string
	TTLMinutes int
	Reason     string
	NewEmail   string
}

// BlockedAccountEmail alerts a user that their account was blocked or that a
// high-risk sign-in was seen. Link is either a single-use unblock link (an
// automatic block the user may lift themselves) or a password-reset link (an
// admin block / risk alert, which the user must not be able to undo).
type BlockedAccountEmail struct {
	To         string
	Link       string
	AppName    string
	Reason     string
	TTLMinutes int
}

// PasswordBreachEmail warns that the user's password appears in a known breach.
type PasswordBreachEmail struct {
	To      string
	Link    string
	AppName string
}

// AdminActivityEmail reports one privileged administrative action to somebody
// accountable for it — the tier above the actor, or the actor themselves when
// the action is sensitive enough that a copy is worth having.
//
// ActionLabel is the human phrasing ("rotated a client secret"), resolved by the
// caller from the audit action key; this type carries no action key of its own,
// so the wording lives in one place rather than being reinvented per template.
type AdminActivityEmail struct {
	To           string
	ActorEmail   string
	ActorRole    string // "owner", "co-owner" — spelled for humans
	ActionLabel  string
	TenantName   string
	ResourceName string // application or other resource, when the action had one
	OccurredAt   string // preformatted; templates do no date arithmetic
	IPAddress    string
	Link         string // deep link into monitoring for this event
	// Count is how many identical actions in quick succession this message
	// stands for. 0 or 1 reads as a single event.
	Count int
}

// AccessChangedEmail tells somebody their own administrative access changed.
//
// ActionLabel is phrased in the second person ("Your applications were
// changed"), unlike AdminActivityEmail's third — the reader is the subject here,
// not an observer.
type AccessChangedEmail struct {
	To           string
	ActionLabel  string
	ActorEmail   string
	ActorRole    string
	TenantName   string
	ResourceName string // the applications they administer after the change
	OccurredAt   string
}

// Mailer sends transactional emails. Each method takes an optional per-scope
// sender (nil = global) and an optional template override (nil = built-in).
type Mailer interface {
	SendReset(ctx context.Context, sender *SMTPConfig, tmpl *Template, email ResetEmail) error
	SendMFACode(ctx context.Context, sender *SMTPConfig, tmpl *Template, email MFACodeEmail) error
	SendMagicLink(ctx context.Context, sender *SMTPConfig, tmpl *Template, email MagicLinkEmail) error
	SendVerification(ctx context.Context, sender *SMTPConfig, tmpl *Template, email VerificationEmail) error
	SendWelcome(ctx context.Context, sender *SMTPConfig, tmpl *Template, email WelcomeEmail) error
	SendPasswordChanged(ctx context.Context, sender *SMTPConfig, tmpl *Template, email PasswordChangedEmail) error
	SendInvitation(ctx context.Context, sender *SMTPConfig, tmpl *Template, email InvitationEmail) error
	SendChangeEmail(ctx context.Context, sender *SMTPConfig, tmpl *Template, email ChangeEmailEmail) error
	SendBlockedAccount(ctx context.Context, sender *SMTPConfig, tmpl *Template, email BlockedAccountEmail) error
	SendPasswordBreach(ctx context.Context, sender *SMTPConfig, tmpl *Template, email PasswordBreachEmail) error
	SendAdminActivity(ctx context.Context, sender *SMTPConfig, tmpl *Template, email AdminActivityEmail) error
	SendAccessChanged(ctx context.Context, sender *SMTPConfig, tmpl *Template, email AccessChangedEmail) error
	// SendTest renders the given template type with sample data and delivers it to
	// `to`, so an admin can verify a sender/provider configuration end-to-end.
	SendTest(ctx context.Context, sender *SMTPConfig, tmpl *Template, tt TemplateType, to string) error
	// GlobalProvider names the transport the global sender uses ("smtp",
	// "sendgrid", or "dev" when nothing is configured). Reported by the test
	// endpoint so an admin can see that a send fell through to the server
	// default — or, in dev, that it was only logged and never transmitted.
	GlobalProvider() string
}

// ---------------------------------------------------------------------------
// Branding resolution.
// ---------------------------------------------------------------------------

type branding struct {
	ProductName   string
	LogoURL       string
	SubjectPrefix string
}

func brandingFrom(sender *SMTPConfig) branding {
	b := branding{ProductName: defaultProductName}
	if sender != nil {
		if sender.ProductName != "" {
			b.ProductName = sender.ProductName
		}
		b.LogoURL = sender.LogoURL
		b.SubjectPrefix = sender.SubjectPrefix
	}
	return b
}

func (b branding) subjectWith(subject string) string {
	if b.SubjectPrefix != "" {
		return b.SubjectPrefix + " " + subject
	}
	return subject
}

// tlsFor selects the SMTP TLS mode: explicit override wins, otherwise derived
// from the port (465 = implicit TLS, everything else = mandatory STARTTLS).
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

// ---------------------------------------------------------------------------
// mailerImpl — the single Mailer implementation. It holds the global sender
// config; per-send overrides replace it.
// ---------------------------------------------------------------------------

type mailerImpl struct {
	global   SMTPConfig // global sender (From/branding/provider/creds)
	globalTr transport  // transport for the global sender (smtp/sendgrid/dev)
	logger   zerolog.Logger
}

// dispatch renders one email and sends it via the resolved transport.
func (m *mailerImpl) dispatch(ctx context.Context, sender *SMTPConfig, tmpl *Template, tt TemplateType, to string, data TemplateData) error {
	b := brandingFrom(sender)
	data.ProductName = b.ProductName
	data.LogoURL = b.LogoURL
	data.Email = to

	// Resolve the template: custom override → built-in default. A custom
	// template that fails to render falls back to the built-in default.
	def, ok := builtinTemplates[tt]
	if !ok {
		return fmt.Errorf("no template for type %q", tt)
	}
	use := def
	if tmpl != nil {
		use = *tmpl
	}
	out, err := use.render(data)
	if err != nil {
		if tmpl != nil {
			m.logger.Warn().Err(err).Str("type", string(tt)).Msg("custom template render failed — using built-in default")
			if out, err = def.render(data); err != nil {
				return fmt.Errorf("render built-in %s: %w", tt, err)
			}
		} else {
			return fmt.Errorf("render %s: %w", tt, err)
		}
	}

	from, fromName, replyTo := m.global.From, m.global.FromName, m.global.ReplyTo
	tr := m.globalTr
	if sender != nil {
		from, fromName, replyTo = sender.From, sender.FromName, sender.ReplyTo
		tr = pickTransport(sender, m.logger)
	}

	return tr.send(ctx, outMessage{
		From:     from,
		FromName: fromName,
		ReplyTo:  replyTo,
		To:       to,
		Subject:  b.subjectWith(out.Subject),
		HTML:     out.HTML,
		Text:     out.Text,
	})
}

// defaultResetTTLMinutes states the reset-link validity window when a caller
// leaves ResetEmail.TTLMinutes unset. It mirrors auth.ResetTokenTTL; callers
// that know the real window should always pass it so the body cannot drift from
// the token's actual expiry.
const defaultResetTTLMinutes = 15

func (m *mailerImpl) SendReset(ctx context.Context, sender *SMTPConfig, tmpl *Template, e ResetEmail) error {
	ttl := e.TTLMinutes
	if ttl <= 0 {
		ttl = defaultResetTTLMinutes
	}
	err := m.dispatch(ctx, sender, tmpl, TemplatePasswordReset, e.To, TemplateData{Link: e.ResetLink, TTLMinutes: ttl})
	if err == nil {
		m.logger.Info().Str("to", e.To).Msg("password reset email sent")
	}
	return err
}

func (m *mailerImpl) SendMFACode(ctx context.Context, sender *SMTPConfig, tmpl *Template, e MFACodeEmail) error {
	err := m.dispatch(ctx, sender, tmpl, TemplateMFACode, e.To, TemplateData{Code: e.Code, AppName: e.AppName, TTLMinutes: e.TTLMinutes})
	if err == nil {
		m.logger.Info().Str("to", e.To).Str("app", e.AppName).Msg("MFA code email sent")
	}
	return err
}

func (m *mailerImpl) SendMagicLink(ctx context.Context, sender *SMTPConfig, tmpl *Template, e MagicLinkEmail) error {
	err := m.dispatch(ctx, sender, tmpl, TemplateMagicLink, e.To, TemplateData{Link: e.Link, AppName: e.AppName, TTLMinutes: e.TTLMinutes})
	if err == nil {
		m.logger.Info().Str("to", e.To).Str("app", e.AppName).Msg("magic link email sent")
	}
	return err
}

func (m *mailerImpl) SendVerification(ctx context.Context, sender *SMTPConfig, tmpl *Template, e VerificationEmail) error {
	err := m.dispatch(ctx, sender, tmpl, TemplateEmailVerification, e.To, TemplateData{Link: e.Link, AppName: e.AppName, TTLMinutes: e.TTLMinutes})
	if err == nil {
		m.logger.Info().Str("to", e.To).Str("app", e.AppName).Msg("verification email sent")
	}
	return err
}

func (m *mailerImpl) SendWelcome(ctx context.Context, sender *SMTPConfig, tmpl *Template, e WelcomeEmail) error {
	err := m.dispatch(ctx, sender, tmpl, TemplateWelcome, e.To, TemplateData{Name: e.Name, AppName: e.AppName})
	if err == nil {
		m.logger.Info().Str("to", e.To).Msg("welcome email sent")
	}
	return err
}

func (m *mailerImpl) SendPasswordChanged(ctx context.Context, sender *SMTPConfig, tmpl *Template, e PasswordChangedEmail) error {
	err := m.dispatch(ctx, sender, tmpl, TemplatePasswordChanged, e.To, TemplateData{})
	if err == nil {
		m.logger.Info().Str("to", e.To).Msg("password-changed email sent")
	}
	return err
}

func (m *mailerImpl) SendInvitation(ctx context.Context, sender *SMTPConfig, tmpl *Template, e InvitationEmail) error {
	err := m.dispatch(ctx, sender, tmpl, TemplateUserInvitation, e.To, TemplateData{
		Link: e.Link, AppName: e.AppName, InviterName: e.InviterName, Name: e.Name, TTLMinutes: e.TTLMinutes,
	})
	if err == nil {
		m.logger.Info().Str("to", e.To).Str("app", e.AppName).Msg("invitation email sent")
	}
	return err
}

func (m *mailerImpl) SendChangeEmail(ctx context.Context, sender *SMTPConfig, tmpl *Template, e ChangeEmailEmail) error {
	err := m.dispatch(ctx, sender, tmpl, TemplateChangeEmail, e.To, TemplateData{
		Link: e.Link, AppName: e.AppName, TTLMinutes: e.TTLMinutes,
		Reason: e.Reason, NewEmail: e.NewEmail,
	})
	if err == nil {
		m.logger.Info().Str("to", e.To).Str("reason", e.Reason).Msg("change-email message sent")
	}
	return err
}

func (m *mailerImpl) SendBlockedAccount(ctx context.Context, sender *SMTPConfig, tmpl *Template, e BlockedAccountEmail) error {
	err := m.dispatch(ctx, sender, tmpl, TemplateBlockedAccount, e.To, TemplateData{
		Link: e.Link, AppName: e.AppName, Reason: e.Reason, TTLMinutes: e.TTLMinutes,
	})
	if err == nil {
		m.logger.Info().Str("to", e.To).Str("reason", e.Reason).Msg("blocked-account email sent")
	}
	return err
}

func (m *mailerImpl) SendPasswordBreach(ctx context.Context, sender *SMTPConfig, tmpl *Template, e PasswordBreachEmail) error {
	err := m.dispatch(ctx, sender, tmpl, TemplatePasswordBreach, e.To, TemplateData{Link: e.Link, AppName: e.AppName})
	if err == nil {
		m.logger.Info().Str("to", e.To).Msg("password-breach alert sent")
	}
	return err
}

func (m *mailerImpl) SendAdminActivity(ctx context.Context, sender *SMTPConfig, tmpl *Template, e AdminActivityEmail) error {
	err := m.dispatch(ctx, sender, tmpl, TemplateAdminActivity, e.To, TemplateData{
		ActorEmail:   e.ActorEmail,
		ActorRole:    e.ActorRole,
		ActionLabel:  e.ActionLabel,
		TenantName:   e.TenantName,
		ResourceName: e.ResourceName,
		OccurredAt:   e.OccurredAt,
		IPAddress:    e.IPAddress,
		Link:         e.Link,
		Count:        e.Count,
	})
	if err == nil {
		m.logger.Info().
			Str("to", e.To).Str("actor", e.ActorEmail).Str("action", e.ActionLabel).
			Msg("admin-activity notification sent")
	}
	return err
}

func (m *mailerImpl) SendAccessChanged(ctx context.Context, sender *SMTPConfig, tmpl *Template, e AccessChangedEmail) error {
	err := m.dispatch(ctx, sender, tmpl, TemplateAccessChanged, e.To, TemplateData{
		ActionLabel:  e.ActionLabel,
		ActorEmail:   e.ActorEmail,
		ActorRole:    e.ActorRole,
		TenantName:   e.TenantName,
		ResourceName: e.ResourceName,
		OccurredAt:   e.OccurredAt,
	})
	if err == nil {
		m.logger.Info().Str("to", e.To).Str("change", e.ActionLabel).Msg("access-changed notice sent")
	}
	return err
}

// sampleTestData is the placeholder variable set used when rendering a test
// email — every template field gets a representative value so the preview looks
// realistic regardless of the chosen template type.
func sampleTestData() TemplateData {
	return TemplateData{
		AppName:     "Example App",
		Link:        "https://example.com/action?token=SAMPLE_TOKEN",
		Code:        "123456",
		TTLMinutes:  15,
		Name:        "Alex Doe",
		InviterName: "Jordan Smith",
		Reason:      BlockReasonFailedAttempts,
		// admin_activity fields — without these the test send for that type
		// renders a message with no subject content and empty rows.
		ActorEmail:   "jordan.smith@example.com",
		ActorRole:    "owner",
		ActionLabel:  "rotated a client secret",
		TenantName:   "Example Tenant",
		ResourceName: "Example App",
		OccurredAt:   "31 Jul 2026, 16:42",
		IPAddress:    "203.0.113.9",
		Count:        1,
	}
}

// GlobalProvider names the global transport. The empty Provider set by
// NewMailer's default branch means the log-only dev transport, which is
// reported as "dev" rather than blank — an admin seeing a successful test that
// never arrives needs to be told nothing was actually transmitted.
func (m *mailerImpl) GlobalProvider() string {
	if m.global.Provider == "" {
		return "dev"
	}
	return m.global.Provider
}

func (m *mailerImpl) SendTest(ctx context.Context, sender *SMTPConfig, tmpl *Template, tt TemplateType, to string) error {
	// TemplateProviderTest is intentionally absent from AllTemplateTypes (it is
	// not customizable), so ValidTemplateType rejects it — accept it explicitly
	// rather than silently coercing a provider test into a verification email.
	// Anything else unrecognised falls back to the diagnostic template too: a
	// test send should never impersonate a real account email.
	if tt != TemplateProviderTest && !ValidTemplateType(tt) {
		tt = TemplateProviderTest
	}
	err := m.dispatch(ctx, sender, tmpl, tt, to, sampleTestData())
	if err == nil {
		m.logger.Info().Str("to", to).Str("type", string(tt)).Msg("test email sent")
	}
	return err
}

// ---------------------------------------------------------------------------
// Construction.
// ---------------------------------------------------------------------------

// MailerConfig holds the configuration for constructing the global Mailer.
type MailerConfig struct {
	Env string

	// Provider selects the global transport: "smtp" or "sendgrid". Empty is
	// inferred: "sendgrid" when SendGridAPIKey is set, else "smtp" when SMTPHost
	// is set, else the log-only dev transport.
	Provider string

	// SMTP relay (Provider="smtp").
	SMTPHost     string
	SMTPPort     int
	SMTPUsername string
	SMTPPassword string
	SMTPTLS      string

	// SendGrid (Provider="sendgrid").
	SendGridAPIKey string

	// EmailFrom is the global From address (both providers).
	EmailFrom string
	FromName  string

	Logger zerolog.Logger
}

// resolveProvider infers the global provider when not set explicitly.
func (cfg MailerConfig) resolveProvider() string {
	switch strings.ToLower(cfg.Provider) {
	case ProviderSendGrid:
		return ProviderSendGrid
	case ProviderSMTP:
		return ProviderSMTP
	}
	if cfg.SendGridAPIKey != "" {
		return ProviderSendGrid
	}
	if cfg.SMTPHost != "" {
		return ProviderSMTP
	}
	return "" // dev / log-only
}

// NewMailer builds the global Mailer. With no provider configured (no SendGrid
// key and no SMTP host) it logs emails instead of sending them, preserving the
// original dev behaviour (a warning is emitted in production).
func NewMailer(cfg MailerConfig) Mailer {
	m := &mailerImpl{
		logger: cfg.Logger,
		global: SMTPConfig{From: cfg.EmailFrom, FromName: cfg.FromName},
	}
	// Same trimming rationale as pickTransport: a trailing newline on an env
	// var is invisible in a 401 and costs hours to find.
	switch cfg.resolveProvider() {
	case ProviderSendGrid:
		m.global.Provider = ProviderSendGrid
		m.global.APIKey = strings.TrimSpace(cfg.SendGridAPIKey)
		m.globalTr = &sendGridTransport{apiKey: strings.TrimSpace(cfg.SendGridAPIKey), logger: cfg.Logger}
	case ProviderSMTP:
		m.global.Provider = ProviderSMTP
		m.globalTr = &smtpTransport{
			host:     strings.TrimSpace(cfg.SMTPHost),
			port:     cfg.SMTPPort,
			username: strings.TrimSpace(cfg.SMTPUsername),
			password: strings.TrimSpace(cfg.SMTPPassword),
			tlsMode:  cfg.SMTPTLS,
			logger:   cfg.Logger,
		}
	default:
		if cfg.Env == "production" {
			cfg.Logger.Warn().Msg("no email provider configured in production — falling back to console mailer")
		}
		m.globalTr = &devTransport{logger: cfg.Logger}
	}
	return m
}
