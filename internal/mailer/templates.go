package mailer

import (
	"bytes"
	"fmt"
	"html/template"
	"strings"
	tmpltext "text/template"
)

// TemplateType identifies one transactional email. Every type has a built-in
// default (builtinTemplates) that a tenant/application may override in the DB.
type TemplateType string

const (
	// TemplateEmailVerification confirms ownership of an email address (sent on
	// self-service registration).
	TemplateEmailVerification TemplateType = "email_verification"
	// TemplatePasswordReset is the forgot-password reset link.
	TemplatePasswordReset TemplateType = "password_reset"
	// TemplateWelcome greets a user once their email is verified.
	TemplateWelcome TemplateType = "welcome"
	// TemplateMFACode is the one-time email MFA code.
	TemplateMFACode TemplateType = "mfa_code"
	// TemplateMagicLink is the passwordless sign-in link.
	TemplateMagicLink TemplateType = "magic_link"
	// TemplatePasswordChanged is the confirmation sent after a password change.
	TemplatePasswordChanged TemplateType = "password_changed"
	// TemplateUserInvitation invites a user to join a tenant/application (an
	// admin-created account that has not yet been claimed).
	TemplateUserInvitation TemplateType = "user_invitation"
	// TemplateChangeEmail confirms ownership of a new address when a user changes
	// their email.
	TemplateChangeEmail TemplateType = "change_email"
	// TemplateBlockedAccount alerts a user that their account was blocked after a
	// suspicious sign-in, with a link to unblock/secure it.
	TemplateBlockedAccount TemplateType = "blocked_account"
	// TemplatePasswordBreach warns a user that their password was found in a known
	// data breach and should be changed.
	TemplatePasswordBreach TemplateType = "password_breach"
	// TemplateTenantLockoutAlert warns a tenant's owner and the co-owners of an
	// affected application that many accounts locked inside one window — the
	// credential-stuffing signal (issue #72). Addressed to operators, not to the
	// account holder, and sent only in aggregate: see the template body for why a
	// per-account version of this email would be self-defeating.
	TemplateTenantLockoutAlert TemplateType = "tenant_lockout_alert"

	// TemplateProviderTest is the diagnostic email sent by the admin "send test"
	// action. It is deliberately NOT in AllTemplateTypes: it is not a
	// customizable, user-facing email, so it must not appear in the template
	// editor or be overridable per scope.
	//
	// It exists because the test used to render email_verification, which meant
	// the recipient received a genuine-looking "Verify your email address"
	// message containing a dead sample link. That is actively harmful: it trains
	// people to click verification links that go nowhere, and an admin checking
	// their inbox cannot tell a configuration test from a real verification bug.
	// A test email should announce itself as a test.
	TemplateProviderTest TemplateType = "provider_test"

	// TemplateAdminActivity reports a privileged administrative action to the
	// people accountable for it: the tier above the actor (a platform admin for an
	// owner's action, the tenant's owners for a co-owner's), and for sensitive
	// actions the actor themselves — the same reasoning as password_changed,
	// where a copy of your own action is how you discover it was not you.
	TemplateAdminActivity TemplateType = "admin_activity"
	// TemplateAccessChanged tells someone that THEIR OWN administrative access
	// was granted, narrowed or withdrawn. Distinct from admin_activity, which
	// reports an action to the people overseeing it: this one is addressed to
	// the person the action was taken on, who would otherwise discover it only
	// by being refused something they could do yesterday.
	TemplateAccessChanged TemplateType = "access_changed"
)

// AllTemplateTypes lists every customizable template, for admin listing and
// validation. Add new types here (and to builtinTemplates) to expose them.
var AllTemplateTypes = []TemplateType{
	TemplateEmailVerification,
	TemplatePasswordReset,
	TemplateWelcome,
	TemplateMFACode,
	TemplateMagicLink,
	TemplatePasswordChanged,
	TemplateUserInvitation,
	TemplateChangeEmail,
	TemplateBlockedAccount,
	TemplatePasswordBreach,
	TemplateTenantLockoutAlert,
	TemplateAdminActivity,
	TemplateAccessChanged,
}

// ValidTemplateType reports whether t is a known template type.
func ValidTemplateType(t TemplateType) bool {
	for _, k := range AllTemplateTypes {
		if k == t {
			return true
		}
	}
	return false
}

// Template is a raw (unrendered) email template: Go-template source for the
// subject, HTML body, and plain-text body. A DB override and a built-in default
// share this shape, so rendering is identical for both.
type Template struct {
	Subject string
	HTML    string
	Text    string
}

// TemplateData is the variable set available to every template. Individual
// templates reference only the fields they need; unused fields render empty.
type TemplateData struct {
	ProductName string // branding product name (defaulted)
	LogoURL     string // optional logo image URL
	AppName     string // requesting application name (may be empty)
	Link        string // action URL (verify/reset/magic link)
	Code        string // one-time code (MFA)
	TTLMinutes  int    // validity window for links/codes
	Name        string // recipient display name (may be empty)
	Email       string // recipient address
	InviterName string // who sent an invitation (user_invitation; may be empty)
	// Reason selects a variant within a template that covers several events: one
	// of the BlockReason* values for blocked_account, or EmailChangeApplied for
	// change_email. Empty in every other template.
	Reason string
	// NewEmail is the address an account was moved to (change_email's
	// EmailChangeApplied variant, sent to the previous address). Empty elsewhere.
	NewEmail string

	// Fields below describe an administrative action for admin_activity. Empty
	// in every other template.
	//
	// ActionLabel carries the human phrasing ("rotated a client secret") rather
	// than the raw action key, and is resolved in Go. A template covering a dozen
	// actions cannot branch on each one the way Reason does for the three
	// blocked_account variants — it would be unreadable and every new action
	// would mean editing the template as well as the catalogue.
	ActionLabel string
	// ActorEmail and ActorRole identify who acted. The role is spelled for
	// humans ("owner", "co-owner"), since the point of the email is that the
	// recipient can judge whether the action was appropriate for that tier.
	ActorEmail string
	ActorRole  string
	// TenantName and ResourceName answer "where" — the tenant and, where the
	// action had one, the application or other resource it touched.
	TenantName   string
	ResourceName string
	// OccurredAt is preformatted for display; templates must not do date
	// arithmetic. IPAddress may be empty for actions with no request context.
	OccurredAt string
	IPAddress  string
	// Count is the number of collapsed occurrences when several identical
	// actions in quick succession became one email. Zero or one renders as a
	// single event. Reused by tenant_lockout_alert for the number of accounts
	// locked inside the window.
	Count int

	// RetryMinutes is how long until an automatic lock lifts by itself (issue
	// #72). Distinct from TTLMinutes, which is how long the emailed link stays
	// valid: the two are different clocks, and a blocked-account email carries
	// both — "this link works for 60 minutes" and "or just wait 30". Zero when
	// the lock does not expire on its own, which is what keeps the "you can also
	// simply wait" sentence out of a permanent lock's email.
	RetryMinutes int
}

// EmailChangeApplied is the TemplateData.Reason value that turns the
// change_email template into the security notice sent to the PREVIOUS address
// after a change has applied, instead of the confirmation sent to the new one.
const EmailChangeApplied = "email_changed"

// Block reasons carried in TemplateData.Reason. They select the wording of the
// blocked_account email, which covers three distinct events.
const (
	// BlockReasonFailedAttempts is an automatic block after repeated failed
	// sign-ins. The user may lift it themselves via the emailed link.
	BlockReasonFailedAttempts = "failed_attempts"
	// BlockReasonAdmin is an administrator disabling the account. The link is a
	// password reset, not an unblock — only an admin can restore access.
	BlockReasonAdmin = "admin"
	// BlockReasonSuspiciousLogin is a high-risk sign-in that succeeded. Nothing
	// is blocked; this is an alert telling the user to secure the account.
	BlockReasonSuspiciousLogin = "suspicious_login"
	// BlockReasonFailedAttemptsWarning is the early warning (issue #72): repeated
	// failures, nothing locked yet. It exists so a victim hears about an attack
	// while it is still running rather than once they cannot sign in. The link is
	// a password reset, since there is nothing to unblock.
	BlockReasonFailedAttemptsWarning = "failed_attempts_warning"
	// BlockReasonSoftLocked is a TEMPORARY refusal that lifts on its own. No
	// account state changed, so the wording must not tell the user to contact an
	// administrator — there is nothing for an operator to undo, and the advice
	// would generate support load for an event that resolves itself.
	BlockReasonSoftLocked = "soft_locked"
)

// LockoutAlertReasons select the wording of the tenant_lockout_alert email.
const (
	// LockoutAlertSpike is many accounts locking inside one window — the
	// credential-stuffing signal sent to a tenant's owner and affected co-owners.
	LockoutAlertSpike = "lockout_spike"
)

// rendered is the output of applying a Template to TemplateData.
type rendered struct {
	Subject string
	HTML    string
	Text    string
}

// render applies a Template to data. HTML is rendered with html/template
// (auto-escaping); subject and text use text/template. Any parse/exec error is
// returned so a broken custom template falls back to the built-in default
// rather than sending a malformed message.
func (t Template) render(data TemplateData) (rendered, error) {
	subj, err := renderTextTmpl("subject", t.Subject, data)
	if err != nil {
		return rendered{}, fmt.Errorf("render subject: %w", err)
	}
	text, err := renderTextTmpl("text", t.Text, data)
	if err != nil {
		return rendered{}, fmt.Errorf("render text: %w", err)
	}
	htmlTmpl, err := template.New("html").Parse(t.HTML)
	if err != nil {
		return rendered{}, fmt.Errorf("parse html: %w", err)
	}
	var htmlBuf bytes.Buffer
	if err := htmlTmpl.Execute(&htmlBuf, data); err != nil {
		return rendered{}, fmt.Errorf("exec html: %w", err)
	}
	return rendered{Subject: strings.TrimSpace(subj), HTML: htmlBuf.String(), Text: text}, nil
}

func renderTextTmpl(name, src string, data TemplateData) (string, error) {
	tmpl, err := tmpltext.New(name).Parse(src)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// Validate parses every part of a template so a syntactically broken custom
// template is rejected at upsert time (before it can break a live send).
func (t Template) Validate() error {
	if strings.TrimSpace(t.Subject) == "" || strings.TrimSpace(t.HTML) == "" {
		return fmt.Errorf("subject and html body are required")
	}
	if _, err := tmpltext.New("subject").Parse(t.Subject); err != nil {
		return fmt.Errorf("subject template: %w", err)
	}
	if _, err := template.New("html").Parse(t.HTML); err != nil {
		return fmt.Errorf("html template: %w", err)
	}
	if t.Text != "" {
		if _, err := tmpltext.New("text").Parse(t.Text); err != nil {
			return fmt.Errorf("text template: %w", err)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Built-in default templates.
// ---------------------------------------------------------------------------

// htmlShellHead / htmlShellFoot wrap per-type inner HTML in the shared layout
// (logo + product-name footer). Custom DB templates supply their own full HTML;
// these builtins reuse the shell so they stay visually consistent.
const htmlShellHead = `<!doctype html>
<html><body style="font-family:Arial,Helvetica,sans-serif;color:#1a1a1a;line-height:1.5">
{{if .LogoURL}}<p><img src="{{.LogoURL}}" alt="{{.ProductName}}" style="max-height:40px"></p>{{end}}
`

const htmlShellFoot = `
<hr style="border:none;border-top:1px solid #eee;margin:24px 0">
<p style="font-size:12px;color:#666">{{.ProductName}}</p>
</body></html>`

// button renders a CTA anchor + fallback link line for the action URL.
const button = `<p><a href="{{.Link}}" style="display:inline-block;padding:10px 18px;background:#2563eb;color:#fff;text-decoration:none;border-radius:6px">%s</a></p>
<p style="font-size:12px;color:#666">Or paste this link into your browser:<br>{{.Link}}</p>`

func shell(inner string) string { return htmlShellHead + inner + htmlShellFoot }

// builtinTemplates holds the default Template for every TemplateType.
var builtinTemplates = map[TemplateType]Template{
	// Diagnostic only — see TemplateProviderTest. Contains no links and no
	// call to action, so it cannot be mistaken for a real account email.
	TemplateProviderTest: {
		Subject: "Test email",
		HTML: shell(`<h2>Your email configuration works</h2>
<p>This is a test message sent from the {{.ProductName}} admin console to confirm that email delivery is working.</p>
<p>Nothing else is required — no action is needed and no account was changed. If you were not expecting this, you can ignore it.</p>`),
		Text: `Your email configuration works.

This is a test message sent from the {{.ProductName}} admin console to confirm that email delivery is working.

No action is needed and no account was changed. If you were not expecting this, you can ignore it.

- {{.ProductName}}`,
	},
	TemplateEmailVerification: {
		Subject: "Verify your email address",
		HTML: shell(`<h2>Confirm your email</h2>
<p>Thanks for signing up{{if .AppName}} for {{.AppName}}{{end}}. Please confirm this is your email address.</p>
<p>This link is valid for {{.TTLMinutes}} minutes.</p>
` + fmt.Sprintf(button, "Verify email") + `
<p>If you did not create an account, you can safely ignore this email.</p>`),
		Text: `Confirm your email address to finish signing up{{if .AppName}} for {{.AppName}}{{end}}.

{{.Link}}

This link is valid for {{.TTLMinutes}} minutes. If you did not create an account, ignore this email.

- {{.ProductName}}`,
	},
	TemplatePasswordReset: {
		Subject: "Password Reset Request",
		HTML: shell(`<h2>Reset your password</h2>
<p>You requested a password reset for your account.</p>
<p>Click the button below to choose a new password. This link is valid for {{.TTLMinutes}} minutes.</p>
` + fmt.Sprintf(button, "Reset password") + `
<p>If you did not request this, you can safely ignore this email — your password will not change.</p>`),
		Text: `You requested a password reset for your account.

{{.Link}}

This link is valid for {{.TTLMinutes}} minutes. If you did not request this, ignore this email — your password will not change.

- {{.ProductName}}`,
	},
	TemplateWelcome: {
		Subject: "Welcome to {{.ProductName}}",
		HTML: shell(`<h2>Welcome{{if .Name}}, {{.Name}}{{end}}!</h2>
<p>Your email has been verified and your account{{if .AppName}} for {{.AppName}}{{end}} is ready to use.</p>
<p>We're glad to have you on board.</p>`),
		Text: `Welcome{{if .Name}}, {{.Name}}{{end}}!

Your email has been verified and your account{{if .AppName}} for {{.AppName}}{{end}} is ready to use.

- {{.ProductName}}`,
	},
	TemplateMFACode: {
		Subject: "{{if .AppName}}Your {{.AppName}} verification code{{else}}Your verification code{{end}}",
		HTML: shell(`<h2>Your verification code</h2>
<p>Your one-time verification code for {{if .AppName}}{{.AppName}}{{else}}your account{{end}} is:</p>
<p style="font-size:24px;font-weight:bold;letter-spacing:3px;font-family:monospace">{{.Code}}</p>
<p>It expires in {{.TTLMinutes}} minutes. If you did not try to sign in, secure your account by changing your password.</p>`),
		Text: `Your one-time verification code for {{if .AppName}}{{.AppName}}{{else}}your account{{end}} is:

    {{.Code}}

It expires in {{.TTLMinutes}} minutes. If you did not try to sign in, secure your account by changing your password.

- {{.ProductName}}`,
	},
	TemplateMagicLink: {
		Subject: "Sign in to {{if .AppName}}{{.AppName}}{{else}}your account{{end}}",
		HTML: shell(`<h2>Sign in</h2>
<p>Click the button below to sign in to {{if .AppName}}{{.AppName}}{{else}}your account{{end}}. This link is valid for {{.TTLMinutes}} minutes and can be used once.</p>
` + fmt.Sprintf(button, "Sign in") + `
<p>If you did not request this, you can safely ignore this email.</p>`),
		Text: `Click the link below to sign in to {{if .AppName}}{{.AppName}}{{else}}your account{{end}}. Valid for {{.TTLMinutes}} minutes, single use.

{{.Link}}

If you did not request this, ignore this email.

- {{.ProductName}}`,
	},
	TemplatePasswordChanged: {
		Subject: "Your password was changed",
		HTML: shell(`<h2>Your password was changed</h2>
<p>This is a confirmation that the password for your account was just changed.</p>
<p>If you did not make this change, contact support immediately — your account may be compromised.</p>`),
		Text: `This is a confirmation that the password for your account was just changed.

If you did not make this change, contact support immediately.

- {{.ProductName}}`,
	},
	TemplateUserInvitation: {
		Subject: "{{if .InviterName}}{{.InviterName}} invited you to {{end}}{{if .AppName}}{{.AppName}}{{else}}{{.ProductName}}{{end}}",
		HTML: shell(`<h2>You've been invited</h2>
<p>{{if .InviterName}}{{.InviterName}} has invited you{{else}}You have been invited{{end}} to join {{if .AppName}}{{.AppName}}{{else}}{{.ProductName}}{{end}}.</p>
<p>Accept the invitation to set up your account. This link is valid for {{.TTLMinutes}} minutes.</p>
` + fmt.Sprintf(button, "Accept invitation") + `
<p>If you were not expecting this invitation, you can safely ignore this email.</p>`),
		Text: `{{if .InviterName}}{{.InviterName}} has invited you{{else}}You have been invited{{end}} to join {{if .AppName}}{{.AppName}}{{else}}{{.ProductName}}{{end}}.

{{.Link}}

This link is valid for {{.TTLMinutes}} minutes. If you were not expecting this, ignore this email.

- {{.ProductName}}`,
	},
	// One template, two events — selected by .Reason. The default is the
	// confirmation sent to the NEW address; "email_changed" is the notice sent to
	// the PREVIOUS address once the change has applied, so the original owner
	// always learns about it and can act if it was not their doing.
	TemplateChangeEmail: {
		Subject: `{{if eq .Reason "email_changed"}}Security alert — the email address on your account was changed{{else}}Confirm your new email address{{end}}`,
		HTML: shell(`{{if eq .Reason "email_changed"}}<h2>Your account email was changed</h2>
<p>The email address on your account{{if .AppName}} for {{.AppName}}{{end}} was changed to <strong>{{.NewEmail}}</strong>. This message is the last one we will send to this address.</p>
<p>If you made this change, no action is needed. If you did not, your account may be compromised — reset your password immediately and contact support.</p>
` + fmt.Sprintf(button, "Reset password") + `
{{else}}<h2>Confirm your new email</h2>
<p>We received a request to change the email address on your account to this one. Please confirm it belongs to you.</p>
<p>This link is valid for {{.TTLMinutes}} minutes.</p>
` + fmt.Sprintf(button, "Confirm email") + `
<p>If you did not request this change, you can safely ignore this email — your address will not be updated.</p>{{end}}`),
		Text: `{{if eq .Reason "email_changed"}}The email address on your account{{if .AppName}} for {{.AppName}}{{end}} was changed to {{.NewEmail}}.

If you did not make this change, reset your password immediately and contact support:
{{.Link}}
{{else}}Confirm your new email address for your account.

{{.Link}}

This link is valid for {{.TTLMinutes}} minutes. If you did not request this change, ignore this email.
{{end}}
- {{.ProductName}}`,
	},
	// One template, five events — selected by .Reason. "suspicious_login" is an
	// alert (nothing is blocked), "admin" is an operator action the user cannot
	// undo (link = password reset), "failed_attempts_warning" and "soft_locked"
	// are the pre-block escalation tiers from issue #72 (nothing to unblock, so
	// the link is a password reset), and the default is an automatic lockout the
	// user may lift via the emailed single-use link.
	//
	// The two #72 tiers deliberately avoid the phrase "contact your administrator":
	// neither one is an operator-clearable state, and sending users to support for
	// something that resolves itself in minutes is how a security feature becomes
	// a helpdesk cost.
	TemplateBlockedAccount: {
		Subject: `{{if eq .Reason "suspicious_login"}}Security alert — unusual sign-in to your account{{else if eq .Reason "failed_attempts_warning"}}Security alert — failed sign-in attempts on your account{{else if eq .Reason "soft_locked"}}Sign-in temporarily locked{{else}}Your account has been blocked{{end}}`,
		HTML: shell(`{{if eq .Reason "suspicious_login"}}<h2>Unusual sign-in detected</h2>
<p>Someone signed in to your account{{if .AppName}} for {{.AppName}}{{end}} from a device or location we have not seen before. Your account has not been blocked.</p>
<p>If this was you, no action is needed. If it was not, secure your account now by changing your password.</p>
` + fmt.Sprintf(button, "Change password") + `
{{else if eq .Reason "failed_attempts_warning"}}<h2>Failed sign-in attempts on your account</h2>
<p>There have been several failed attempts to sign in to your account{{if .AppName}} for {{.AppName}}{{end}}. Your account is still active and nothing has been locked.</p>
<p>If this was you, you can ignore this message — or reset your password below if you have forgotten it.</p>
` + fmt.Sprintf(button, "Reset password") + `
<p>If this was not you, someone may be trying to guess your password. We recommend changing it now, and enabling two-factor authentication if you have not already.</p>
{{else if eq .Reason "soft_locked"}}<h2>Sign-in temporarily locked</h2>
<p>We have temporarily paused sign-ins to your account{{if .AppName}} for {{.AppName}}{{end}} after too many failed attempts. This is a security measure and your account has not been blocked.</p>
<p>You can try again in about {{.TTLMinutes}} minutes. No action is needed — the lock lifts on its own.</p>
<p>If you have forgotten your password, you can reset it now instead of waiting.</p>
` + fmt.Sprintf(button, "Reset password") + `
<p>If these attempts were not you, someone may be trying to guess your password — we recommend changing it.</p>
{{else if eq .Reason "admin"}}<h2>Your account has been blocked</h2>
<p>An administrator has blocked access to your account{{if .AppName}} for {{.AppName}}{{end}}.</p>
<p>Contact your administrator to restore access. If you believe your password was compromised, you can reset it using the link below.</p>
` + fmt.Sprintf(button, "Reset password") + `
{{else}}<h2>Your account was blocked</h2>
<p>We blocked access to your account{{if .AppName}} for {{.AppName}}{{end}} after too many failed sign-in attempts, to keep it secure.</p>
<p>If this was you, use the link below to unblock your account. This link is valid for {{.TTLMinutes}} minutes and can be used once.</p>
` + fmt.Sprintf(button, "Unblock account") + `
{{if .RetryMinutes}}<p>You can also simply wait: access is restored automatically in about {{.RetryMinutes}} minutes.</p>{{end}}
<p>If this was not you, someone may be trying to guess your password — we recommend changing it.</p>
{{end}}`),
		Text: `{{if eq .Reason "suspicious_login"}}Someone signed in to your account{{if .AppName}} for {{.AppName}}{{end}} from a device or location we have not seen before. Your account has not been blocked.

If this was not you, secure your account by changing your password:
{{.Link}}
{{else if eq .Reason "failed_attempts_warning"}}There have been several failed attempts to sign in to your account{{if .AppName}} for {{.AppName}}{{end}}. Your account is still active and nothing has been locked.

If this was you, you can ignore this message. To reset your password:
{{.Link}}

If this was not you, someone may be trying to guess your password. We recommend changing it, and enabling two-factor authentication.
{{else if eq .Reason "soft_locked"}}We have temporarily paused sign-ins to your account{{if .AppName}} for {{.AppName}}{{end}} after too many failed attempts. Your account has not been blocked.

You can try again in about {{.TTLMinutes}} minutes. No action is needed — the lock lifts on its own.

If you have forgotten your password, you can reset it now instead of waiting:
{{.Link}}
{{else if eq .Reason "admin"}}An administrator has blocked access to your account{{if .AppName}} for {{.AppName}}{{end}}.

Contact your administrator to restore access. To reset your password:
{{.Link}}
{{else}}We blocked access to your account{{if .AppName}} for {{.AppName}}{{end}} after too many failed sign-in attempts.

If this was you, unblock your account here:
{{.Link}}

This link is valid for {{.TTLMinutes}} minutes and can be used once.{{if .RetryMinutes}} You can also simply wait: access is restored automatically in about {{.RetryMinutes}} minutes.{{end}} If this was not you, change your password.
{{end}}
- {{.ProductName}}`,
	},

	// Tenant-level attack alert (issue #72), sent to a tenant's owner and to the
	// co-owners of affected applications.
	//
	// This is the ONLY lockout email staff receive, and it is deliberately
	// aggregated. A per-lock notification would, at credential-stuffing volume,
	// turn this server into a mail flood aimed at its own operators — and worse,
	// it would train them to filter the sender, so the one alert that mattered
	// would arrive in a spam folder. One account locking is routine; twenty
	// locking inside a window is an incident, and only the second is worth an
	// interrupt.
	TemplateTenantLockoutAlert: {
		Subject: `Security alert — {{.Count}} accounts locked{{if .TenantName}} in {{.TenantName}}{{end}}`,
		HTML: shell(`<h2>Multiple accounts locked</h2>
<p><strong>{{.Count}} accounts</strong>{{if .TenantName}} in {{.TenantName}}{{end}} were locked after repeated failed sign-in attempts within {{.TTLMinutes}} minutes.</p>
<p>A cluster this size usually means an automated password-guessing attack rather than users forgetting their passwords. The accounts are protected — each one locked automatically — but it is worth confirming the source.</p>
{{if .AppName}}<p>Affected application: <strong>{{.AppName}}</strong></p>{{end}}
` + fmt.Sprintf(button, "Review locked accounts") + `
<p>Locked accounts are restored automatically once the lock expires, or you can unlock any of them immediately from the users page.</p>`),
		Text: `{{.Count}} accounts{{if .TenantName}} in {{.TenantName}}{{end}} were locked after repeated failed sign-in attempts within {{.TTLMinutes}} minutes.

A cluster this size usually means an automated password-guessing attack rather than users forgetting their passwords. The accounts are protected — each one locked automatically — but it is worth confirming the source.
{{if .AppName}}
Affected application: {{.AppName}}
{{end}}
Review locked accounts:
{{.Link}}

Locked accounts are restored automatically once the lock expires, or you can unlock any of them immediately from the users page.

- {{.ProductName}}`,
	},
	TemplatePasswordBreach: {
		Subject: "Security alert — please change your password",
		HTML: shell(`<h2>Your password may be compromised</h2>
<p>Your current password was found in a known third-party data breach. To keep your account secure, please choose a new password now.</p>
` + fmt.Sprintf(button, "Change password") + `
<p>This does not necessarily mean your account has been accessed, but reusing a breached password puts it at risk.</p>`),
		Text: `Your current password was found in a known third-party data breach. Please choose a new password now to keep your account secure.

{{.Link}}

Reusing a breached password puts your account at risk.

- {{.ProductName}}`,
	},

	// No CTA button: there is no single action to take, and the recipient may be
	// reading this only to confirm the change was expected. The monitoring link
	// is offered as plain text so it survives a text-only client.
	TemplateAdminActivity: {
		Subject: "{{if .ActorRole}}{{.ActorRole}}{{else}}An administrator{{end}} {{.ActionLabel}}{{if .TenantName}} in {{.TenantName}}{{end}}",
		HTML: shell(`<h2>Administrator activity</h2>
<p><strong>{{.ActorEmail}}</strong>{{if .ActorRole}} ({{.ActorRole}}){{end}} {{.ActionLabel}}{{if gt .Count 1}}, {{.Count}} times in quick succession{{end}}.</p>
<table style="font-size:14px;border-collapse:collapse">
{{if .TenantName}}<tr><td style="padding:2px 16px 2px 0;color:#666">Tenant</td><td>{{.TenantName}}</td></tr>{{end}}
{{if .ResourceName}}<tr><td style="padding:2px 16px 2px 0;color:#666">Application</td><td>{{.ResourceName}}</td></tr>{{end}}
{{if .OccurredAt}}<tr><td style="padding:2px 16px 2px 0;color:#666">When</td><td>{{.OccurredAt}}</td></tr>{{end}}
{{if .IPAddress}}<tr><td style="padding:2px 16px 2px 0;color:#666">From</td><td>{{.IPAddress}}</td></tr>{{end}}
</table>
{{if .Link}}<p style="font-size:12px;color:#666">Review in monitoring:<br>{{.Link}}</p>{{end}}
<p style="font-size:12px;color:#666">You are receiving this because you are responsible for this tenant. If this change was not expected, review it now.</p>`),
		Text: `{{.ActorEmail}}{{if .ActorRole}} ({{.ActorRole}}){{end}} {{.ActionLabel}}{{if gt .Count 1}}, {{.Count}} times in quick succession{{end}}.

{{if .TenantName}}Tenant:      {{.TenantName}}
{{end}}{{if .ResourceName}}Application: {{.ResourceName}}
{{end}}{{if .OccurredAt}}When:        {{.OccurredAt}}
{{end}}{{if .IPAddress}}From:        {{.IPAddress}}
{{end}}{{if .Link}}
Review in monitoring: {{.Link}}
{{end}}
If this change was not expected, review it now.

- {{.ProductName}}`,
	},

	// Addressed to the person the change was made TO, so it speaks in the second
	// person and leads with what they can do now rather than who did it. Who did
	// it still matters — it is how they tell an expected change from one worth
	// querying — so it appears, just not first.
	TemplateAccessChanged: {
		Subject: "Your administrator access{{if .TenantName}} in {{.TenantName}}{{end}} has changed",
		HTML: shell(`<h2>Your access has changed</h2>
<p>{{.ActionLabel}}{{if .ActorEmail}}, by {{.ActorEmail}}{{if .ActorRole}} ({{.ActorRole}}){{end}}{{end}}.</p>
<table style="font-size:14px;border-collapse:collapse">
{{if .TenantName}}<tr><td style="padding:2px 16px 2px 0;color:#666">Tenant</td><td>{{.TenantName}}</td></tr>{{end}}
{{if .ResourceName}}<tr><td style="padding:2px 16px 2px 0;color:#666">Applications</td><td>{{.ResourceName}}</td></tr>{{end}}
{{if .OccurredAt}}<tr><td style="padding:2px 16px 2px 0;color:#666">When</td><td>{{.OccurredAt}}</td></tr>{{end}}
</table>
<p>You will see the change the next time you sign in.</p>
<p style="font-size:12px;color:#666">If you were not expecting this, contact whoever administers this tenant.</p>`),
		Text: `Your administrator access has changed.

{{.ActionLabel}}{{if .ActorEmail}}, by {{.ActorEmail}}{{if .ActorRole}} ({{.ActorRole}}){{end}}{{end}}.

{{if .TenantName}}Tenant:       {{.TenantName}}
{{end}}{{if .ResourceName}}Applications: {{.ResourceName}}
{{end}}{{if .OccurredAt}}When:         {{.OccurredAt}}
{{end}}
You will see the change the next time you sign in. If you were not expecting
this, contact whoever administers this tenant.

- {{.ProductName}}`,
	},
}

// BuiltinTemplate returns the default template for a type (used by the admin
// API to seed the editor and by the mailer as the render fallback).
func BuiltinTemplate(t TemplateType) (Template, bool) {
	tmpl, ok := builtinTemplates[t]
	return tmpl, ok
}
