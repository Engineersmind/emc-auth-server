package mailer

// TemplateVariable describes one variable a custom template may reference. It
// feeds the console editor's variable list, so the list shown to an author is the
// one this server actually renders rather than a copy that can drift.
type TemplateVariable struct {
	// Name is the reference as written in a template, e.g. "{{.Link}}".
	Name        string `json:"name"`
	Description string `json:"description"`
	// Availability is VarAlways when every send fills it, or VarOptional when it
	// can be empty — in which case the template should wrap it in {{if}} so the
	// surrounding row disappears instead of rendering blank.
	Availability string `json:"availability"`
}

// Variable availability values.
const (
	VarAlways   = "always"
	VarOptional = "optional"
)

func v(name, desc, avail string) TemplateVariable {
	return TemplateVariable{Name: "{{." + name + "}}", Description: desc, Availability: avail}
}

// commonVariables are filled for every template type.
var commonVariables = []TemplateVariable{
	v("ProductName", "Product name from the sender's branding", VarAlways),
	v("LogoURL", "Logo image URL from the sender's branding", VarOptional),
	v("Email", "The recipient's email address", VarAlways),
	v("MaskedEmail", "The recipient's address with the local part hidden (a***@acme.com)", VarAlways),
	v("SupportEmail", "The sender's reply-to address, else its From address", VarAlways),
	v("Year", "The current year", VarAlways),
	v("OccurredAt", "When the email was sent, in the recipient's timezone when known, else UTC", VarAlways),
	v("Timezone", "The timezone OccurredAt and ExpiryTime are shown in", VarAlways),
}

// contextVariables describe the end user's device and place. Declared for every
// type so any template can use them, but only populated for emails triggered by
// the recipient's own request, and only when the application's backend forwarded
// the user's identity (or the user called directly).
var contextVariables = []TemplateVariable{
	v("Browser", "The user's browser, e.g. Chrome", VarOptional),
	v("OS", "The user's operating system, e.g. Windows 10", VarOptional),
	v("City", "Approximate city of the request", VarOptional),
	v("Country", "Approximate country of the request", VarOptional),
	v("Location", "City and country together, e.g. Pune, India", VarOptional),
}

// typeVariables are the variables specific to each template type.
var typeVariables = map[TemplateType][]TemplateVariable{
	TemplateEmailVerification: {
		v("Link", "The full verification URL, including the token", VarAlways),
		v("Token", "The verification token only, for building a link to your own page", VarAlways),
		v("AppName", "The application name", VarOptional),
		v("TTLMinutes", "Minutes the link stays valid", VarAlways),
		v("ExpiryTime", "Clock time the link stops working", VarAlways),
		v("Name", "The recipient's first name", VarOptional),
	},
	TemplatePasswordReset: {
		v("Link", "The full password-reset URL, including the token", VarAlways),
		v("Token", "The reset token only, for building a link to your own page", VarAlways),
		v("TenantName", "The account's tenant name", VarOptional),
		v("TTLMinutes", "Minutes the link stays valid", VarAlways),
		v("ExpiryTime", "Clock time the link stops working", VarAlways),
		v("Name", "The recipient's first name", VarOptional),
	},
	TemplateWelcome: {
		v("Name", "The recipient's first name", VarOptional),
		v("AppName", "The application name", VarOptional),
		v("LoginURL", "Where the recipient signs in", VarOptional),
	},
	TemplateMFACode: {
		v("Code", "The one-time code", VarAlways),
		v("Purpose", "What the code is for, to finish \"use the code to …\"", VarAlways),
		v("AppName", "The application name", VarOptional),
		v("TTLMinutes", "Minutes the code stays valid", VarAlways),
		v("ExpiryTime", "Clock time the code stops working", VarAlways),
		v("Name", "The recipient's first name", VarOptional),
	},
	TemplateMagicLink: {
		v("Link", "The full sign-in URL, including the token", VarAlways),
		v("Token", "The one-time token only, for building a link to your own page", VarAlways),
		v("AppName", "The application name", VarOptional),
		v("TTLMinutes", "Minutes the link stays valid", VarAlways),
		v("ExpiryTime", "Clock time the link stops working", VarAlways),
		v("Name", "The recipient's first name", VarOptional),
	},
	TemplatePasswordChanged: {},
	TemplateUserInvitation: {
		v("Link", "The full invitation URL, including the token", VarAlways),
		v("Token", "The invitation token only, for building a link to your own page", VarAlways),
		v("AppName", "The application name", VarOptional),
		v("InviterName", "Who sent the invitation", VarOptional),
		v("Name", "The invitee's name", VarOptional),
		v("AdminRole", "The administrator role conferred, when it is an admin invitation", VarOptional),
		v("TenantName", "The tenant name, for an admin invitation", VarOptional),
		v("TTLMinutes", "Minutes the invitation stays valid", VarAlways),
	},
	TemplateChangeEmail: {
		v("Link", "The confirmation URL", VarOptional),
		v("AppName", "The application name", VarOptional),
		v("NewEmail", "The address the account moved to (notice to the old address)", VarOptional),
		v("Reason", "email_changed for the notice to the previous address", VarOptional),
		v("TTLMinutes", "Minutes the link stays valid", VarOptional),
	},
	TemplateBlockedAccount: {
		v("Link", "The unlock or password-reset URL, depending on Reason", VarAlways),
		v("ResetLink", "A password-reset URL offered beside the unlock link", VarOptional),
		v("Reason", "failed_attempts, failed_attempts_warning, soft_locked, admin or suspicious_login", VarAlways),
		v("Count", "Number of failed sign-ins that caused the lock", VarOptional),
		v("AppName", "The application name", VarOptional),
		v("TTLMinutes", "Minutes the link stays valid", VarAlways),
		v("RetryMinutes", "Minutes until an automatic lock lifts on its own", VarOptional),
		v("Name", "The recipient's first name", VarOptional),
	},
	TemplatePasswordBreach: {
		v("Link", "Where the recipient changes their password", VarOptional),
		v("AppName", "The application name", VarOptional),
	},
	TemplateTenantLockoutAlert: {
		v("Link", "The filtered users page", VarOptional),
		v("TenantName", "The tenant name", VarOptional),
		v("AppName", "The affected application", VarOptional),
		v("Count", "Number of accounts locked in the window", VarAlways),
		v("TTLMinutes", "The window, in minutes", VarAlways),
	},
	TemplateAdminActivity: {
		v("ActionLabel", "What was done, in words", VarAlways),
		v("ActorEmail", "Who did it", VarAlways),
		v("ActorRole", "The actor's role", VarOptional),
		v("TenantName", "The tenant", VarOptional),
		v("ResourceName", "The application or resource touched", VarOptional),
		v("IPAddress", "The actor's IP address", VarOptional),
		v("Count", "How many identical actions were collapsed into this email", VarOptional),
	},
	TemplateAccessChanged: {
		v("ActionLabel", "What changed, in words", VarAlways),
		v("ActorEmail", "Who changed it", VarOptional),
		v("TenantName", "The tenant", VarOptional),
		v("AdminRole", "The role granted or withdrawn", VarOptional),
	},
	TemplatePasswordlessCode: {
		v("Code", "The one-time code", VarAlways),
		v("Purpose", "What the code is for: sign in, or confirm your email address", VarAlways),
		v("Reason", "verify when the code confirms an address, otherwise a sign-in", VarOptional),
		v("Origin", "Approximate request origin", VarOptional),
		v("AppName", "The application name", VarOptional),
		v("TTLMinutes", "Minutes the code stays valid", VarAlways),
		v("ExpiryTime", "Clock time the code stops working", VarAlways),
		v("Name", "The recipient's first name", VarOptional),
	},
}

// VariablesFor lists every variable a custom template of this type may use:
// the common set, the type's own, and the device/place set.
func VariablesFor(tt TemplateType) []TemplateVariable {
	own := typeVariables[tt]
	out := make([]TemplateVariable, 0, len(commonVariables)+len(own)+len(contextVariables))
	out = append(out, commonVariables...)
	out = append(out, own...)
	out = append(out, contextVariables...)
	return out
}
