package mailer

import (
	"embed"
	"fmt"
	"io/fs"
	"strings"
)

// templates/*.html holds the HTML body for every customizable template, plus the
// diagnostic provider_test. They are embedded rather than kept as Go string
// literals so that the markup lives in files a browser can open and a designer
// can edit — transactional email markup is table-based, inline-styled and long,
// and reviewing it inside a backtick literal is how the double-encoded glyphs
// and the "expires in 4320 minutes" strings survived as long as they did.
//
// Only the HTML is embedded. Subject and Text stay in builtinTemplates (see
// templates.go), because both are short, neither benefits from a browser, and
// the subject lines carry Go template conditionals that are easier to review
// beside the type they belong to.
//
// build.sh in that directory regenerates the files from a shared head/foot plus
// one body per template; _SHARED.md documents the palette, which is the admin
// console's own token set. Edit the body in build.sh and re-run it rather than
// hand-editing a generated file, or the next regeneration discards the change.
//
//go:embed templates/*.html
var templateFS embed.FS

// htmlFiles maps each type to its file. Explicit rather than derived from the
// numeric filename prefix: a rename or a reordering would silently repoint a
// template at the wrong body, and "welcome" arriving as a password reset is not
// a failure any test would obviously catch.
var htmlFiles = map[TemplateType]string{
	TemplateEmailVerification:  "templates/01_email_verification.html",
	TemplatePasswordReset:      "templates/02_password_reset.html",
	TemplateWelcome:            "templates/03_welcome.html",
	TemplateMFACode:            "templates/04_mfa_code.html",
	TemplateMagicLink:          "templates/05_magic_link.html",
	TemplatePasswordChanged:    "templates/06_password_changed.html",
	TemplateUserInvitation:     "templates/07_user_invitation.html",
	TemplateChangeEmail:        "templates/08_change_email.html",
	TemplateBlockedAccount:     "templates/09_blocked_account.html",
	TemplatePasswordBreach:     "templates/10_password_breach.html",
	TemplateTenantLockoutAlert: "templates/11_tenant_lockout_alert.html",
	TemplateAdminActivity:      "templates/12_admin_activity.html",
	TemplateAccessChanged:      "templates/13_access_changed.html",
	TemplateProviderTest:       "templates/14_provider_test.html",
}

// init replaces each built-in's HTML with the embedded file.
//
// Done in init rather than lazily at send time on purpose: a missing or unparsable
// file is a build-artefact problem, and discovering it when the first password
// reset of the day fails is far worse than discovering it at startup. panic is
// therefore the right response — the binary cannot send correct mail, and every
// file it needs is compiled into it, so this cannot fail for an environmental
// reason that a retry would fix.
//
// Subject and Text are carried through untouched.
func init() {
	for tt, path := range htmlFiles {
		raw, err := fs.ReadFile(templateFS, path)
		if err != nil {
			panic(fmt.Sprintf("mailer: embedded template %s for %q: %v", path, tt, err))
		}
		body := strings.TrimSpace(string(raw))
		if body == "" {
			panic(fmt.Sprintf("mailer: embedded template %s for %q is empty", path, tt))
		}

		existing, ok := builtinTemplates[tt]
		if !ok {
			panic(fmt.Sprintf("mailer: embedded template %s names unknown type %q", path, tt))
		}
		existing.HTML = body
		builtinTemplates[tt] = existing
	}

	// Every customizable type must have a body. AllTemplateTypes is the list the
	// admin API validates and the template editor renders, so a type present
	// there with no file would offer an operator a template that cannot send.
	// Checked here so adding a type to that list without adding its HTML fails
	// immediately rather than at the first send.
	for _, tt := range AllTemplateTypes {
		if _, ok := htmlFiles[tt]; !ok {
			panic(fmt.Sprintf("mailer: template type %q has no embedded HTML file", tt))
		}
	}
}
