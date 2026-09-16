package mailer

import (
	"strings"
	"testing"
)

// Every customizable template must render from its embedded file, for every
// variant, with no Go template error and nothing left unsubstituted.
//
// This is the test the wiring exists for. The bodies are generated files edited
// through build.sh, so the failure mode is not a compile error but a template
// that renders to something wrong — an unclosed {{if}}, a field that does not
// exist on TemplateData, or a variant branch that produces an empty card.
func TestEmbeddedTemplates_RenderEveryVariant(t *testing.T) {
	data := TemplateData{
		ProductName:  "EMC Auth",
		AppName:      "Acme Portal",
		Link:         "https://console.acme.test/action?token=abc",
		Code:         "482913",
		TTLMinutes:   60,
		Name:         "Sam Rivera",
		Email:        "sam@acme.test",
		InviterName:  "Dana Okafor",
		NewEmail:     "sam.rivera@acme.test",
		ActionLabel:  "rotated a client secret",
		ActorEmail:   "dana@acme.test",
		ActorRole:    "owner",
		TenantName:   "Acme Corp",
		ResourceName: "Acme Portal",
		OccurredAt:   "10 Sep 2026, 14:02 UTC",
		IPAddress:    "203.0.113.42",
		Count:        47,
		RetryMinutes: 30,
	}

	// The types whose single template covers several events, keyed by the Reason
	// values that select each branch. "" is the default branch.
	variants := map[TemplateType][]string{
		TemplateChangeEmail: {"", EmailChangeApplied},
		TemplateBlockedAccount: {
			"",
			BlockReasonFailedAttempts,
			BlockReasonAdmin,
			BlockReasonSuspiciousLogin,
			BlockReasonFailedAttemptsWarning,
			BlockReasonSoftLocked,
		},
	}

	for tt := range htmlFiles {
		reasons, ok := variants[tt]
		if !ok {
			reasons = []string{""}
		}
		for _, reason := range reasons {
			name := string(tt)
			if reason != "" {
				name += "/" + reason
			}
			t.Run(name, func(t *testing.T) {
				tmpl, ok := BuiltinTemplate(tt)
				if !ok {
					t.Fatalf("no built-in template for %q", tt)
				}

				d := data
				d.Reason = reason
				out, err := tmpl.render(d)
				if err != nil {
					t.Fatalf("render: %v", err)
				}

				// A variant whose branch produced nothing still renders the card
				// frame, so length alone is a weak check — but an empty or tiny
				// body means the file was not embedded at all.
				if len(out.HTML) < 500 {
					t.Errorf("HTML is %d bytes, too short to be a rendered email:\n%s", len(out.HTML), out.HTML)
				}
				// The generator substitutes these; one surviving into a render means
				// a file was shipped straight from head.part.
				for _, token := range []string{"__TITLE__", "__PREHEADER__"} {
					if strings.Contains(out.HTML, token) {
						t.Errorf("HTML still contains the generator token %s", token)
					}
				}
				// Go leaves this behind for a nil/missing value, which is how a
				// renamed TemplateData field would present.
				if strings.Contains(out.HTML, "<no value>") {
					t.Error("HTML contains <no value> — a template references a field that is not set")
				}
				if strings.TrimSpace(out.Subject) == "" {
					t.Error("subject rendered empty")
				}
			})
		}
	}
}

// The embedded HTML must actually be in use — not the old Go string literals.
//
// Asserted on the palette rather than on copy: #16181d is the console's dark
// --app-bg and appears in every generated file, while the previous inline
// templates used a bare white shell. If init() ever stops overwriting the map,
// this is what notices.
func TestEmbeddedTemplates_ReplaceTheInlineBodies(t *testing.T) {
	for tt := range htmlFiles {
		tmpl, ok := BuiltinTemplate(tt)
		if !ok {
			t.Fatalf("no built-in template for %q", tt)
		}
		if !strings.Contains(tmpl.HTML, "#16181d") {
			t.Errorf("%q does not carry the console palette; the embedded file is not wired in", tt)
		}
		if !strings.Contains(tmpl.HTML, "Space Grotesk") {
			t.Errorf("%q does not use the console typeface; the embedded file is not wired in", tt)
		}
	}
}

// Every type the admin API exposes must have a body. init() panics otherwise, so
// this documents the guarantee and fails loudly if that check is ever removed.
func TestEmbeddedTemplates_CoverEveryCustomizableType(t *testing.T) {
	for _, tt := range AllTemplateTypes {
		if _, ok := htmlFiles[tt]; !ok {
			t.Errorf("customizable type %q has no embedded HTML file", tt)
		}
	}
	// provider_test is deliberately NOT in AllTemplateTypes — it must not appear
	// in the template editor — but it is still sent, so it needs a body too.
	if _, ok := htmlFiles[TemplateProviderTest]; !ok {
		t.Error("provider_test has no embedded HTML file")
	}
}
