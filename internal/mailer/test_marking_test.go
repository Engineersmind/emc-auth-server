package mailer

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The admin "send test" action mails the template an operator just saved, to
// whatever recipient they name. That is what the feature is for, and it is also
// a phishing primitive if the result is indistinguishable from a real product
// email: one apps:write token can author the HTML AND pick who receives it,
// from a verified sender identity with SPF and DKIM passing.
//
// What makes it safe is the marking applied in markAsTest — a [Test] subject
// prefix and an in-body notice. The tests below are the enforcement of that
// trade, so each one covers a specific way the marking could be lost:
//
//   - suppressed by a custom template (the operator controls the body)
//   - missing from the plain-text alternative (clients that render text only)
//   - leaked into real notifications (which must never say "test")
//   - dropped on the built-in fallback path (custom template fails to render)

// TestSendTest_MarksSubjectAndBody is the baseline: both the subject and the
// HTML carry the marking, so neither a subject line in a notification list nor
// the opened message can be mistaken for a genuine one.
func TestSendTest_MarksSubjectAndBody(t *testing.T) {
	m, tr := newCapturingMailer()

	if err := m.SendTest(context.Background(), nil, nil, TemplateWelcome, "qa@elsewhere.example"); err != nil {
		t.Fatalf("SendTest: %v", err)
	}
	got := tr.msgs[0]

	if !strings.HasPrefix(got.Subject, TestSubjectPrefix) {
		t.Errorf("subject = %q, want the %s prefix — a recipient scanning an inbox sees only this", got.Subject, TestSubjectPrefix)
	}
	if !strings.Contains(got.HTML, testNoticeHeading) {
		t.Errorf("HTML carries no test notice heading:\n%s", got.HTML)
	}
	if !strings.Contains(got.HTML, "does not appear in real emails") {
		t.Errorf("HTML notice does not tell the reader this text is absent from real mail:\n%s", got.HTML)
	}
	// The template's own content must survive: a marked message that lost the
	// template would put us back where we started.
	if !strings.Contains(strings.ToLower(got.HTML), "welcome") {
		t.Errorf("the welcome template's own content is missing:\n%s", got.HTML)
	}
}

// TestSendTest_CustomTemplateCannotSuppressTheMarking is the one that carries
// the security argument.
//
// The marking is applied after rendering precisely because the operator
// controls the template body. A flag threaded into TemplateData would be
// defeatable by a template that never referenced it; this fixture is that
// attack — a complete document, with its own <body>, that mentions nothing
// about being a test and tries to look like a real account notification.
func TestSendTest_CustomTemplateCannotSuppressTheMarking(t *testing.T) {
	m, tr := newCapturingMailer()

	hostile := &Template{
		Subject: "Your account requires immediate verification",
		HTML:    `<html><head><title>Verify</title></head><body style="margin:0"><h1>Verify your account</h1><p>Click here to keep your access.</p></body></html>`,
		Text:    "Verify your account. Click here to keep your access.",
	}

	if err := m.SendTest(context.Background(), nil, hostile, TemplateWelcome, "victim@elsewhere.example"); err != nil {
		t.Fatalf("SendTest: %v", err)
	}
	got := tr.msgs[0]

	if !strings.HasPrefix(got.Subject, TestSubjectPrefix) {
		t.Errorf("a custom subject escaped the prefix: %q", got.Subject)
	}
	if !strings.Contains(got.HTML, testNoticeHeading) {
		t.Errorf("a custom template suppressed the in-body notice:\n%s", got.HTML)
	}
	if !strings.Contains(got.Text, testNoticeHeading) {
		t.Errorf("a custom text body suppressed the notice:\n%s", got.Text)
	}

	// The notice must land INSIDE <body>, not before <html> where a client may
	// drop it while still rendering the document.
	bodyAt := strings.Index(strings.ToLower(got.HTML), "<body")
	noticeAt := strings.Index(got.HTML, testNoticeHeading)
	if bodyAt < 0 || noticeAt < bodyAt {
		t.Errorf("notice at %d is not inside <body> at %d:\n%s", noticeAt, bodyAt, got.HTML)
	}
	// And ahead of the template's own content, so it is visible without
	// scrolling past a long message.
	if h1 := strings.Index(got.HTML, "<h1>"); h1 >= 0 && noticeAt > h1 {
		t.Errorf("notice (%d) renders after the template's heading (%d) — below the fold on a long template", noticeAt, h1)
	}
}

// TestSendTest_MarksTheTextAlternative covers clients that render text/plain.
// An unmarked text part would make the whole control conditional on the
// recipient's mail client.
func TestSendTest_MarksTheTextAlternative(t *testing.T) {
	m, tr := newCapturingMailer()

	if err := m.SendTest(context.Background(), nil, nil, TemplatePasswordReset, "qa@elsewhere.example"); err != nil {
		t.Fatalf("SendTest: %v", err)
	}
	text := tr.msgs[0].Text

	if !strings.Contains(text, testNoticeHeading) {
		t.Errorf("text part is unmarked:\n%s", text)
	}
	if !strings.Contains(text, "No action is required") {
		t.Errorf("text notice omits the reassurance that nothing changed:\n%s", text)
	}
}

// TestRealFlowsAreNeverMarkedAsTest is the mirror of the whole feature: a real
// password reset, verification or invitation that announced itself as a test
// would train users to ignore genuine security mail, and would be a worse bug
// than the one this change fixes.
//
// Covers every flow reachable through dispatch, so a new send path added later
// is caught here by name rather than by inspection.
func TestRealFlowsAreNeverMarkedAsTest(t *testing.T) {
	ctx := context.Background()

	flows := map[string]func(m *mailerImpl) error{
		"reset": func(m *mailerImpl) error {
			return m.SendReset(ctx, nil, nil, ResetEmail{To: "u@x.test", ResetLink: "https://x/r"})
		},
		"mfa": func(m *mailerImpl) error {
			return m.SendMFACode(ctx, nil, nil, MFACodeEmail{To: "u@x.test", Code: "123456"})
		},
		"magic link": func(m *mailerImpl) error {
			return m.SendMagicLink(ctx, nil, nil, MagicLinkEmail{To: "u@x.test", Link: "https://x/m"})
		},
		"verification": func(m *mailerImpl) error {
			return m.SendVerification(ctx, nil, nil, VerificationEmail{To: "u@x.test", Link: "https://x/v"})
		},
		"welcome": func(m *mailerImpl) error {
			return m.SendWelcome(ctx, nil, nil, WelcomeEmail{To: "u@x.test", Name: "Sam"})
		},
	}

	for name, send := range flows {
		t.Run(name, func(t *testing.T) {
			m, tr := newCapturingMailer()
			if err := send(m); err != nil {
				t.Fatalf("send: %v", err)
			}
			got := tr.msgs[0]

			if strings.Contains(got.Subject, TestSubjectPrefix) {
				t.Errorf("a real %s email is subject-prefixed as a test: %q", name, got.Subject)
			}
			if strings.Contains(got.HTML, testNoticeHeading) {
				t.Errorf("a real %s email carries the test notice in its body", name)
			}
			if strings.Contains(got.Text, testNoticeHeading) {
				t.Errorf("a real %s email carries the test notice in its text part", name)
			}
		})
	}
}

// TestSendTest_MarksTheBuiltInFallback closes the last render path. A custom
// template that fails to render falls back to the built-in default inside
// dispatch; the marking is applied after that branch, so the fallback must be
// marked too. Marking before it would have left this route unmarked.
func TestSendTest_MarksTheBuiltInFallback(t *testing.T) {
	m, tr := newCapturingMailer()

	// Unparseable action — render fails, dispatch falls back to the built-in.
	broken := &Template{Subject: "x", HTML: `{{ if }}`, Text: "x"}

	if err := m.SendTest(context.Background(), nil, broken, TemplateWelcome, "qa@elsewhere.example"); err != nil {
		t.Fatalf("SendTest: %v", err)
	}
	got := tr.msgs[0]

	if !strings.HasPrefix(got.Subject, TestSubjectPrefix) {
		t.Errorf("the built-in fallback escaped the subject prefix: %q", got.Subject)
	}
	if !strings.Contains(got.HTML, testNoticeHeading) {
		t.Errorf("the built-in fallback body is unmarked:\n%s", got.HTML)
	}
}

// TestMarkAsTest_HandlesAFragment pins the no-<body> case directly: several
// built-in templates are fragments, and the notice must still be present and
// lead the content.
func TestMarkAsTest_HandlesAFragment(t *testing.T) {
	out := markAsTest(rendered{
		Subject: "Hello",
		HTML:    `<p>Fragment body</p>`,
		Text:    "Fragment body",
	})

	if out.Subject != TestSubjectPrefix+" Hello" {
		t.Errorf("subject = %q", out.Subject)
	}
	if !strings.HasPrefix(out.HTML, "<div") {
		t.Errorf("notice does not lead a fragment:\n%s", out.HTML)
	}
	if !strings.Contains(out.HTML, "Fragment body") {
		t.Errorf("fragment content was lost:\n%s", out.HTML)
	}
}

// An empty text part must not produce a message whose text is only separators.
func TestMarkAsTest_EmptyTextPart(t *testing.T) {
	out := markAsTest(rendered{Subject: "S", HTML: "<p>h</p>", Text: ""})

	if strings.Contains(out.Text, "---") {
		t.Errorf("empty text part rendered a dangling separator: %q", out.Text)
	}
	if !strings.Contains(out.Text, testNoticeHeading) {
		t.Errorf("empty text part is unmarked: %q", out.Text)
	}
}

// TestSendTest_CustomTemplateUsingYearIsNotDiscarded is the reported failure,
// reduced to its cause.
//
// A saved verification template whose footer read "© {{.Year}} InsuredDesk"
// produced the BUILT-IN default instead. Year was not a TemplateData field, and
// html/template fails the entire render on an unknown field rather than
// emitting a blank — so dispatch logged a warning, fell back, and the operator
// received an email that looked exactly like no template had ever been saved.
//
// The variable the template needs must render, and the template must survive.
func TestSendTest_CustomTemplateUsingYearIsNotDiscarded(t *testing.T) {
	m, tr := newCapturingMailer()

	// The shape of the real template: two valid variables and a copyright year.
	tmpl := &Template{
		Subject: "Verify your email address",
		HTML:    `<html><body><p>Confirm via {{.Link}} within {{.TTLMinutes}} minutes.</p><footer>&copy; {{.Year}} InsuredDesk</footer></body></html>`,
		Text:    "Confirm via {{.Link}} within {{.TTLMinutes}} minutes.",
	}

	if err := m.SendTest(context.Background(), nil, tmpl, TemplateEmailVerification, "qa@example.test"); err != nil {
		t.Fatalf("SendTest: %v", err)
	}
	got := tr.msgs[0]

	// The custom content survived: the built-in carries an "Automated message
	// from ... on behalf of ..." footer that this template does not.
	if !strings.Contains(got.HTML, "InsuredDesk") {
		t.Errorf("the custom template was discarded for the built-in default:\n%s", got.HTML)
	}
	if strings.Contains(got.HTML, "Automated message from") {
		t.Error("the built-in default was sent — the custom template did not render")
	}
	if !strings.Contains(got.HTML, strconv.Itoa(time.Now().Year())) {
		t.Errorf("{{.Year}} did not render the current year:\n%s", got.HTML)
	}
}

// TestValidateTemplate_NamesTheOffendingField backs the editor's error message.
// Falling back silently is correct for real mail and wrong for a test send, so
// the validator has to identify what broke.
func TestValidateTemplate_NamesTheOffendingField(t *testing.T) {
	err := ValidateTemplate(&Template{Subject: "s", HTML: "{{.NoSuchThing}}", Text: "t"}, TemplateWelcome)
	if err == nil {
		t.Fatal("an unknown field was accepted; the test send would silently deliver the built-in default")
	}
	if !strings.Contains(err.Error(), "NoSuchThing") {
		t.Errorf("the error does not name the field an operator has to fix: %v", err)
	}

	// Every variable a template is offered must pass, Year included.
	for name, html := range map[string]string{
		"year":     "{{.Year}}",
		"link":     "{{.Link}}",
		"branding": "{{.ProductName}} {{.LogoURL}}",
		"ttl":      "{{.TTLMinutes}}",
	} {
		if err := ValidateTemplate(&Template{Subject: "s", HTML: html, Text: "t"}, TemplateWelcome); err != nil {
			t.Errorf("%s: a documented variable was rejected: %v", name, err)
		}
	}

	// No override is always valid — the built-in renders by construction.
	if err := ValidateTemplate(nil, TemplateWelcome); err != nil {
		t.Errorf("a nil template (built-in default) was rejected: %v", err)
	}
}
