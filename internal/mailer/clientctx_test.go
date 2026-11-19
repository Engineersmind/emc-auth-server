package mailer

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/engineersmind/emc-auth-server/internal/requestctx"
)

const chromeWindowsUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

func testMailer(geo GeoLookup) *mailerImpl {
	return &mailerImpl{
		global: SMTPConfig{From: "no-reply@platform.test"},
		logger: zerolog.Nop(),
		geo:    geo,
	}
}

func puneGeo(ip string) (GeoPlace, bool) {
	if ip == "203.0.113.7" {
		return GeoPlace{City: "Pune", Country: "India", TimeZone: "Asia/Kolkata"}, true
	}
	return GeoPlace{}, false
}

func trustedCtx(ip, ua, tz string) context.Context {
	return requestctx.WithClientIdentity(context.Background(), ip, ua, tz, true)
}

func TestClientContext_TrustedIdentityFillsDeviceAndPlace(t *testing.T) {
	m := testMailer(puneGeo)
	d := TemplateData{}
	loc := m.applyClientContext(trustedCtx("203.0.113.7", chromeWindowsUA, ""), TemplateBlockedAccount, &d)

	if d.Browser != "Chrome" || !strings.Contains(d.OS, "Windows") {
		t.Errorf("device = %q on %q, want Chrome on Windows", d.Browser, d.OS)
	}
	if d.City != "Pune" || d.Country != "India" || d.Location != "Pune, India" {
		t.Errorf("place = %q / %q / %q", d.City, d.Country, d.Location)
	}
	// No forwarded timezone, so the GeoIP zone is used.
	if loc.String() != "Asia/Kolkata" {
		t.Errorf("zone = %s, want Asia/Kolkata (from GeoIP)", loc)
	}
}

func TestClientContext_ForwardedTimezoneBeatsGeoZone(t *testing.T) {
	m := testMailer(puneGeo)
	loc := m.applyClientContext(trustedCtx("203.0.113.7", chromeWindowsUA, "America/New_York"), TemplatePasswordReset, &TemplateData{})
	if loc.String() != "America/New_York" {
		t.Errorf("zone = %s, want the user's own forwarded timezone", loc)
	}
}

// The central safety property: a backend calling on its own behalf must never
// have ITS address and browser presented to a person as theirs.
func TestClientContext_UntrustedIdentityShowsNothing(t *testing.T) {
	m := testMailer(puneGeo)
	ctx := requestctx.WithClientIdentity(context.Background(), "203.0.113.7", chromeWindowsUA, "Asia/Kolkata", false)
	d := TemplateData{}
	loc := m.applyClientContext(ctx, TemplateBlockedAccount, &d)

	if d.Browser != "" || d.OS != "" || d.City != "" || d.Country != "" || d.Location != "" {
		t.Errorf("untrusted request leaked context: %+v", d)
	}
	if loc != time.UTC {
		t.Errorf("zone = %s, want UTC", loc)
	}
}

func TestClientContext_NoRequestShowsNothing(t *testing.T) {
	d := TemplateData{}
	testMailer(puneGeo).applyClientContext(context.Background(), TemplatePasswordReset, &d)
	if d.Browser != "" || d.Location != "" {
		t.Errorf("a background send claimed an identity: %+v", d)
	}
}

func TestClientContext_ExplicitSuppression(t *testing.T) {
	ctx := requestctx.WithoutClientContext(trustedCtx("203.0.113.7", chromeWindowsUA, ""))
	d := TemplateData{}
	testMailer(puneGeo).applyClientContext(ctx, TemplatePasswordReset, &d)
	if d.Browser != "" || d.Location != "" {
		t.Errorf("suppressed send leaked context: %+v", d)
	}
}

func TestClientContext_AdminBlockIsNotTheAccountHoldersRequest(t *testing.T) {
	d := TemplateData{Reason: BlockReasonAdmin}
	testMailer(puneGeo).applyClientContext(trustedCtx("203.0.113.7", chromeWindowsUA, ""), TemplateBlockedAccount, &d)
	if d.Browser != "" || d.Location != "" {
		t.Errorf("admin block showed the admin's context: %+v", d)
	}

	// Every other reason is the account holder's own sign-in.
	d = TemplateData{Reason: BlockReasonSuspiciousLogin}
	testMailer(puneGeo).applyClientContext(trustedCtx("203.0.113.7", chromeWindowsUA, ""), TemplateBlockedAccount, &d)
	if d.Browser == "" {
		t.Error("a suspicious-login alert should describe the sign-in")
	}
}

func TestClientContext_OnlyTemplatesAboutTheRecipientsOwnRequest(t *testing.T) {
	ctx := trustedCtx("203.0.113.7", chromeWindowsUA, "")
	for _, tt := range []TemplateType{TemplateUserInvitation, TemplateTenantLockoutAlert, TemplateAdminActivity, TemplateAccessChanged, TemplateProviderTest} {
		d := TemplateData{}
		testMailer(puneGeo).applyClientContext(ctx, tt, &d)
		if d.Browser != "" || d.Location != "" {
			t.Errorf("%s must not carry the requester's context, got %+v", tt, d)
		}
	}
	for _, tt := range []TemplateType{
		TemplateEmailVerification, TemplatePasswordReset, TemplateWelcome, TemplateMFACode, TemplateMagicLink,
		TemplatePasswordChanged, TemplateChangeEmail, TemplateBlockedAccount, TemplatePasswordBreach, TemplatePasswordlessCode,
	} {
		d := TemplateData{}
		testMailer(puneGeo).applyClientContext(ctx, tt, &d)
		if d.Browser == "" || d.Location == "" {
			t.Errorf("%s should describe the user's request, got %+v", tt, d)
		}
	}
}

func TestClientContext_NoGeoDatabaseStillGivesDevice(t *testing.T) {
	d := TemplateData{}
	testMailer(nil).applyClientContext(trustedCtx("203.0.113.7", chromeWindowsUA, ""), TemplatePasswordReset, &d)
	if d.Browser != "Chrome" {
		t.Errorf("browser = %q", d.Browser)
	}
	if d.Location != "" || d.City != "" {
		t.Errorf("location without a GeoIP database: %+v", d)
	}
}

func TestClientContext_PrivateOrUnknownIPLeavesLocationEmpty(t *testing.T) {
	d := TemplateData{}
	testMailer(puneGeo).applyClientContext(trustedCtx("10.0.0.5", chromeWindowsUA, ""), TemplatePasswordReset, &d)
	if d.Location != "" {
		t.Errorf("location for an unresolvable IP: %q", d.Location)
	}
}

func TestClientContext_CallerValuesWin(t *testing.T) {
	d := TemplateData{Browser: "Firefox", OS: "Linux", Location: "Oslo, Norway"}
	testMailer(puneGeo).applyClientContext(trustedCtx("203.0.113.7", chromeWindowsUA, ""), TemplatePasswordReset, &d)
	if d.Browser != "Firefox" || d.OS != "Linux" || d.Location != "Oslo, Norway" {
		t.Errorf("explicit values were overwritten: %+v", d)
	}
}

func TestCentralFields_TimeAndExpiryInUserZone(t *testing.T) {
	m := testMailer(puneGeo)
	d := TemplateData{TTLMinutes: 60}
	m.applyCentralFields(trustedCtx("203.0.113.7", chromeWindowsUA, ""), nil, TemplatePasswordReset, "alex@acme.test", &d)

	if d.Timezone != "IST" {
		t.Errorf("Timezone = %q, want IST", d.Timezone)
	}
	if d.OccurredAt == "" || d.ExpiryTime == "" {
		t.Errorf("OccurredAt=%q ExpiryTime=%q", d.OccurredAt, d.ExpiryTime)
	}
	if d.MaskedEmail != "a***@acme.test" {
		t.Errorf("MaskedEmail = %q", d.MaskedEmail)
	}
}

func TestCentralFields_DefaultsToUTCWithoutIdentity(t *testing.T) {
	d := TemplateData{}
	testMailer(nil).applyCentralFields(context.Background(), nil, TemplatePasswordReset, "a@b.test", &d)
	if d.Timezone != "UTC" {
		t.Errorf("Timezone = %q, want UTC", d.Timezone)
	}
	if d.ExpiryTime != "" {
		t.Errorf("ExpiryTime = %q with no TTL", d.ExpiryTime)
	}
}

func TestCentralFields_SupportEmailPrecedence(t *testing.T) {
	m := testMailer(nil)
	m.global.ReplyTo = "help@platform.test"

	cases := []struct {
		name   string
		sender *SMTPConfig
		want   string
	}{
		{"app reply-to wins", &SMTPConfig{From: "app@x.test", ReplyTo: "support@app.test"}, "support@app.test"},
		{"sender From when no reply-to", &SMTPConfig{From: "app@x.test"}, "app@x.test"},
		{"global reply-to with no sender", nil, "help@platform.test"},
	}
	for _, c := range cases {
		d := TemplateData{}
		m.applyCentralFields(context.Background(), c.sender, TemplatePasswordReset, "a@b.test", &d)
		if d.SupportEmail != c.want {
			t.Errorf("%s: SupportEmail = %q, want %q", c.name, d.SupportEmail, c.want)
		}
	}

	m.global.ReplyTo = ""
	d := TemplateData{}
	m.applyCentralFields(context.Background(), nil, TemplatePasswordReset, "a@b.test", &d)
	if d.SupportEmail != "no-reply@platform.test" {
		t.Errorf("global From fallback = %q", d.SupportEmail)
	}
}

func TestCentralFields_PresetValuesKept(t *testing.T) {
	d := TemplateData{OccurredAt: "1 Jan 2026, 09:00", SupportEmail: "x@y.test", Timezone: "PST"}
	testMailer(nil).applyCentralFields(context.Background(), nil, TemplatePasswordReset, "a@b.test", &d)
	if d.OccurredAt != "1 Jan 2026, 09:00" || d.SupportEmail != "x@y.test" || d.Timezone != "PST" {
		t.Errorf("preset values overwritten: %+v", d)
	}
}

func TestMaskEmail(t *testing.T) {
	for in, want := range map[string]string{
		"alex@acme.com": "a***@acme.com",
		"a@b.co":        "a***@b.co",
		"not-an-email":  "not-an-email",
		"@x.com":        "@x.com",
		"":              "",
	} {
		if got := maskEmail(in); got != want {
			t.Errorf("maskEmail(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestZoneLabel(t *testing.T) {
	at := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	for zone, want := range map[string]string{
		"UTC":               "UTC",
		"Asia/Kolkata":      "IST",
		"America/Sao_Paulo": "UTC-3", // tzdata gives a numeric abbreviation here
	} {
		loc, err := time.LoadLocation(zone)
		if err != nil {
			t.Fatalf("LoadLocation(%s): %v", zone, err)
		}
		if got := zoneLabel(at.In(loc)); got != want {
			t.Errorf("zoneLabel(%s) = %q, want %q", zone, got, want)
		}
	}
}

// Every variable the catalogue advertises for a type must actually render, in a
// custom template, for EVERY type. This is what keeps the console's variable list
// honest and guarantees an author using any advertised variable — in any
// template — cannot silently fall back to the built-in.
func TestCatalogue_EveryAdvertisedVariableRendersForEveryType(t *testing.T) {
	for _, tt := range AllTemplateTypes {
		var b strings.Builder
		for _, vr := range VariablesFor(tt) {
			b.WriteString("[" + vr.Name + "]")
		}
		tmpl := Template{Subject: "s", HTML: b.String(), Text: b.String()}
		if _, err := tmpl.render(sampleTestData()); err != nil {
			t.Errorf("%s: advertised variable does not render: %v", tt, err)
		}
	}
}

// Declared for every type: location, device, token and the rest must be usable
// from ANY template without breaking the render.
func TestCatalogue_NewFieldsUsableInEveryTemplateType(t *testing.T) {
	const body = `{{.Browser}}{{.OS}}{{.City}}{{.Country}}{{.Location}}{{.Timezone}}{{.ExpiryTime}}` +
		`{{.SupportEmail}}{{.MaskedEmail}}{{.Purpose}}{{.ResetLink}}{{.LoginURL}}{{.Token}}` +
		`{{if .Location}}x{{end}}`
	for _, tt := range AllTemplateTypes {
		if _, err := (Template{Subject: "s", HTML: body}).render(TemplateData{}); err != nil {
			t.Errorf("%s: %v", tt, err)
		}
	}
}

func TestSampleData_TokenIsObviouslyFake(t *testing.T) {
	if got := sampleTestData().Token; got != "SAMPLE_TOKEN" {
		t.Errorf("sample token = %q; a test send must not carry anything resembling a real token", got)
	}
}

func TestSendFunctions_PassTokenAndPurpose(t *testing.T) {
	rec := &recordingTransport{}
	m := testMailer(nil)
	m.globalTr = rec
	custom := &Template{Subject: "s", HTML: "T={{.Token}} L={{.Link}} P={{.Purpose}} N={{.Name}}"}
	ctx := context.Background()

	_ = m.SendVerification(ctx, nil, custom, VerificationEmail{To: "a@b.test", Link: "https://x/verify?token=RAW", Token: "RAW", Name: "Alex"})
	_ = m.SendMagicLink(ctx, nil, custom, MagicLinkEmail{To: "a@b.test", Link: "https://x/m?token=MRAW", Token: "MRAW"})
	_ = m.SendReset(ctx, nil, custom, ResetEmail{To: "a@b.test", ResetLink: "https://x/r?token=RRAW", Token: "RRAW"})
	_ = m.SendInvitation(ctx, nil, custom, InvitationEmail{To: "a@b.test", Link: "https://x/i?token=IRAW", Token: "IRAW"})
	_ = m.SendMFACode(ctx, nil, custom, MFACodeEmail{To: "a@b.test", Code: "123456"})
	_ = m.SendPasswordlessCode(ctx, nil, custom, PasswordlessCodeEmail{To: "a@b.test", Code: "123456", Verify: true})

	want := []string{
		"T=RAW L=https://x/verify?token=RAW",
		"T=MRAW L=https://x/m?token=MRAW",
		"T=RRAW L=https://x/r?token=RRAW",
		"T=IRAW L=https://x/i?token=IRAW",
		"P=finish signing in",
		"P=confirm your email address",
	}
	if len(rec.sent) != len(want) {
		t.Fatalf("sent %d messages, want %d", len(rec.sent), len(want))
	}
	for i, w := range want {
		if !strings.Contains(rec.sent[i].HTML, w) {
			t.Errorf("message %d = %q, want it to contain %q", i, rec.sent[i].HTML, w)
		}
	}
	if !strings.Contains(rec.sent[0].HTML, "N=Alex") {
		t.Errorf("first name not passed: %q", rec.sent[0].HTML)
	}
}

type recordingTransport struct{ sent []outMessage }

func (r *recordingTransport) send(_ context.Context, m outMessage) error {
	r.sent = append(r.sent, m)
	return nil
}
