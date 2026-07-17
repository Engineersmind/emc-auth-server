package auth_test

import (
	"errors"
	"net/url"
	"testing"

	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// tokenFromLink extracts the ?token=… parameter from an emailed magic link.
func tokenFromLink(t *testing.T, link string) string {
	t.Helper()
	u, err := url.Parse(link)
	if err != nil {
		t.Fatalf("parse magic link %q: %v", link, err)
	}
	token := u.Query().Get("token")
	if token == "" {
		t.Fatalf("no token in magic link %q", link)
	}
	return token
}

// enableMagicLink turns magic link on for an app with the demo redirect URL.
func (f *mfaFixture) enableMagicLink(t *testing.T, appID int64) {
	t.Helper()
	enabled := true
	redirect := "https://app.example.com/magic"
	if err := f.totpSvc.SetAppMagicLink(f.ctx, f.tenantID, appID, &enabled, &redirect, nil); err != nil {
		t.Fatalf("SetAppMagicLink: %v", err)
	}
}

func TestMagicLink_HappyPathAndSingleUse(t *testing.T) {
	f := newMFAFixture(t)
	app, appID := f.createApp(t, "magic-app")
	email := uniqueEmail("magic")
	f.registerAppUser(t, app, email, "Password123!")

	// Disabled by default → 403-class error.
	if err := f.authSvc.RequestMagicLink(f.ctx, app.ClientID, app.ClientSecret, email); !errors.Is(err, auth.ErrMagicLinkDisabled) {
		t.Fatalf("RequestMagicLink(disabled) error = %v, want ErrMagicLinkDisabled", err)
	}

	// Enabling without a redirect URL is rejected up front.
	enabled := true
	if err := f.totpSvc.SetAppMagicLink(f.ctx, f.tenantID, appID, &enabled, nil, nil); !errors.Is(err, auth.ErrMagicLinkNotConfigured) {
		t.Fatalf("SetAppMagicLink(no URL) error = %v, want ErrMagicLinkNotConfigured", err)
	}
	badURL := "not-a-url"
	if err := f.totpSvc.SetAppMagicLink(f.ctx, f.tenantID, appID, &enabled, &badURL, nil); !errors.Is(err, auth.ErrMagicLinkNotConfigured) {
		t.Fatalf("SetAppMagicLink(bad URL) error = %v, want ErrMagicLinkNotConfigured", err)
	}
	f.enableMagicLink(t, appID)

	// Request → link emailed with the app's name.
	if err := f.authSvc.RequestMagicLink(f.ctx, app.ClientID, app.ClientSecret, email); err != nil {
		t.Fatalf("RequestMagicLink: %v", err)
	}
	link := f.mail.lastLink(t)
	if link.To != email || link.AppName != "magic-app" {
		t.Errorf("magic link email = %+v, want to=%q app=magic-app", link, email)
	}
	token := tokenFromLink(t, link.Link)

	// Verify → tokens with the app_id claim (no MFA enrolled, optional mode).
	result, err := f.authSvc.VerifyMagicLink(f.ctx, app.ClientID, app.ClientSecret, token)
	if err != nil {
		t.Fatalf("VerifyMagicLink: %v", err)
	}
	if result.Token == nil {
		t.Fatalf("VerifyMagicLink = %+v, want tokens", result)
	}
	claims, err := f.jwtSvc.Verify(f.ctx, result.Token.AccessToken)
	if err != nil {
		t.Fatalf("Verify(access token): %v", err)
	}
	if claims.AppID != app.ID || claims.Email != email {
		t.Errorf("claims = app_id %q email %q, want %q / %q", claims.AppID, claims.Email, app.ID, email)
	}

	// Single-use: the same token is dead.
	if _, err := f.authSvc.VerifyMagicLink(f.ctx, app.ClientID, app.ClientSecret, token); !errors.Is(err, auth.ErrInvalidMagicLink) {
		t.Errorf("second VerifyMagicLink error = %v, want ErrInvalidMagicLink", err)
	}
}

func TestMagicLink_UnknownEmailPretendsSuccess(t *testing.T) {
	f := newMFAFixture(t)
	app, appID := f.createApp(t, "magic-enum-app")
	f.enableMagicLink(t, appID)

	before := f.mail.linkCount()
	if err := f.authSvc.RequestMagicLink(f.ctx, app.ClientID, app.ClientSecret, "nobody@nowhere.test"); err != nil {
		t.Fatalf("RequestMagicLink(unknown email) error = %v, want nil (anti-enumeration)", err)
	}
	if f.mail.linkCount() != before {
		t.Error("an email was sent for an unknown account")
	}
}

// TestMagicLink_MFAGateStillApplies proves a link click can never bypass MFA:
// an enrolled user gets an OTP challenge, and a 'required' app forces
// enrollment — exactly like a password login.
func TestMagicLink_MFAGateStillApplies(t *testing.T) {
	f := newMFAFixture(t)
	app, appID := f.createApp(t, "magic-mfa-app")
	f.enableMagicLink(t, appID)

	// Case 1: user with active TOTP → OTP challenge after link verification.
	enrolled := uniqueEmail("magic-enrolled")
	enrolledID := f.registerAppUser(t, app, enrolled, "Password123!")
	secret := f.enrollAndActivate(t, enrolledID, enrolled)

	if err := f.authSvc.RequestMagicLink(f.ctx, app.ClientID, app.ClientSecret, enrolled); err != nil {
		t.Fatalf("RequestMagicLink: %v", err)
	}
	result, err := f.authSvc.VerifyMagicLink(f.ctx, app.ClientID, app.ClientSecret, tokenFromLink(t, f.mail.lastLink(t).Link))
	if err != nil {
		t.Fatalf("VerifyMagicLink: %v", err)
	}
	if result.OTPChallenge == nil {
		t.Fatalf("VerifyMagicLink(enrolled user) = %+v, want OTP challenge", result)
	}
	tokens, err := f.authSvc.LoginOTP(f.ctx, auth.LoginOTPInput{
		OTPSessionToken: result.OTPChallenge.OTPSessionToken,
		Code:            codeFor(t, secret),
	})
	if err != nil {
		t.Fatalf("LoginOTP after magic link: %v", err)
	}
	if claims, _ := f.jwtSvc.Verify(f.ctx, tokens.AccessToken); claims == nil || claims.AppID != app.ID {
		t.Error("app_id claim lost through magic-link + OTP flow")
	}

	// Case 2: 'required' mode + unenrolled user → forced enrollment challenge.
	if err := f.totpSvc.SetAppMFAPolicy(f.ctx, f.tenantID, appID, auth.MFAModeRequired, nil, nil); err != nil {
		t.Fatalf("SetAppMFAPolicy: %v", err)
	}
	fresh := uniqueEmail("magic-fresh")
	f.registerAppUser(t, app, fresh, "Password123!")
	if err := f.authSvc.RequestMagicLink(f.ctx, app.ClientID, app.ClientSecret, fresh); err != nil {
		t.Fatalf("RequestMagicLink(fresh): %v", err)
	}
	result2, err := f.authSvc.VerifyMagicLink(f.ctx, app.ClientID, app.ClientSecret, tokenFromLink(t, f.mail.lastLink(t).Link))
	if err != nil {
		t.Fatalf("VerifyMagicLink(fresh): %v", err)
	}
	if result2.MFAEnrollment == nil {
		t.Fatalf("VerifyMagicLink(required, unenrolled) = %+v, want enrollment challenge", result2)
	}
}

// TestMagicLink_BoundToIssuingApplication proves a token minted for app A is
// worthless when presented through app B's credentials.
func TestMagicLink_BoundToIssuingApplication(t *testing.T) {
	f := newMFAFixture(t)
	appA, appAID := f.createApp(t, "magic-bind-a")
	appB, _ := f.createApp(t, "magic-bind-b")
	f.enableMagicLink(t, appAID)

	email := uniqueEmail("magic-bind")
	f.registerAppUser(t, appA, email, "Password123!")

	if err := f.authSvc.RequestMagicLink(f.ctx, appA.ClientID, appA.ClientSecret, email); err != nil {
		t.Fatalf("RequestMagicLink: %v", err)
	}
	token := tokenFromLink(t, f.mail.lastLink(t).Link)

	if _, err := f.authSvc.VerifyMagicLink(f.ctx, appB.ClientID, appB.ClientSecret, token); !errors.Is(err, auth.ErrInvalidMagicLink) {
		t.Fatalf("VerifyMagicLink(foreign app) error = %v, want ErrInvalidMagicLink", err)
	}
	// NOTE: the cross-app attempt consumed the token (atomic GETDEL) — a
	// stolen-token replay against the right app afterwards must also fail.
	if _, err := f.authSvc.VerifyMagicLink(f.ctx, appA.ClientID, appA.ClientSecret, token); !errors.Is(err, auth.ErrInvalidMagicLink) {
		t.Errorf("VerifyMagicLink(replay after foreign attempt) error = %v, want ErrInvalidMagicLink", err)
	}
}
