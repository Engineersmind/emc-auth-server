package auth_test

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// ---------------------------------------------------------------------------
// Per-application MFA master switch (#192, stage 1 of #189)
// ---------------------------------------------------------------------------

func boolPtr(b bool) *bool { return &b }

// An application with no settings row is ON, and the switch round-trips
// through UpdateAppMFASettings, reporting the value it replaced.
func TestMFASwitch_DefaultOnAndRoundTrip(t *testing.T) {
	f := newMFAFixture(t)
	_, appID := f.createApp(t, "switch-roundtrip")

	cfg, err := f.totpSvc.GetAppMFAConfig(f.ctx, appID)
	if err != nil {
		t.Fatalf("GetAppMFAConfig: %v", err)
	}
	if !cfg.Enabled || cfg.Mode != auth.MFAModeOptional {
		t.Fatalf("no-row config = %+v, want enabled + optional", cfg)
	}
	policy, err := f.totpSvc.GetAppMFAPolicy(f.ctx, f.tenantID, appID)
	if err != nil {
		t.Fatalf("GetAppMFAPolicy: %v", err)
	}
	if !policy.MFAEnabled {
		t.Error("no-row policy reports mfa_enabled = false")
	}

	prev, err := f.totpSvc.SetAppMFAEnabled(f.ctx, f.tenantID, appID, false, nil)
	if err != nil {
		t.Fatalf("SetAppMFAEnabled(false): %v", err)
	}
	if !prev {
		t.Error("prev = false on first switch-off, want true (no row = on)")
	}
	if cfg, _ = f.totpSvc.GetAppMFAConfig(f.ctx, appID); cfg.Enabled {
		t.Error("switch still on after turning it off")
	}

	// Re-sending the current value is not a change.
	res, err := f.totpSvc.UpdateAppMFASettings(f.ctx, f.tenantID, appID, auth.AppMFAUpdate{Enabled: boolPtr(false)}, nil)
	if err != nil {
		t.Fatalf("UpdateAppMFASettings(false again): %v", err)
	}
	if res.SwitchChanged() {
		t.Errorf("redundant off reported as a change: %+v", res)
	}

	res, err = f.totpSvc.UpdateAppMFASettings(f.ctx, f.tenantID, appID, auth.AppMFAUpdate{Enabled: boolPtr(true)}, nil)
	if err != nil {
		t.Fatalf("UpdateAppMFASettings(true): %v", err)
	}
	if !res.SwitchChanged() || res.PrevEnabled || !res.NewEnabled {
		t.Errorf("switch-on result = %+v, want false → true", res)
	}
}

// Turning the switch off keeps mode and allowed methods; turning it back on
// restores them untouched.
func TestMFASwitch_OffKeepsModeAndMethods(t *testing.T) {
	f := newMFAFixture(t)
	_, appID := f.createApp(t, "switch-keeps")

	if err := f.totpSvc.SetAppMFAPolicy(f.ctx, f.tenantID, appID, auth.MFAModeRequired,
		[]string{auth.MFAMethodTOTP, auth.MFAMethodEmail}, nil); err != nil {
		t.Fatalf("SetAppMFAPolicy: %v", err)
	}
	if _, err := f.totpSvc.SetAppMFAEnabled(f.ctx, f.tenantID, appID, false, nil); err != nil {
		t.Fatalf("SetAppMFAEnabled(false): %v", err)
	}
	cfg, err := f.totpSvc.GetAppMFAConfig(f.ctx, appID)
	if err != nil {
		t.Fatalf("GetAppMFAConfig: %v", err)
	}
	if cfg.Enabled || cfg.Mode != auth.MFAModeRequired || len(cfg.Methods) != 2 {
		t.Errorf("config after switch-off = %+v, want disabled switch with required + both methods kept", cfg)
	}
}

// A tenant can never flip another tenant's application.
func TestMFASwitch_TenantIsolation(t *testing.T) {
	f := newMFAFixture(t)
	_, appID := f.createApp(t, "switch-isolation")

	var other int64
	slug := fmt.Sprintf("mfa-switch-other-%d", time.Now().UnixNano())
	if err := f.pool.QueryRow(f.ctx,
		`INSERT INTO tenants (name, slug, jwt_secret) VALUES ($1, $1, 'secret') RETURNING id`, slug,
	).Scan(&other); err != nil {
		t.Fatalf("create other tenant: %v", err)
	}

	_, err := f.totpSvc.UpdateAppMFASettings(f.ctx, other, appID, auth.AppMFAUpdate{Enabled: boolPtr(false)}, nil)
	if !errors.Is(err, auth.ErrAppNotFound) {
		t.Fatalf("cross-tenant switch-off error = %v, want ErrAppNotFound", err)
	}
	if cfg, _ := f.totpSvc.GetAppMFAConfig(f.ctx, appID); !cfg.Enabled {
		t.Fatal("cross-tenant call turned the switch off")
	}
}

// The admin PUT is atomic: a magic-link error after a valid switch/mode change
// rolls the whole update back.
func TestMFASwitch_UpdateIsAtomic(t *testing.T) {
	f := newMFAFixture(t)
	_, appID := f.createApp(t, "switch-atomic")

	bad := "http://not-loopback.example.com/cb" // cleartext to a public host — rejected
	_, err := f.totpSvc.UpdateAppMFASettings(f.ctx, f.tenantID, appID, auth.AppMFAUpdate{
		Enabled:              boolPtr(false),
		Mode:                 auth.MFAModeRequired,
		MagicLinkEnabled:     boolPtr(true),
		MagicLinkRedirectURL: &bad,
	}, nil)
	if !errors.Is(err, auth.ErrMagicLinkNotConfigured) {
		t.Fatalf("error = %v, want ErrMagicLinkNotConfigured", err)
	}
	cfg, err := f.totpSvc.GetAppMFAConfig(f.ctx, appID)
	if err != nil {
		t.Fatalf("GetAppMFAConfig: %v", err)
	}
	if !cfg.Enabled || cfg.Mode != auth.MFAModeOptional {
		t.Errorf("config after failed update = %+v, want untouched (enabled, optional)", cfg)
	}
}

// Switch off: a user with an active TOTP is not challenged; the factor stays
// enrolled. Switch back on: the challenge returns at the next login.
func TestMFASwitch_OffSkipsChallengeForEnrolledUser(t *testing.T) {
	f := newMFAFixture(t)
	app, appID := f.createApp(t, "switch-enrolled")
	email := uniqueEmail("switch-enrolled")
	userID := f.registerAppUser(t, app, email, "Password123!")
	f.enrollAndActivate(t, userID, email)

	if _, err := f.totpSvc.SetAppMFAEnabled(f.ctx, f.tenantID, appID, false, nil); err != nil {
		t.Fatalf("SetAppMFAEnabled(false): %v", err)
	}
	res, err := f.appLogin(t, app, email, "Password123!")
	if err != nil {
		t.Fatalf("Login(off): %v", err)
	}
	if res.Token == nil || res.OTPChallenge != nil {
		t.Fatalf("Login(off) = %+v, want tokens and no challenge", res)
	}
	if active, _ := f.totpSvc.IsActive(f.ctx, userID); !active {
		t.Error("switch-off removed the user's TOTP enrolment")
	}

	if _, err := f.totpSvc.SetAppMFAEnabled(f.ctx, f.tenantID, appID, true, nil); err != nil {
		t.Fatalf("SetAppMFAEnabled(true): %v", err)
	}
	res, err = f.appLogin(t, app, email, "Password123!")
	if err != nil {
		t.Fatalf("Login(on): %v", err)
	}
	if res.OTPChallenge == nil {
		t.Fatalf("Login(on) = %+v, want OTP challenge again", res)
	}
}

// Switch off under 'required': an unenrolled user is not forced to enrol.
func TestMFASwitch_OffSkipsForcedEnrolmentUnderRequired(t *testing.T) {
	f := newMFAFixture(t)
	app, appID := f.createApp(t, "switch-required")
	if err := f.totpSvc.SetAppMFAPolicy(f.ctx, f.tenantID, appID, auth.MFAModeRequired, nil, nil); err != nil {
		t.Fatalf("SetAppMFAPolicy(required): %v", err)
	}
	email := uniqueEmail("switch-required")
	f.registerAppUser(t, app, email, "Password123!")

	if _, err := f.totpSvc.SetAppMFAEnabled(f.ctx, f.tenantID, appID, false, nil); err != nil {
		t.Fatalf("SetAppMFAEnabled(false): %v", err)
	}
	res, err := f.appLogin(t, app, email, "Password123!")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if res.Token == nil || res.MFAEnrollment != nil {
		t.Fatalf("Login = %+v, want tokens and no forced enrolment", res)
	}
}

// Enrolment is refused with ErrMFASwitchedOff for both methods while the
// switch is off — distinct from mode 'disabled'.
func TestMFASwitch_OffRefusesEnrolment(t *testing.T) {
	f := newMFAFixture(t)
	app, appID := f.createApp(t, "switch-enrol")
	if err := f.totpSvc.SetAppMFAPolicy(f.ctx, f.tenantID, appID, auth.MFAModeOptional,
		[]string{auth.MFAMethodTOTP, auth.MFAMethodEmail}, nil); err != nil {
		t.Fatalf("SetAppMFAPolicy: %v", err)
	}
	email := uniqueEmail("switch-enrol")
	userID := f.registerAppUser(t, app, email, "Password123!")

	if _, err := f.totpSvc.SetAppMFAEnabled(f.ctx, f.tenantID, appID, false, nil); err != nil {
		t.Fatalf("SetAppMFAEnabled(false): %v", err)
	}
	if _, err := f.totpSvc.EnrollUser(f.ctx, userID, f.tenantID, email, ""); !errors.Is(err, auth.ErrMFASwitchedOff) {
		t.Errorf("TOTP EnrollUser error = %v, want ErrMFASwitchedOff", err)
	}
	if err := f.emailSvc.BeginEnrollment(f.ctx, userID, f.tenantID, email); !errors.Is(err, auth.ErrMFASwitchedOff) {
		t.Errorf("email BeginEnrollment error = %v, want ErrMFASwitchedOff", err)
	}
}

// Under 'required', the last factor cannot normally be removed — but while the
// switch is off there is no mandate, so it can.
func TestMFASwitch_OffLiftsLastFactorGuard(t *testing.T) {
	f := newMFAFixture(t)
	app, appID := f.createApp(t, "switch-lastfactor")
	email := uniqueEmail("switch-lastfactor")
	userID := f.registerAppUser(t, app, email, "Password123!")
	secret := f.enrollAndActivate(t, userID, email)

	if err := f.totpSvc.SetAppMFAPolicy(f.ctx, f.tenantID, appID, auth.MFAModeRequired, nil, nil); err != nil {
		t.Fatalf("SetAppMFAPolicy(required): %v", err)
	}
	if err := f.totpSvc.DisableUser(f.ctx, userID, f.tenantID, codeFor(t, secret)); !errors.Is(err, auth.ErrMFARequiredByPolicy) {
		t.Fatalf("DisableUser(on, required) error = %v, want ErrMFARequiredByPolicy", err)
	}

	if _, err := f.totpSvc.SetAppMFAEnabled(f.ctx, f.tenantID, appID, false, nil); err != nil {
		t.Fatalf("SetAppMFAEnabled(false): %v", err)
	}
	if err := f.totpSvc.DisableUser(f.ctx, userID, f.tenantID, codeFor(t, secret)); err != nil {
		t.Fatalf("DisableUser(off) error = %v, want nil", err)
	}
}

// /auth/me/mfa for an application user follows the application's policy
// (#189): allowed = switch on && mode != disabled && method allowed.
func TestMFASwitch_MyMFAStatusForAppUser(t *testing.T) {
	f := newMFAFixture(t)
	f.withAdminMFA(t)
	app, appID := f.createApp(t, "switch-status")
	email := uniqueEmail("switch-status")
	userID := f.registerAppUser(t, app, email, "Password123!")

	allowed := func(t *testing.T) (map[string]bool, *auth.MFAStatus) {
		t.Helper()
		st, err := f.authSvc.MyMFAStatus(f.ctx, userID, f.tenantID, nil)
		if err != nil {
			t.Fatalf("MyMFAStatus: %v", err)
		}
		out := map[string]bool{}
		for _, m := range st.Methods {
			out[m.Method] = m.Allowed
		}
		return out, st
	}

	// Default: TOTP only.
	got, st := allowed(t)
	if !st.MFAEnabled || st.Mode != auth.MFAModeOptional || st.MFARequired {
		t.Errorf("default status = %+v, want enabled, optional, not admin-required", st)
	}
	if !got[auth.MFAMethodTOTP] || got[auth.MFAMethodEmail] {
		t.Errorf("default allowed = %v, want totp only (the #189 bug reported email allowed)", got)
	}

	// Mode disabled: nothing allowed.
	if err := f.totpSvc.SetAppMFAPolicy(f.ctx, f.tenantID, appID, auth.MFAModeDisabled,
		[]string{auth.MFAMethodTOTP, auth.MFAMethodEmail}, nil); err != nil {
		t.Fatalf("SetAppMFAPolicy(disabled): %v", err)
	}
	if got, st = allowed(t); got[auth.MFAMethodTOTP] || got[auth.MFAMethodEmail] || st.Mode != auth.MFAModeDisabled {
		t.Errorf("disabled: allowed = %v mode = %q, want nothing allowed", got, st.Mode)
	}

	// Optional with both methods, switch off: nothing allowed, mfa_enabled false.
	if err := f.totpSvc.SetAppMFAPolicy(f.ctx, f.tenantID, appID, auth.MFAModeOptional, nil, nil); err != nil {
		t.Fatalf("SetAppMFAPolicy(optional): %v", err)
	}
	if _, err := f.totpSvc.SetAppMFAEnabled(f.ctx, f.tenantID, appID, false, nil); err != nil {
		t.Fatalf("SetAppMFAEnabled(false): %v", err)
	}
	if got, st = allowed(t); got[auth.MFAMethodTOTP] || got[auth.MFAMethodEmail] || st.MFAEnabled {
		t.Errorf("switch off: allowed = %v mfa_enabled = %v, want nothing allowed and false", got, st.MFAEnabled)
	}

	// Switch back on: both allowed.
	if _, err := f.totpSvc.SetAppMFAEnabled(f.ctx, f.tenantID, appID, true, nil); err != nil {
		t.Fatalf("SetAppMFAEnabled(true): %v", err)
	}
	if got, st = allowed(t); !got[auth.MFAMethodTOTP] || !got[auth.MFAMethodEmail] || !st.MFAEnabled {
		t.Errorf("switch on: allowed = %v, want both", got)
	}

	if on, err := f.totpSvc.AppMFAEnabledForUser(f.ctx, userID, f.tenantID); err != nil || !on {
		t.Errorf("AppMFAEnabledForUser = %v, %v; want true", on, err)
	}
}

// Administrators keep the administrator-policy logic and are never governed by
// any application's switch.
func TestMFASwitch_MyMFAStatusForAdmin(t *testing.T) {
	f := newMFAFixture(t)
	svc := f.withAdminMFA(t)
	f.setAdminPolicy(t, svc, auth.MFAMethodTOTP)
	id, _ := f.registerOwner(t, "switch-admin-status")

	st, err := f.authSvc.MyMFAStatus(f.ctx, id, f.tenantID, nil)
	if err != nil {
		t.Fatalf("MyMFAStatus: %v", err)
	}
	if !st.MFARequired || !st.MFAEnabled || st.Mode != auth.MFAModeRequired {
		t.Errorf("admin status = %+v, want required, enabled, mode required", st)
	}
	for _, m := range st.Methods {
		if want := m.Method == auth.MFAMethodTOTP; m.Allowed != want {
			t.Errorf("admin %s allowed = %v, want %v (admin policy)", m.Method, m.Allowed, want)
		}
	}
}

// ---------------------------------------------------------------------------
// AuthorizeMFASwitchOff
// ---------------------------------------------------------------------------

// mfaSession signs an app user in with TOTP and returns the verified claims of
// the resulting access token — a session whose amr records MFA.
func (f *mfaFixture) mfaSession(t *testing.T, prefix string) *auth.Claims {
	t.Helper()
	app, _ := f.createApp(t, prefix)
	email := uniqueEmail(prefix)
	userID := f.registerAppUser(t, app, email, "Password123!")
	secret := f.enrollAndActivate(t, userID, email)

	res, err := f.appLogin(t, app, email, "Password123!")
	if err != nil || res.OTPChallenge == nil {
		t.Fatalf("Login = %+v, %v; want OTP challenge", res, err)
	}
	tok, err := f.authSvc.LoginOTP(f.ctx, auth.LoginOTPInput{
		OTPSessionToken: res.OTPChallenge.OTPSessionToken,
		Code:            codeFor(t, secret),
	})
	if err != nil {
		t.Fatalf("LoginOTP: %v", err)
	}
	claims, err := f.jwtSvc.Verify(f.ctx, tok.AccessToken)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	return claims
}

func TestMFASwitchOff_RecentMFASessionAllowed(t *testing.T) {
	f := newMFAFixture(t)
	c := f.mfaSession(t, "switchoff-fresh")
	if err := f.totpSvc.AuthorizeMFASwitchOff(f.ctx, c.Gty, c.SessionID, c.UserID); err != nil {
		t.Fatalf("fresh MFA session refused: %v", err)
	}
}

func TestMFASwitchOff_StaleSessionRefused(t *testing.T) {
	f := newMFAFixture(t)
	c := f.mfaSession(t, "switchoff-stale")
	if _, err := f.pool.Exec(f.ctx,
		`UPDATE user_sessions SET auth_time = NOW() - INTERVAL '11 minutes' WHERE id::TEXT = $1`, c.SessionID,
	); err != nil {
		t.Fatalf("age session: %v", err)
	}
	if err := f.totpSvc.AuthorizeMFASwitchOff(f.ctx, c.Gty, c.SessionID, c.UserID); !errors.Is(err, auth.ErrMFASwitchOffStaleSession) {
		t.Fatalf("stale session error = %v, want ErrMFASwitchOffStaleSession", err)
	}
}

func TestMFASwitchOff_SessionWithoutMFARefused(t *testing.T) {
	f := newMFAFixture(t)
	app, _ := f.createApp(t, "switchoff-nomfa")
	email := uniqueEmail("switchoff-nomfa")
	f.registerAppUser(t, app, email, "Password123!")
	res, err := f.appLogin(t, app, email, "Password123!")
	if err != nil || res.Token == nil {
		t.Fatalf("Login = %+v, %v; want tokens", res, err)
	}
	c, err := f.jwtSvc.Verify(f.ctx, res.Token.AccessToken)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if err := f.totpSvc.AuthorizeMFASwitchOff(f.ctx, c.Gty, c.SessionID, c.UserID); !errors.Is(err, auth.ErrMFASwitchOffStaleSession) {
		t.Fatalf("password-only session error = %v, want ErrMFASwitchOffStaleSession", err)
	}
}

func TestMFASwitchOff_ServiceTokensRefused(t *testing.T) {
	f := newMFAFixture(t)
	for _, gty := range []string{auth.GrantAPIKey, auth.GrantClientCredentials} {
		if err := f.totpSvc.AuthorizeMFASwitchOff(f.ctx, gty, "", "client-id"); !errors.Is(err, auth.ErrMFASwitchOffServiceToken) {
			t.Errorf("gty=%s error = %v, want ErrMFASwitchOffServiceToken", gty, err)
		}
	}
	// A human grant without a session cannot prove a recent MFA.
	if err := f.totpSvc.AuthorizeMFASwitchOff(f.ctx, auth.GrantPassword, "", "1"); !errors.Is(err, auth.ErrMFASwitchOffStaleSession) {
		t.Errorf("sessionless human token error = %v, want ErrMFASwitchOffStaleSession", err)
	}
}
