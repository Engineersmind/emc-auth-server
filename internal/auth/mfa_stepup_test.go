package auth_test

import (
	"errors"
	"testing"

	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// ---------------------------------------------------------------------------
// Step-up at refresh (#197)
// ---------------------------------------------------------------------------

// setRefreshStepUp flips the application's refresh_step_up setting.
func (f *mfaFixture) setRefreshStepUp(t *testing.T, appID int64, on bool) auth.AppMFAUpdateResult {
	t.Helper()
	res, err := f.totpSvc.UpdateAppMFASettings(f.ctx, f.tenantID, appID, auth.AppMFAUpdate{RefreshStepUp: &on}, nil)
	if err != nil {
		t.Fatalf("UpdateAppMFASettings(refresh_step_up=%v): %v", on, err)
	}
	return res
}

// setSessionAMR overwrites the amr of the session behind accessToken.
func (f *mfaFixture) setSessionAMR(t *testing.T, accessToken string, amr ...string) {
	t.Helper()
	claims, err := f.jwtSvc.Verify(f.ctx, accessToken)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if _, err := f.pool.Exec(f.ctx, `UPDATE user_sessions SET amr = $2 WHERE id::TEXT = $1`, claims.SessionID, amr); err != nil {
		t.Fatalf("set session amr: %v", err)
	}
}

// passwordSession signs the user in while nothing is required and returns the
// token pair of a password-only session.
func (f *mfaFixture) passwordSession(t *testing.T, app *auth.AppResult, email string) *auth.AuthResult {
	t.Helper()
	res, err := f.appLogin(t, app, email, "Password123!")
	if err != nil || res.Token == nil {
		t.Fatalf("appLogin(%q) = %+v, %v; want tokens", email, res, err)
	}
	return res.Token
}

func TestRefreshStepUp_OffByDefault(t *testing.T) {
	f := newMFAFixture(t)
	app, appID := f.createApp(t, "stepup-default")
	email := uniqueEmail("stepup-default")
	f.registerAppUser(t, app, email, "Password123!")
	tok := f.passwordSession(t, app, email)

	policy, err := f.totpSvc.GetAppMFAPolicy(f.ctx, f.tenantID, appID)
	if err != nil {
		t.Fatalf("GetAppMFAPolicy: %v", err)
	}
	if policy.RefreshStepUp {
		t.Fatal("refresh_step_up defaults to true, want false")
	}

	// MFA becomes required, but the flag is off: refresh behaves as before.
	if err := f.totpSvc.SetAppMFAPolicy(f.ctx, f.tenantID, appID, auth.MFAModeRequired, nil, nil); err != nil {
		t.Fatalf("SetAppMFAPolicy(required): %v", err)
	}
	next, err := f.authSvc.Refresh(f.ctx, tok.RefreshToken)
	if err != nil {
		t.Fatalf("Refresh with the flag off: %v", err)
	}
	if _, _, err := f.authSvc.RefreshWithLock(f.ctx, next.RefreshToken, nil); err != nil {
		t.Fatalf("RefreshWithLock with the flag off: %v", err)
	}
}

func TestRefreshStepUp_RefusesWithoutSideEffect(t *testing.T) {
	f := newMFAFixture(t)
	app, appID := f.createApp(t, "stepup-refuse")
	email := uniqueEmail("stepup-refuse")
	f.registerAppUser(t, app, email, "Password123!")
	tok := f.passwordSession(t, app, email)

	res := f.setRefreshStepUp(t, appID, true)
	if !res.RefreshStepUpChanged() || res.PrevRefreshStepUp || !res.NewRefreshStepUp {
		t.Fatalf("update result = %+v, want false → true", res)
	}
	// Flag on, but the app is still 'optional': nothing is required, refresh ok.
	next, err := f.authSvc.Refresh(f.ctx, tok.RefreshToken)
	if err != nil {
		t.Fatalf("Refresh on an optional app: %v", err)
	}

	if err := f.totpSvc.SetAppMFAPolicy(f.ctx, f.tenantID, appID, auth.MFAModeRequired, nil, nil); err != nil {
		t.Fatalf("SetAppMFAPolicy(required): %v", err)
	}
	if _, err := f.authSvc.Refresh(f.ctx, next.RefreshToken); !errors.Is(err, auth.ErrStepUpRequired) {
		t.Fatalf("Refresh = %v, want ErrStepUpRequired", err)
	}
	if _, _, err := f.authSvc.RefreshWithLock(f.ctx, next.RefreshToken, nil); !errors.Is(err, auth.ErrStepUpRequired) {
		t.Fatalf("RefreshWithLock = %v, want ErrStepUpRequired", err)
	}

	// No side effect: the token was neither rotated nor revoked, so once the
	// requirement is lifted the very same token still refreshes.
	f.setRefreshStepUp(t, appID, false)
	if _, err := f.authSvc.Refresh(f.ctx, next.RefreshToken); err != nil {
		t.Fatalf("Refresh after the refusal (flag off again): %v — the refusal had a side effect", err)
	}
}

// A session established with MFA always refreshes.
func TestRefreshStepUp_MFASessionPasses(t *testing.T) {
	f := newMFAFixture(t)
	app, appID := f.createApp(t, "stepup-mfa")
	email := uniqueEmail("stepup-mfa")
	userID := f.registerAppUser(t, app, email, "Password123!")
	secret := f.enrollAndActivate(t, userID, email)
	if err := f.totpSvc.SetAppMFAPolicy(f.ctx, f.tenantID, appID, auth.MFAModeRequired, nil, nil); err != nil {
		t.Fatalf("SetAppMFAPolicy(required): %v", err)
	}
	f.setRefreshStepUp(t, appID, true)

	res, err := f.appLogin(t, app, email, "Password123!")
	if err != nil || res.OTPChallenge == nil {
		t.Fatalf("appLogin = %+v, %v; want OTP challenge", res, err)
	}
	tok, err := f.authSvc.LoginOTP(f.ctx, auth.LoginOTPInput{OTPSessionToken: res.OTPChallenge.OTPSessionToken, Code: codeFor(t, secret)})
	if err != nil {
		t.Fatalf("LoginOTP: %v", err)
	}
	if _, err := f.authSvc.Refresh(f.ctx, tok.RefreshToken); err != nil {
		t.Fatalf("Refresh of an MFA session: %v", err)
	}
}

// A role rule makes the user 'required' for step-up purposes too.
func TestRefreshStepUp_RoleRule(t *testing.T) {
	f := newMFAFixture(t)
	app, appID := f.createApp(t, "stepup-role")
	email := uniqueEmail("stepup-role")
	userID := f.registerAppUser(t, app, email, "Password123!")
	tok := f.passwordSession(t, app, email)
	f.setRefreshStepUp(t, appID, true)

	role := f.appRole(t, &appID, "stepup")
	f.grantRole(t, userID, role)
	f.setRules(t, appID, role)

	if _, err := f.authSvc.Refresh(f.ctx, tok.RefreshToken); !errors.Is(err, auth.ErrStepUpRequired) {
		t.Fatalf("Refresh of a rule-covered user = %v, want ErrStepUpRequired", err)
	}
}

// Social / passkey sessions follow federated_mfa, as at login.
func TestRefreshStepUp_FederatedFollowsSetting(t *testing.T) {
	f := newMFAFixture(t)
	app, appID := f.createApp(t, "stepup-fed")
	email := uniqueEmail("stepup-fed")
	f.registerAppUser(t, app, email, "Password123!")
	tok := f.passwordSession(t, app, email)
	f.setSessionAMR(t, tok.AccessToken, auth.AMRFederated)

	if err := f.totpSvc.SetAppMFAPolicy(f.ctx, f.tenantID, appID, auth.MFAModeRequired, nil, nil); err != nil {
		t.Fatalf("SetAppMFAPolicy(required): %v", err)
	}
	f.setRefreshStepUp(t, appID, true)

	// trust (default): a social session is not stepped up.
	next, err := f.authSvc.Refresh(f.ctx, tok.RefreshToken)
	if err != nil {
		t.Fatalf("Refresh of a social session under trust: %v", err)
	}
	if _, err := f.totpSvc.UpdateAppMFASettings(f.ctx, f.tenantID, appID, auth.AppMFAUpdate{FederatedMFA: auth.FederatedMFAEnforce}, nil); err != nil {
		t.Fatalf("set federated_mfa=enforce: %v", err)
	}
	if _, err := f.authSvc.Refresh(f.ctx, next.RefreshToken); !errors.Is(err, auth.ErrStepUpRequired) {
		t.Fatalf("Refresh of a social session under enforce = %v, want ErrStepUpRequired", err)
	}
}

// A tenant-level user has no application and is never stepped up.
func TestRefreshStepUp_TenantUserUnaffected(t *testing.T) {
	f := newMFAFixture(t)
	email := uniqueEmail("stepup-tenant")
	f.registerTenantUser(t, email)
	res := f.tenantLogin(t, email)
	if res.Token == nil {
		t.Fatalf("tenant login returned a challenge: %+v", res)
	}
	if _, err := f.authSvc.Refresh(f.ctx, res.Token.RefreshToken); err != nil {
		t.Fatalf("Refresh of a tenant-level session: %v", err)
	}
}
