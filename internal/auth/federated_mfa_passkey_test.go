package auth_test

import (
	"errors"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// ---------------------------------------------------------------------------
// federated_mfa for passkey sign-in (#194)
//
// Decided: a user-verified passkey SATISFIES application MFA (no extra
// challenge). A passkey WITHOUT user verification on an 'enforce' application
// goes through the normal application MFA gate. 'trust' (the default) is
// unchanged.
// ---------------------------------------------------------------------------

// federatedPasskeyEnv is a passkey fixture whose AuthService can also run TOTP
// challenges, plus one application-scoped user with a registered passkey.
type federatedPasskeyEnv struct {
	f        *passkeyFixture
	totpSvc  *auth.TOTPService
	dev      *virtualAuthenticator
	userID   int64
	appRowID int64
	handle   []byte
}

func newFederatedPasskeyEnv(t *testing.T) *federatedPasskeyEnv {
	t.Helper()
	f := newPasskeyFixture(t)
	f.allowPasskeys(t, false) // user verification not required, so a non-UV assertion verifies
	totpSvc, err := auth.NewTOTPService(f.pool, totpEnvKey(), "development", testhelper.TestLogger())
	if err != nil {
		t.Fatalf("NewTOTPService: %v", err)
	}
	f.authSvc.WithTOTP(totpSvc, f.rdb)
	dev := newVirtualAuthenticator(t)
	userID, appRowID, handle := appScopedPasskeyUser(t, f, dev)
	return &federatedPasskeyEnv{f: f, totpSvc: totpSvc, dev: dev, userID: userID, appRowID: appRowID, handle: handle}
}

func (e *federatedPasskeyEnv) setPolicy(t *testing.T, mode, federated string) {
	t.Helper()
	if _, err := e.totpSvc.UpdateAppMFASettings(e.f.ctx, e.f.tenantID, e.appRowID,
		auth.AppMFAUpdate{Mode: mode, FederatedMFA: federated}, nil); err != nil {
		t.Fatalf("UpdateAppMFASettings(%s, %s): %v", mode, federated, err)
	}
}

// login runs a passkey sign-in, with or without the user-verification flag.
func (e *federatedPasskeyEnv) login(t *testing.T, userVerified bool) (*auth.LoginResult, error) {
	t.Helper()
	e.dev.userVerified = userVerified
	assertion, token, err := e.f.svc.LoginBegin(e.f.ctx, testOrigin)
	if err != nil {
		t.Fatalf("LoginBegin: %v", err)
	}
	req := e.dev.AssertionRequest(t, testRPID, testOrigin, assertion.Response.Challenge.String(), e.handle)
	res, _, err := e.f.authSvc.LoginWebAuthn(e.f.ctx, token, req)
	return res, err
}

// enrollTOTP activates TOTP for the env's user and returns the secret.
func (e *federatedPasskeyEnv) enrollTOTP(t *testing.T) string {
	t.Helper()
	res, err := e.totpSvc.EnrollUser(e.f.ctx, e.userID, e.f.tenantID, "passkey-totp@emc.local", "")
	if err != nil {
		t.Fatalf("EnrollUser: %v", err)
	}
	u, err := url.Parse(res.OTPURI)
	if err != nil {
		t.Fatalf("parse otp uri: %v", err)
	}
	secret := u.Query().Get("secret")
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	if err := e.totpSvc.VerifyAndActivate(e.f.ctx, e.userID, code); err != nil {
		t.Fatalf("VerifyAndActivate: %v", err)
	}
	return secret
}

func TestFederatedMFA_Passkey(t *testing.T) {
	t.Run("trust: unverified passkey on a required app gets tokens (unchanged)", func(t *testing.T) {
		e := newFederatedPasskeyEnv(t)
		e.setPolicy(t, auth.MFAModeRequired, auth.FederatedMFATrust)
		res, err := e.login(t, false)
		if err != nil || res == nil || res.Token == nil {
			t.Fatalf("login = %+v, %v; want tokens", res, err)
		}
	})

	t.Run("enforce: user-verified passkey satisfies app MFA", func(t *testing.T) {
		e := newFederatedPasskeyEnv(t)
		e.setPolicy(t, auth.MFAModeRequired, auth.FederatedMFAEnforce)
		e.enrollTOTP(t)
		res, err := e.login(t, true)
		if err != nil || res == nil || res.Token == nil {
			t.Fatalf("login = %+v, %v; want tokens with no challenge", res, err)
		}
	})

	t.Run("enforce: unverified passkey, unenrolled user on a required app is sent to enrol", func(t *testing.T) {
		e := newFederatedPasskeyEnv(t)
		e.setPolicy(t, auth.MFAModeRequired, auth.FederatedMFAEnforce)
		res, err := e.login(t, false)
		if err != nil || res == nil || res.MFAEnrollment == nil || res.Token != nil {
			t.Fatalf("login = %+v, %v; want forced enrolment and no tokens", res, err)
		}
	})

	t.Run("enforce: unverified passkey, optional app, no factor gets tokens", func(t *testing.T) {
		e := newFederatedPasskeyEnv(t)
		e.setPolicy(t, auth.MFAModeOptional, auth.FederatedMFAEnforce)
		res, err := e.login(t, false)
		if err != nil || res == nil || res.Token == nil {
			t.Fatalf("login = %+v, %v; want tokens", res, err)
		}
	})

	t.Run("enforce: unverified passkey, enrolled user is challenged and completes with the passkey grant", func(t *testing.T) {
		e := newFederatedPasskeyEnv(t)
		e.setPolicy(t, auth.MFAModeOptional, auth.FederatedMFAEnforce)
		secret := e.enrollTOTP(t)
		res, err := e.login(t, false)
		if err != nil || res == nil || res.OTPChallenge == nil || res.Token != nil {
			t.Fatalf("login = %+v, %v; want an OTP challenge and no tokens", res, err)
		}
		code, err := totp.GenerateCode(secret, time.Now())
		if err != nil {
			t.Fatalf("GenerateCode: %v", err)
		}
		tokens, err := e.f.authSvc.LoginOTP(e.f.ctx, auth.LoginOTPInput{
			OTPSessionToken: res.OTPChallenge.OTPSessionToken, Code: code,
		})
		if err != nil || tokens == nil || tokens.AccessToken == "" {
			t.Fatalf("LoginOTP = %+v, %v; want tokens", tokens, err)
		}
		var amr []string
		if err := e.f.pool.QueryRow(e.f.ctx,
			`SELECT amr FROM user_sessions WHERE user_id = $1 ORDER BY id DESC LIMIT 1`, e.userID).Scan(&amr); err != nil {
			t.Fatalf("read session amr: %v", err)
		}
		for _, want := range []string{auth.AMRWebAuthn, auth.AMROTP, auth.AMRMFA} {
			if !slices.Contains(amr, want) {
				t.Errorf("session amr = %v, missing %q", amr, want)
			}
		}
		if slices.Contains(amr, auth.AMRPassword) {
			t.Errorf("session amr = %v claims a password that was never used", amr)
		}
	})

	t.Run("enforce but switch off: no gate", func(t *testing.T) {
		e := newFederatedPasskeyEnv(t)
		e.setPolicy(t, auth.MFAModeRequired, auth.FederatedMFAEnforce)
		if _, err := e.totpSvc.SetAppMFAEnabled(e.f.ctx, e.f.tenantID, e.appRowID, false, nil); err != nil {
			t.Fatalf("SetAppMFAEnabled(false): %v", err)
		}
		res, err := e.login(t, false)
		if err != nil || res == nil || res.Token == nil {
			t.Fatalf("login = %+v, %v; want tokens", res, err)
		}
	})
}

// federated_mfa round-trips through the admin update, defaults to trust,
// rejects unknown values, and reports a real change exactly once.
func TestFederatedMFA_Setting(t *testing.T) {
	f := newMFAFixture(t)
	_, appID := f.createApp(t, "federated-setting")

	cfg, err := f.totpSvc.GetAppMFAConfig(f.ctx, appID)
	if err != nil {
		t.Fatalf("GetAppMFAConfig: %v", err)
	}
	if cfg.FederatedMFA != auth.FederatedMFATrust {
		t.Fatalf("no-row federated_mfa = %q, want trust", cfg.FederatedMFA)
	}

	if _, err := f.totpSvc.UpdateAppMFASettings(f.ctx, f.tenantID, appID,
		auth.AppMFAUpdate{FederatedMFA: "sometimes"}, nil); !errors.Is(err, auth.ErrInvalidFederatedMFA) {
		t.Fatalf("invalid value error = %v, want ErrInvalidFederatedMFA", err)
	}

	res, err := f.totpSvc.UpdateAppMFASettings(f.ctx, f.tenantID, appID,
		auth.AppMFAUpdate{FederatedMFA: auth.FederatedMFAEnforce}, nil)
	if err != nil {
		t.Fatalf("UpdateAppMFASettings(enforce): %v", err)
	}
	if !res.FederatedMFAChanged() || res.PrevFederatedMFA != auth.FederatedMFATrust || res.NewFederatedMFA != auth.FederatedMFAEnforce {
		t.Errorf("result = %+v, want trust → enforce", res)
	}
	if res.SwitchChanged() {
		t.Error("a federated_mfa-only update reported a switch change")
	}
	policy, err := f.totpSvc.GetAppMFAPolicy(f.ctx, f.tenantID, appID)
	if err != nil {
		t.Fatalf("GetAppMFAPolicy: %v", err)
	}
	if policy.FederatedMFA != auth.FederatedMFAEnforce || policy.Mode != auth.MFAModeOptional {
		t.Errorf("policy = %+v, want enforce with mode untouched (optional)", policy)
	}

	res, err = f.totpSvc.UpdateAppMFASettings(f.ctx, f.tenantID, appID,
		auth.AppMFAUpdate{FederatedMFA: auth.FederatedMFAEnforce}, nil)
	if err != nil {
		t.Fatalf("UpdateAppMFASettings(enforce again): %v", err)
	}
	if res.FederatedMFAChanged() {
		t.Errorf("redundant enforce reported as a change: %+v", res)
	}
}
