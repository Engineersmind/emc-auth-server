package auth

import (
	"context"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// ---------------------------------------------------------------------------
// federated_mfa for social sign-in (#194)
//
// 'trust' (default): the login_code exchange returns tokens exactly as before.
// 'enforce': the same application MFA gate as password login runs at the
// exchange, returning the password-login challenge shapes.
// ---------------------------------------------------------------------------

// withMFA attaches a TOTP service (and Redis) to the env's AuthService so the
// application MFA gate can run, and returns it.
func (env *oauthTestEnv) withMFA(t *testing.T) *TOTPService {
	t.Helper()
	totpSvc, err := NewTOTPService(env.pool, strings.Repeat("0", 64), "development", testhelper.TestLogger())
	if err != nil {
		t.Fatalf("NewTOTPService: %v", err)
	}
	env.svc.authSvc.WithTOTP(totpSvc, testhelper.NewTestRedis(t))
	return totpSvc
}

func (env *oauthTestEnv) socialUserID(t *testing.T, sub string) int64 {
	t.Helper()
	var id int64
	if err := env.pool.QueryRow(context.Background(),
		`SELECT id FROM users WHERE tenant_id = $1 AND email = $2 AND deleted_at IS NULL`,
		env.tenantID, sub+"@example.com").Scan(&id); err != nil {
		t.Fatalf("social user id: %v", err)
	}
	return id
}

func activateTOTP(t *testing.T, svc *TOTPService, userID, tenantID int64) string {
	t.Helper()
	ctx := context.Background()
	res, err := svc.EnrollUser(ctx, userID, tenantID, "social@example.com", "")
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
	if err := svc.VerifyAndActivate(ctx, userID, code); err != nil {
		t.Fatalf("VerifyAndActivate: %v", err)
	}
	return secret
}

func TestFederatedMFA_Social(t *testing.T) {
	ctx := context.Background()

	t.Run("trust: required app still gets tokens at exchange (unchanged)", func(t *testing.T) {
		sg := newStubGoogle(t)
		env := newOAuthTestEnv(t, sg)
		totpSvc := env.withMFA(t)
		if err := totpSvc.SetAppMFAPolicy(ctx, env.tenantID, env.appRowID, MFAModeRequired, nil, nil); err != nil {
			t.Fatalf("SetAppMFAPolicy: %v", err)
		}
		code, _ := env.loginCodeFor(t, sg, "fed-trust", LoginBinding{})
		res, err := env.svc.ExchangeLoginCode(ctx, env.clientID, code, "")
		if err != nil || res == nil || res.Token == nil || res.OTPChallenge != nil || res.MFAEnrollment != nil {
			t.Fatalf("exchange = %+v, %v; want tokens only", res, err)
		}
	})

	t.Run("enforce: required app, unenrolled user is sent to enrol", func(t *testing.T) {
		sg := newStubGoogle(t)
		env := newOAuthTestEnv(t, sg)
		totpSvc := env.withMFA(t)
		if _, err := totpSvc.UpdateAppMFASettings(ctx, env.tenantID, env.appRowID,
			AppMFAUpdate{Mode: MFAModeRequired, FederatedMFA: FederatedMFAEnforce}, nil); err != nil {
			t.Fatalf("UpdateAppMFASettings: %v", err)
		}
		code, _ := env.loginCodeFor(t, sg, "fed-enrol", LoginBinding{})
		res, err := env.svc.ExchangeLoginCode(ctx, env.clientID, code, "")
		if err != nil || res == nil || res.MFAEnrollment == nil || res.Token != nil {
			t.Fatalf("exchange = %+v, %v; want forced enrolment and no tokens", res, err)
		}
		// The login code is spent either way: it cannot be exchanged again
		// to dodge the challenge.
		if _, err := env.svc.ExchangeLoginCode(ctx, env.clientID, code, ""); err == nil {
			t.Fatal("login code was redeemable a second time")
		}
	})

	t.Run("enforce: optional app, no factor gets tokens", func(t *testing.T) {
		sg := newStubGoogle(t)
		env := newOAuthTestEnv(t, sg)
		totpSvc := env.withMFA(t)
		if _, err := totpSvc.UpdateAppMFASettings(ctx, env.tenantID, env.appRowID,
			AppMFAUpdate{FederatedMFA: FederatedMFAEnforce}, nil); err != nil {
			t.Fatalf("UpdateAppMFASettings: %v", err)
		}
		code, _ := env.loginCodeFor(t, sg, "fed-optional", LoginBinding{})
		res, err := env.svc.ExchangeLoginCode(ctx, env.clientID, code, "")
		if err != nil || res == nil || res.Token == nil {
			t.Fatalf("exchange = %+v, %v; want tokens", res, err)
		}
	})

	t.Run("enforce: enrolled user is challenged, completes with the social grant", func(t *testing.T) {
		sg := newStubGoogle(t)
		env := newOAuthTestEnv(t, sg)
		totpSvc := env.withMFA(t)
		if _, err := totpSvc.UpdateAppMFASettings(ctx, env.tenantID, env.appRowID,
			AppMFAUpdate{FederatedMFA: FederatedMFAEnforce}, nil); err != nil {
			t.Fatalf("UpdateAppMFASettings: %v", err)
		}
		// First sign-in creates the account (no factor yet → tokens).
		code, _ := env.loginCodeFor(t, sg, "fed-otp", LoginBinding{})
		if _, err := env.svc.ExchangeLoginCode(ctx, env.clientID, code, ""); err != nil {
			t.Fatalf("first exchange: %v", err)
		}
		userID := env.socialUserID(t, "fed-otp")
		secret := activateTOTP(t, totpSvc, userID, env.tenantID)

		code, _ = env.loginCodeFor(t, sg, "fed-otp", LoginBinding{})
		res, err := env.svc.ExchangeLoginCode(ctx, env.clientID, code, "")
		if err != nil || res == nil || res.OTPChallenge == nil || res.Token != nil {
			t.Fatalf("exchange = %+v, %v; want an OTP challenge and no tokens", res, err)
		}
		otp, err := totp.GenerateCode(secret, time.Now())
		if err != nil {
			t.Fatalf("GenerateCode: %v", err)
		}
		tokens, err := env.svc.authSvc.LoginOTP(ctx, LoginOTPInput{OTPSessionToken: res.OTPChallenge.OTPSessionToken, Code: otp})
		if err != nil || tokens == nil || tokens.AccessToken == "" {
			t.Fatalf("LoginOTP = %+v, %v; want tokens", tokens, err)
		}
		claims, err := env.svc.authSvc.jwtSvc.Verify(ctx, tokens.AccessToken)
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if claims.Gty != GrantSocial {
			t.Errorf("gty = %q, want %q — the session began with a social sign-in", claims.Gty, GrantSocial)
		}
		var amr []string
		if err := env.pool.QueryRow(ctx,
			`SELECT amr FROM user_sessions WHERE user_id = $1 ORDER BY id DESC LIMIT 1`, userID).Scan(&amr); err != nil {
			t.Fatalf("read session amr: %v", err)
		}
		for _, want := range []string{AMRFederated, AMROTP, AMRMFA} {
			if !slices.Contains(amr, want) {
				t.Errorf("session amr = %v, missing %q", amr, want)
			}
		}
	})
}

// The completed session of a held social or passkey sign-in keeps its own
// grant and amr rather than falling back to the password defaults.
func TestCompletionSessionContext_FederatedFirstFactors(t *testing.T) {
	cases := []struct {
		first string
		grant string
		amr0  string
	}{
		{"", GrantPassword, AMRPassword},
		{FirstFactorEmailOTP, GrantEmailOTP, AMREmailOTP},
		{FirstFactorSocial, GrantSocial, AMRFederated},
		{FirstFactorPasskey, GrantPasskey, AMRWebAuthn},
	}
	for _, c := range cases {
		sc := completionSessionContext(&OTPSession{FirstFactor: c.first})
		if sc.grant != c.grant || len(sc.amr) == 0 || sc.amr[0] != c.amr0 || !slices.Contains(sc.amr, AMRMFA) {
			t.Errorf("first factor %q: grant %q amr %v; want grant %q, amr starting %q and including mfa",
				c.first, sc.grant, sc.amr, c.grant, c.amr0)
		}
	}
}
