package auth_test

import (
	"testing"

	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// TestMFA_PolicyGovernsExistingEnrollments proves the application policy is
// authoritative at login: a factor the user already activated is NOT offered or
// emailed once the owner removes it from allowed_methods. This is the fix for
// "I set TOTP-only but the app still sends an email OTP" — the email factor
// stays enrolled but is no longer challenged.
func TestMFA_PolicyGovernsExistingEnrollments(t *testing.T) {
	f := newMFAFixture(t)
	app, appID := f.createApp(t, "policy-authoritative-app")

	// Allow both methods, then a user enrolls BOTH TOTP and email.
	if err := f.totpSvc.SetAppMFAPolicy(f.ctx, f.tenantID, appID, auth.MFAModeOptional,
		[]string{auth.MFAMethodTOTP, auth.MFAMethodEmail}, nil); err != nil {
		t.Fatalf("SetAppMFAPolicy(both): %v", err)
	}
	email := uniqueEmail("policy-auth")
	userID := f.registerAppUser(t, app, email, "Password123!")

	secret := f.enrollAndActivate(t, userID, email) // active TOTP

	if err := f.emailSvc.BeginEnrollment(f.ctx, userID, f.tenantID, email); err != nil {
		t.Fatalf("BeginEnrollment: %v", err)
	}
	if err := f.emailSvc.ActivateEnrollment(f.ctx, userID, f.mail.lastCode(t).Code); err != nil {
		t.Fatalf("ActivateEnrollment: %v", err)
	}
	if active, _ := f.emailSvc.IsActive(f.ctx, userID); !active {
		t.Fatal("email MFA not active after activation")
	}

	// Owner tightens the policy to TOTP-only.
	if err := f.totpSvc.SetAppMFAPolicy(f.ctx, f.tenantID, appID, auth.MFAModeRequired,
		[]string{auth.MFAMethodTOTP}, nil); err != nil {
		t.Fatalf("SetAppMFAPolicy(totp-only): %v", err)
	}

	// Login: the still-active email factor must NOT be offered or emailed.
	before := f.mail.codeCount()
	result, err := f.appLogin(t, app, email, "Password123!")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if result.OTPChallenge == nil {
		t.Fatalf("Login = %+v, want OTP challenge", result)
	}
	if len(result.OTPChallenge.Methods) != 1 || result.OTPChallenge.Methods[0] != auth.MFAMethodTOTP {
		t.Errorf("challenge methods = %v, want [totp] only (email removed from policy)", result.OTPChallenge.Methods)
	}
	if f.mail.codeCount() != before {
		t.Error("an email code was sent even though email is no longer in allowed_methods")
	}

	// TOTP still completes the login.
	if _, err := f.authSvc.LoginOTP(f.ctx, auth.LoginOTPInput{
		OTPSessionToken: result.OTPChallenge.OTPSessionToken,
		Code:            codeFor(t, secret),
	}); err != nil {
		t.Fatalf("LoginOTP(totp): %v", err)
	}
}

// TestMFA_DisallowedSoleFactorForcesReenrollment proves that when a user's ONLY
// active factor is removed from the policy under 'required' mode, login forces
// re-enrollment of a permitted method instead of silently issuing tokens or
// sending the disallowed factor's code.
func TestMFA_DisallowedSoleFactorForcesReenrollment(t *testing.T) {
	f := newMFAFixture(t)
	app, appID := f.createApp(t, "sole-email-app")

	if err := f.totpSvc.SetAppMFAPolicy(f.ctx, f.tenantID, appID, auth.MFAModeOptional,
		[]string{auth.MFAMethodEmail}, nil); err != nil {
		t.Fatalf("SetAppMFAPolicy(email): %v", err)
	}
	email := uniqueEmail("sole-email")
	userID := f.registerAppUser(t, app, email, "Password123!")

	if err := f.emailSvc.BeginEnrollment(f.ctx, userID, f.tenantID, email); err != nil {
		t.Fatalf("BeginEnrollment: %v", err)
	}
	if err := f.emailSvc.ActivateEnrollment(f.ctx, userID, f.mail.lastCode(t).Code); err != nil {
		t.Fatalf("ActivateEnrollment: %v", err)
	}

	// Tighten to required TOTP-only. The user's sole factor (email) is now
	// disallowed → login must force enrollment, not send an email code.
	if err := f.totpSvc.SetAppMFAPolicy(f.ctx, f.tenantID, appID, auth.MFAModeRequired,
		[]string{auth.MFAMethodTOTP}, nil); err != nil {
		t.Fatalf("SetAppMFAPolicy(totp-only): %v", err)
	}

	before := f.mail.codeCount()
	result, err := f.appLogin(t, app, email, "Password123!")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if result.MFAEnrollment == nil {
		t.Fatalf("Login = %+v, want forced enrollment (sole factor disallowed)", result)
	}
	if f.mail.codeCount() != before {
		t.Error("an email code was sent despite email being disallowed by policy")
	}
}
