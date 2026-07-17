package auth_test

import (
	"errors"
	"testing"

	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// TestEmailMFA_EnrollActivateAndLoginChallenge covers the voluntary email-MFA
// journey: policy gating, code-verified enrollment, and the email-code login
// challenge with the app_id claim preserved.
func TestEmailMFA_EnrollActivateAndLoginChallenge(t *testing.T) {
	f := newMFAFixture(t)
	app, appID := f.createApp(t, "email-mfa-app")
	email := uniqueEmail("email-mfa")
	userID := f.registerAppUser(t, app, email, "Password123!")

	// Default method set is TOTP-only → email enrollment rejected.
	if err := f.emailSvc.BeginEnrollment(f.ctx, userID, f.tenantID, email); !errors.Is(err, auth.ErrMFAMethodNotAllowed) {
		t.Fatalf("BeginEnrollment(default methods) error = %v, want ErrMFAMethodNotAllowed", err)
	}

	// Owner allows email → enrollment sends a code.
	if err := f.totpSvc.SetAppMFAPolicy(f.ctx, f.tenantID, appID, auth.MFAModeOptional, []string{auth.MFAMethodTOTP, auth.MFAMethodEmail}, nil); err != nil {
		t.Fatalf("SetAppMFAPolicy: %v", err)
	}
	if err := f.emailSvc.BeginEnrollment(f.ctx, userID, f.tenantID, email); err != nil {
		t.Fatalf("BeginEnrollment: %v", err)
	}
	sent := f.mail.lastCode(t)
	if sent.To != email || sent.AppName != "email-mfa-app" || len(sent.Code) != auth.EmailOTPLength {
		t.Fatalf("code email = %+v, want to=%q app=%q %d-digit code", sent, email, "email-mfa-app", auth.EmailOTPLength)
	}

	// Wrong code → rejected; right code → active.
	if err := f.emailSvc.ActivateEnrollment(f.ctx, userID, "000000"); !errors.Is(err, auth.ErrEmailCodeInvalid) {
		t.Fatalf("ActivateEnrollment(wrong) error = %v, want ErrEmailCodeInvalid", err)
	}
	if err := f.emailSvc.ActivateEnrollment(f.ctx, userID, sent.Code); err != nil {
		t.Fatalf("ActivateEnrollment: %v", err)
	}
	if active, _ := f.emailSvc.IsActive(f.ctx, userID); !active {
		t.Fatal("email MFA not active after activation")
	}

	// Login → challenge with the email method; a login code was emailed.
	result, err := f.appLogin(t, app, email, "Password123!")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if result.OTPChallenge == nil {
		t.Fatalf("Login = %+v, want OTP challenge", result)
	}
	if len(result.OTPChallenge.Methods) != 1 || result.OTPChallenge.Methods[0] != auth.MFAMethodEmail {
		t.Errorf("challenge methods = %v, want [email]", result.OTPChallenge.Methods)
	}

	loginCode := f.mail.lastCode(t)
	if loginCode.Code == sent.Code {
		t.Error("login code equals enrollment code — codes must be minted per challenge")
	}
	tokens, err := f.authSvc.LoginOTP(f.ctx, auth.LoginOTPInput{
		OTPSessionToken: result.OTPChallenge.OTPSessionToken,
		Code:            loginCode.Code,
	})
	if err != nil {
		t.Fatalf("LoginOTP(email code): %v", err)
	}
	claims, err := f.jwtSvc.Verify(f.ctx, tokens.AccessToken)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.AppID != app.ID {
		t.Errorf("claims.AppID = %q, want %q", claims.AppID, app.ID)
	}

	// The emailed login code is single-use: the consumed session is gone.
	if _, err := f.authSvc.LoginOTP(f.ctx, auth.LoginOTPInput{
		OTPSessionToken: result.OTPChallenge.OTPSessionToken,
		Code:            loginCode.Code,
	}); err == nil {
		t.Error("LoginOTP with consumed session succeeded, want error")
	}
}

// TestEmailMFA_RequiredMode_EmailPathCompletesLogin covers forced enrollment
// through the email method when the application allows only email.
func TestEmailMFA_RequiredMode_EmailPathCompletesLogin(t *testing.T) {
	f := newMFAFixture(t)
	app, appID := f.createApp(t, "email-only-app")
	email := uniqueEmail("email-required")
	f.registerAppUser(t, app, email, "Password123!")

	if err := f.totpSvc.SetAppMFAPolicy(f.ctx, f.tenantID, appID, auth.MFAModeRequired, []string{auth.MFAMethodEmail}, nil); err != nil {
		t.Fatalf("SetAppMFAPolicy: %v", err)
	}

	result, err := f.appLogin(t, app, email, "Password123!")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if result.MFAEnrollment == nil {
		t.Fatalf("Login = %+v, want MFA enrollment challenge", result)
	}
	if len(result.MFAEnrollment.AllowedMethods) != 1 || result.MFAEnrollment.AllowedMethods[0] != auth.MFAMethodEmail {
		t.Errorf("allowed methods = %v, want [email]", result.MFAEnrollment.AllowedMethods)
	}

	// The TOTP path is closed for an email-only application.
	if _, _, err := f.authSvc.EnrollPending(f.ctx, result.MFAEnrollment.EnrollmentToken); !errors.Is(err, auth.ErrMFAMethodNotAllowed) {
		t.Errorf("EnrollPending(email-only app) error = %v, want ErrMFAMethodNotAllowed", err)
	}

	// Email path: send code → activate → tokens.
	if _, err := f.authSvc.SendPendingEnrollmentCode(f.ctx, result.MFAEnrollment.EnrollmentToken); err != nil {
		t.Fatalf("SendPendingEnrollmentCode: %v", err)
	}
	code := f.mail.lastCode(t)

	tokens, _, err := f.authSvc.ActivatePending(f.ctx, result.MFAEnrollment.EnrollmentToken, code.Code)
	if err != nil {
		t.Fatalf("ActivatePending(email code): %v", err)
	}
	claims, err := f.jwtSvc.Verify(f.ctx, tokens.AccessToken)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.AppID != app.ID {
		t.Errorf("claims.AppID = %q, want %q", claims.AppID, app.ID)
	}

	// Email MFA is now the user's active factor: next login → email challenge.
	result2, err := f.appLogin(t, app, email, "Password123!")
	if err != nil {
		t.Fatalf("second Login: %v", err)
	}
	if result2.OTPChallenge == nil || !containsString(result2.OTPChallenge.Methods, auth.MFAMethodEmail) {
		t.Fatalf("second Login = %+v, want email OTP challenge", result2)
	}
}

// TestEmailMFA_ResendRotatesCodeAndIsCapped verifies the re-send budget and
// that each re-send invalidates the previous code.
func TestEmailMFA_ResendRotatesCodeAndIsCapped(t *testing.T) {
	f := newMFAFixture(t)
	app, appID := f.createApp(t, "resend-app")
	email := uniqueEmail("email-resend")
	userID := f.registerAppUser(t, app, email, "Password123!")

	if err := f.totpSvc.SetAppMFAPolicy(f.ctx, f.tenantID, appID, auth.MFAModeOptional, []string{auth.MFAMethodEmail}, nil); err != nil {
		t.Fatalf("SetAppMFAPolicy: %v", err)
	}
	if err := f.emailSvc.BeginEnrollment(f.ctx, userID, f.tenantID, email); err != nil {
		t.Fatalf("BeginEnrollment: %v", err)
	}
	if err := f.emailSvc.ActivateEnrollment(f.ctx, userID, f.mail.lastCode(t).Code); err != nil {
		t.Fatalf("ActivateEnrollment: %v", err)
	}

	result, err := f.appLogin(t, app, email, "Password123!")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	token := result.OTPChallenge.OTPSessionToken
	firstCode := f.mail.lastCode(t).Code

	// Re-sends within budget succeed and rotate the code.
	for i := 0; i < auth.EmailOTPMaxResends; i++ {
		if err := f.authSvc.ResendLoginOTP(f.ctx, token); err != nil {
			t.Fatalf("ResendLoginOTP #%d: %v", i+1, err)
		}
	}
	if err := f.authSvc.ResendLoginOTP(f.ctx, token); !errors.Is(err, auth.ErrTooManyResends) {
		t.Errorf("over-budget resend error = %v, want ErrTooManyResends", err)
	}

	// The original code was rotated away; the latest one works.
	if _, err := f.authSvc.LoginOTP(f.ctx, auth.LoginOTPInput{OTPSessionToken: token, Code: firstCode}); err == nil {
		t.Error("stale (rotated) email code accepted, want rejection")
	}
	if _, err := f.authSvc.LoginOTP(f.ctx, auth.LoginOTPInput{OTPSessionToken: token, Code: f.mail.lastCode(t).Code}); err != nil {
		t.Errorf("latest email code rejected: %v", err)
	}
}

// TestEmailMFA_LastFactorGuards verifies that under a 'required' policy the
// last active factor cannot be removed, while a redundant one can.
func TestEmailMFA_LastFactorGuards(t *testing.T) {
	f := newMFAFixture(t)
	app, appID := f.createApp(t, "guard-app")
	email := uniqueEmail("email-guard")
	userID := f.registerAppUser(t, app, email, "Password123!")

	if err := f.totpSvc.SetAppMFAPolicy(f.ctx, f.tenantID, appID, auth.MFAModeRequired, []string{auth.MFAMethodTOTP, auth.MFAMethodEmail}, nil); err != nil {
		t.Fatalf("SetAppMFAPolicy: %v", err)
	}

	// Enroll email only (via the self-service path — required mode still
	// allows voluntary enrollment).
	if err := f.emailSvc.BeginEnrollment(f.ctx, userID, f.tenantID, email); err != nil {
		t.Fatalf("BeginEnrollment: %v", err)
	}
	if err := f.emailSvc.ActivateEnrollment(f.ctx, userID, f.mail.lastCode(t).Code); err != nil {
		t.Fatalf("ActivateEnrollment: %v", err)
	}

	// Email is the ONLY factor → cannot be disabled under 'required'.
	if err := f.emailSvc.SendVerificationCode(f.ctx, userID, f.tenantID, email); err != nil {
		t.Fatalf("SendVerificationCode: %v", err)
	}
	if err := f.emailSvc.Disable(f.ctx, userID, f.tenantID, f.mail.lastCode(t).Code); !errors.Is(err, auth.ErrMFARequiredByPolicy) {
		t.Fatalf("Disable(last factor) error = %v, want ErrMFARequiredByPolicy", err)
	}

	// Add TOTP as a second factor → now TOTP can be disabled (email remains).
	secret := f.enrollAndActivate(t, userID, email)
	if err := f.totpSvc.DisableUser(f.ctx, userID, f.tenantID, codeFor(t, secret)); err != nil {
		t.Fatalf("DisableUser(TOTP with email active) error = %v, want success", err)
	}
	if active, _ := f.emailSvc.IsActive(f.ctx, userID); !active {
		t.Error("email MFA lost while disabling TOTP")
	}

	// Admin reset clears the email factor too.
	if err := f.totpSvc.ResetUserMFA(f.ctx, f.tenantID, &appID, userID); err != nil {
		t.Fatalf("ResetUserMFA: %v", err)
	}
	if active, _ := f.emailSvc.IsActive(f.ctx, userID); active {
		t.Error("email MFA still active after admin reset")
	}
}

// containsString reports whether s appears in list.
func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
