package auth_test

import (
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// ---------------------------------------------------------------------------
// Mandatory administrator MFA (migration 00094)
// ---------------------------------------------------------------------------

const adminMFAPassword = "Password123!"

// withAdminMFA turns on mandatory administrator MFA for the fixture.
func (f *mfaFixture) withAdminMFA(t *testing.T) *auth.AdminMFAPolicyService {
	t.Helper()
	svc := auth.NewAdminMFAPolicyService(f.pool, testhelper.TestLogger())
	f.authSvc.WithAdminMFAPolicy(svc)
	return svc
}

// registerTenantUser creates a tenant-level (console) account in the seeded
// tenant and returns its user id.
func (f *mfaFixture) registerTenantUser(t *testing.T, email string) int64 {
	t.Helper()
	if _, err := f.authSvc.Register(f.ctx, auth.RegisterInput{Email: email, Password: adminMFAPassword}); err != nil {
		t.Fatalf("Register(%q): %v", email, err)
	}
	var id int64
	if err := f.pool.QueryRow(f.ctx,
		`SELECT id FROM users WHERE email = $1 AND tenant_id = $2 AND application_id IS NULL AND deleted_at IS NULL`,
		email, f.tenantID).Scan(&id); err != nil {
		t.Fatalf("fetch user %q: %v", email, err)
	}
	return id
}

// registerOwner creates a tenant-level account holding an activated owner
// grant — an administrator.
func (f *mfaFixture) registerOwner(t *testing.T, prefix string) (int64, string) {
	t.Helper()
	email := uniqueEmail(prefix)
	id := f.registerTenantUser(t, email)
	if _, err := f.pool.Exec(f.ctx, `
		INSERT INTO admin_grants (user_id, tenant_id, admin_role, activated_at)
		VALUES ($1, $2, 'owner', NOW())
	`, id, f.tenantID); err != nil {
		t.Fatalf("grant owner: %v", err)
	}
	return id, email
}

func (f *mfaFixture) setAdminPolicy(t *testing.T, svc *auth.AdminMFAPolicyService, methods ...string) {
	t.Helper()
	if _, err := f.pool.Exec(f.ctx, `
		INSERT INTO admin_mfa_policies (tenant_id, allowed_methods) VALUES ($1, $2)
		ON CONFLICT (tenant_id) WHERE tenant_id IS NOT NULL
		DO UPDATE SET allowed_methods = EXCLUDED.allowed_methods
	`, f.tenantID, methods); err != nil {
		t.Fatalf("set admin MFA policy: %v", err)
	}
	svc.InvalidateCache()
}

func (f *mfaFixture) tenantLogin(t *testing.T, email string) *auth.LoginResult {
	t.Helper()
	res, err := f.authSvc.Login(f.ctx, auth.LoginInput{Email: email, Password: adminMFAPassword})
	if err != nil {
		t.Fatalf("Login(%q): %v", email, err)
	}
	return res
}

func (f *mfaFixture) sessionAMR(t *testing.T, accessToken string) []string {
	t.Helper()
	claims, err := f.jwtSvc.Verify(f.ctx, accessToken)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	var amr []string
	if err := f.pool.QueryRow(f.ctx, `SELECT amr FROM user_sessions WHERE id::TEXT = $1`, claims.SessionID).Scan(&amr); err != nil {
		t.Fatalf("read session amr: %v", err)
	}
	return amr
}

// enrollEmail marks an administrator's email factor as set up (its address
// confirmed with a code), as the email enrollment flow does.
func (f *mfaFixture) enrollEmail(t *testing.T, userID int64) {
	t.Helper()
	if _, err := f.pool.Exec(f.ctx, `
		INSERT INTO email_mfa_settings (user_id, tenant_id, is_active) VALUES ($1, $2, true)
		ON CONFLICT (user_id) DO UPDATE SET is_active = true
	`, userID, f.tenantID); err != nil {
		t.Fatalf("enroll email MFA: %v", err)
	}
}

// A new administrator has no second factor. Their first sign-in never hands
// out tokens and never mails anything: it asks them to choose a method to set
// up — the authenticator app or email — and either completes the sign-in.
func TestAdminMFA_FirstSignInChoosesAMethodToSetUp(t *testing.T) {
	f := newMFAFixture(t)
	f.withAdminMFA(t)
	_, email := f.registerOwner(t, "admin-mfa-first")

	res := f.tenantLogin(t, email)
	if res.Token != nil || res.OTPChallenge != nil || res.MFAEnrollment == nil {
		t.Fatalf("Login = %+v, want a set-up step and no tokens", res)
	}
	if got := res.MFAEnrollment.AllowedMethods; !slices.Equal(got, []string{auth.MFAMethodTOTP, auth.MFAMethodEmail}) {
		t.Errorf("AllowedMethods = %v, want [totp email] to choose from", got)
	}
	if f.mail.codeCount() != 0 {
		t.Error("a code was emailed before the administrator chose email")
	}

	// Choosing the authenticator app: scan, confirm the first code, signed in.
	enroll, _, err := f.authSvc.EnrollPending(f.ctx, res.MFAEnrollment.EnrollmentToken)
	if err != nil {
		t.Fatalf("EnrollPending: %v", err)
	}
	tokens, _, err := f.authSvc.ActivatePendingForCookieSession(f.ctx, res.MFAEnrollment.EnrollmentToken,
		codeFor(t, secretFromOTPURI(t, enroll.OTPURI)))
	if err != nil {
		t.Fatalf("ActivatePendingForCookieSession: %v", err)
	}
	if amr := f.sessionAMR(t, tokens.AccessToken); !slices.Contains(amr, auth.AMRMFA) {
		t.Errorf("session amr = %v, want it to record mfa", amr)
	}

	// From then on the app is what the sign-in asks for, with email as the fallback.
	again := f.tenantLogin(t, email)
	if again.OTPChallenge == nil || !slices.Equal(again.OTPChallenge.Methods, []string{auth.MFAMethodTOTP, auth.MFAMethodEmail}) {
		t.Errorf("next sign-in = %+v, want an authenticator-app challenge", again)
	}
}

// The other choice at the first sign-in: email. The code is sent only once
// email is chosen, and confirming it both sets email up and signs in.
func TestAdminMFA_FirstSignInCanChooseEmail(t *testing.T) {
	f := newMFAFixture(t)
	f.withAdminMFA(t)
	_, email := f.registerOwner(t, "admin-mfa-first-email")

	res := f.tenantLogin(t, email)
	if res.MFAEnrollment == nil {
		t.Fatalf("Login = %+v, want a set-up step", res)
	}
	if _, err := f.authSvc.SendPendingEnrollmentCode(f.ctx, res.MFAEnrollment.EnrollmentToken); err != nil {
		t.Fatalf("SendPendingEnrollmentCode: %v", err)
	}
	if _, _, err := f.authSvc.ActivatePendingForCookieSession(f.ctx, res.MFAEnrollment.EnrollmentToken,
		f.mail.lastCode(t).Code); err != nil {
		t.Fatalf("ActivatePendingForCookieSession(emailed code): %v", err)
	}

	// Email is now set up: the next sign-in is an email challenge, with the code
	// mailed up front because it is the only method.
	again := f.tenantLogin(t, email)
	if again.OTPChallenge == nil || !slices.Equal(again.OTPChallenge.Methods, []string{auth.MFAMethodEmail}) ||
		!again.OTPChallenge.EmailCodeSent {
		t.Errorf("next sign-in = %+v, want an email challenge with the code sent", again.OTPChallenge)
	}
}

// Where the policy allows only the app, that is the one method offered.
func TestAdminMFA_PolicyLimitsTheSetUpChoice(t *testing.T) {
	f := newMFAFixture(t)
	svc := f.withAdminMFA(t)
	_, email := f.registerOwner(t, "admin-mfa-enroll")
	f.setAdminPolicy(t, svc, auth.MFAMethodTOTP)

	res := f.tenantLogin(t, email)
	if res.MFAEnrollment == nil {
		t.Fatalf("Login = %+v, want a set-up step", res)
	}
	if got := res.MFAEnrollment.AllowedMethods; !slices.Equal(got, []string{auth.MFAMethodTOTP}) {
		t.Errorf("AllowedMethods = %v, want [totp]", got)
	}
}

// With both set up, both are offered, and email is not mailed until chosen.
func TestAdminMFA_BothMethodsAreOfferedOnceSetUp(t *testing.T) {
	f := newMFAFixture(t)
	f.withAdminMFA(t)
	id, email := f.registerOwner(t, "admin-mfa-both")
	secret := f.enrollAndActivate(t, id, email)
	f.enrollEmail(t, id)

	res := f.tenantLogin(t, email)
	if res.OTPChallenge == nil {
		t.Fatalf("Login = %+v, want a challenge", res)
	}
	if !slices.Equal(res.OTPChallenge.Methods, []string{auth.MFAMethodTOTP, auth.MFAMethodEmail}) {
		t.Errorf("Methods = %v, want [totp email]", res.OTPChallenge.Methods)
	}
	if res.OTPChallenge.EmailCodeSent || f.mail.codeCount() != 0 {
		t.Error("an email code was sent although the app is also available")
	}
	if _, err := f.authSvc.LoginOTPForCookieSession(f.ctx, auth.LoginOTPInput{
		OTPSessionToken: res.OTPChallenge.OTPSessionToken, Code: codeFor(t, secret),
	}); err != nil {
		t.Fatalf("LoginOTPForCookieSession(app code): %v", err)
	}
}

// A lost or deleted authenticator entry: the administrator only ever set up the
// app, yet the challenge still offers an email code, sent only on request.
func TestAdminMFA_EmailFallbackWithOnlyTheAppSetUp(t *testing.T) {
	f := newMFAFixture(t)
	f.withAdminMFA(t)
	id, email := f.registerOwner(t, "admin-mfa-lostapp")
	f.enrollAndActivate(t, id, email)

	res := f.tenantLogin(t, email)
	if res.OTPChallenge == nil {
		t.Fatalf("Login = %+v, want a challenge", res)
	}
	if !slices.Equal(res.OTPChallenge.Methods, []string{auth.MFAMethodTOTP, auth.MFAMethodEmail}) {
		t.Errorf("Methods = %v, want [totp email]", res.OTPChallenge.Methods)
	}
	if res.OTPChallenge.EmailCodeSent || f.mail.codeCount() != 0 {
		t.Error("an email code was sent before the administrator asked for one")
	}
	if err := f.authSvc.ResendLoginOTP(f.ctx, res.OTPChallenge.OTPSessionToken); err != nil {
		t.Fatalf("ResendLoginOTP (choose email): %v", err)
	}
	if _, err := f.authSvc.LoginOTPForCookieSession(f.ctx, auth.LoginOTPInput{
		OTPSessionToken: res.OTPChallenge.OTPSessionToken, Code: f.mail.lastCode(t).Code,
	}); err != nil {
		t.Fatalf("LoginOTPForCookieSession(emailed code): %v", err)
	}
}

// A policy without email removes the fallback: only the app (and its backup
// codes) remain.
func TestAdminMFA_NoEmailFallbackWhenPolicyRefusesEmail(t *testing.T) {
	f := newMFAFixture(t)
	svc := f.withAdminMFA(t)
	id, email := f.registerOwner(t, "admin-mfa-nofallback")
	f.enrollAndActivate(t, id, email)
	f.setAdminPolicy(t, svc, auth.MFAMethodTOTP)

	res := f.tenantLogin(t, email)
	if res.OTPChallenge == nil {
		t.Fatalf("Login = %+v, want a challenge", res)
	}
	if !slices.Equal(res.OTPChallenge.Methods, []string{auth.MFAMethodTOTP}) {
		t.Errorf("Methods = %v, want [totp]", res.OTPChallenge.Methods)
	}
}

// The fallback: with both set up, an administrator without their phone asks
// for an email code on the same challenge and finishes with it.
func TestAdminMFA_EmailFallbackOnRequest(t *testing.T) {
	f := newMFAFixture(t)
	f.withAdminMFA(t)
	id, email := f.registerOwner(t, "admin-mfa-fallback")
	f.enrollAndActivate(t, id, email)
	f.enrollEmail(t, id)

	res := f.tenantLogin(t, email)
	if res.OTPChallenge == nil {
		t.Fatalf("Login = %+v, want an OTP challenge", res)
	}
	if err := f.authSvc.ResendLoginOTP(f.ctx, res.OTPChallenge.OTPSessionToken); err != nil {
		t.Fatalf("ResendLoginOTP (choose email): %v", err)
	}
	if _, err := f.authSvc.LoginOTPForCookieSession(f.ctx, auth.LoginOTPInput{
		OTPSessionToken: res.OTPChallenge.OTPSessionToken, Code: f.mail.lastCode(t).Code,
	}); err != nil {
		t.Fatalf("LoginOTPForCookieSession(emailed code): %v", err)
	}
}

// A tenant-level account that administers nothing keeps the old behaviour.
func TestAdminMFA_NonAdministratorIsUnaffected(t *testing.T) {
	f := newMFAFixture(t)
	f.withAdminMFA(t)
	email := uniqueEmail("admin-mfa-plain")
	f.registerTenantUser(t, email)

	if res := f.tenantLogin(t, email); res.Token == nil {
		t.Fatalf("Login = %+v, want tokens for a non-administrator", res)
	}
}

// Only factors the policy accepts count: an administrator whose one factor the
// tenant has since disallowed must set up an allowed one.
func TestAdminMFA_PolicyDecidesWhichFactorsCount(t *testing.T) {
	f := newMFAFixture(t)
	svc := f.withAdminMFA(t)
	id, email := f.registerOwner(t, "admin-mfa-policy")
	f.enrollAndActivate(t, id, email)
	f.setAdminPolicy(t, svc, auth.MFAMethodEmail)

	res := f.tenantLogin(t, email)
	if res.MFAEnrollment == nil {
		t.Fatalf("Login = %+v, want set-up of an allowed method", res)
	}
	if !slices.Equal(res.MFAEnrollment.AllowedMethods, []string{auth.MFAMethodEmail}) {
		t.Errorf("AllowedMethods = %v, want [email]", res.MFAEnrollment.AllowedMethods)
	}
}

// With no allowed method this deployment can run, sign-in fails closed.
func TestAdminMFA_NoUsableMethodFailsClosed(t *testing.T) {
	f := newMFAFixture(t)
	svc := f.withAdminMFA(t)
	_, email := f.registerOwner(t, "admin-mfa-closed")
	f.setAdminPolicy(t, svc, auth.MFAMethodEmail)

	// A deployment that runs TOTP but has no mail sender: the email-only policy
	// cannot be satisfied, and the sign-in must be refused, never let through.
	noMail := auth.NewAuthService(f.pool, f.jwtSvc, testhelper.TestLogger()).
		WithTOTP(f.totpSvc, testhelper.NewTestRedis(t)).
		WithAdminMFAPolicy(svc)
	_, err := noMail.Login(f.ctx, auth.LoginInput{Email: email, Password: adminMFAPassword})
	if !errors.Is(err, auth.ErrAdminMFAUnavailable) {
		t.Fatalf("Login err = %v, want ErrAdminMFAUnavailable", err)
	}
}

// An administrator cannot turn off their last accepted factor, and cannot set
// up one the policy would never accept.
func TestAdminMFA_SelfServiceGuards(t *testing.T) {
	f := newMFAFixture(t)
	svc := f.withAdminMFA(t)
	id, email := f.registerOwner(t, "admin-mfa-guards")
	f.enrollAndActivate(t, id, email)
	perms := []string{} // an owner is recognised by their grant, not a permission

	// Only the app is set up: it is the last factor and stays.
	if err := f.authSvc.AdminFactorRemovalAllowed(f.ctx, id, f.tenantID, perms, auth.MFAMethodTOTP); !errors.Is(err, auth.ErrMFARequiredByPolicy) {
		t.Errorf("removing the only factor: err = %v, want ErrMFARequiredByPolicy", err)
	}

	// With email set up as well, either may go — the other remains.
	f.enrollEmail(t, id)
	if err := f.authSvc.AdminFactorRemovalAllowed(f.ctx, id, f.tenantID, perms, auth.MFAMethodTOTP); err != nil {
		t.Errorf("removing the app with email set up: err = %v, want nil", err)
	}
	if err := f.authSvc.AdminFactorRemovalAllowed(f.ctx, id, f.tenantID, perms, auth.MFAMethodEmail); err != nil {
		t.Errorf("removing email with the app set up: err = %v, want nil", err)
	}

	// TOTP-only policy: email counts for nothing and may not be set up.
	f.setAdminPolicy(t, svc, auth.MFAMethodTOTP)
	if err := f.authSvc.AdminFactorRemovalAllowed(f.ctx, id, f.tenantID, perms, auth.MFAMethodTOTP); !errors.Is(err, auth.ErrMFARequiredByPolicy) {
		t.Errorf("removing the app when email is not accepted: err = %v, want ErrMFARequiredByPolicy", err)
	}
	if err := f.authSvc.AdminMethodEnrollable(f.ctx, id, f.tenantID, perms, auth.MFAMethodEmail); !errors.Is(err, auth.ErrAdminMFAMethodNotAllowed) {
		t.Errorf("enrolling email under a TOTP-only policy: err = %v, want ErrAdminMFAMethodNotAllowed", err)
	}

	// A non-administrator is not governed by the administrator policy.
	plain := f.registerTenantUser(t, uniqueEmail("admin-mfa-guards-plain"))
	if err := f.authSvc.AdminMethodEnrollable(f.ctx, plain, f.tenantID, perms, auth.MFAMethodEmail); err != nil {
		t.Errorf("non-administrator enrollment: err = %v, want nil", err)
	}
}

// A session established without MFA cannot be carried into another tenant.
func TestAdminMFA_TenantSwitchRequiresAnMFASession(t *testing.T) {
	f := newMFAFixture(t)
	id, email := f.registerOwner(t, "admin-mfa-switch")

	// Signed in before the requirement existed: a password-only session.
	res := f.tenantLogin(t, email)
	if res.Token == nil {
		t.Fatalf("Login = %+v, want tokens before admin MFA is enforced", res)
	}
	claims, err := f.jwtSvc.Verify(f.ctx, res.Token.AccessToken)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	var other int64
	slug := fmt.Sprintf("admin-mfa-switch-%d", time.Now().UnixNano())
	if err := f.pool.QueryRow(f.ctx,
		`INSERT INTO tenants (name, slug, jwt_secret) VALUES ($1, $1, 'secret') RETURNING id`, slug,
	).Scan(&other); err != nil {
		t.Fatalf("create second tenant: %v", err)
	}
	if _, err := f.pool.Exec(f.ctx,
		`INSERT INTO admin_grants (user_id, tenant_id, admin_role, activated_at) VALUES ($1, $2, 'owner', NOW())`,
		id, other); err != nil {
		t.Fatalf("grant second tenant: %v", err)
	}

	f.withAdminMFA(t)
	_, err = f.authSvc.SwitchTenantContextForClaims(f.ctx, id, f.tenantID, other, false, claims.SessionID, true)
	if !errors.Is(err, auth.ErrMFAStepUpRequired) {
		t.Fatalf("switch with a password-only session: err = %v, want ErrMFAStepUpRequired", err)
	}

	// An API-key caller has no session to step up and is not refused for it.
	_, err = f.authSvc.SwitchTenantContextForClaims(f.ctx, id, f.tenantID, other, false, "", false)
	if errors.Is(err, auth.ErrMFAStepUpRequired) {
		t.Fatalf("non-human switch was refused for MFA: %v", err)
	}
}

// The settings page reads one call for the whole picture.
func TestAdminMFA_MyMFAStatus(t *testing.T) {
	f := newMFAFixture(t)
	f.withAdminMFA(t)
	id, email := f.registerOwner(t, "admin-mfa-status")
	f.enrollAndActivate(t, id, email)

	st, err := f.authSvc.MyMFAStatus(f.ctx, id, f.tenantID, nil)
	if err != nil {
		t.Fatalf("MyMFAStatus: %v", err)
	}
	if !st.MFARequired {
		t.Error("MFARequired = false for an administrator")
	}
	byMethod := map[string]auth.MFAMethodStatus{}
	for _, m := range st.Methods {
		byMethod[m.Method] = m
	}
	if m := byMethod[auth.MFAMethodTOTP]; !m.Allowed || !m.Available || !m.Active || m.BackupCodesRemaining == 0 {
		t.Errorf("totp = %+v, want allowed, available, active, with backup codes", m)
	}
	if m := byMethod[auth.MFAMethodEmail]; !m.Allowed || !m.Available || m.Active {
		t.Errorf("email = %+v, want allowed and available but not set up", m)
	}
	if len(st.Methods) != 2 {
		t.Errorf("methods = %+v, want exactly the two second factors", st.Methods)
	}
}

func TestValidateAdminMFAMethods(t *testing.T) {
	for _, tc := range []struct {
		methods []string
		ok      bool
	}{
		{[]string{"totp"}, true},
		{[]string{"totp", "email"}, true},
		{[]string{"passkey"}, false}, // a sign-in method, not a second factor
		{nil, false},
		{[]string{}, false},
		{[]string{"sms"}, false},
		{[]string{"totp", "totp"}, false},
	} {
		err := auth.ValidateAdminMFAMethods(tc.methods)
		if (err == nil) != tc.ok {
			t.Errorf("ValidateAdminMFAMethods(%v) = %v, want ok=%v", tc.methods, err, tc.ok)
		}
		if err != nil && !errors.Is(err, auth.ErrInvalidAdminMFAPolicy) {
			t.Errorf("ValidateAdminMFAMethods(%v) error does not wrap ErrInvalidAdminMFAPolicy: %v", tc.methods, err)
		}
	}
}

func TestOrderAdminMFAMethods(t *testing.T) {
	got := auth.OrderAdminMFAMethods([]string{"email", "totp"})
	if want := []string{"totp", "email"}; !slices.Equal(got, want) {
		t.Errorf("OrderAdminMFAMethods = %v, want %v", got, want)
	}
}

// The console's sign-in is no longer a captcha flow.
func TestCaptcha_SessionFlowRemoved(t *testing.T) {
	for _, f := range auth.ValidCaptchaFlows {
		if f == "session" {
			t.Fatal(`"session" is still a valid captcha flow`)
		}
	}
	if slices.Contains(auth.DefaultCaptchaPolicy.ProtectedFlows, "session") {
		t.Error(`the default captcha policy still protects "session"`)
	}
}
