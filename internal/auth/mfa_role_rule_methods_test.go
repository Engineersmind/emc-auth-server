package auth_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// ---------------------------------------------------------------------------
// Per-role allowed MFA methods (#199)
// ---------------------------------------------------------------------------

func (f *mfaFixture) setRuleSpecs(t *testing.T, appID int64, specs ...auth.MFARoleRuleSpec) auth.MFARoleRulesUpdate {
	t.Helper()
	res, err := f.totpSvc.SetAppMFARoleRuleSpecs(f.ctx, f.tenantID, appID, specs, nil)
	if err != nil {
		t.Fatalf("SetAppMFARoleRuleSpecs(%+v): %v", specs, err)
	}
	return res
}

// appWithMethods creates an 'optional' application allowing methods.
func (f *mfaFixture) appWithMethods(t *testing.T, name string, methods ...string) (*auth.AppResult, int64) {
	t.Helper()
	app, appID := f.createApp(t, name)
	if err := f.totpSvc.SetAppMFAPolicy(f.ctx, f.tenantID, appID, auth.MFAModeOptional, methods, nil); err != nil {
		t.Fatalf("SetAppMFAPolicy(%v): %v", methods, err)
	}
	return app, appID
}

func TestRoleRuleMethods_WriteValidation(t *testing.T) {
	f := newMFAFixture(t)
	_, appID := f.appWithMethods(t, "rrm-validate", auth.MFAMethodTOTP)
	role := f.appRole(t, &appID, "rrm")

	for name, methods := range map[string][]string{
		"empty list":             {},
		"unknown method":         {"sms"},
		"not allowed by the app": {auth.MFAMethodEmail},
		"partly outside the app": {auth.MFAMethodTOTP, auth.MFAMethodEmail},
	} {
		if _, err := f.totpSvc.SetAppMFARoleRuleSpecs(f.ctx, f.tenantID, appID,
			[]auth.MFARoleRuleSpec{{RoleID: role, AllowedMethods: methods}}, nil); !errors.Is(err, auth.ErrMFARoleRuleInvalidMethods) {
			t.Errorf("%s: error = %v, want ErrMFARoleRuleInvalidMethods", name, err)
		}
	}

	res := f.setRuleSpecs(t, appID, auth.MFARoleRuleSpec{RoleID: role, AllowedMethods: []string{auth.MFAMethodTOTP}})
	if !res.Changed() || len(res.New) != 1 || !slices.Equal(res.New[0].AllowedMethods, []string{auth.MFAMethodTOTP}) {
		t.Fatalf("write = %+v, want one rule restricted to totp", res)
	}
	// Same rule, methods back to the app's list (nil): a change.
	if res = f.setRuleSpecs(t, appID, auth.MFARoleRuleSpec{RoleID: role}); !res.Changed() || res.New[0].AllowedMethods != nil {
		t.Errorf("methods → nil = %+v, want a change to null", res)
	}
	// Re-sending it: no change.
	if res = f.setRuleSpecs(t, appID, auth.MFARoleRuleSpec{RoleID: role}); res.Changed() {
		t.Errorf("redundant write reported a change: %+v", res)
	}
}

// A covered user is held to the rule's methods: an enrolled email factor does
// not count when the rule wants TOTP, so the user must enrol TOTP.
func TestRoleRuleMethods_GateUsesNarrowedSet(t *testing.T) {
	f := newMFAFixture(t)
	app, appID := f.appWithMethods(t, "rrm-gate", auth.MFAMethodTOTP, auth.MFAMethodEmail)
	email := uniqueEmail("rrm-gate")
	userID := f.registerAppUser(t, app, email, "Password123!")
	f.enrollEmail(t, userID)
	role := f.appRole(t, &appID, "rrm-gate")
	f.grantRole(t, userID, role)

	// Unrestricted rule: the email factor is challenged.
	f.setRules(t, appID, role)
	res, err := f.appLogin(t, app, email, "Password123!")
	if err != nil || res.OTPChallenge == nil || !slices.Contains(res.OTPChallenge.Methods, auth.MFAMethodEmail) {
		t.Fatalf("unrestricted rule = %+v, %v; want an email OTP challenge", res, err)
	}

	f.setRuleSpecs(t, appID, auth.MFARoleRuleSpec{RoleID: role, AllowedMethods: []string{auth.MFAMethodTOTP}})
	res, err = f.appLogin(t, app, email, "Password123!")
	if err != nil || res.MFAEnrollment == nil || !slices.Equal(res.MFAEnrollment.AllowedMethods, []string{auth.MFAMethodTOTP}) {
		t.Fatalf("totp-only rule = %+v, %v; want forced TOTP enrolment", res, err)
	}

	// Enrolment guards and status follow the narrowed set.
	if err := f.emailSvc.BeginEnrollment(f.ctx, userID, f.tenantID, email); !errors.Is(err, auth.ErrMFAMethodNotAllowed) {
		t.Errorf("email enrolment under a totp-only rule = %v, want ErrMFAMethodNotAllowed", err)
	}
	st, err := f.authSvc.MyMFAStatus(f.ctx, userID, f.tenantID, nil)
	if err != nil {
		t.Fatalf("MyMFAStatus: %v", err)
	}
	for _, m := range st.Methods {
		want := m.Method == auth.MFAMethodTOTP
		if m.Allowed != want {
			t.Errorf("status %s allowed = %v, want %v", m.Method, m.Allowed, want)
		}
	}
}

// Rules whose methods exclude each other — or a rule left with nothing after
// the application's list shrank — fail closed.
func TestRoleRuleMethods_EmptyIntersectionFailsClosed(t *testing.T) {
	f := newMFAFixture(t)
	app, appID := f.appWithMethods(t, "rrm-empty", auth.MFAMethodTOTP, auth.MFAMethodEmail)
	email := uniqueEmail("rrm-empty")
	userID := f.registerAppUser(t, app, email, "Password123!")
	totpRole := f.appRole(t, &appID, "rrm-totp")
	emailRole := f.appRole(t, &appID, "rrm-email")
	f.grantRole(t, userID, totpRole)
	f.grantRole(t, userID, emailRole)

	f.setRuleSpecs(t, appID,
		auth.MFARoleRuleSpec{RoleID: totpRole, AllowedMethods: []string{auth.MFAMethodTOTP}},
		auth.MFARoleRuleSpec{RoleID: emailRole, AllowedMethods: []string{auth.MFAMethodEmail}})
	if _, err := f.appLogin(t, app, email, "Password123!"); !errors.Is(err, auth.ErrAppMFAUnavailable) {
		t.Fatalf("exclusive rules: error = %v, want ErrAppMFAUnavailable", err)
	}

	// One email-only rule, then the application stops allowing email.
	f.setRuleSpecs(t, appID, auth.MFARoleRuleSpec{RoleID: emailRole, AllowedMethods: []string{auth.MFAMethodEmail}})
	if err := f.totpSvc.SetAppMFAPolicy(f.ctx, f.tenantID, appID, auth.MFAModeOptional, []string{auth.MFAMethodTOTP}, nil); err != nil {
		t.Fatalf("shrink app methods: %v", err)
	}
	if _, err := f.appLogin(t, app, email, "Password123!"); !errors.Is(err, auth.ErrAppMFAUnavailable) {
		t.Fatalf("shrunk app list: error = %v, want ErrAppMFAUnavailable", err)
	}
}

// The last-factor guard counts only factors the narrowed set permits.
func TestRoleRuleMethods_LastFactorGuard(t *testing.T) {
	f := newMFAFixture(t)
	app, appID := f.appWithMethods(t, "rrm-guard", auth.MFAMethodTOTP, auth.MFAMethodEmail)
	email := uniqueEmail("rrm-guard")
	userID := f.registerAppUser(t, app, email, "Password123!")
	secret := f.enrollAndActivate(t, userID, email)
	f.enrollEmail(t, userID)
	role := f.appRole(t, &appID, "rrm-guard")
	f.grantRole(t, userID, role)
	f.setRuleSpecs(t, appID, auth.MFARoleRuleSpec{RoleID: role, AllowedMethods: []string{auth.MFAMethodTOTP}})

	// Email is still active, but cannot satisfy the rule: TOTP is the last
	// factor that counts.
	if err := f.totpSvc.DisableUser(f.ctx, userID, f.tenantID, codeFor(t, secret)); !errors.Is(err, auth.ErrMFARequiredByPolicy) {
		t.Fatalf("DisableUser = %v, want ErrMFARequiredByPolicy", err)
	}
}
