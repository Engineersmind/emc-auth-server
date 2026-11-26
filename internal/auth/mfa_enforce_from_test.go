package auth_test

import (
	"errors"
	"testing"
	"time"

	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// ---------------------------------------------------------------------------
// enforce_from grace date for required-mode rollout (#198)
// ---------------------------------------------------------------------------

// setEnforceFrom writes the application's grace date (nil clears it).
func (f *mfaFixture) setEnforceFrom(t *testing.T, appID int64, at *time.Time) auth.AppMFAUpdateResult {
	t.Helper()
	res, err := f.totpSvc.UpdateAppMFASettings(f.ctx, f.tenantID, appID, auth.AppMFAUpdate{SetEnforceFrom: true, EnforceFrom: at}, nil)
	if err != nil {
		t.Fatalf("UpdateAppMFASettings(enforce_from=%v): %v", at, err)
	}
	return res
}

func (f *mfaFixture) requireMFA(t *testing.T, appID int64) {
	t.Helper()
	if err := f.totpSvc.SetAppMFAPolicy(f.ctx, f.tenantID, appID, auth.MFAModeRequired, nil, nil); err != nil {
		t.Fatalf("SetAppMFAPolicy(required): %v", err)
	}
}

func TestEnforceFrom_WriteReadAndClear(t *testing.T) {
	f := newMFAFixture(t)
	_, appID := f.createApp(t, "ef-crud")

	policy, err := f.totpSvc.GetAppMFAPolicy(f.ctx, f.tenantID, appID)
	if err != nil {
		t.Fatalf("GetAppMFAPolicy: %v", err)
	}
	if policy.EnforceFrom != nil {
		t.Fatalf("default enforce_from = %v, want nil", policy.EnforceFrom)
	}

	at := time.Now().Add(48 * time.Hour).Truncate(time.Second)
	res := f.setEnforceFrom(t, appID, &at)
	if !res.EnforceFromChanged() || res.PrevEnforceFrom != nil || res.NewEnforceFrom == nil || !res.NewEnforceFrom.Equal(at) {
		t.Fatalf("set result = %+v, want nil → %v", res, at)
	}
	if res = f.setEnforceFrom(t, appID, &at); res.EnforceFromChanged() {
		t.Errorf("same date reported as a change: %+v", res)
	}
	policy, _ = f.totpSvc.GetAppMFAPolicy(f.ctx, f.tenantID, appID)
	if policy.EnforceFrom == nil || !policy.EnforceFrom.Equal(at) {
		t.Errorf("stored enforce_from = %v, want %v", policy.EnforceFrom, at)
	}
	// Another field leaves it alone.
	f.requireMFA(t, appID)
	if policy, _ = f.totpSvc.GetAppMFAPolicy(f.ctx, f.tenantID, appID); policy.EnforceFrom == nil {
		t.Error("mode update cleared enforce_from")
	}
	if res = f.setEnforceFrom(t, appID, nil); !res.EnforceFromChanged() || res.NewEnforceFrom != nil {
		t.Errorf("clear result = %+v, want → nil", res)
	}
}

// Before enforce_from an unenrolled user signs in with tokens marked
// "enrolment recommended"; after it, enrolment is forced.
func TestEnforceFrom_GraceThenForcedEnrolment(t *testing.T) {
	f := newMFAFixture(t)
	app, appID := f.createApp(t, "ef-grace")
	email := uniqueEmail("ef-grace")
	f.registerAppUser(t, app, email, "Password123!")
	f.requireMFA(t, appID)

	future := time.Now().Add(72 * time.Hour).Truncate(time.Second)
	f.setEnforceFrom(t, appID, &future)
	res, err := f.appLogin(t, app, email, "Password123!")
	if err != nil {
		t.Fatalf("appLogin in grace: %v", err)
	}
	if res.Token == nil || !res.Token.MFAEnrollmentRecommended || res.Token.MFAEnforceFrom == nil || !res.Token.MFAEnforceFrom.Equal(future) {
		t.Fatalf("in grace = %+v, want tokens with mfa_enrollment_recommended and enforce_from=%v", res, future)
	}

	past := time.Now().Add(-time.Minute)
	f.setEnforceFrom(t, appID, &past)
	if res, err = f.appLogin(t, app, email, "Password123!"); err != nil || res.MFAEnrollment == nil {
		t.Fatalf("after enforce_from = %+v, %v; want forced enrolment", res, err)
	}

	// No grace date at all: forced enrolment, as before #198.
	f.setEnforceFrom(t, appID, nil)
	if res, err = f.appLogin(t, app, email, "Password123!"); err != nil || res.MFAEnrollment == nil {
		t.Fatalf("no enforce_from = %+v, %v; want forced enrolment", res, err)
	}
}

// The grace covers enrolment only: a user with a factor is challenged.
func TestEnforceFrom_EnrolledUserStillChallenged(t *testing.T) {
	f := newMFAFixture(t)
	app, appID := f.createApp(t, "ef-enrolled")
	email := uniqueEmail("ef-enrolled")
	userID := f.registerAppUser(t, app, email, "Password123!")
	f.enrollAndActivate(t, userID, email)
	f.requireMFA(t, appID)
	future := time.Now().Add(72 * time.Hour)
	f.setEnforceFrom(t, appID, &future)

	res, err := f.appLogin(t, app, email, "Password123!")
	if err != nil || res.OTPChallenge == nil {
		t.Fatalf("enrolled user in grace = %+v, %v; want OTP challenge", res, err)
	}
}

// A role rule's 'required' gets the same grace.
func TestEnforceFrom_RoleRuleGrace(t *testing.T) {
	f := newMFAFixture(t)
	app, appID := f.createApp(t, "ef-role")
	email := uniqueEmail("ef-role")
	userID := f.registerAppUser(t, app, email, "Password123!")
	role := f.appRole(t, &appID, "ef")
	f.grantRole(t, userID, role)
	f.setRules(t, appID, role)
	future := time.Now().Add(72 * time.Hour)
	f.setEnforceFrom(t, appID, &future)

	res, err := f.appLogin(t, app, email, "Password123!")
	if err != nil || res.Token == nil || !res.Token.MFAEnrollmentRecommended {
		t.Fatalf("rule-covered user in grace = %+v, %v; want recommended tokens", res, err)
	}
}

// Step-up at refresh (#197) respects the grace for unenrolled users.
func TestEnforceFrom_StepUpRespectsGrace(t *testing.T) {
	f := newMFAFixture(t)
	app, appID := f.createApp(t, "ef-stepup")
	email := uniqueEmail("ef-stepup")
	f.registerAppUser(t, app, email, "Password123!")
	tok := f.passwordSession(t, app, email)
	f.requireMFA(t, appID)
	f.setRefreshStepUp(t, appID, true)

	future := time.Now().Add(72 * time.Hour)
	f.setEnforceFrom(t, appID, &future)
	next, err := f.authSvc.Refresh(f.ctx, tok.RefreshToken)
	if err != nil {
		t.Fatalf("Refresh in grace: %v", err)
	}
	if next.MFAEnrollmentRecommended {
		t.Error("refresh response carries mfa_enrollment_recommended; it is a login-only hint")
	}

	past := time.Now().Add(-time.Minute)
	f.setEnforceFrom(t, appID, &past)
	if _, err := f.authSvc.Refresh(f.ctx, next.RefreshToken); !errors.Is(err, auth.ErrStepUpRequired) {
		t.Fatalf("Refresh after enforce_from = %v, want ErrStepUpRequired", err)
	}
}

// /auth/me/mfa reports the grace date.
func TestEnforceFrom_ReportedInStatus(t *testing.T) {
	f := newMFAFixture(t)
	app, appID := f.createApp(t, "ef-status")
	email := uniqueEmail("ef-status")
	userID := f.registerAppUser(t, app, email, "Password123!")
	f.requireMFA(t, appID)
	at := time.Now().Add(24 * time.Hour).Truncate(time.Second)
	f.setEnforceFrom(t, appID, &at)

	st, err := f.authSvc.MyMFAStatus(f.ctx, userID, f.tenantID, nil)
	if err != nil {
		t.Fatalf("MyMFAStatus: %v", err)
	}
	if st.EnforceFrom == nil || !st.EnforceFrom.Equal(at) {
		t.Errorf("status enforce_from = %v, want %v", st.EnforceFrom, at)
	}
}

// During a grace period, role rules that leave a covered user no allowed method
// refuse the refresh with ErrAppMFAUnavailable — as login refuses that user —
// instead of the grace exception keeping the session alive. Nothing is rotated:
// the same refresh token works once the rules no longer conflict (PR #247).
func TestEnforceFrom_StepUpEmptyMethodSetUnavailableInGrace(t *testing.T) {
	f := newMFAFixture(t)
	app, appID := f.appWithMethods(t, "ef-empty", auth.MFAMethodTOTP, auth.MFAMethodEmail)
	email := uniqueEmail("ef-empty")
	userID := f.registerAppUser(t, app, email, "Password123!")
	tok := f.passwordSession(t, app, email)

	totpRole := f.appRole(t, &appID, "ef-empty-totp")
	emailRole := f.appRole(t, &appID, "ef-empty-email")
	f.grantRole(t, userID, totpRole)
	f.grantRole(t, userID, emailRole)
	f.setRuleSpecs(t, appID,
		auth.MFARoleRuleSpec{RoleID: totpRole, AllowedMethods: []string{auth.MFAMethodTOTP}},
		auth.MFARoleRuleSpec{RoleID: emailRole, AllowedMethods: []string{auth.MFAMethodEmail}})
	f.setRefreshStepUp(t, appID, true)
	future := time.Now().Add(72 * time.Hour)
	f.setEnforceFrom(t, appID, &future)

	if _, err := f.appLogin(t, app, email, "Password123!"); !errors.Is(err, auth.ErrAppMFAUnavailable) {
		t.Fatalf("login = %v, want ErrAppMFAUnavailable", err)
	}
	if _, err := f.authSvc.Refresh(f.ctx, tok.RefreshToken); !errors.Is(err, auth.ErrAppMFAUnavailable) {
		t.Fatalf("Refresh in grace with no allowed method = %v, want ErrAppMFAUnavailable", err)
	}
	if _, _, err := f.authSvc.RefreshWithLock(f.ctx, tok.RefreshToken, nil); !errors.Is(err, auth.ErrAppMFAUnavailable) {
		t.Fatalf("RefreshWithLock in grace with no allowed method = %v, want ErrAppMFAUnavailable", err)
	}

	f.setRules(t, appID)
	if _, err := f.authSvc.Refresh(f.ctx, tok.RefreshToken); err != nil {
		t.Fatalf("Refresh after clearing the rules: %v; the refused refresh must not have rotated the token", err)
	}
}

// During a grace period, a session signed in by passwordless email code does
// not count an enrolled email factor as a usable second factor — the login
// gate's rule — so a user whose only factor is email keeps refreshing, while
// the same user's password session is stepped up (PR #247).
func TestEnforceFrom_StepUpExcludesEmailAfterEmailCodeSignIn(t *testing.T) {
	f := newMFAFixture(t)
	app, appID := f.appWithMethods(t, "ef-inbox", auth.MFAMethodTOTP, auth.MFAMethodEmail)
	email := uniqueEmail("ef-inbox")
	userID := f.registerAppUser(t, app, email, "Password123!")
	tok := f.passwordSession(t, app, email)
	f.enrollEmail(t, userID)
	f.requireMFA(t, appID)
	f.setRefreshStepUp(t, appID, true)
	future := time.Now().Add(72 * time.Hour)
	f.setEnforceFrom(t, appID, &future)

	f.setSessionAMR(t, tok.AccessToken, auth.AMRPassword)
	if _, err := f.authSvc.Refresh(f.ctx, tok.RefreshToken); !errors.Is(err, auth.ErrStepUpRequired) {
		t.Fatalf("password session with an email factor = %v, want ErrStepUpRequired", err)
	}

	f.setSessionAMR(t, tok.AccessToken, auth.AMREmailOTP)
	if _, err := f.authSvc.Refresh(f.ctx, tok.RefreshToken); err != nil {
		t.Fatalf("email-code session in grace = %v, want a refresh (email is the first factor, not a second)", err)
	}
}
