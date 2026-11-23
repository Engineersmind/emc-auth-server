package auth_test

import (
	"errors"
	"testing"

	"github.com/engineersmind/emc-auth-server/internal/audit"
	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

func (f *pwFixture) adminSvc() *auth.PasswordlessAdminService {
	return auth.NewPasswordlessAdminService(f.pool, f.policy)
}

func (f *pwFixture) seedAudit(t *testing.T, appID, userID int64, action, method, status string) {
	t.Helper()
	if _, err := f.pool.Exec(f.ctx, `
		INSERT INTO audit_logs (tenant_id, application_id, user_id, action, auth_method, status)
		VALUES ($1, $2, NULLIF($3, 0), $4, $5, $6)`, f.tenantID, appID, userID, action, method, status); err != nil {
		t.Fatalf("seed audit: %v", err)
	}
}

// The impact preview counts who is affected and flags a switch that would strand
// users, which the switch guard then refuses unless overridden.
func TestPasswordlessAdmin_ImpactAndSwitchGuard(t *testing.T) {
	f := newPWFixture(t)
	app, appID := f.createApp(t, "adm-impact")
	f.enable(t, appID, true) // both: codes on, passwords on

	withPw := f.registerAppUser(t, app, uniqueEmail("adm-pw"), "Password123!")
	noPw := uniqueEmail("adm-nopw")
	noPwID := f.registerAppUser(t, app, noPw, "Password123!")
	if _, err := f.pool.Exec(f.ctx, `DELETE FROM user_credentials WHERE user_id = $1`, noPwID); err != nil {
		t.Fatal(err)
	}
	f.seedAudit(t, appID, withPw, audit.ActionAuthLogin, audit.AuthMethodPassword, "success")
	f.seedAudit(t, appID, withPw, audit.ActionAuthLogin, audit.AuthMethodPassword, "success")

	svc := f.adminSvc()

	// Closing the password flow: risky, no override needed (passwords are kept).
	im, err := svc.Impact(f.ctx, f.tenantID, appID, auth.PasswordlessPolicyRow{
		EmailOTPEnabled: ref(true), PasswordEnabled: ref(false), SignupEnabled: ref(true),
	})
	if err != nil {
		t.Fatalf("Impact: %v", err)
	}
	if im.ModeBefore != auth.PasswordlessModeBoth || im.ModeAfter != auth.PasswordlessModeOnly {
		t.Errorf("modes = %s -> %s, want both -> passwordless_only", im.ModeBefore, im.ModeAfter)
	}
	if im.UsersWithPassword != 1 || im.UsersWithoutPassword != 1 || im.ActiveUsers != 2 {
		t.Errorf("counts = %+v, want 1 with and 1 without a password, 2 active", im)
	}
	if im.PasswordSignIns7d != 2 || im.PasswordSignInUsers7d != 1 {
		t.Errorf("password sign-ins 7d = %d by %d users, want 2 by 1", im.PasswordSignIns7d, im.PasswordSignInUsers7d)
	}
	if !im.Risky {
		t.Error("closing the password flow must be flagged risky (typed confirmation)")
	}
	if im.RequiresOverride {
		t.Error("closing the password flow must not require the no-password override")
	}

	// Switching to password only would strand the user without a password.
	back := auth.PasswordlessPolicyRow{EmailOTPEnabled: ref(false), PasswordEnabled: ref(true)}
	im, err = svc.Impact(f.ctx, f.tenantID, appID, back)
	if err != nil || !im.RequiresOverride {
		t.Fatalf("password-only impact = %+v, %v; want requires_override", im, err)
	}
	if err := svc.SwitchGuard(f.ctx, f.tenantID, appID, back, false); !errors.Is(err, auth.ErrPasswordlessNoPasswordUsers) {
		t.Errorf("guard without override = %v, want ErrPasswordlessNoPasswordUsers", err)
	}
	if err := svc.SwitchGuard(f.ctx, f.tenantID, appID, back, true); err != nil {
		t.Errorf("guard with override = %v, want nil", err)
	}

	// A proposal that leaves no first factor is shown as a warning, not an error.
	im, err = svc.Impact(f.ctx, f.tenantID, appID, auth.PasswordlessPolicyRow{
		EmailOTPEnabled: ref(false), PasswordEnabled: ref(false),
	})
	if err != nil || len(im.Warnings) == 0 {
		t.Errorf("no-first-factor impact = %+v, %v; want a warning", im, err)
	}
}

func TestPasswordlessAdmin_StatsCountTheAuditLog(t *testing.T) {
	f := newPWFixture(t)
	_, appID := f.createApp(t, "adm-stats")
	uid := int64(0)
	for _, a := range []struct{ action, method, status string }{
		{audit.ActionAuthPasswordlessStarted, audit.AuthMethodEmailOTP, "success"},
		{audit.ActionAuthPasswordlessStarted, audit.AuthMethodEmailOTP, "success"},
		{audit.ActionAuthPasswordlessThrottled, audit.AuthMethodEmailOTP, "success"},
		{audit.ActionAuthLogin, audit.AuthMethodEmailOTP, "success"},
		{audit.ActionAuthLoginFailed, audit.AuthMethodEmailOTP, "failure"},
		{audit.ActionUserCreatedPasswordless, audit.AuthMethodEmailOTP, "success"},
	} {
		f.seedAudit(t, appID, uid, a.action, a.method, a.status)
	}
	st, err := f.adminSvc().Stats(f.ctx, f.tenantID, appID, "24h")
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if st.CodesRequested != 2 || st.CodesThrottled != 1 || st.SignInsByCode != 1 || st.FailedVerifies != 1 || st.AccountsCreated != 1 {
		t.Errorf("stats = %+v", st)
	}
	if st.VerifySuccessRate != "50.0%" {
		t.Errorf("success rate = %q, want 50.0%%", st.VerifySuccessRate)
	}
}

func TestPasswordlessAdmin_UserAuthMethods(t *testing.T) {
	f := newPWFixture(t)
	app, appID := f.createApp(t, "adm-methods")
	f.enable(t, appID, false)
	email := uniqueEmail("adm-methods")
	id := f.registerAppUser(t, app, email, "Password123!")
	f.seedAudit(t, appID, id, audit.ActionAuthLogin, audit.AuthMethodPassword, "success")

	res, err := f.adminSvc().UserAuthMethods(f.ctx, f.tenantID, appID, id)
	if err != nil {
		t.Fatalf("UserAuthMethods: %v", err)
	}
	byName := map[string]auth.UserAuthMethod{}
	for _, m := range res.Methods {
		byName[m.Method] = m
	}
	if !byName["password"].Enabled || byName["password"].LastUsed == nil {
		t.Errorf("password method = %+v, want enabled with a last-used time", byName["password"])
	}
	if !byName["email_code"].Enabled {
		t.Errorf("email_code method = %+v, want enabled (the policy allows it)", byName["email_code"])
	}
	if byName["passkey"].Enabled {
		t.Error("passkey reported enabled for a user with none")
	}
	if res.Mode != auth.PasswordlessModeBoth {
		t.Errorf("mode = %q, want both", res.Mode)
	}
	// Another application's user is not visible through this application.
	_, otherApp := f.createApp(t, "adm-methods-other")
	if _, err := f.adminSvc().UserAuthMethods(f.ctx, f.tenantID, otherApp, id); err == nil {
		t.Error("a user was readable through an application it does not belong to")
	}
}

// Lost-mailbox recovery: the address moves, the new one is verified, every session
// ends, the old address is told, and a taken address is refused.
func TestPasswordlessAdmin_AdminChangeEmail(t *testing.T) {
	f := newPWFixture(t)
	app, appID := f.createApp(t, "adm-email")
	oldEmail, newEmail := uniqueEmail("adm-old"), uniqueEmail("adm-new")
	id := f.registerAppUser(t, app, oldEmail, "Password123!")
	session, err := f.appLogin(t, app, oldEmail, "Password123!")
	if err != nil || session.Token == nil {
		t.Fatalf("login: %+v, %v", session, err)
	}
	taken := uniqueEmail("adm-taken")
	f.registerAppUser(t, app, taken, "Password123!")

	chg := auth.NewEmailChangeService(f.pool, f.mail, "http://localhost:9090", testhelper.TestLogger())
	if _, err := chg.AdminChange(f.ctx, f.tenantID, &appID, id, taken); !errors.Is(err, auth.ErrEmailTaken) {
		t.Fatalf("change to a taken address = %v, want ErrEmailTaken", err)
	}
	res, err := chg.AdminChange(f.ctx, f.tenantID, &appID, id, newEmail)
	if err != nil || res.OldEmail != oldEmail {
		t.Fatalf("AdminChange = %+v, %v", res, err)
	}

	var email string
	var verified bool
	if err := f.pool.QueryRow(f.ctx, `SELECT email, email_verified FROM users WHERE id = $1`, id).Scan(&email, &verified); err != nil {
		t.Fatal(err)
	}
	if email != newEmail || !verified {
		t.Errorf("user = %q verified %v, want %q verified", email, verified, newEmail)
	}
	if _, err := f.authSvc.Refresh(f.ctx, session.Token.RefreshToken); err == nil {
		t.Error("a session survived the email change")
	}
	if len(f.mail.emailChanges) == 0 || f.mail.emailChanges[len(f.mail.emailChanges)-1].To != oldEmail {
		t.Error("the previous address was not told about the change")
	}
	if _, err := chg.AdminChange(f.ctx, f.tenantID, &appID, id, "not-an-email"); !errors.Is(err, auth.ErrInvalidEmailChange) {
		t.Errorf("invalid address = %v, want ErrInvalidEmailChange", err)
	}
}

func TestPasswordlessAdmin_MarkVerifiedAndUserLookups(t *testing.T) {
	f := newPWFixture(t)
	app, appID := f.createApp(t, "adm-verify")
	email := uniqueEmail("adm-verify")
	id := f.registerAppUser(t, app, email, "Password123!")
	svc := f.adminSvc()

	changed, err := svc.MarkEmailVerified(f.ctx, f.tenantID, appID, id)
	if err != nil || !changed {
		t.Fatalf("first MarkEmailVerified = %v, %v; want a change", changed, err)
	}
	if changed, _ = svc.MarkEmailVerified(f.ctx, f.tenantID, appID, id); changed {
		t.Error("a second MarkEmailVerified reported a change")
	}
	if got, err := svc.UserEmail(f.ctx, f.tenantID, appID, id); err != nil || got != email {
		t.Errorf("UserEmail = %q, %v", got, err)
	}
	if got, err := svc.UserApplication(f.ctx, f.tenantID, id); err != nil || got != appID {
		t.Errorf("UserApplication = %d, %v; want %d", got, err, appID)
	}
}
