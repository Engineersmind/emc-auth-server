package auth_test

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// ---------------------------------------------------------------------------
// Role-based MFA rules (#195, stage 2 of #189)
// ---------------------------------------------------------------------------

// appRole creates a live role scoped to the application (appID nil = a
// tenant-level role) and returns its id.
func (f *mfaFixture) appRole(t *testing.T, appID *int64, name string) int64 {
	t.Helper()
	var id int64
	if err := f.pool.QueryRow(f.ctx, `
		INSERT INTO roles (tenant_id, application_id, name, is_system, created_at)
		VALUES ($1, $2, $3, false, NOW()) RETURNING id
	`, f.tenantID, appID, fmt.Sprintf("%s-%d", name, time.Now().UnixNano())).Scan(&id); err != nil {
		t.Fatalf("insert role %s: %v", name, err)
	}
	return id
}

// grantRole gives the user the role as an ADDITIONAL grant (user_roles only,
// not the primary users.role_id).
func (f *mfaFixture) grantRole(t *testing.T, userID, roleID int64) {
	t.Helper()
	if _, err := f.pool.Exec(f.ctx,
		`INSERT INTO user_roles (user_id, role_id, tenant_id) VALUES ($1, $2, $3)`,
		userID, roleID, f.tenantID); err != nil {
		t.Fatalf("grant role: %v", err)
	}
}

// setPrimaryRole sets users.role_id alone, with no user_roles row, so the test
// proves the primary column is read on its own.
func (f *mfaFixture) setPrimaryRole(t *testing.T, userID, roleID int64) {
	t.Helper()
	if _, err := f.pool.Exec(f.ctx, `DELETE FROM user_roles WHERE user_id = $1`, userID); err != nil {
		t.Fatalf("clear user_roles: %v", err)
	}
	if _, err := f.pool.Exec(f.ctx, `UPDATE users SET role_id = $2 WHERE id = $1`, userID, roleID); err != nil {
		t.Fatalf("set primary role: %v", err)
	}
}

func (f *mfaFixture) setRules(t *testing.T, appID int64, roleIDs ...int64) auth.MFARoleRulesUpdate {
	t.Helper()
	res, err := f.totpSvc.SetAppMFARoleRules(f.ctx, f.tenantID, appID, roleIDs, nil)
	if err != nil {
		t.Fatalf("SetAppMFARoleRules(%v): %v", roleIDs, err)
	}
	return res
}

func TestMFARoleRules_WriteValidation(t *testing.T) {
	f := newMFAFixture(t)
	_, appID := f.createApp(t, "rr-validate")
	_, otherAppID := f.createApp(t, "rr-validate-other")
	own := f.appRole(t, &appID, "own")
	foreign := f.appRole(t, &otherAppID, "foreign")
	tenantLevel := f.appRole(t, nil, "tenant")
	deleted := f.appRole(t, &appID, "deleted")
	if _, err := f.pool.Exec(f.ctx, `UPDATE roles SET deleted_at = NOW() WHERE id = $1`, deleted); err != nil {
		t.Fatalf("soft-delete role: %v", err)
	}

	for name, id := range map[string]int64{"another application's role": foreign, "tenant-level role": tenantLevel, "deleted role": deleted, "no such role": 987654321} {
		if _, err := f.totpSvc.SetAppMFARoleRules(f.ctx, f.tenantID, appID, []int64{own, id}, nil); !errors.Is(err, auth.ErrMFARoleRuleInvalidRole) {
			t.Errorf("%s: error = %v, want ErrMFARoleRuleInvalidRole", name, err)
		}
	}
	if rules, _ := f.totpSvc.ListAppMFARoleRules(f.ctx, f.tenantID, appID); len(rules) != 0 {
		t.Fatalf("refused writes left rules behind: %+v", rules)
	}

	res := f.setRules(t, appID, own, own) // duplicates collapse
	if !res.Changed() || len(res.New) != 1 || len(res.Old) != 0 {
		t.Fatalf("first write = %+v, want [] → [own]", res)
	}
	if res = f.setRules(t, appID, own); res.Changed() {
		t.Errorf("redundant write reported a change: %+v", res)
	}

	// Another tenant cannot touch this application's rules.
	var other int64
	if err := f.pool.QueryRow(f.ctx,
		`INSERT INTO tenants (name, slug, jwt_secret) VALUES ($1, $1, 'secret') RETURNING id`,
		fmt.Sprintf("rr-other-%d", time.Now().UnixNano())).Scan(&other); err != nil {
		t.Fatalf("create other tenant: %v", err)
	}
	if _, err := f.totpSvc.SetAppMFARoleRules(f.ctx, other, appID, nil, nil); !errors.Is(err, auth.ErrAppNotFound) {
		t.Errorf("cross-tenant write error = %v, want ErrAppNotFound", err)
	}

	// Too many.
	many := make([]int64, auth.MaxMFARoleRules+1)
	for i := range many {
		many[i] = int64(i + 1)
	}
	if _, err := f.totpSvc.SetAppMFARoleRules(f.ctx, f.tenantID, appID, many, nil); !errors.Is(err, auth.ErrTooManyMFARoleRules) {
		t.Errorf("oversized list error = %v, want ErrTooManyMFARoleRules", err)
	}
}

// Writing a rule is refused while the switch is off or the mode is disabled;
// clearing is allowed in any state.
func TestMFARoleRules_RefusedWhileInactive(t *testing.T) {
	f := newMFAFixture(t)
	_, appID := f.createApp(t, "rr-inactive")
	role := f.appRole(t, &appID, "inactive")
	f.setRules(t, appID, role)

	if _, err := f.totpSvc.SetAppMFAEnabled(f.ctx, f.tenantID, appID, false, nil); err != nil {
		t.Fatalf("SetAppMFAEnabled(false): %v", err)
	}
	if _, err := f.totpSvc.SetAppMFARoleRules(f.ctx, f.tenantID, appID, []int64{role}, nil); !errors.Is(err, auth.ErrMFARoleRulesInactive) {
		t.Errorf("switch off: error = %v, want ErrMFARoleRulesInactive", err)
	}
	if _, err := f.totpSvc.SetAppMFAEnabled(f.ctx, f.tenantID, appID, true, nil); err != nil {
		t.Fatalf("SetAppMFAEnabled(true): %v", err)
	}
	if err := f.totpSvc.SetAppMFAPolicy(f.ctx, f.tenantID, appID, auth.MFAModeDisabled, nil, nil); err != nil {
		t.Fatalf("SetAppMFAPolicy(disabled): %v", err)
	}
	if _, err := f.totpSvc.SetAppMFARoleRules(f.ctx, f.tenantID, appID, []int64{role}, nil); !errors.Is(err, auth.ErrMFARoleRulesInactive) {
		t.Errorf("mode disabled: error = %v, want ErrMFARoleRulesInactive", err)
	}
	res := f.setRules(t, appID) // clear is fine
	if len(res.New) != 0 || len(res.Old) != 1 {
		t.Errorf("clear while inactive = %+v, want [role] → []", res)
	}
}

// A holder of a listed role — via user_roles or via the primary role — is
// treated as 'required' on an 'optional' app; others are not. Rules stop
// applying with the switch off or the mode disabled.
func TestMFARoleRules_LoginEnforcement(t *testing.T) {
	f := newMFAFixture(t)
	app, appID := f.createApp(t, "rr-login")
	covered := f.appRole(t, &appID, "finance")
	uncovered := f.appRole(t, &appID, "viewer")
	f.setRules(t, appID, covered)

	grantEmail := uniqueEmail("rr-grant")
	grantUser := f.registerAppUser(t, app, grantEmail, "Password123!")
	f.grantRole(t, grantUser, covered)

	primaryEmail := uniqueEmail("rr-primary")
	primaryUser := f.registerAppUser(t, app, primaryEmail, "Password123!")
	f.setPrimaryRole(t, primaryUser, covered)

	plainEmail := uniqueEmail("rr-plain")
	plainUser := f.registerAppUser(t, app, plainEmail, "Password123!")
	f.grantRole(t, plainUser, uncovered)

	for name, email := range map[string]string{"additional grant": grantEmail, "primary role": primaryEmail} {
		res, err := f.appLogin(t, app, email, "Password123!")
		if err != nil || res.MFAEnrollment == nil || res.Token != nil {
			t.Errorf("%s: Login = %+v, %v; want forced enrolment", name, res, err)
		}
	}
	res, err := f.appLogin(t, app, plainEmail, "Password123!")
	if err != nil || res.Token == nil {
		t.Errorf("uncovered user: Login = %+v, %v; want tokens", res, err)
	}

	// Mode disabled: rules no longer apply.
	if err := f.totpSvc.SetAppMFAPolicy(f.ctx, f.tenantID, appID, auth.MFAModeDisabled, nil, nil); err != nil {
		t.Fatalf("SetAppMFAPolicy(disabled): %v", err)
	}
	if res, err = f.appLogin(t, app, grantEmail, "Password123!"); err != nil || res.Token == nil {
		t.Errorf("mode disabled: Login = %+v, %v; want tokens", res, err)
	}
	// Optional again, switch off: rules no longer apply.
	if err := f.totpSvc.SetAppMFAPolicy(f.ctx, f.tenantID, appID, auth.MFAModeOptional, nil, nil); err != nil {
		t.Fatalf("SetAppMFAPolicy(optional): %v", err)
	}
	if _, err := f.totpSvc.SetAppMFAEnabled(f.ctx, f.tenantID, appID, false, nil); err != nil {
		t.Fatalf("SetAppMFAEnabled(false): %v", err)
	}
	if res, err = f.appLogin(t, app, grantEmail, "Password123!"); err != nil || res.Token == nil {
		t.Errorf("switch off: Login = %+v, %v; want tokens", res, err)
	}
}

// Forced enrolment under a rule offers only allowed methods the deployment can
// run; none at all refuses the login.
func TestMFARoleRules_EnrolmentOffersRunnableMethodsOnly(t *testing.T) {
	f := newMFAFixture(t)
	app, appID := f.createApp(t, "rr-methods")
	if err := f.totpSvc.SetAppMFAPolicy(f.ctx, f.tenantID, appID, auth.MFAModeOptional,
		[]string{auth.MFAMethodTOTP, auth.MFAMethodEmail}, nil); err != nil {
		t.Fatalf("SetAppMFAPolicy: %v", err)
	}
	role := f.appRole(t, &appID, "ops")
	f.setRules(t, appID, role)
	email := uniqueEmail("rr-methods")
	userID := f.registerAppUser(t, app, email, "Password123!")
	f.grantRole(t, userID, role)

	// No email MFA service on this deployment.
	noEmail := f.bareAuthService().WithTOTP(f.totpSvc, testhelper.NewTestRedis(t))
	res, err := f.bareLogin(noEmail, app, email)
	if err != nil || res.MFAEnrollment == nil {
		t.Fatalf("Login = %+v, %v; want forced enrolment", res, err)
	}
	if got := res.MFAEnrollment.AllowedMethods; len(got) != 1 || got[0] != auth.MFAMethodTOTP {
		t.Errorf("offered methods = %v, want [totp] (email is not runnable here)", got)
	}

	// Email is the only allowed method and it cannot run: refused.
	if err := f.totpSvc.SetAppMFAPolicy(f.ctx, f.tenantID, appID, auth.MFAModeOptional,
		[]string{auth.MFAMethodEmail}, nil); err != nil {
		t.Fatalf("SetAppMFAPolicy(email only): %v", err)
	}
	res, err = f.bareLogin(noEmail, app, email)
	requireRefused(t, res, err, auth.ErrAppMFAUnavailable)
}

// A covered user cannot remove their last factor; once the rule is cleared
// they can. /auth/me/mfa reports the rule.
func TestMFARoleRules_LastFactorGuardAndStatus(t *testing.T) {
	f := newMFAFixture(t)
	app, appID := f.createApp(t, "rr-guard")
	role := f.appRole(t, &appID, "auditor")
	f.setRules(t, appID, role)
	email := uniqueEmail("rr-guard")
	userID := f.registerAppUser(t, app, email, "Password123!")
	f.grantRole(t, userID, role)
	secret := f.enrollAndActivate(t, userID, email)

	st, err := f.authSvc.MyMFAStatus(f.ctx, userID, f.tenantID, nil)
	if err != nil {
		t.Fatalf("MyMFAStatus: %v", err)
	}
	var roleName string
	if err := f.pool.QueryRow(f.ctx, `SELECT name FROM roles WHERE id = $1`, role).Scan(&roleName); err != nil {
		t.Fatalf("role name: %v", err)
	}
	if st.MFARequiredBy != "role:"+roleName {
		t.Errorf("mfa_required_by = %q, want %q", st.MFARequiredBy, "role:"+roleName)
	}

	if err := f.totpSvc.DisableUser(f.ctx, userID, f.tenantID, codeFor(t, secret)); !errors.Is(err, auth.ErrMFARequiredByPolicy) {
		t.Fatalf("DisableUser while covered: error = %v, want ErrMFARequiredByPolicy", err)
	}

	f.setRules(t, appID)
	if st, err = f.authSvc.MyMFAStatus(f.ctx, userID, f.tenantID, nil); err != nil || st.MFARequiredBy != "" {
		t.Errorf("after clearing: mfa_required_by = %q (err %v), want empty", st.MFARequiredBy, err)
	}
	if err := f.totpSvc.DisableUser(f.ctx, userID, f.tenantID, codeFor(t, secret)); err != nil {
		t.Fatalf("DisableUser after clearing the rule: %v", err)
	}
}

// Rules reach a passkey sign-in only through federated_mfa = enforce.
func TestMFARoleRules_PasskeyOnlyUnderEnforce(t *testing.T) {
	e := newFederatedPasskeyEnv(t)
	var roleID int64
	if err := e.f.pool.QueryRow(e.f.ctx, `
		INSERT INTO roles (tenant_id, application_id, name, is_system, created_at)
		VALUES ($1, $2, $3, false, NOW()) RETURNING id
	`, e.f.tenantID, e.appRowID, fmt.Sprintf("pk-rule-%d", time.Now().UnixNano())).Scan(&roleID); err != nil {
		t.Fatalf("insert role: %v", err)
	}
	if _, err := e.f.pool.Exec(e.f.ctx,
		`INSERT INTO user_roles (user_id, role_id, tenant_id) VALUES ($1, $2, $3)`,
		e.userID, roleID, e.f.tenantID); err != nil {
		t.Fatalf("grant role: %v", err)
	}
	if _, err := e.totpSvc.SetAppMFARoleRules(e.f.ctx, e.f.tenantID, e.appRowID, []int64{roleID}, nil); err != nil {
		t.Fatalf("SetAppMFARoleRules: %v", err)
	}

	res, err := e.login(t, false)
	if err != nil || res == nil || res.Token == nil {
		t.Fatalf("trust: login = %+v, %v; want tokens (rules do not reach trusted passkeys)", res, err)
	}
	e.setPolicy(t, auth.MFAModeOptional, auth.FederatedMFAEnforce)
	res, err = e.login(t, false)
	if err != nil || res == nil || res.MFAEnrollment == nil {
		t.Fatalf("enforce: login = %+v, %v; want forced enrolment from the role rule", res, err)
	}
}
