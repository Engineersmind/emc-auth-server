package auth_test

import (
	"errors"
	"net/url"
	"testing"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// Mode switching (passwordless plan sections 4.9 and 4.11): password only
// (default), both, and passwordless only. Moving between them never changes or
// deletes a stored password; passwordless only closes the password flow.

func (f *pwFixture) resetSvc(t *testing.T) *auth.ResetService {
	t.Helper()
	return auth.NewResetService(f.pool, f.mail, "http://localhost:8080", testhelper.TestLogger()).
		WithPasswordless(f.policy)
}

func (f *pwFixture) passwordHash(t *testing.T, userID int64) string {
	t.Helper()
	var h string
	if err := f.pool.QueryRow(f.ctx, `SELECT password_hash FROM user_credentials WHERE user_id = $1`, userID).Scan(&h); err != nil {
		t.Fatalf("read password hash: %v", err)
	}
	return h
}

func (f *pwFixture) setPasswordEnabled(t *testing.T, appID int64, enabled bool) {
	t.Helper()
	f.setPolicy(t, appID, func(r *auth.PasswordlessPolicyRow) {
		r.EmailOTPEnabled = ref(true)
		r.PasswordEnabled = ref(enabled)
	})
}

// With no policy, or with codes enabled alongside passwords ("both"), password
// login behaves exactly as it always has.
func TestModes_PasswordStillWorksByDefaultAndInBoth(t *testing.T) {
	f := newPWFixture(t)
	app, appID := f.createApp(t, "mode-both")
	email := uniqueEmail("mode-both")
	f.registerAppUser(t, app, email, "Password123!")

	if res, err := f.appLogin(t, app, email, "Password123!"); err != nil || res.Token == nil {
		t.Fatalf("login with no policy = %+v, %v", res, err)
	}
	f.setPasswordEnabled(t, appID, true) // both
	if res, err := f.appLogin(t, app, email, "Password123!"); err != nil || res.Token == nil {
		t.Fatalf("login in both mode = %+v, %v", res, err)
	}
	// And the code path works for the same user.
	chID, code := f.startAndCode(t, app, email)
	if res, _, err := f.verify(app, chID, code); err != nil || res.Token == nil {
		t.Fatalf("code sign-in in both mode = %+v, %v", res, err)
	}
}

// Closing the password flow refuses password endpoints before any lookup, keeps
// the hashes byte-identical, does not count toward lockout, and is reversible.
func TestModes_PasswordlessOnlyClosesThePasswordFlowAndIsReversible(t *testing.T) {
	f := newPWFixture(t)
	app, appID := f.createApp(t, "mode-only")
	email := uniqueEmail("mode-only")
	id := f.registerAppUser(t, app, email, "Password123!")
	hashBefore := f.passwordHash(t, id)

	f.setPasswordEnabled(t, appID, false) // passwordless only

	// Login: refused even with the CORRECT password, and with a wrong one.
	for _, pw := range []string{"Password123!", "wrong-password-1"} {
		if _, err := f.appLogin(t, app, email, pw); !errors.Is(err, auth.ErrPasswordAuthDisabled) {
			t.Fatalf("login (%q) = %v, want ErrPasswordAuthDisabled", pw, err)
		}
	}
	// Not counted toward lockout: many refused attempts leave the counter at 0.
	for i := 0; i < 12; i++ {
		f.appLogin(t, app, email, "wrong-password-1") //nolint:errcheck
	}
	var failed int
	var active bool
	if err := f.pool.QueryRow(f.ctx, `SELECT failed_login_attempts, is_active FROM users WHERE id = $1`, id).Scan(&failed, &active); err != nil {
		t.Fatal(err)
	}
	if failed != 0 || !active {
		t.Errorf("failed_login_attempts = %d, is_active = %v; refused attempts must not count toward lockout", failed, active)
	}

	// Register is closed and creates nothing.
	_, err := f.authSvc.Register(f.ctx, auth.RegisterInput{
		ClientID: app.ClientID, ClientSecret: app.ClientSecret,
		Email: uniqueEmail("mode-reg"), Password: "Password123!",
	})
	if !errors.Is(err, auth.ErrPasswordAuthDisabled) {
		t.Errorf("register = %v, want ErrPasswordAuthDisabled", err)
	}

	// Forgot-password is closed for users.
	if err := f.resetSvc(t).ForgotPassword(f.ctx, f.tenantID, &appID, email); !errors.Is(err, auth.ErrPasswordAuthDisabled) {
		t.Errorf("forgot-password = %v, want ErrPasswordAuthDisabled", err)
	}

	// The code flow is the way in, and the stored hash was never touched.
	chID, code := f.startAndCode(t, app, email)
	if res, _, err := f.verify(app, chID, code); err != nil || res.Token == nil {
		t.Fatalf("code sign-in in passwordless-only mode = %+v, %v", res, err)
	}
	if got := f.passwordHash(t, id); got != hashBefore {
		t.Error("the stored password hash changed while the password flow was closed")
	}

	// Reversible: re-enabling passwords makes the stored password work again.
	f.setPasswordEnabled(t, appID, true)
	if res, err := f.appLogin(t, app, email, "Password123!"); err != nil || res.Token == nil {
		t.Errorf("login after switching back = %+v, %v; want the stored password to work again", res, err)
	}
	if got := f.passwordHash(t, id); got != hashBefore {
		t.Error("the stored password hash changed after a round trip")
	}
}

// A reset link issued before the flow was closed stops working when redeemed,
// and is left unspent so it works again if the flow is reopened.
func TestModes_ResetLinkIssuedBeforeClosureIsRefused(t *testing.T) {
	f := newPWFixture(t)
	app, appID := f.createApp(t, "mode-reset")
	email := uniqueEmail("mode-reset")
	id := f.registerAppUser(t, app, email, "Password123!")
	hashBefore := f.passwordHash(t, id)
	f.setPasswordEnabled(t, appID, true)

	rs := f.resetSvc(t)
	if err := rs.ForgotPassword(f.ctx, f.tenantID, &appID, email); err != nil {
		t.Fatalf("forgot-password while open: %v", err)
	}
	if len(f.mail.resets) == 0 {
		t.Fatal("no reset email was captured")
	}
	u, err := url.Parse(f.mail.resets[len(f.mail.resets)-1].ResetLink)
	if err != nil {
		t.Fatal(err)
	}
	token := u.Query().Get("token")
	if token == "" {
		t.Fatalf("no token in reset link %q", u)
	}

	f.setPasswordEnabled(t, appID, false)
	err = rs.ResetPassword(f.ctx, auth.ResetPasswordInput{RawToken: token, NewPassword: "Another-Pass-1!"})
	if !errors.Is(err, auth.ErrPasswordAuthDisabled) {
		t.Fatalf("redeem while closed = %v, want ErrPasswordAuthDisabled", err)
	}
	if got := f.passwordHash(t, id); got != hashBefore {
		t.Error("a refused reset changed the stored hash")
	}

	f.setPasswordEnabled(t, appID, true)
	if err := rs.ResetPassword(f.ctx, auth.ResetPasswordInput{RawToken: token, NewPassword: "Another-Pass-1!"}); err != nil {
		t.Errorf("redeem after reopening = %v, want the unspent token to work", err)
	}
}

// Sessions that exist when the password flow closes keep working: a refresh does
// not depend on how the user signed in.
func TestModes_ExistingSessionsSurviveClosure(t *testing.T) {
	f := newPWFixture(t)
	app, appID := f.createApp(t, "mode-session")
	email := uniqueEmail("mode-session")
	f.registerAppUser(t, app, email, "Password123!")
	res, err := f.appLogin(t, app, email, "Password123!")
	if err != nil || res.Token == nil {
		t.Fatalf("login: %+v, %v", res, err)
	}

	f.setPasswordEnabled(t, appID, false)
	if _, err := f.authSvc.Refresh(f.ctx, res.Token.RefreshToken); err != nil {
		t.Errorf("refresh after closing the password flow = %v, want success", err)
	}
}

// The passwordless feature switched off (service not wired) means password
// endpoints never consult the policy, whatever the database says.
func TestModes_FeatureOffIgnoresPolicy(t *testing.T) {
	f := newMFAFixture(t) // no WithPasswordless
	app, appID := f.createApp(t, "mode-off")
	policy := auth.NewPasswordlessPolicyService(f.pool, testhelper.TestLogger())
	sc := auth.PasswordlessScope{TenantID: &f.tenantID, ApplicationID: &appID}
	if _, err := policy.Put(f.ctx, sc, auth.PasswordlessWriteInput{Row: auth.PasswordlessPolicyRow{
		EmailOTPEnabled: ref(true), PasswordEnabled: ref(false),
	}}); err != nil {
		t.Fatal(err)
	}
	email := uniqueEmail("mode-off")
	f.registerAppUser(t, app, email, "Password123!")
	if res, err := f.appLogin(t, app, email, "Password123!"); err != nil || res.Token == nil {
		t.Errorf("login with the feature off = %+v, %v; the policy must be ignored", res, err)
	}
}
