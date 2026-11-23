package auth_test

import (
	"strconv"
	"strings"
	"testing"

	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// Characterisation tests for the passwordless plan (docs/plans/passwordless-email-otp.md,
// section 0 and Phase 0, issue #203).
//
// They pin what the platform does TODAY, including behaviour the plan records as
// a known gap and deliberately does not fix. A failure here means live behaviour
// changed: either revert the change, or, if it is intended, say so in the PR and
// update the pin on purpose.
//
// Where today's behaviour is already pinned by an existing test, that test is the
// pin and is not duplicated here:
//
//	password login, lockout        lockout_test.go, login_timing_test.go
//	magic link happy path, scoping magic_link_test.go
//	MFA gate, TOTP, enrolment      mfa_test.go, mfa_policy_authoritative_test.go
//	email MFA                      email_mfa_test.go, email_sender_test.go
//	admin MFA                      admin_mfa_test.go
//	organization selection         internal/api/handlers/organizations_test.go
//	social login                   github_test.go, google_test.go, oauth_login_binding_test.go
//	hosted login page              internal/api/handlers/oauth_authorize_*_test.go
//
// This file adds the pins those do not cover: the mfaGate options variant, and
// gaps G1, G4 and "login for a user with no password" from plan section 2.

// activeEmailMFA enrols email as an active second factor for the user.
func activeEmailMFA(t *testing.T, f *mfaFixture, userID int64) {
	t.Helper()
	f.enrollEmail(t, userID)
}

// offeredMethods returns the second-factor methods a gate result offers, or nil
// when the gate lets the caller issue tokens directly.
func offeredMethods(res *auth.LoginResult) []string {
	if res == nil || res.OTPChallenge == nil {
		return nil
	}
	return res.OTPChallenge.Methods
}

// The zero value of the gate options is today's behaviour, through every path
// the gate has: no factor, email only, TOTP and email, required and unenrolled.
func TestCharacterisation_MFAGateZeroOptionsEqualsToday(t *testing.T) {
	f := newMFAFixture(t)
	app, appID := f.createApp(t, "char-gate-zero")
	appRow := strconv.FormatInt(appID, 10)
	if err := f.totpSvc.SetAppMFAPolicy(f.ctx, f.tenantID, appID, auth.MFAModeOptional,
		[]string{auth.MFAMethodTOTP, auth.MFAMethodEmail}, nil); err != nil {
		t.Fatalf("SetAppMFAPolicy: %v", err)
	}

	cases := []struct {
		name  string
		setup func(userID int64, email string)
	}{
		{"no factor", func(int64, string) {}},
		{"email only", func(id int64, _ string) { activeEmailMFA(t, f, id) }},
		{"totp and email", func(id int64, email string) {
			f.enrollAndActivate(t, id, email)
			activeEmailMFA(t, f, id)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			email := uniqueEmail("char-gate")
			id := f.registerAppUser(t, app, email, "Password123!")
			tc.setup(id, email)

			today, err := auth.ExportedMFAGate(f.ctx, f.authSvc, id, f.tenantID, appID, appRow, email)
			if err != nil {
				t.Fatalf("mfaGate: %v", err)
			}
			zero, err := auth.ExportedMFAGateZeroOptions(f.ctx, f.authSvc, id, f.tenantID, appID, appRow, email)
			if err != nil {
				t.Fatalf("mfaGateWith(zero): %v", err)
			}
			if (today == nil) != (zero == nil) {
				t.Fatalf("mfaGate = %+v, mfaGateWith(zero) = %+v: one is nil", today, zero)
			}
			if strings.Join(offeredMethods(today), ",") != strings.Join(offeredMethods(zero), ",") {
				t.Errorf("offered methods differ: mfaGate %v, zero options %v", offeredMethods(today), offeredMethods(zero))
			}
		})
	}

	t.Run("required and unenrolled", func(t *testing.T) {
		if err := f.totpSvc.SetAppMFAPolicy(f.ctx, f.tenantID, appID, auth.MFAModeRequired,
			[]string{auth.MFAMethodTOTP, auth.MFAMethodEmail}, nil); err != nil {
			t.Fatalf("SetAppMFAPolicy: %v", err)
		}
		email := uniqueEmail("char-gate-req")
		id := f.registerAppUser(t, app, email, "Password123!")
		today, err := auth.ExportedMFAGate(f.ctx, f.authSvc, id, f.tenantID, appID, appRow, email)
		if err != nil || today == nil || today.MFAEnrollment == nil {
			t.Fatalf("mfaGate = %+v, %v; want an enrolment challenge", today, err)
		}
		zero, err := auth.ExportedMFAGateZeroOptions(f.ctx, f.authSvc, id, f.tenantID, appID, appRow, email)
		if err != nil || zero == nil || zero.MFAEnrollment == nil {
			t.Fatalf("mfaGateWith(zero) = %+v, %v; want an enrolment challenge", zero, err)
		}
		if strings.Join(today.MFAEnrollment.AllowedMethods, ",") != strings.Join(zero.MFAEnrollment.AllowedMethods, ",") {
			t.Errorf("allowed methods differ: %v vs %v", today.MFAEnrollment.AllowedMethods, zero.MFAEnrollment.AllowedMethods)
		}
	})
}

// With inboxFirstFactor the email method is never offered as a second factor:
// TOTP still is, and a user whose only factor is email is not challenged with it.
func TestCharacterisation_MFAGateInboxFirstFactorDropsEmail(t *testing.T) {
	f := newMFAFixture(t)
	app, appID := f.createApp(t, "char-gate-inbox")
	appRow := strconv.FormatInt(appID, 10)
	if err := f.totpSvc.SetAppMFAPolicy(f.ctx, f.tenantID, appID, auth.MFAModeOptional,
		[]string{auth.MFAMethodTOTP, auth.MFAMethodEmail}, nil); err != nil {
		t.Fatalf("SetAppMFAPolicy: %v", err)
	}

	t.Run("email only is not challenged", func(t *testing.T) {
		email := uniqueEmail("char-inbox-email")
		id := f.registerAppUser(t, app, email, "Password123!")
		activeEmailMFA(t, f, id)
		before := f.mail.codeCount()

		res, err := auth.ExportedMFAGateInboxFirst(f.ctx, f.authSvc, id, f.tenantID, appID, appRow, email)
		if err != nil {
			t.Fatalf("mfaGateWith(inbox): %v", err)
		}
		if res != nil {
			t.Errorf("gate = %+v, want nil (tokens may be issued)", res)
		}
		if f.mail.codeCount() != before {
			t.Error("an email MFA code was sent after an inbox first factor")
		}
	})

	t.Run("totp is still offered, email is not", func(t *testing.T) {
		email := uniqueEmail("char-inbox-both")
		id := f.registerAppUser(t, app, email, "Password123!")
		f.enrollAndActivate(t, id, email)
		activeEmailMFA(t, f, id)
		before := f.mail.codeCount()

		res, err := auth.ExportedMFAGateInboxFirst(f.ctx, f.authSvc, id, f.tenantID, appID, appRow, email)
		if err != nil {
			t.Fatalf("mfaGateWith(inbox): %v", err)
		}
		got := offeredMethods(res)
		if len(got) != 1 || got[0] != auth.MFAMethodTOTP {
			t.Errorf("offered methods = %v, want [totp]", got)
		}
		if f.mail.codeCount() != before {
			t.Error("an email MFA code was sent after an inbox first factor")
		}
	})

	t.Run("required mode enrols without the email method", func(t *testing.T) {
		if err := f.totpSvc.SetAppMFAPolicy(f.ctx, f.tenantID, appID, auth.MFAModeRequired,
			[]string{auth.MFAMethodTOTP, auth.MFAMethodEmail}, nil); err != nil {
			t.Fatalf("SetAppMFAPolicy: %v", err)
		}
		email := uniqueEmail("char-inbox-req")
		id := f.registerAppUser(t, app, email, "Password123!")
		activeEmailMFA(t, f, id)

		res, err := auth.ExportedMFAGateInboxFirst(f.ctx, f.authSvc, id, f.tenantID, appID, appRow, email)
		if err != nil || res == nil || res.MFAEnrollment == nil {
			t.Fatalf("gate = %+v, %v; want an enrolment challenge", res, err)
		}
		got := res.MFAEnrollment.AllowedMethods
		if len(got) != 1 || got[0] != auth.MFAMethodTOTP {
			t.Errorf("allowed methods = %v, want [totp]", got)
		}
	})
}

// G4, pinned as it is today and NOT fixed by the passwordless plan: after a
// magic link, a user with email MFA is still offered email as the second factor.
func TestCharacterisation_MagicLinkStillOffersEmailMFA_G4(t *testing.T) {
	f := newMFAFixture(t)
	app, appID := f.createApp(t, "char-g4")
	f.enableMagicLink(t, appID)
	if err := f.totpSvc.SetAppMFAPolicy(f.ctx, f.tenantID, appID, auth.MFAModeOptional,
		[]string{auth.MFAMethodTOTP, auth.MFAMethodEmail}, nil); err != nil {
		t.Fatalf("SetAppMFAPolicy: %v", err)
	}
	email := uniqueEmail("char-g4")
	id := f.registerAppUser(t, app, email, "Password123!")
	activeEmailMFA(t, f, id)

	if err := f.authSvc.RequestMagicLink(f.ctx, app.ClientID, app.ClientSecret, email); err != nil {
		t.Fatalf("RequestMagicLink: %v", err)
	}
	res, err := f.authSvc.VerifyMagicLink(f.ctx, app.ClientID, app.ClientSecret, tokenFromLink(t, f.mail.lastLink(t).Link))
	if err != nil {
		t.Fatalf("VerifyMagicLink: %v", err)
	}
	got := offeredMethods(res)
	if len(got) != 1 || got[0] != auth.MFAMethodEmail {
		t.Errorf("offered methods after magic link = %v, want [email] (gap G4, unchanged)", got)
	}
}

// A user with no credential row (invited, imported, or created by social login)
// gets the same generic refusal on password login as a wrong password, with no
// hint that another method exists. The passwordless plan relies on this.
func TestCharacterisation_PasswordLoginWithoutCredentialIsGeneric(t *testing.T) {
	f := newMFAFixture(t)
	app, _ := f.createApp(t, "char-nocred")
	email := uniqueEmail("char-nocred")
	id := f.registerAppUser(t, app, email, "Password123!")

	_, wrongErr := f.appLogin(t, app, email, "Wrong-Password-1!")
	if wrongErr == nil {
		t.Fatal("login with a wrong password succeeded")
	}

	if _, err := f.pool.Exec(f.ctx, `DELETE FROM user_credentials WHERE user_id = $1`, id); err != nil {
		t.Fatalf("remove credential row: %v", err)
	}
	_, noCredErr := f.appLogin(t, app, email, "Password123!")
	if noCredErr == nil {
		t.Fatal("login for a user with no credential row succeeded")
	}
	if noCredErr.Error() != wrongErr.Error() {
		t.Errorf("no-credential error = %q, wrong-password error = %q; they must be identical", noCredErr, wrongErr)
	}
}
