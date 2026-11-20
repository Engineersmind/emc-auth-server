package auth_test

import (
	"fmt"
	"testing"

	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// Parity: the email-code sign-in repeats the steps password Login performs after
// its credential check, in a separate function. This table runs BOTH through the
// same user states and asserts the same outcome class, which is what stops them
// drifting apart (passwordless plan section 4.6, decision D3). Login is not
// edited, so a change to its post-credential behaviour that is not mirrored in
// completePasswordlessLogin fails here.

type parityOutcome string

const (
	outTokens  parityOutcome = "tokens"
	outOTP     parityOutcome = "otp_challenge"
	outEnroll  parityOutcome = "mfa_enrollment"
	outRefused parityOutcome = "refused"
)

func outcomeOf(res *auth.LoginResult, err error) parityOutcome {
	switch {
	case err != nil || res == nil:
		return outRefused
	case res.OTPChallenge != nil:
		return outOTP
	case res.MFAEnrollment != nil:
		return outEnroll
	case res.Token != nil:
		return outTokens
	}
	return outRefused
}

func TestParity_PasswordLoginAndCodeLoginAgree(t *testing.T) {
	f := newPWFixture(t)

	cases := []struct {
		name  string
		setup func(t *testing.T, app *auth.AppResult, appID, userID int64, email string)
		roles []string
		want  parityOutcome
	}{
		{
			name:  "active user, no MFA",
			setup: func(*testing.T, *auth.AppResult, int64, int64, string) {},
			want:  outTokens,
		},
		{
			name: "deactivated user",
			setup: func(t *testing.T, _ *auth.AppResult, _, id int64, _ string) {
				if _, err := f.pool.Exec(f.ctx, `UPDATE users SET is_active = false WHERE id = $1`, id); err != nil {
					t.Fatal(err)
				}
			},
			want: outRefused,
		},
		{
			name: "MFA optional, user enrolled in TOTP",
			setup: func(t *testing.T, _ *auth.AppResult, appID, id int64, email string) {
				if err := f.totpSvc.SetAppMFAPolicy(f.ctx, f.tenantID, appID, auth.MFAModeOptional,
					[]string{auth.MFAMethodTOTP}, nil); err != nil {
					t.Fatal(err)
				}
				f.enrollAndActivate(t, id, email)
			},
			want: outOTP,
		},
		{
			name: "MFA required, user not enrolled",
			setup: func(t *testing.T, _ *auth.AppResult, appID, _ int64, _ string) {
				if err := f.totpSvc.SetAppMFAPolicy(f.ctx, f.tenantID, appID, auth.MFAModeRequired,
					[]string{auth.MFAMethodTOTP}, nil); err != nil {
					t.Fatal(err)
				}
			},
			want: outEnroll,
		},
		{
			name:  "session scoped to a role the user does not hold",
			setup: func(*testing.T, *auth.AppResult, int64, int64, string) {},
			roles: []string{"not-a-role-this-user-holds"},
			want:  outRefused,
		},
		{
			name: "session scoped to a role the user holds",
			setup: func(t *testing.T, _ *auth.AppResult, appID, id int64, _ string) {
				var roleID int64
				if err := f.pool.QueryRow(f.ctx, `
					INSERT INTO roles (tenant_id, application_id, name, is_default, is_system)
					VALUES ($1, $2, 'staff', false, false) RETURNING id`, f.tenantID, appID).Scan(&roleID); err != nil {
					t.Fatal(err)
				}
				if _, err := f.pool.Exec(f.ctx, `
					INSERT INTO user_roles (user_id, role_id, tenant_id) VALUES ($1, $2, $3)`, id, roleID, f.tenantID); err != nil {
					t.Fatal(err)
				}
			},
			roles: []string{"staff"},
			want:  outTokens,
		},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app, appID := f.createApp(t, fmt.Sprintf("parity-case-%d", i))
			f.setPolicy(t, appID, func(r *auth.PasswordlessPolicyRow) {
				r.EmailOTPEnabled = ref(true)
				r.PasswordEnabled = ref(true)
			})
			email := uniqueEmail("parity")
			id := f.registerAppUser(t, app, email, "Password123!")
			tc.setup(t, app, appID, id, email)

			// Password.
			pwRes, pwErr := f.authSvc.Login(f.ctx, auth.LoginInput{
				ClientID: app.ClientID, ClientSecret: app.ClientSecret,
				Email: email, Password: "Password123!", Roles: tc.roles,
			})
			// Code. For a deactivated user the challenge is a decoy, so there is no
			// real code to prove: that case is refused at start, which is the
			// outcome class being compared.
			var codeRes *auth.LoginResult
			var codeErr error
			before := f.mail.passwordlessCount()
			start, startMeta, err := f.start(t, app, email)
			if err != nil {
				t.Fatalf("start: %v", err)
			}
			if startMeta.Outcome != "sent" {
				// A decoy: nothing was mailed, so there is no real code to prove.
				codeRes, codeErr = nil, auth.ErrPasswordlessInvalidCode
			} else {
				code := f.mail.lastPasswordless(t, before).Code
				codeRes, _, codeErr = f.authSvc.PasswordlessVerify(f.ctx, auth.PasswordlessVerifyInput{
					ClientID: app.ClientID, ClientSecret: app.ClientSecret,
					ChallengeID: start.ChallengeID, Code: code, Roles: tc.roles,
				})
			}

			gotPW, gotCode := outcomeOf(pwRes, pwErr), outcomeOf(codeRes, codeErr)
			if gotPW != tc.want {
				t.Errorf("password login = %s, want %s (err %v)", gotPW, tc.want, pwErr)
			}
			if gotCode != tc.want {
				t.Errorf("code login = %s, want %s (err %v)", gotCode, tc.want, codeErr)
			}
			if gotPW != gotCode {
				t.Errorf("PARITY BROKEN: password login = %s, code login = %s", gotPW, gotCode)
			}
		})
	}
}
