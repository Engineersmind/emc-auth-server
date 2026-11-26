package auth_test

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// ---------------------------------------------------------------------------
// The application MFA gate fails closed (#193)
//
// Before #193 the gate returned "no challenge" whenever the deployment had no
// TOTP service or Redis, and read a factor-status error as "not enrolled". Both
// issued tokens to a user the application required a second factor of. Each
// test below pins one branch: refused when a challenge is due and cannot be
// run, unchanged when nothing is due.
// ---------------------------------------------------------------------------

// bareAuthService is an AuthService on the fixture's database with NO TOTP
// service, NO Redis and NO email MFA — a deployment that cannot run any second
// factor.
func (f *mfaFixture) bareAuthService() *auth.AuthService {
	return auth.NewAuthService(f.pool, f.jwtSvc, testhelper.TestLogger()).WithApplications(f.appSvc)
}

// bareLogin runs an application login through svc.
func (f *mfaFixture) bareLogin(svc *auth.AuthService, app *auth.AppResult, email string) (*auth.LoginResult, error) {
	return svc.Login(f.ctx, auth.LoginInput{
		ClientID: app.ClientID, ClientSecret: app.ClientSecret,
		Email: email, Password: "Password123!",
	})
}

// requireRefused asserts a login was refused with want and produced nothing a
// client could use.
func requireRefused(t *testing.T, res *auth.LoginResult, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
	if res != nil {
		t.Fatalf("result = %+v, want nil (no tokens, no challenge)", res)
	}
}

// closedPool returns a pool that has already been closed: every query on it
// fails. Used to make one service's reads error while the rest of the login
// path keeps a working database.
func closedPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set — skipping DB integration test")
	}
	p, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	p.Close()
	return p
}

// Mode 'required', deployment without TOTP/Redis: refused, not let through.
func TestAppMFAFailClosed_RequiredWithoutServicesRefused(t *testing.T) {
	f := newMFAFixture(t)
	app, appID := f.createApp(t, "fc-required")
	if err := f.totpSvc.SetAppMFAPolicy(f.ctx, f.tenantID, appID, auth.MFAModeRequired, nil, nil); err != nil {
		t.Fatalf("SetAppMFAPolicy(required): %v", err)
	}
	email := uniqueEmail("fc-required")
	f.registerAppUser(t, app, email, "Password123!")

	res, err := f.bareLogin(f.bareAuthService(), app, email)
	requireRefused(t, res, err, auth.ErrAppMFAUnavailable)
}

// An enrolled user on an 'optional' app, deployment without TOTP/Redis:
// refused. The user set a factor up; skipping it would be a silent bypass.
func TestAppMFAFailClosed_EnrolledUserWithoutServicesRefused(t *testing.T) {
	f := newMFAFixture(t)
	app, _ := f.createApp(t, "fc-enrolled")
	email := uniqueEmail("fc-enrolled")
	userID := f.registerAppUser(t, app, email, "Password123!")
	f.enrollAndActivate(t, userID, email)

	res, err := f.bareLogin(f.bareAuthService(), app, email)
	requireRefused(t, res, err, auth.ErrAppMFAUnavailable)
}

// Redis alone missing is enough to refuse: the challenge has nowhere to live.
func TestAppMFAFailClosed_NoRedisRefused(t *testing.T) {
	f := newMFAFixture(t)
	app, _ := f.createApp(t, "fc-noredis")
	email := uniqueEmail("fc-noredis")
	userID := f.registerAppUser(t, app, email, "Password123!")
	f.enrollAndActivate(t, userID, email)

	svc := f.bareAuthService().WithTOTP(f.totpSvc, nil)
	res, err := f.bareLogin(svc, app, email)
	requireRefused(t, res, err, auth.ErrAppMFAUnavailable)
}

// The user's only active factor is email and this deployment has no email
// MFA service: refused. Before, the factor was simply not looked at.
func TestAppMFAFailClosed_EmailOnlyWithoutEmailServiceRefused(t *testing.T) {
	f := newMFAFixture(t)
	app, appID := f.createApp(t, "fc-emailonly")
	if err := f.totpSvc.SetAppMFAPolicy(f.ctx, f.tenantID, appID, auth.MFAModeOptional,
		[]string{auth.MFAMethodTOTP, auth.MFAMethodEmail}, nil); err != nil {
		t.Fatalf("SetAppMFAPolicy: %v", err)
	}
	email := uniqueEmail("fc-emailonly")
	userID := f.registerAppUser(t, app, email, "Password123!")
	if _, err := f.pool.Exec(f.ctx,
		`INSERT INTO email_mfa_settings (user_id, tenant_id, is_active) VALUES ($1, $2, true)`,
		userID, f.tenantID); err != nil {
		t.Fatalf("activate email MFA: %v", err)
	}

	// TOTP and Redis present, email MFA service absent.
	svc := f.bareAuthService().WithTOTP(f.totpSvc, testhelper.NewTestRedis(t))
	res, err := f.bareLogin(svc, app, email)
	requireRefused(t, res, err, auth.ErrAppMFAUnavailable)
}

// Nothing due — switch off, or optional with no factor — means the missing
// services do not matter: tokens exactly as before #193.
func TestAppMFAFailClosed_NothingDueUnchanged(t *testing.T) {
	f := newMFAFixture(t)
	bare := f.bareAuthService()

	t.Run("switch off under required, enrolled user", func(t *testing.T) {
		app, appID := f.createApp(t, "fc-off")
		if err := f.totpSvc.SetAppMFAPolicy(f.ctx, f.tenantID, appID, auth.MFAModeRequired, nil, nil); err != nil {
			t.Fatalf("SetAppMFAPolicy(required): %v", err)
		}
		email := uniqueEmail("fc-off")
		userID := f.registerAppUser(t, app, email, "Password123!")
		f.enrollAndActivate(t, userID, email)
		if _, err := f.totpSvc.SetAppMFAEnabled(f.ctx, f.tenantID, appID, false, nil); err != nil {
			t.Fatalf("SetAppMFAEnabled(false): %v", err)
		}
		res, err := f.bareLogin(bare, app, email)
		if err != nil || res == nil || res.Token == nil {
			t.Fatalf("Login = %+v, %v; want tokens", res, err)
		}
	})

	t.Run("optional, no factor", func(t *testing.T) {
		app, _ := f.createApp(t, "fc-optional")
		email := uniqueEmail("fc-optional")
		f.registerAppUser(t, app, email, "Password123!")
		res, err := f.bareLogin(bare, app, email)
		if err != nil || res == nil || res.Token == nil {
			t.Fatalf("Login = %+v, %v; want tokens", res, err)
		}
	})

	t.Run("enrolled factor the app no longer allows", func(t *testing.T) {
		app, appID := f.createApp(t, "fc-notallowed")
		email := uniqueEmail("fc-notallowed")
		userID := f.registerAppUser(t, app, email, "Password123!")
		f.enrollAndActivate(t, userID, email)
		if err := f.totpSvc.SetAppMFAPolicy(f.ctx, f.tenantID, appID, auth.MFAModeOptional,
			[]string{auth.MFAMethodEmail}, nil); err != nil {
			t.Fatalf("SetAppMFAPolicy(email only): %v", err)
		}
		res, err := f.bareLogin(bare, app, email)
		if err != nil || res == nil || res.Token == nil {
			t.Fatalf("Login = %+v, %v; want tokens (TOTP is not a permitted factor)", res, err)
		}
	})
}

// A TOTP status read error fails closed: before #193 it was logged and read as
// "not enrolled", so the user skipped the challenge and got tokens.
func TestAppMFAFailClosed_TOTPStatusErrorRefused(t *testing.T) {
	f := newMFAFixture(t)
	app, _ := f.createApp(t, "fc-totperr")
	email := uniqueEmail("fc-totperr")
	f.registerAppUser(t, app, email, "Password123!")

	broken, err := auth.NewTOTPService(closedPool(t), totpEnvKey(), "development", testhelper.TestLogger())
	if err != nil {
		t.Fatalf("NewTOTPService: %v", err)
	}
	svc := f.bareAuthService().WithTOTP(broken, testhelper.NewTestRedis(t)).WithEmailMFA(f.emailSvc)
	res, err := f.bareLogin(svc, app, email)
	requireRefused(t, res, err, auth.ErrAppMFAUnavailable)
}

// An email MFA status read error fails closed the same way.
func TestAppMFAFailClosed_EmailStatusErrorRefused(t *testing.T) {
	f := newMFAFixture(t)
	app, appID := f.createApp(t, "fc-emailerr")
	if err := f.totpSvc.SetAppMFAPolicy(f.ctx, f.tenantID, appID, auth.MFAModeOptional,
		[]string{auth.MFAMethodTOTP, auth.MFAMethodEmail}, nil); err != nil {
		t.Fatalf("SetAppMFAPolicy: %v", err)
	}
	email := uniqueEmail("fc-emailerr")
	f.registerAppUser(t, app, email, "Password123!")

	broken := auth.NewEmailMFAService(closedPool(t), testhelper.NewTestRedis(t), f.mail, testhelper.TestLogger())
	svc := f.bareAuthService().WithTOTP(f.totpSvc, testhelper.NewTestRedis(t)).WithEmailMFA(broken)
	res, err := f.bareLogin(svc, app, email)
	requireRefused(t, res, err, auth.ErrAppMFAUnavailable)
}

// With every service present the gate behaves as before: an enrolled user is
// challenged, an unenrolled one under 'required' is sent to enrol.
func TestAppMFAFailClosed_FullDeploymentUnchanged(t *testing.T) {
	f := newMFAFixture(t)
	app, appID := f.createApp(t, "fc-full")
	enrolled := uniqueEmail("fc-full-enrolled")
	userID := f.registerAppUser(t, app, enrolled, "Password123!")
	f.enrollAndActivate(t, userID, enrolled)

	res, err := f.appLogin(t, app, enrolled, "Password123!")
	if err != nil || res.OTPChallenge == nil {
		t.Fatalf("Login(enrolled) = %+v, %v; want OTP challenge", res, err)
	}

	if err := f.totpSvc.SetAppMFAPolicy(f.ctx, f.tenantID, appID, auth.MFAModeRequired, nil, nil); err != nil {
		t.Fatalf("SetAppMFAPolicy(required): %v", err)
	}
	fresh := uniqueEmail("fc-full-fresh")
	f.registerAppUser(t, app, fresh, "Password123!")
	res, err = f.appLogin(t, app, fresh, "Password123!")
	if err != nil || res.MFAEnrollment == nil {
		t.Fatalf("Login(unenrolled, required) = %+v, %v; want forced enrolment", res, err)
	}
}

// A Redis failure while storing the challenge fails closed as
// ErrAppMFAUnavailable — 503 at the handlers, not 500 login_failed or
// "incorrect password" — and the cause stays in the chain for the logs.
func TestAppMFAFailClosed_ChallengeStoreErrorIsUnavailable(t *testing.T) {
	f := newMFAFixture(t)
	app, _ := f.createApp(t, "fc-redisdown")
	email := uniqueEmail("fc-redisdown")
	userID := f.registerAppUser(t, app, email, "Password123!")
	f.enrollAndActivate(t, userID, email)

	down := testhelper.NewTestRedis(t)
	if err := down.Close(); err != nil {
		t.Fatalf("close redis: %v", err)
	}
	svc := f.bareAuthService().WithTOTP(f.totpSvc, down)
	res, err := f.bareLogin(svc, app, email)
	requireRefused(t, res, err, auth.ErrAppMFAUnavailable)
	if !errors.Is(err, redis.ErrClosed) {
		t.Fatalf("error = %v, want the Redis cause preserved", err)
	}
}
