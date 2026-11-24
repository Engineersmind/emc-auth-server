package auth_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// Tests for passwordless sign-in and sign-up by emailed code (issue #203).

var pwKey = []byte("0123456789abcdef0123456789abcdef")

func ref[T any](v T) *T { return &v }

// pwFixture is the MFA fixture plus the passwordless policy service.
type pwFixture struct {
	*mfaFixture
	policy *auth.PasswordlessPolicyService
	rc     *redis.Client
}

func (f *pwFixture) rdb() *redis.Client { return f.rc }

func newPWFixture(t *testing.T) *pwFixture {
	t.Helper()
	f := newMFAFixture(t)
	// Policy rows are tenant- and platform-wide, so one test's rows would leak into
	// the next (a tenant row enabling codes would break "disabled by default").
	if _, err := f.pool.Exec(f.ctx, `TRUNCATE passwordless_policies, passwordless_policy_history`); err != nil {
		t.Fatalf("clear passwordless policies: %v", err)
	}
	policy := auth.NewPasswordlessPolicyService(f.pool, testhelper.TestLogger()).
		WithMFAConfig(func(ctx context.Context, appRowID int64) (string, []string, error) {
			return f.totpSvc.GetAppMFAConfig(ctx, appRowID)
		})
	f.authSvc.WithPasswordless(policy, pwKey, nil)
	return &pwFixture{mfaFixture: f, policy: policy, rc: testhelper.NewTestRedis(t)}
}

// setPolicy writes the application-level overrides.
func (f *pwFixture) setPolicy(t *testing.T, appID int64, mut func(*auth.PasswordlessPolicyRow)) {
	t.Helper()
	sc := auth.PasswordlessScope{TenantID: &f.tenantID, ApplicationID: &appID}
	row := auth.PasswordlessPolicyRow{}
	version := 0
	if v, err := f.policy.View(f.ctx, sc); err == nil && v.Row != nil {
		row, version = *v.Row, v.Row.Version
	}
	mut(&row)
	if _, err := f.policy.Put(f.ctx, sc, auth.PasswordlessWriteInput{Row: row, Version: version}); err != nil {
		t.Fatalf("Put policy: %v", err)
	}
}

func (f *pwFixture) enable(t *testing.T, appID int64, signup bool) {
	t.Helper()
	f.setPolicy(t, appID, func(r *auth.PasswordlessPolicyRow) {
		r.EmailOTPEnabled = ref(true)
		r.SignupEnabled = ref(signup)
	})
}

func (f *pwFixture) start(t *testing.T, app *auth.AppResult, email string) (*auth.PasswordlessStartResult, *auth.PasswordlessStartMeta, error) {
	t.Helper()
	return f.authSvc.PasswordlessStart(f.ctx, auth.PasswordlessStartInput{
		ClientID: app.ClientID, ClientSecret: app.ClientSecret, Email: email, IP: "203.0.113.7",
	})
}

func (f *pwFixture) verify(app *auth.AppResult, challenge, code string) (*auth.LoginResult, *auth.PasswordlessVerifyMeta, error) {
	return f.authSvc.PasswordlessVerify(f.ctx, auth.PasswordlessVerifyInput{
		ClientID: app.ClientID, ClientSecret: app.ClientSecret, ChallengeID: challenge, Code: code,
	})
}

// startAndCode requests a code and returns the challenge id and the mailed code.
func (f *pwFixture) startAndCode(t *testing.T, app *auth.AppResult, email string) (string, string) {
	t.Helper()
	before := f.mail.passwordlessCount()
	res, _, err := f.start(t, app, email)
	if err != nil {
		t.Fatalf("PasswordlessStart: %v", err)
	}
	return res.ChallengeID, f.mail.lastPasswordless(t, before).Code
}

func wrongCode(code string) string {
	if code == "000000" {
		return "111111"
	}
	return "000000"
}

// ---------------------------------------------------------------------------

func TestPasswordless_SignUpThenSignIn(t *testing.T) {
	f := newPWFixture(t)
	app, appID := f.createApp(t, "pw-signup")
	f.enable(t, appID, true)
	email := uniqueEmail("pw-new")

	// Start for an unknown address with sign-up on: writes NOTHING durable.
	chID, code := f.startAndCode(t, app, email)
	var n int
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM users WHERE email = $1`, email).Scan(&n); err != nil || n != 0 {
		t.Fatalf("users rows after start = %d (%v), want 0: the account is created at verify", n, err)
	}

	res, meta, err := f.verify(app, chID, code)
	if err != nil || res.Token == nil {
		t.Fatalf("verify = %+v, %v; want tokens", res, err)
	}
	if !meta.Created {
		t.Error("meta.Created = false, want true")
	}

	var verified bool
	var hasCred bool
	if err := f.pool.QueryRow(f.ctx, `
		SELECT u.email_verified, EXISTS (SELECT 1 FROM user_credentials c WHERE c.user_id = u.id)
		FROM users u WHERE u.email = $1`, email).Scan(&verified, &hasCred); err != nil {
		t.Fatalf("load user: %v", err)
	}
	if !verified {
		t.Error("created user is not email_verified")
	}
	if hasCred {
		t.Error("created user has a credential row; passwordless users have none")
	}

	claims, err := f.jwtSvc.Verify(f.ctx, res.Token.AccessToken)
	if err != nil || claims == nil {
		t.Fatalf("Verify token: %v", err)
	}
	if claims.Gty != auth.GrantEmailOTP {
		t.Errorf("gty = %q, want %q", claims.Gty, auth.GrantEmailOTP)
	}
	if amr := f.sessionAMR(t, res.Token.AccessToken); len(amr) != 1 || amr[0] != auth.AMREmailOTP {
		t.Errorf("amr = %v, want [email_otp]", amr)
	}

	// The code is single use.
	if _, _, err := f.verify(app, chID, code); !errors.Is(err, auth.ErrPasswordlessInvalidCode) {
		t.Errorf("second verify error = %v, want invalid_or_expired_code", err)
	}

	// A second sign-in finds the existing account and does not create another.
	chID2, code2 := f.startAndCode(t, app, email)
	res2, meta2, err := f.verify(app, chID2, code2)
	if err != nil || res2.Token == nil || meta2.Created {
		t.Fatalf("second sign-in = %+v, meta %+v, %v; want tokens and no creation", res2, meta2, err)
	}
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM users WHERE email = $1`, email).Scan(&n); err != nil || n != 1 {
		t.Errorf("users rows = %d, want 1", n)
	}
}

// Off by default: no policy row means password only, exactly as before.
func TestPasswordless_DisabledByDefault(t *testing.T) {
	f := newPWFixture(t)
	app, _ := f.createApp(t, "pw-off")
	if _, _, err := f.start(t, app, uniqueEmail("pw-off")); !errors.Is(err, auth.ErrPasswordlessDisabled) {
		t.Errorf("start with no policy = %v, want ErrPasswordlessDisabled", err)
	}
}

// Sign-up off: an unknown address is answered like any other and never gets mail.
func TestPasswordless_SignUpOffIsADecoy(t *testing.T) {
	f := newPWFixture(t)
	app, appID := f.createApp(t, "pw-nosignup")
	f.enable(t, appID, false)

	before := f.mail.passwordlessCount()
	res, meta, err := f.start(t, app, uniqueEmail("pw-ghost"))
	if err != nil || res == nil {
		t.Fatalf("start = %+v, %v; want a normal response", res, err)
	}
	if meta.Outcome != "decoy" {
		t.Errorf("outcome = %q, want decoy", meta.Outcome)
	}
	time.Sleep(150 * time.Millisecond)
	if f.mail.passwordlessCount() != before {
		t.Error("a code was mailed to an address that cannot sign in")
	}
	// A guess against the decoy fails with the uniform error.
	if _, _, err := f.verify(app, res.ChallengeID, "123456"); !errors.Is(err, auth.ErrPasswordlessInvalidCode) {
		t.Errorf("verify against decoy = %v, want invalid_or_expired_code", err)
	}
}

// The response to start is identical in shape for every kind of address.
func TestPasswordless_StartResponseIsUniform(t *testing.T) {
	f := newPWFixture(t)
	app, appID := f.createApp(t, "pw-uniform")
	f.enable(t, appID, false)
	f.setPolicy(t, appID, func(r *auth.PasswordlessPolicyRow) { r.StartsPerHour = ref(1) })

	known := uniqueEmail("pw-known")
	f.registerAppUser(t, app, known, "Password123!")
	blocked := uniqueEmail("pw-blocked")
	blockedID := f.registerAppUser(t, app, blocked, "Password123!")
	if _, err := f.pool.Exec(f.ctx, `UPDATE users SET is_active = false WHERE id = $1`, blockedID); err != nil {
		t.Fatal(err)
	}

	cases := map[string]string{
		"known":   known,
		"unknown": uniqueEmail("pw-unknown"),
		"blocked": blocked,
	}
	var shapes []string
	for name, email := range cases {
		res, _, err := f.start(t, app, email)
		if err != nil {
			t.Fatalf("%s: start error %v", name, err)
		}
		shapes = append(shapes, fmt.Sprintf("%d|%d|%d|%d", len(res.ChallengeID), res.ExpiresIn, res.ResendAfter, res.CodeLength))
	}
	// Throttled: StartsPerHour is 1, so a second start for the same address is
	// throttled, and must look the same.
	res, meta, err := f.start(t, app, known)
	if err != nil || meta.Outcome != "throttled" {
		t.Fatalf("second start = %+v, meta %+v, %v; want a throttled outcome with no error", res, meta, err)
	}
	shapes = append(shapes, fmt.Sprintf("%d|%d|%d|%d", len(res.ChallengeID), res.ExpiresIn, res.ResendAfter, res.CodeLength))
	for _, s := range shapes[1:] {
		if s != shapes[0] {
			t.Errorf("response shapes differ: %v", shapes)
			break
		}
	}
}

func TestPasswordless_StartDeadlineIsUniform(t *testing.T) {
	f := newPWFixture(t)
	app, appID := f.createApp(t, "pw-timing")
	f.enable(t, appID, false)
	known := uniqueEmail("pw-t-known")
	f.registerAppUser(t, app, known, "Password123!")

	timeIt := func(email string) time.Duration {
		began := time.Now()
		if _, _, err := f.start(t, app, email); err != nil {
			t.Fatal(err)
		}
		return time.Since(began)
	}
	real, decoy := timeIt(known), timeIt(uniqueEmail("pw-t-ghost"))
	// Both are padded to the same floor, so neither is meaningfully faster.
	if diff := real - decoy; diff > 100*time.Millisecond || diff < -100*time.Millisecond {
		t.Errorf("latency differs: real %v, decoy %v", real, decoy)
	}
	if real < 140*time.Millisecond || decoy < 140*time.Millisecond {
		t.Errorf("start returned before the floor: real %v, decoy %v", real, decoy)
	}
}

func TestPasswordless_AttemptBudgetBurnsTheChallenge(t *testing.T) {
	f := newPWFixture(t)
	app, appID := f.createApp(t, "pw-attempts")
	f.enable(t, appID, true)
	email := uniqueEmail("pw-attempts")
	chID, code := f.startAndCode(t, app, email)

	for i := 0; i < 5; i++ {
		if _, _, err := f.verify(app, chID, wrongCode(code)); !errors.Is(err, auth.ErrPasswordlessInvalidCode) {
			t.Fatalf("wrong guess %d = %v, want invalid_or_expired_code", i, err)
		}
	}
	// The right code no longer works: the challenge was destroyed.
	if _, _, err := f.verify(app, chID, code); !errors.Is(err, auth.ErrPasswordlessInvalidCode) {
		t.Errorf("correct code after 5 wrong = %v, want invalid_or_expired_code", err)
	}
}

// Many challenges cannot multiply the guesses: after 10 failures an address is
// blocked, even for a correct code, and the block is lifted by an administrator.
func TestPasswordless_FailureBudgetBlocksAddress(t *testing.T) {
	f := newPWFixture(t)
	app, appID := f.createApp(t, "pw-block")
	f.enable(t, appID, true)
	f.setPolicy(t, appID, func(r *auth.PasswordlessPolicyRow) { r.StartsPerHour = ref(10) })
	email := uniqueEmail("pw-block")

	var chID, code string
	for round := 0; round < 4; round++ { // 3 wrong guesses x 3 rounds crosses 10
		chID, code = f.startAndCode(t, app, email)
		for g := 0; g < 3; g++ {
			f.verify(app, chID, wrongCode(code)) //nolint:errcheck
		}
	}
	chID, code = f.startAndCode(t, app, email)
	if _, _, err := f.verify(app, chID, code); !errors.Is(err, auth.ErrPasswordlessInvalidCode) {
		t.Fatalf("correct code while blocked = %v, want invalid_or_expired_code", err)
	}
	if err := f.authSvc.ClearPasswordlessThrottle(f.ctx, appID, email); err != nil {
		t.Fatal(err)
	}
	chID, code = f.startAndCode(t, app, email)
	if res, _, err := f.verify(app, chID, code); err != nil || res.Token == nil {
		t.Errorf("verify after the throttle was cleared = %+v, %v; want tokens", res, err)
	}
}

func TestPasswordless_ResendRotatesCode(t *testing.T) {
	f := newPWFixture(t)
	app, appID := f.createApp(t, "pw-resend")
	f.enable(t, appID, true)
	f.setPolicy(t, appID, func(r *auth.PasswordlessPolicyRow) {
		r.ResendCooldownSecs = ref(30)
		r.MaxResends = ref(1)
	})
	email := uniqueEmail("pw-resend")
	chID, oldCode := f.startAndCode(t, app, email)

	// Inside the cooldown.
	var cool *auth.PasswordlessCooldownError
	if _, err := f.authSvc.PasswordlessResend(f.ctx, app.ClientID, app.ClientSecret, chID); !errors.As(err, &cool) {
		t.Fatalf("immediate resend = %v, want a cooldown error", err)
	}

	// Move the challenge's last send into the past to leave the cooldown.
	if err := f.rdb().HSet(f.ctx, "pwless:ch:"+chID, "sent_at", time.Now().Add(-time.Minute).Unix()).Err(); err != nil {
		t.Fatal(err)
	}
	before := f.mail.passwordlessCount()
	res, err := f.authSvc.PasswordlessResend(f.ctx, app.ClientID, app.ClientSecret, chID)
	if err != nil || res.ResendsLeft != 0 {
		t.Fatalf("resend = %+v, %v; want 0 left", res, err)
	}
	newCode := f.mail.lastPasswordless(t, before).Code

	if newCode != oldCode {
		if _, _, err := f.verify(app, chID, oldCode); !errors.Is(err, auth.ErrPasswordlessInvalidCode) {
			t.Errorf("old code after rotation = %v, want invalid_or_expired_code", err)
		}
	}
	// The budget of 1 is spent.
	if err := f.rdb().HSet(f.ctx, "pwless:ch:"+chID, "sent_at", time.Now().Add(-time.Minute).Unix()).Err(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.authSvc.PasswordlessResend(f.ctx, app.ClientID, app.ClientSecret, chID); !errors.Is(err, auth.ErrPasswordlessTooManyResends) {
		t.Errorf("resend past the budget = %v, want too_many_resends", err)
	}
	if res, _, err := f.verify(app, chID, newCode); err != nil || res.Token == nil {
		t.Errorf("verify with the rotated code = %+v, %v; want tokens", res, err)
	}
}

// A code issued for one application is worthless through another.
func TestPasswordless_BoundToIssuingApplication(t *testing.T) {
	f := newPWFixture(t)
	appA, aID := f.createApp(t, "pw-bind-a")
	appB, bID := f.createApp(t, "pw-bind-b")
	f.enable(t, aID, true)
	f.enable(t, bID, true)
	chID, code := f.startAndCode(t, appA, uniqueEmail("pw-bind"))
	if _, _, err := f.verify(appB, chID, code); !errors.Is(err, auth.ErrPasswordlessInvalidCode) {
		t.Errorf("verify via the other application = %v, want invalid_or_expired_code", err)
	}
	// And the failed attempt did not consume it for its rightful owner... but it
	// DID spend an attempt, which is the intended cost of a wrong application.
	if res, _, err := f.verify(appA, chID, code); err != nil || res.Token == nil {
		t.Errorf("verify via the issuing application = %+v, %v; want tokens", res, err)
	}
}

// A deactivated account is a decoy and can never sign in by code.
func TestPasswordless_InactiveUserIsRefused(t *testing.T) {
	f := newPWFixture(t)
	app, appID := f.createApp(t, "pw-inactive")
	f.enable(t, appID, true)
	email := uniqueEmail("pw-inactive")
	id := f.registerAppUser(t, app, email, "Password123!")
	if _, err := f.pool.Exec(f.ctx, `UPDATE users SET is_active = false WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	before := f.mail.passwordlessCount()
	res, meta, err := f.start(t, app, email)
	if err != nil || meta.Outcome != "decoy" {
		t.Fatalf("start = %+v, %+v, %v; want a decoy", res, meta, err)
	}
	time.Sleep(150 * time.Millisecond)
	if f.mail.passwordlessCount() != before {
		t.Error("a code was mailed to a deactivated account")
	}
}

// Domain lists restrict SIGN-UP only; an existing user is unaffected.
func TestPasswordless_DomainPolicy(t *testing.T) {
	f := newPWFixture(t)
	app, appID := f.createApp(t, "pw-domain")
	f.enable(t, appID, true)
	f.setPolicy(t, appID, func(r *auth.PasswordlessPolicyRow) {
		r.AllowedEmailDomains = []string{"corp.example"}
	})
	local := fmt.Sprintf("pwd%d", time.Now().UnixNano())

	// Outside the allow list: a decoy.
	_, meta, err := f.start(t, app, local+"@other.example")
	if err != nil || meta.Outcome != "decoy" {
		t.Fatalf("refused domain: meta %+v, %v; want a decoy", meta, err)
	}
	// Inside: a real code, and an account.
	chID, code := f.startAndCode(t, app, local+"@corp.example")
	if res, _, err := f.verify(app, chID, code); err != nil || res.Token == nil {
		t.Errorf("allowed domain verify = %+v, %v; want tokens", res, err)
	}
	// An existing user outside the list can still sign in.
	existing := local + "-x@other.example"
	f.registerAppUser(t, app, existing, "Password123!")
	chID, code = f.startAndCode(t, app, existing)
	if res, _, err := f.verify(app, chID, code); err != nil || res.Token == nil {
		t.Errorf("existing user verify = %+v, %v; want tokens", res, err)
	}
}

// Pre-hijack safeguard: the owner proving the inbox on an account an attacker
// registered ends the attacker's sessions, verifies the address, and keeps the
// stored password exactly as it was.
func TestPasswordless_PreHijackSafeguard(t *testing.T) {
	f := newPWFixture(t)
	app, appID := f.createApp(t, "pw-prehijack")
	f.enable(t, appID, false)
	email := uniqueEmail("pw-victim")
	id := f.registerAppUser(t, app, email, "AttackerPass123!")

	// The attacker holds a live session from before.
	attacker, err := f.appLogin(t, app, email, "AttackerPass123!")
	if err != nil || attacker.Token == nil {
		t.Fatalf("attacker login = %+v, %v", attacker, err)
	}
	var hashBefore string
	var tvBefore int
	if err := f.pool.QueryRow(f.ctx, `SELECT c.password_hash, u.token_version FROM user_credentials c JOIN users u ON u.id = c.user_id WHERE u.id = $1`, id).Scan(&hashBefore, &tvBefore); err != nil {
		t.Fatal(err)
	}

	chID, code := f.startAndCode(t, app, email)
	res, _, err := f.verify(app, chID, code)
	if err != nil || res.Token == nil {
		t.Fatalf("owner verify = %+v, %v", res, err)
	}

	var verified bool
	var hashAfter string
	var tvAfter int
	if err := f.pool.QueryRow(f.ctx, `SELECT u.email_verified, c.password_hash, u.token_version FROM user_credentials c JOIN users u ON u.id = c.user_id WHERE u.id = $1`, id).Scan(&verified, &hashAfter, &tvAfter); err != nil {
		t.Fatal(err)
	}
	if !verified {
		t.Error("address was not marked verified")
	}
	if hashAfter != hashBefore {
		t.Error("the stored password hash changed; it must be kept exactly")
	}
	if tvAfter != tvBefore+1 {
		t.Errorf("token_version = %d, want %d", tvAfter, tvBefore+1)
	}
	var live int
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM refresh_tokens WHERE user_id = $1 AND revoked_at IS NULL AND created_at < NOW()`, id).Scan(&live); err != nil {
		t.Fatal(err)
	}
	// Only the owner's new session is live; the attacker's was revoked.
	if live != 1 {
		t.Errorf("live refresh tokens = %d, want 1 (the owner's)", live)
	}
}

// An invited user (no password, unverified) signs in by code, which verifies them.
func TestPasswordless_InvitedUserIsVerified(t *testing.T) {
	f := newPWFixture(t)
	app, appID := f.createApp(t, "pw-invited")
	f.enable(t, appID, false)
	email := uniqueEmail("pw-invited")
	id := f.registerAppUser(t, app, email, "Password123!")
	if _, err := f.pool.Exec(f.ctx, `DELETE FROM user_credentials WHERE user_id = $1`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(f.ctx, `UPDATE users SET email_verified = false WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	chID, code := f.startAndCode(t, app, email)
	if res, _, err := f.verify(app, chID, code); err != nil || res.Token == nil {
		t.Fatalf("verify = %+v, %v", res, err)
	}
	var verified bool
	if err := f.pool.QueryRow(f.ctx, `SELECT email_verified FROM users WHERE id = $1`, id).Scan(&verified); err != nil || !verified {
		t.Errorf("email_verified = %v (%v), want true", verified, err)
	}
}

// Two verifies racing to create the same address end with exactly one account,
// and both callers get a session.
func TestPasswordless_ConcurrentSignUpCreatesOneAccount(t *testing.T) {
	f := newPWFixture(t)
	app, appID := f.createApp(t, "pw-race")
	f.enable(t, appID, true)
	email := uniqueEmail("pw-race")

	ch1, code1 := f.startAndCode(t, app, email)
	var wg sync.WaitGroup
	results := make([]error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Both use the same challenge: only one can consume it, the other must
			// fail cleanly, never create a duplicate.
			_, _, results[i] = f.verify(app, ch1, code1)
		}(i)
	}
	wg.Wait()
	ok := 0
	for _, e := range results {
		if e == nil {
			ok++
		}
	}
	if ok != 1 {
		t.Errorf("successful verifies = %d (%v), want exactly 1 (single use)", ok, results)
	}
	var n int
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM users WHERE email = $1`, email).Scan(&n); err != nil || n != 1 {
		t.Errorf("users rows = %d, want 1", n)
	}
}

// Only the application's own default, non-system role is assigned on sign-up.
func TestPasswordless_SignUpGetsOnlyTheDefaultRole(t *testing.T) {
	f := newPWFixture(t)
	app, appID := f.createApp(t, "pw-role")
	f.enable(t, appID, true)
	var roleID int64
	if err := f.pool.QueryRow(f.ctx, `
		INSERT INTO roles (tenant_id, application_id, name, is_default, is_system)
		VALUES ($1, $2, 'member', true, false) RETURNING id`, f.tenantID, appID).Scan(&roleID); err != nil {
		t.Fatalf("seed default role: %v", err)
	}
	email := uniqueEmail("pw-role")
	chID, code := f.startAndCode(t, app, email)
	if _, _, err := f.verify(app, chID, code); err != nil {
		t.Fatal(err)
	}
	rows, err := f.pool.Query(f.ctx, `
		SELECT r.name, r.is_system FROM user_roles ur JOIN roles r ON r.id = ur.role_id
		JOIN users u ON u.id = ur.user_id WHERE u.email = $1`, email)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var name string
		var sys bool
		if err := rows.Scan(&name, &sys); err != nil {
			t.Fatal(err)
		}
		if sys {
			t.Errorf("sign-up granted the system role %q", name)
		}
		got = append(got, name)
	}
	if len(got) != 1 || got[0] != "member" {
		t.Errorf("roles = %v, want [member]", got)
	}
}

// ---------------------------------------------------------------------------
// MFA interaction
// ---------------------------------------------------------------------------

// After an emailed first factor the email method is never offered, but TOTP is,
// and the finished session still says how it began.
func TestPasswordless_MFAOffersTOTPNotEmail(t *testing.T) {
	f := newPWFixture(t)
	app, appID := f.createApp(t, "pw-mfa")
	f.enable(t, appID, false)
	if err := f.totpSvc.SetAppMFAPolicy(f.ctx, f.tenantID, appID, auth.MFAModeOptional,
		[]string{auth.MFAMethodTOTP, auth.MFAMethodEmail}, nil); err != nil {
		t.Fatal(err)
	}
	email := uniqueEmail("pw-mfa")
	id := f.registerAppUser(t, app, email, "Password123!")
	secret := f.enrollAndActivate(t, id, email)
	f.enrollEmail(t, id)

	before := f.mail.codeCount()
	chID, code := f.startAndCode(t, app, email)
	res, _, err := f.verify(app, chID, code)
	if err != nil || res.OTPChallenge == nil {
		t.Fatalf("verify = %+v, %v; want an OTP challenge", res, err)
	}
	if m := res.OTPChallenge.Methods; len(m) != 1 || m[0] != auth.MFAMethodTOTP {
		t.Errorf("offered methods = %v, want [totp]", m)
	}
	if f.mail.codeCount() != before {
		t.Error("an email MFA code was sent after an emailed first factor")
	}

	tokens, err := f.authSvc.LoginOTP(f.ctx, auth.LoginOTPInput{OTPSessionToken: res.OTPChallenge.OTPSessionToken, Code: codeFor(t, secret)})
	if err != nil {
		t.Fatalf("LoginOTP: %v", err)
	}
	claims, err := f.jwtSvc.Verify(f.ctx, tokens.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Gty != auth.GrantEmailOTP {
		t.Errorf("gty after MFA = %q, want email_otp (the grant that began the flow)", claims.Gty)
	}
	amr := f.sessionAMR(t, tokens.AccessToken)
	if strings.Join(amr, ",") != "email_otp,otp,mfa" {
		t.Errorf("amr = %v, want [email_otp otp mfa]", amr)
	}
}

// 'required' mode with an unenrolled user forces enrolment, without email.
func TestPasswordless_RequiredMFAForcesEnrolmentWithoutEmail(t *testing.T) {
	f := newPWFixture(t)
	app, appID := f.createApp(t, "pw-mfa-req")
	f.enable(t, appID, true)
	if err := f.totpSvc.SetAppMFAPolicy(f.ctx, f.tenantID, appID, auth.MFAModeRequired,
		[]string{auth.MFAMethodTOTP, auth.MFAMethodEmail}, nil); err != nil {
		t.Fatal(err)
	}
	chID, code := f.startAndCode(t, app, uniqueEmail("pw-mfa-req"))
	res, _, err := f.verify(app, chID, code)
	if err != nil || res.MFAEnrollment == nil {
		t.Fatalf("verify = %+v, %v; want an enrolment challenge", res, err)
	}
	if m := res.MFAEnrollment.AllowedMethods; len(m) != 1 || m[0] != auth.MFAMethodTOTP {
		t.Errorf("allowed methods = %v, want [totp]", m)
	}
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

func TestPasswordlessPolicy_ResolutionAndRules(t *testing.T) {
	f := newPWFixture(t)
	_, appID := f.createApp(t, "pw-policy")
	tenant := auth.PasswordlessScope{TenantID: &f.tenantID}
	app := auth.PasswordlessScope{TenantID: &f.tenantID, ApplicationID: &appID}

	// No row anywhere: password only.
	v, err := f.policy.View(f.ctx, app)
	if err != nil || v.Mode != auth.PasswordlessModePasswordOnly || !v.Effective.PasswordEnabled {
		t.Fatalf("default view = %+v, %v; want password only", v, err)
	}

	// A tenant row is inherited by the application, with its source reported.
	if _, err := f.policy.Put(f.ctx, tenant, auth.PasswordlessWriteInput{Row: auth.PasswordlessPolicyRow{
		EmailOTPEnabled: ref(true), CodeTTLSeconds: ref(600),
	}}); err != nil {
		t.Fatal(err)
	}
	v, _ = f.policy.View(f.ctx, app)
	if !v.Effective.EmailOTPEnabled || v.Effective.Sources["email_otp_enabled"] != "tenant" || v.Mode != auth.PasswordlessModeBoth {
		t.Errorf("inherited view = %+v", v)
	}
	// An application override beats the tenant.
	f.setPolicy(t, appID, func(r *auth.PasswordlessPolicyRow) { r.CodeTTLSeconds = ref(400) })
	if v, _ = f.policy.View(f.ctx, app); v.Effective.CodeTTLSeconds != 400 || v.Effective.Sources["code_ttl_seconds"] != "application" {
		t.Errorf("override view = %+v", v.Effective)
	}

	// At least one first factor must remain.
	err = func() error {
		_, e := f.policy.Put(f.ctx, app, auth.PasswordlessWriteInput{
			Row: auth.PasswordlessPolicyRow{EmailOTPEnabled: ref(false), PasswordEnabled: ref(false)}, Version: 1,
		})
		return e
	}()
	if !errors.Is(err, auth.ErrPasswordlessNoFirstFactor) {
		t.Errorf("no first factor = %v, want ErrPasswordlessNoFirstFactor", err)
	}

	// A stale version is a conflict.
	if _, err = f.policy.Put(f.ctx, app, auth.PasswordlessWriteInput{
		Row: auth.PasswordlessPolicyRow{CodeTTLSeconds: ref(500)}, Version: 99,
	}); !errors.Is(err, auth.ErrPasswordlessVersionConflict) {
		t.Errorf("stale version = %v, want ErrPasswordlessVersionConflict", err)
	}

	// Out-of-range values are refused.
	if _, err = f.policy.Put(f.ctx, tenant, auth.PasswordlessWriteInput{
		Row: auth.PasswordlessPolicyRow{CodeTTLSeconds: ref(60)}, Version: 1,
	}); !errors.Is(err, auth.ErrPasswordlessInvalid) {
		t.Errorf("ttl 60 = %v, want ErrPasswordlessInvalid", err)
	}

	// Platform values are ceilings.
	if _, err = f.policy.Put(f.ctx, auth.PasswordlessScope{}, auth.PasswordlessWriteInput{
		Row: auth.PasswordlessPolicyRow{CodeTTLSeconds: ref(450)},
	}); err != nil {
		t.Fatal(err)
	}
	if v, _ = f.policy.View(f.ctx, app); v.Effective.CodeTTLSeconds != 400 {
		t.Errorf("effective ttl = %d, want 400 (own value below the ceiling)", v.Effective.CodeTTLSeconds)
	}
	if _, err = f.policy.Put(f.ctx, tenant, auth.PasswordlessWriteInput{
		Row: auth.PasswordlessPolicyRow{EmailOTPEnabled: ref(true), CodeTTLSeconds: ref(800)}, Version: 1,
	}); !errors.Is(err, auth.ErrPasswordlessCeiling) {
		t.Errorf("ttl above the ceiling = %v, want ErrPasswordlessCeiling", err)
	}

	// History is append-only and restore writes a new version.
	hist, err := f.policy.History(f.ctx, app, 10)
	if err != nil || len(hist) == 0 {
		t.Fatalf("history = %v, %v", hist, err)
	}
	oldest := hist[len(hist)-1]
	cur, _ := f.policy.View(f.ctx, app)
	restored, err := f.policy.Restore(f.ctx, app, oldest.ID, cur.Row.Version, nil)
	if err != nil || restored.Version != cur.Row.Version+1 {
		t.Errorf("restore = %+v, %v; want a new version", restored, err)
	}
}

// Email codes cannot be enabled where required MFA allows only email.
func TestPasswordlessPolicy_MFAConflict(t *testing.T) {
	f := newPWFixture(t)
	_, appID := f.createApp(t, "pw-conflict")
	if err := f.totpSvc.SetAppMFAPolicy(f.ctx, f.tenantID, appID, auth.MFAModeRequired, []string{auth.MFAMethodEmail}, nil); err != nil {
		t.Fatal(err)
	}
	_, err := f.policy.Put(f.ctx, auth.PasswordlessScope{TenantID: &f.tenantID, ApplicationID: &appID},
		auth.PasswordlessWriteInput{Row: auth.PasswordlessPolicyRow{EmailOTPEnabled: ref(true)}})
	if !errors.Is(err, auth.ErrPasswordlessMFAConflict) {
		t.Errorf("enable codes with required email-only MFA = %v, want ErrPasswordlessMFAConflict", err)
	}
}

func TestPasswordlessSettings_DomainPermitted(t *testing.T) {
	s := auth.DefaultPasswordlessSettings()
	s.BlockedEmailDomains = []string{"mailinator.com"}
	s.AllowedEmailDomains = []string{"corp.example"}
	for email, want := range map[string]bool{
		"a@corp.example":       true,
		"a@other.example":      false,
		"a@mailinator.com":     false,
		"a@sub.mailinator.com": false,
		"not-an-email":         false,
		"a@":                   false,
		"a@CORP.example":       true,
	} {
		if got := s.DomainPermitted(email); got != want {
			t.Errorf("DomainPermitted(%q) = %v, want %v", email, got, want)
		}
	}
	open := auth.DefaultPasswordlessSettings()
	if !open.DomainPermitted("anyone@anywhere.example") {
		t.Error("no lists should permit every domain")
	}
}

func TestNormalizePasswordlessDomains(t *testing.T) {
	got, err := auth.NormalizePasswordlessDomains([]string{" Corp.Example ", "@corp.example", "b.example", ""})
	if err != nil || len(got) != 2 || got[0] != "corp.example" || got[1] != "b.example" {
		t.Errorf("normalise = %v, %v", got, err)
	}
	for _, bad := range []string{"bücher.example", "no_underscore.example", "nodots", "a..b.example"} {
		if _, err := auth.NormalizePasswordlessDomains([]string{bad}); !errors.Is(err, auth.ErrPasswordlessInvalid) {
			t.Errorf("domain %q accepted, want ErrPasswordlessInvalid", bad)
		}
	}
}

// Codes cannot be enabled while the sign-in-code email is switched off for the
// application: they would be requested and never arrive.
func TestPasswordlessPolicy_RefusesCodesWhileTheTemplateIsOff(t *testing.T) {
	f := newPWFixture(t)
	_, appID := f.createApp(t, "pw-tmpl-off")
	off := auth.NewPasswordlessPolicyService(f.pool, testhelper.TestLogger()).
		WithTemplateEnabled(func(context.Context, int64, *int64) bool { return false })
	sc := auth.PasswordlessScope{TenantID: &f.tenantID, ApplicationID: &appID}

	_, err := off.Put(f.ctx, sc, auth.PasswordlessWriteInput{Row: auth.PasswordlessPolicyRow{EmailOTPEnabled: ref(true)}})
	if !errors.Is(err, auth.ErrPasswordlessTemplateDisabled) {
		t.Errorf("enable codes with the template off = %v, want ErrPasswordlessTemplateDisabled", err)
	}
	// Turning codes OFF is never blocked by it.
	if _, err := off.Put(f.ctx, sc, auth.PasswordlessWriteInput{Row: auth.PasswordlessPolicyRow{EmailOTPEnabled: ref(false)}}); err != nil {
		t.Errorf("disable codes with the template off = %v, want nil", err)
	}
}
