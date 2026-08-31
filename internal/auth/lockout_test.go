package auth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/store"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// ---------------------------------------------------------------------------
// Account lockout escalation (issue #72).
//
// Covers the acceptance criteria: soft lock with no DB write, hard lock with a
// DB write, auto-expiry, window reset, and — the one that makes the soft tier a
// real control rather than theatre — that a CORRECT password is still refused
// while soft-locked.
// ---------------------------------------------------------------------------

// lockoutFixture is a login stack with the lockout tiers fully wired, plus a
// registered account to attack.
type lockoutFixture struct {
	svc      *auth.AuthService
	pool     *pgxpool.Pool
	mail     *testhelper.RecordingMailer
	email    string
	password string
	tenantID int64
	userID   int64
}

func newLockoutFixture(t *testing.T) lockoutFixture {
	t.Helper()
	pool := testhelper.NewTestDB(t)
	rdb := testhelper.NewTestRedis(t)
	logger := testhelper.TestLogger()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Deliberately no CleanupTables here. It registers a t.Cleanup that TRUNCATEs
	// the shared database when THIS test ends, which for a package running tests
	// sequentially against one database destroys the seed every sibling test is
	// still relying on. Each test instead works on its own uniquely-named account
	// and removes only its own tenant-scoped policy row.
	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}

	jwtSvc := newTestJWTService(t, pool, "https://auth.emc.local")
	svc := auth.NewAuthService(pool, jwtSvc, logger).WithTOTP(nil, rdb)

	mail := &testhelper.RecordingMailer{}
	blockSvc := auth.NewAccountBlockService(pool, mail, "https://auth.test", logger).
		WithRedis(rdb).
		WithLockoutPolicy(svc.LockoutPolicy())
	svc.WithAccountBlocking(blockSvc)

	f := lockoutFixture{
		svc: svc, pool: pool, mail: mail,
		email:    uniqueEmail("lockout"),
		password: "CorrectPassword123!",
	}
	// No TenantSlug: registration resolves the platform tenant itself now, so the
	// field no longer exists on RegisterInput.
	if _, err := svc.Register(ctx, auth.RegisterInput{
		Email: f.email, Password: f.password,
		FirstName: "Lock", LastName: "Out",
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT id, tenant_id FROM users WHERE email = $1`, f.email).
		Scan(&f.userID, &f.tenantID); err != nil {
		t.Fatalf("resolve user: %v", err)
	}

	// Redis is shared across runs; a leftover soft lock from a previous test with a
	// recycled user id would make this one fail for the wrong reason.
	blockSvc.ClearSoftLock(ctx, f.tenantID, f.userID)
	return f
}

// failLogin submits n wrong passwords, asserting each one is refused.
//
// Returns nothing: most callers only want the side effect on the counter, and a
// returned error every one of them had to explicitly discard would be noise. Use
// failLoginLast when the error from the final attempt is the assertion.
func (f lockoutFixture) failLogin(t *testing.T, n int) {
	t.Helper()
	_ = f.failLoginLast(t, n) // discarding the error IS the point of this wrapper
}

// failLoginLast is failLogin, returning the error from the final attempt — the
// one that crossed whichever threshold the test is exercising.
func (f lockoutFixture) failLoginLast(t *testing.T, n int) error {
	t.Helper()
	var last error
	for i := 0; i < n; i++ {
		_, last = f.svc.Login(context.Background(), auth.LoginInput{
			Email: f.email, Password: "WrongPassword!",
		})
		if last == nil {
			t.Fatalf("attempt %d: expected failure, got success", i+1)
		}
	}
	return last
}

func (f lockoutFixture) dbState(t *testing.T) (isActive bool, attempts int, blockReason *string) {
	t.Helper()
	if err := f.pool.QueryRow(context.Background(), `
		SELECT is_active, failed_login_attempts, block_reason FROM users WHERE id = $1
	`, f.userID).Scan(&isActive, &attempts, &blockReason); err != nil {
		t.Fatalf("read user state: %v", err)
	}
	return
}

// setPolicy installs a tenant-scoped policy and clears the resolver cache so the
// next login sees it.
func (f lockoutFixture) setPolicy(t *testing.T, notify, soft, softSecs, hard int, hardSecs *int, window int) {
	t.Helper()
	// Upsert-by-hand: tests in this package share one tenant, so a previous test's
	// row may still be present.
	if _, err := f.pool.Exec(context.Background(), `
		DELETE FROM lockout_policies WHERE tenant_id = $1 AND application_id IS NULL
	`, f.tenantID); err != nil {
		t.Fatalf("clear prior policy: %v", err)
	}
	if _, err := f.pool.Exec(context.Background(), `
		INSERT INTO lockout_policies
		    (tenant_id, application_id, notify_user_threshold, soft_lock_threshold,
		     soft_lock_duration_seconds, hard_lock_threshold, hard_lock_duration_seconds,
		     failure_window_seconds, tenant_spike_threshold)
		VALUES ($1, NULL, $2, $3, $4, $5, $6, $7, 10)
	`, f.tenantID, notify, soft, softSecs, hard, hardSecs, window); err != nil {
		t.Fatalf("install policy: %v", err)
	}
	f.svc.LockoutPolicy().InvalidateCache()

	// Remove only this test's own row, and drop the cache again so the next test
	// does not resolve against a policy that no longer exists.
	t.Cleanup(func() {
		if _, err := f.pool.Exec(context.Background(), `
			DELETE FROM lockout_policies WHERE tenant_id = $1 AND application_id IS NULL
		`, f.tenantID); err != nil {
			t.Logf("cleanup policy: %v", err)
		}
		f.svc.LockoutPolicy().InvalidateCache()
	})
}

func TestLockout_SoftLockDoesNotTouchTheDatabase(t *testing.T) {
	f := newLockoutFixture(t)
	f.setPolicy(t, 3, 5, 900, 10, ptr(1800), 900)

	err := f.failLoginLast(t, 5)

	// The acceptance criterion: 5 failures soft-lock with NO account state change.
	isActive, attempts, reason := f.dbState(t)
	if !isActive {
		t.Error("soft lock must not set is_active = false")
	}
	if reason != nil {
		t.Errorf("soft lock must not set block_reason, got %q", *reason)
	}
	if attempts != 5 {
		t.Errorf("failed_login_attempts = %d, want 5", attempts)
	}

	var soft *auth.SoftLockError
	if !errors.As(err, &soft) {
		t.Fatalf("expected SoftLockError on the crossing attempt, got %T: %v", err, err)
	}
	if soft.RetryAfterSeconds() <= 0 {
		t.Error("Retry-After must be positive")
	}
	// Body must stay indistinguishable from any other credential failure.
	if err.Error() != "invalid credentials" {
		t.Errorf("error message = %q; a distinct message leaks that the account exists", err.Error())
	}
}

// The test that matters most: if a correct password lifted the soft lock, an
// attacker who guesses right on the next attempt walks straight in and the tier
// accomplishes nothing.
func TestLockout_CorrectPasswordStillRefusedWhileSoftLocked(t *testing.T) {
	f := newLockoutFixture(t)
	f.setPolicy(t, 3, 5, 900, 10, ptr(1800), 900)

	f.failLogin(t, 5)

	_, err := f.svc.Login(context.Background(), auth.LoginInput{
		Email: f.email, Password: f.password, // the RIGHT password
	})
	if err == nil {
		t.Fatal("correct password bypassed the soft lock — the tier is unenforced")
	}
	var soft *auth.SoftLockError
	if !errors.As(err, &soft) {
		t.Fatalf("expected SoftLockError, got %T: %v", err, err)
	}
}

func TestLockout_HardLockDisablesAccount(t *testing.T) {
	f := newLockoutFixture(t)
	// Soft tier out of the way so this exercises the hard threshold cleanly.
	f.setPolicy(t, 0, 9, 60, 10, ptr(1800), 900)

	f.failLogin(t, 10)

	isActive, _, reason := f.dbState(t)
	if isActive {
		t.Error("hard lock must set is_active = false")
	}
	if reason == nil || *reason != "failed_attempts" {
		t.Errorf("block_reason = %v, want \"failed_attempts\"", reason)
	}

	// A hard-locked account must be indistinguishable from a nonexistent one.
	_, err := f.svc.Login(context.Background(), auth.LoginInput{
		Email: f.email, Password: f.password,
	})
	if err == nil || err.Error() != "invalid credentials" {
		t.Errorf("hard-locked login error = %v, want \"invalid credentials\"", err)
	}
}

// Auto-expiry is the change that stops ten unauthenticated requests from being a
// permanent account-disable primitive.
func TestLockout_HardLockExpiresAndAdmitsLogin(t *testing.T) {
	f := newLockoutFixture(t)
	f.setPolicy(t, 0, 9, 60, 10, ptr(60), 900) // 60s expiry

	f.failLogin(t, 10)
	if isActive, _, _ := f.dbState(t); isActive {
		t.Fatal("expected the account to be hard-locked")
	}

	// Backdate the lock past its expiry rather than sleeping.
	if _, err := f.pool.Exec(context.Background(), `
		UPDATE users SET blocked_at = NOW() - INTERVAL '2 minutes' WHERE id = $1
	`, f.userID); err != nil {
		t.Fatalf("backdate lock: %v", err)
	}

	result, err := f.svc.Login(context.Background(), auth.LoginInput{
		Email: f.email, Password: f.password,
	})
	if err != nil {
		t.Fatalf("login after lock expiry failed: %v", err)
	}
	if result == nil || result.Token == nil {
		t.Fatal("expected tokens after the lock expired")
	}

	isActive, attempts, reason := f.dbState(t)
	if !isActive {
		t.Error("expiry must re-enable the account")
	}
	if reason != nil {
		t.Errorf("expiry must clear block_reason, got %q", *reason)
	}
	if attempts != 0 {
		t.Errorf("expiry must reset the counter, got %d", attempts)
	}
}

// The candidate query admits any locked row past a 60-second floor so the
// authoritative check can run, because in generic mode the tenant is unknown at
// that point. This asserts the floor is only an admission gate: a tenant whose
// expiry is LONGER must still have its accounts refused until its own deadline,
// or the widened predicate would have become an early-unlock bug.
func TestLockout_LongerTenantExpiryStillHoldsPastAdmitWindow(t *testing.T) {
	f := newLockoutFixture(t)
	f.setPolicy(t, 0, 9, 60, 10, ptr(3600), 900) // 1 hour expiry

	f.failLogin(t, 10)

	// Well past the 60s admission floor, nowhere near the tenant's own hour.
	if _, err := f.pool.Exec(context.Background(), `
		UPDATE users SET blocked_at = NOW() - INTERVAL '5 minutes' WHERE id = $1
	`, f.userID); err != nil {
		t.Fatalf("backdate lock: %v", err)
	}

	if _, err := f.svc.Login(context.Background(), auth.LoginInput{
		Email: f.email, Password: f.password,
	}); err == nil {
		t.Fatal("account unlocked after 5 minutes under a 1-hour policy — the admit window is unlocking early")
	}
	if isActive, _, _ := f.dbState(t); isActive {
		t.Error("account was re-enabled before its tenant's expiry elapsed")
	}
}

// An operator's decision must never be undone by a clock.
func TestLockout_AdminBlockNeverAutoExpires(t *testing.T) {
	f := newLockoutFixture(t)
	f.setPolicy(t, 0, 9, 60, 10, ptr(60), 900)

	if _, err := f.pool.Exec(context.Background(), `
		UPDATE users SET is_active = false, blocked_at = NOW() - INTERVAL '1 year',
		                 block_reason = 'admin'
		WHERE id = $1
	`, f.userID); err != nil {
		t.Fatalf("apply admin block: %v", err)
	}

	if _, err := f.svc.Login(context.Background(), auth.LoginInput{
		Email: f.email, Password: f.password,
	}); err == nil {
		t.Fatal("an administrative block must not expire, however old it is")
	}

	isActive, _, reason := f.dbState(t)
	if isActive {
		t.Error("admin block was lifted by the expiry path")
	}
	if reason == nil || *reason != "admin" {
		t.Errorf("block_reason = %v, want \"admin\" preserved", reason)
	}
}

func TestLockout_WindowResetStartsCounterOver(t *testing.T) {
	f := newLockoutFixture(t)
	f.setPolicy(t, 0, 5, 900, 10, ptr(1800), 900)

	f.failLogin(t, 3)
	if _, attempts, _ := f.dbState(t); attempts != 3 {
		t.Fatalf("attempts = %d, want 3", attempts)
	}

	// Age the last failure out of the window.
	if _, err := f.pool.Exec(context.Background(), `
		UPDATE users SET last_failed_login_at = NOW() - INTERVAL '1 hour' WHERE id = $1
	`, f.userID); err != nil {
		t.Fatalf("age failure: %v", err)
	}

	f.failLogin(t, 1)
	if _, attempts, _ := f.dbState(t); attempts != 1 {
		t.Errorf("attempts = %d after the window elapsed, want 1 — stale failures must not accumulate", attempts)
	}
}

func TestLockout_SuccessfulLoginClearsCounter(t *testing.T) {
	f := newLockoutFixture(t)
	f.setPolicy(t, 0, 5, 900, 10, ptr(1800), 900)

	f.failLogin(t, 3)
	if _, err := f.svc.Login(context.Background(), auth.LoginInput{
		Email: f.email, Password: f.password,
	}); err != nil {
		t.Fatalf("login with the correct password failed: %v", err)
	}
	if _, attempts, _ := f.dbState(t); attempts != 0 {
		t.Errorf("attempts = %d after a successful sign-in, want 0", attempts)
	}
}

// Every failure mode must return the same body, or the differences become an
// account-enumeration oracle.
func TestLockout_AllFailuresReturnIdenticalMessage(t *testing.T) {
	f := newLockoutFixture(t)
	f.setPolicy(t, 0, 5, 900, 10, ptr(1800), 900)
	ctx := context.Background()

	cases := map[string]auth.LoginInput{
		"unknown email":  {Email: "nobody-" + f.email, Password: f.password},
		"wrong password": {Email: f.email, Password: "WrongPassword!"},
	}
	for name, in := range cases {
		_, err := f.svc.Login(ctx, in)
		if err == nil {
			t.Fatalf("%s: expected failure", name)
		}
		if err.Error() != "invalid credentials" {
			t.Errorf("%s: message = %q, want \"invalid credentials\"", name, err.Error())
		}
	}

	// Soft-locked and hard-locked must read the same.
	f.failLogin(t, 5)
	if _, err := f.svc.Login(ctx, auth.LoginInput{Email: f.email, Password: f.password}); err == nil ||
		err.Error() != "invalid credentials" {
		t.Errorf("soft-locked: message = %v, want \"invalid credentials\"", err)
	}
	f.failLogin(t, 5)
	if _, err := f.svc.Login(ctx, auth.LoginInput{Email: f.email, Password: f.password}); err == nil ||
		err.Error() != "invalid credentials" {
		t.Errorf("hard-locked: message = %v, want \"invalid credentials\"", err)
	}
}

// The warning email is the tier most likely to regress into a flood: without the
// once-per-window marker it fires on attempt 3 and again on 4, 5, 6...
func TestLockout_UserWarnedOncePerWindow(t *testing.T) {
	f := newLockoutFixture(t)
	f.setPolicy(t, 3, 8, 900, 10, ptr(1800), 900)

	f.failLogin(t, 6) // crosses the notify threshold four times over

	// Sends are detached (see sendBlockedAccountAsync — an inline SMTP handshake on
	// the login path is both slow and a timing oracle), so poll rather than read
	// once. Polling for a STABLE count, not a minimum: the bug this guards against
	// is sending too MANY, which a first-match check would not catch.
	warnings := countWarningsWhenStable(t, f.mail)
	if warnings != 1 {
		t.Errorf("sent %d warning emails across attempts 3-6, want exactly 1", warnings)
	}
}

// countWarningsWhenStable waits for the detached notification goroutines to settle
// and returns how many warning emails were sent.
//
// Deliberately waits out a quiet period instead of returning on the first send: a
// regression here means duplicate mail, so the assertion needs the final count.
func countWarningsWhenStable(t *testing.T, mail *testhelper.RecordingMailer) int {
	t.Helper()
	count := func() int {
		n := 0
		for _, m := range mail.BlockedAccounts() {
			if m.Reason == "failed_attempts_warning" {
				n++
			}
		}
		return n
	}
	last, stable := -1, 0
	for i := 0; i < 60; i++ { // ≤3s, far beyond a local fake mailer's latency
		n := count()
		if n == last {
			if stable++; stable >= 5 {
				return n
			}
		} else {
			last, stable = n, 0
		}
		time.Sleep(50 * time.Millisecond)
	}
	return count()
}

// TestLockout_NotificationDoesNotBlockTheResponse is the regression guard for a
// real production defect: the tier emails were sent inline, so the attempt that
// crossed a threshold waited for a full SMTP handshake — nine seconds against a
// remote relay in practice.
//
// That is two faults. The user waits seconds for a 401 that should be instant,
// and the wait is a TIMING ORACLE: milliseconds on attempts 1-2 versus seconds on
// attempt 3 tells an attacker exactly which addresses have accounts and when a
// threshold was crossed — a far larger leak than the one loginCompareFloor exists
// to prevent.
//
// The mailer here is a local fake, so it cannot reproduce SMTP latency. What this
// asserts is the structural property that makes latency irrelevant: the crossing
// attempt must not take materially longer than the ones before it.
func TestLockout_NotificationDoesNotBlockTheResponse(t *testing.T) {
	f := newLockoutFixture(t)
	f.setPolicy(t, 3, 5, 900, 10, ptr(1800), 900)
	ctx := context.Background()

	attempt := func() time.Duration {
		start := time.Now()
		_, err := f.svc.Login(ctx, auth.LoginInput{Email: f.email, Password: "WrongPassword!"})
		if err == nil {
			t.Fatal("expected the attempt to fail")
		}
		return time.Since(start)
	}

	// Attempts 1-2 send nothing; attempt 3 crosses the notify threshold.
	baseline := attempt()
	if d := attempt(); d > baseline {
		baseline = d
	}
	crossing := attempt()

	// Generous multiple: bcrypt dominates every attempt and varies run to run, so
	// this is calibrated to catch "a network round trip appeared", not jitter.
	if limit := baseline * 3; crossing > limit {
		t.Errorf("crossing attempt took %s vs %s baseline (limit %s) — the notification looks synchronous, "+
			"which both delays the user and leaks threshold state through response timing",
			crossing, baseline, limit)
	}
}

func ptr(n int) *int { return &n }

// TestSeedRestoresPlatformLockoutPolicy guards a failure mode that already bit
// this codebase once with session_policies.
//
// Migration 00070 seeds the platform-default row, but goose marks the migration
// applied and never runs it again — so once the row is deleted it stays deleted.
// And it IS deleted routinely: lockout_policies has a foreign key to tenants, so
// the test helper's `TRUNCATE tenants CASCADE` empties the whole table. Without a
// re-seed on every boot, a developer who had run the suite would silently get
// compiled-in defaults, with the console showing one policy and the login path
// enforcing another.
func TestSeedRestoresPlatformLockoutPolicy(t *testing.T) {
	pool := testhelper.NewTestDB(t)
	ctx := context.Background()

	if _, err := pool.Exec(ctx, `
		DELETE FROM lockout_policies WHERE tenant_id IS NULL AND application_id IS NULL
	`); err != nil {
		t.Fatalf("delete platform default: %v", err)
	}

	if err := store.RunSeed(ctx, pool, testhelper.TestLogger()); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}

	var n int
	if err := pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM lockout_policies WHERE tenant_id IS NULL AND application_id IS NULL
	`).Scan(&n); err != nil {
		t.Fatalf("count platform defaults: %v", err)
	}
	if n != 1 {
		t.Fatalf("platform-default lockout policy rows = %d, want exactly 1 after seed", n)
	}

	// Idempotent: a second seed must not add a duplicate.
	if err := store.RunSeed(ctx, pool, testhelper.TestLogger()); err != nil {
		t.Fatalf("second RunSeed: %v", err)
	}
	if err := pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM lockout_policies WHERE tenant_id IS NULL AND application_id IS NULL
	`).Scan(&n); err != nil {
		t.Fatalf("re-count: %v", err)
	}
	if n != 1 {
		t.Errorf("after a second seed, platform-default rows = %d, want 1", n)
	}
}
