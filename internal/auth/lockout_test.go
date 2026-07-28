package auth_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/engineersmind/emc-auth-server/internal/audit"
	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/store"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// Integration tests for per-account brute-force lockout (issue #72).
//
// Thresholds are deliberately tiny (2/3 rather than the shipped 5/10) so a test
// spends two bcrypt-cost-12 comparisons instead of ten; the tier LOGIC is what
// is under test, not the default numbers.

const lockoutTestPassword = "SecPass123!"

// newLockoutTestService wires an AuthService with lockout enabled at the given
// thresholds, plus a fast-flushing audit logger so lock events can be asserted.
// Returns the drain func that must run before querying audit_logs.
func newLockoutTestService(t *testing.T, soft, hard int) (*auth.AuthService, *pgxpool.Pool, *redis.Client, func()) {
	t.Helper()

	pool := testhelper.NewTestDB(t)
	rdb := testhelper.NewTestRedis(t)
	logger := testhelper.TestLogger()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}

	totpSvc, err := auth.NewTOTPService(pool, os.Getenv("TOTP_ENCRYPTION_KEY"), logger)
	if err != nil {
		t.Fatalf("NewTOTPService: %v", err)
	}

	auditLog := audit.New(pool, logger, audit.WithFlushInterval(20*time.Millisecond))
	drain := func() {
		dctx, dcancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer dcancel()
		if err := auditLog.Close(dctx); err != nil {
			t.Logf("audit close: %v", err)
		}
	}

	svc := auth.NewAuthService(pool, auth.NewJWTService(pool, "https://auth.emc.local"), logger).
		WithTOTP(totpSvc, rdb).
		WithAudit(auditLog).
		// 15/60-minute windows: long enough that nothing expires mid-test, so a
		// failure here is a logic bug and never a timing race.
		WithLockout(rdb, auth.NewLockoutConfig(soft, hard, 15, 60))

	testhelper.CleanupTables(t, pool)
	return svc, pool, rdb, drain
}

// lockoutEmail generates a collision-free address per test.
func lockoutEmail(prefix string) string {
	return fmt.Sprintf("%s-%d@lockout.test", prefix, time.Now().UnixNano())
}

// failCounterKey mirrors internal/auth.loginFailKey so a test can inspect the
// counter without exporting it. Kept in lockstep by TestLockout_CounterKeyShape.
func failCounterKey(email string) string {
	return "login:fail:" + auth.HashToken(strings.ToLower(strings.TrimSpace(email)))
}

// registerLockoutUser creates a tenant-level user in the seeded "emc" tenant.
func registerLockoutUser(t *testing.T, svc *auth.AuthService, email string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := svc.Register(ctx, auth.RegisterInput{
		TenantSlug: "emc",
		Email:      email,
		Password:   lockoutTestPassword,
		FirstName:  "Lock",
		LastName:   "Out",
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}
}

// attemptLogin runs one login and returns its error (nil on success).
func attemptLogin(t *testing.T, svc *auth.AuthService, email, password string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := svc.Login(ctx, auth.LoginInput{Email: email, Password: password})
	return err
}

// lockedUntil reads the persisted lock state for an email.
func lockedUntil(t *testing.T, pool *pgxpool.Pool, email string) (*time.Time, *string, bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var until *time.Time
	var reason *string
	var isActive bool
	err := pool.QueryRow(ctx, `
		SELECT locked_until, locked_reason, is_active FROM users WHERE email = $1
	`, email).Scan(&until, &reason, &isActive)
	if err != nil {
		t.Fatalf("read lock state: %v", err)
	}
	return until, reason, isActive
}

// TestLockout_SoftLockRefusesCorrectPassword is the core soft-tier guarantee:
// once the threshold is reached the right password stops working for the rest of
// the window, and nothing is written to the users row.
func TestLockout_SoftLockRefusesCorrectPassword(t *testing.T) {
	svc, pool, rdb, drain := newLockoutTestService(t, 2, 0)
	defer drain()

	email := lockoutEmail("softlock")
	registerLockoutUser(t, svc, email)

	for i := 1; i <= 2; i++ {
		if err := attemptLogin(t, svc, email, "WrongPass!"); err == nil {
			t.Fatalf("attempt %d: expected failure with wrong password", i)
		}
	}

	// The correct password must now be refused — that is what makes this a lock
	// rather than a rate limit.
	if err := attemptLogin(t, svc, email, lockoutTestPassword); err == nil {
		t.Fatal("soft-locked account accepted the correct password")
	} else if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("soft lock returned %v, want ErrInvalidCredentials", err)
	}

	// No database state changed: a soft lock lives entirely in Redis.
	until, reason, isActive := lockedUntil(t, pool, email)
	if until != nil {
		t.Errorf("soft lock wrote locked_until = %v, want NULL (no DB write at this tier)", until)
	}
	if reason != nil {
		t.Errorf("soft lock wrote locked_reason = %q, want NULL", *reason)
	}
	if !isActive {
		t.Error("soft lock cleared is_active; it must never touch the administrative block flag")
	}

	// The counter is armed with the configured window, so the lock self-heals.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ttl, err := rdb.PTTL(ctx, failCounterKey(email)).Result()
	if err != nil {
		t.Fatalf("PTTL: %v", err)
	}
	if ttl <= 0 || ttl > 15*time.Minute {
		t.Errorf("counter TTL = %v, want 0 < ttl <= 15m (an unbounded key would lock the account forever)", ttl)
	}
}

// TestLockout_HardLockPersistsIndependentlyOfRedis proves the hard tier is
// durable: the lock survives losing the Redis counter entirely, which is the
// whole reason locked_until exists as a column.
func TestLockout_HardLockPersistsIndependentlyOfRedis(t *testing.T) {
	svc, pool, rdb, drain := newLockoutTestService(t, 2, 3)
	defer drain()

	email := lockoutEmail("hardlock")
	registerLockoutUser(t, svc, email)

	// Three failures: the 3rd arrives while the soft lock is already in force and
	// must still be counted, otherwise the hard tier is unreachable.
	for i := 1; i <= 3; i++ {
		if err := attemptLogin(t, svc, email, "WrongPass!"); err == nil {
			t.Fatalf("attempt %d: expected failure", i)
		}
	}

	until, reason, isActive := lockedUntil(t, pool, email)
	if until == nil {
		t.Fatal("hard threshold reached but locked_until is NULL")
	}
	if !until.After(time.Now()) {
		t.Errorf("locked_until = %v is already in the past", until)
	}
	if until.After(time.Now().Add(2 * time.Hour)) {
		t.Errorf("locked_until = %v exceeds the configured 60m duration", until)
	}
	if reason == nil || *reason != "brute_force" {
		t.Errorf("locked_reason = %v, want \"brute_force\"", reason)
	}
	// The non-negotiable: a hard lock must not masquerade as an admin block.
	if !isActive {
		t.Error("hard lock set is_active=false; that would be an attacker-triggered permanent DoS")
	}

	// Drop the counter to simulate a Redis restart / window expiry. The lock must
	// still hold, since only the DB row records it now.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := rdb.Del(ctx, failCounterKey(email)).Err(); err != nil {
		t.Fatalf("Del counter: %v", err)
	}
	if err := attemptLogin(t, svc, email, lockoutTestPassword); err == nil {
		t.Fatal("hard-locked account accepted the correct password after the Redis counter was dropped")
	} else if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("hard lock returned %v, want ErrInvalidCredentials", err)
	}
}

// TestLockout_SuccessfulLoginResetsWindow covers the window-reset criterion: a
// correct password clears accumulated failures so unrelated later typos start
// from zero rather than inheriting an old partial count.
func TestLockout_SuccessfulLoginResetsWindow(t *testing.T) {
	svc, _, rdb, drain := newLockoutTestService(t, 3, 0)
	defer drain()

	email := lockoutEmail("windowreset")
	registerLockoutUser(t, svc, email)

	if err := attemptLogin(t, svc, email, "WrongPass!"); err == nil {
		t.Fatal("expected failure with wrong password")
	}
	if err := attemptLogin(t, svc, email, "WrongPass!"); err == nil {
		t.Fatal("expected failure with wrong password")
	}

	// One below the threshold: the correct password still works and clears the count.
	if err := attemptLogin(t, svc, email, lockoutTestPassword); err != nil {
		t.Fatalf("login below threshold failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	n, err := rdb.Exists(ctx, failCounterKey(email)).Result()
	if err != nil {
		t.Fatalf("Exists: %v", err)
	}
	if n != 0 {
		t.Fatal("successful login left the failure counter in place; later typos would inherit it")
	}

	// Two fresh failures must therefore NOT lock a 3-strike account.
	for i := 0; i < 2; i++ {
		if err := attemptLogin(t, svc, email, "WrongPass!"); err == nil {
			t.Fatal("expected failure with wrong password")
		}
	}
	if err := attemptLogin(t, svc, email, lockoutTestPassword); err != nil {
		t.Fatalf("counter was not reset — login locked out after 2 post-reset failures: %v", err)
	}
}

// TestLockout_ErrorIsIndistinguishableAcrossStates is the enumeration-safety
// criterion: an unknown address, a wrong password, and a locked account must be
// byte-identical to the caller. Anything else re-introduces the oracle that the
// generic error exists to close.
func TestLockout_ErrorIsIndistinguishableAcrossStates(t *testing.T) {
	svc, _, _, drain := newLockoutTestService(t, 2, 3)
	defer drain()

	email := lockoutEmail("identical")
	registerLockoutUser(t, svc, email)

	unknown := attemptLogin(t, svc, lockoutEmail("nosuchuser"), lockoutTestPassword)
	wrongPass := attemptLogin(t, svc, email, "WrongPass!")
	soft := func() error {
		_ = attemptLogin(t, svc, email, "WrongPass!") // reaches the soft threshold
		return attemptLogin(t, svc, email, lockoutTestPassword)
	}()
	hard := attemptLogin(t, svc, email, lockoutTestPassword) // counter now at the hard tier

	for name, err := range map[string]error{
		"unknown email":  unknown,
		"wrong password": wrongPass,
		"soft locked":    soft,
		"hard locked":    hard,
	} {
		if err == nil {
			t.Fatalf("%s: expected an error", name)
		}
		if !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Errorf("%s: errors.Is(ErrInvalidCredentials) = false (err = %v)", name, err)
		}
		if got := err.Error(); got != "invalid credentials" {
			t.Errorf("%s: message = %q, want %q — a distinct message leaks account state",
				name, got, "invalid credentials")
		}
	}
}

// TestLockout_CounterIsCaseInsensitive guards a trivial bypass: if the counter
// keyed on the raw address, an attacker could mint a fresh budget per attempt
// just by varying capitalisation.
func TestLockout_CounterIsCaseInsensitive(t *testing.T) {
	svc, _, _, drain := newLockoutTestService(t, 2, 0)
	defer drain()

	email := lockoutEmail("casefold")
	registerLockoutUser(t, svc, email)

	if err := attemptLogin(t, svc, email, "WrongPass!"); err == nil {
		t.Fatal("expected failure")
	}
	if err := attemptLogin(t, svc, strings.ToUpper(email), "WrongPass!"); err == nil {
		t.Fatal("expected failure")
	}

	// Both attempts shared one counter, so the account is now locked.
	if err := attemptLogin(t, svc, email, lockoutTestPassword); err == nil {
		t.Fatal("case-varied attempts did not share a counter — lockout is bypassable by changing case")
	}
}

// TestLockout_DisabledByZeroThreshold confirms the feature is genuinely opt-out:
// with the threshold at 0, Login behaves exactly as it did before issue #72.
func TestLockout_DisabledByZeroThreshold(t *testing.T) {
	svc, pool, _, drain := newLockoutTestService(t, 0, 0)
	defer drain()

	email := lockoutEmail("disabled")
	registerLockoutUser(t, svc, email)

	for i := 0; i < 6; i++ {
		if err := attemptLogin(t, svc, email, "WrongPass!"); err == nil {
			t.Fatalf("attempt %d: expected failure", i)
		}
	}
	if err := attemptLogin(t, svc, email, lockoutTestPassword); err != nil {
		t.Fatalf("lockout disabled but login was refused after 6 failures: %v", err)
	}
	if until, _, _ := lockedUntil(t, pool, email); until != nil {
		t.Errorf("lockout disabled but locked_until = %v", until)
	}
}

// TestLockout_AuditTrail asserts each tier leaves the trail an operator needs to
// tell "the guard tripped" from "an attack kept running after it tripped".
func TestLockout_AuditTrail(t *testing.T) {
	svc, pool, _, drain := newLockoutTestService(t, 2, 3)

	email := lockoutEmail("audit")
	registerLockoutUser(t, svc, email)

	for i := 1; i <= 3; i++ {
		if err := attemptLogin(t, svc, email, "WrongPass!"); err == nil {
			t.Fatalf("attempt %d: expected failure", i)
		}
	}
	// A 4th attempt arrives against an already-locked account.
	if err := attemptLogin(t, svc, email, lockoutTestPassword); err == nil {
		t.Fatal("expected failure against locked account")
	}

	drain() // flush the async audit pipeline before asserting

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, action := range []string{
		"auth.account_soft_locked",
		"auth.account_hard_locked",
		"auth.login_blocked_account_locked",
	} {
		var count int
		if err := pool.QueryRow(ctx, `
			SELECT COUNT(*) FROM audit_logs WHERE action = $1 AND actor_email = $2
		`, action, email).Scan(&count); err != nil {
			t.Fatalf("count %s: %v", action, err)
		}
		if count == 0 {
			t.Errorf("no %s audit row written", action)
		}
	}
}

// TestLockout_ResetLoginFailuresClearsSoftLock covers the hook the admin unlock
// endpoint depends on: clearing the counter must make the account immediately
// usable again, otherwise the unlock button appears to do nothing until the
// window elapses.
func TestLockout_ResetLoginFailuresClearsSoftLock(t *testing.T) {
	svc, _, _, drain := newLockoutTestService(t, 2, 0)
	defer drain()

	email := lockoutEmail("resetfailures")
	registerLockoutUser(t, svc, email)

	for i := 0; i < 2; i++ {
		if err := attemptLogin(t, svc, email, "WrongPass!"); err == nil {
			t.Fatal("expected failure")
		}
	}
	if err := attemptLogin(t, svc, email, lockoutTestPassword); err == nil {
		t.Fatal("expected the account to be soft-locked")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := svc.ResetLoginFailures(ctx, email); err != nil {
		t.Fatalf("ResetLoginFailures: %v", err)
	}

	if err := attemptLogin(t, svc, email, lockoutTestPassword); err != nil {
		t.Fatalf("login still refused after ResetLoginFailures: %v", err)
	}
}

// TestLockout_NewLockoutConfigClamping pins the guards against a misconfigured
// deployment — a pure-logic test, so it runs without DB or Redis.
func TestLockout_NewLockoutConfigClamping(t *testing.T) {
	tests := []struct {
		name                    string
		soft, hard              int
		windowMin, hardMin      int
		wantSoft, wantHard      int
		wantWindow, wantHardDur time.Duration
	}{
		{
			name: "negatives disable rather than invert",
			soft: -1, hard: -5, windowMin: 15, hardMin: 60,
			wantSoft: 0, wantHard: 0, wantWindow: 15 * time.Minute, wantHardDur: time.Hour,
		},
		{
			name: "hard below soft is raised to soft so the soft tier stays reachable",
			soft: 5, hard: 2, windowMin: 15, hardMin: 60,
			wantSoft: 5, wantHard: 5, wantWindow: 15 * time.Minute, wantHardDur: time.Hour,
		},
		{
			name: "zero durations fall back instead of producing an instant or eternal lock",
			soft: 5, hard: 10, windowMin: 0, hardMin: 0,
			wantSoft: 5, wantHard: 10, wantWindow: 15 * time.Minute, wantHardDur: time.Hour,
		},
		{
			name: "valid values pass through untouched",
			soft: 3, hard: 7, windowMin: 20, hardMin: 120,
			wantSoft: 3, wantHard: 7, wantWindow: 20 * time.Minute, wantHardDur: 2 * time.Hour,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := auth.NewLockoutConfig(tc.soft, tc.hard, tc.windowMin, tc.hardMin)
			if got.SoftThreshold != tc.wantSoft {
				t.Errorf("SoftThreshold = %d, want %d", got.SoftThreshold, tc.wantSoft)
			}
			if got.HardThreshold != tc.wantHard {
				t.Errorf("HardThreshold = %d, want %d", got.HardThreshold, tc.wantHard)
			}
			if got.Window != tc.wantWindow {
				t.Errorf("Window = %v, want %v", got.Window, tc.wantWindow)
			}
			if got.HardDuration != tc.wantHardDur {
				t.Errorf("HardDuration = %v, want %v", got.HardDuration, tc.wantHardDur)
			}
		})
	}
}
