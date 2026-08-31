package auth

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/engineersmind/emc-auth-server/internal/store"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// TestDefaultLockoutPolicyMatchesSeed guards the one invariant that cannot be
// enforced by the compiler: DefaultLockoutPolicy is the fallback used when the
// policy table is unreadable, so if it drifts from the row migration 00086 seeds,
// a database blip silently changes every tenant's lockout behaviour instead of
// preserving it. Mirrors TestDefaultPolicyMatchesSeed for session policy.
func TestDefaultLockoutPolicyMatchesSeed(t *testing.T) {
	pool := testhelper.NewTestDB(t)

	// Re-seed rather than calling CleanupTables. This test READS the seeded
	// platform-default row, and CleanupTables both registers a TRUNCATE that runs
	// when this test ends (destroying the row for every sibling still to run) and
	// leaves this test at the mercy of whether an earlier one already truncated it.
	// RunSeed is idempotent and restores the row if it is missing, so the test
	// asserts on the seed regardless of what ran before it.
	if err := store.RunSeed(context.Background(), pool, testhelper.TestLogger()); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}

	var notify, soft, softDur, hard, window, spike int
	var hardDur *int
	err := pool.QueryRow(context.Background(), `
		SELECT notify_user_threshold, soft_lock_threshold, soft_lock_duration_seconds,
		       hard_lock_threshold, hard_lock_duration_seconds,
		       failure_window_seconds, tenant_spike_threshold
		FROM lockout_policies
		WHERE tenant_id IS NULL AND application_id IS NULL
	`).Scan(&notify, &soft, &softDur, &hard, &hardDur, &window, &spike)
	if err != nil {
		t.Fatalf("read seeded platform-default lockout policy: %v", err)
	}

	d := DefaultLockoutPolicy
	if notify != d.NotifyUserThreshold {
		t.Errorf("notify_user_threshold: seed %d, DefaultLockoutPolicy %d", notify, d.NotifyUserThreshold)
	}
	if soft != d.SoftLockThreshold {
		t.Errorf("soft_lock_threshold: seed %d, DefaultLockoutPolicy %d", soft, d.SoftLockThreshold)
	}
	if got := time.Duration(softDur) * time.Second; got != d.SoftLockDuration {
		t.Errorf("soft_lock_duration: seed %s, DefaultLockoutPolicy %s", got, d.SoftLockDuration)
	}
	if hard != d.HardLockThreshold {
		t.Errorf("hard_lock_threshold: seed %d, DefaultLockoutPolicy %d", hard, d.HardLockThreshold)
	}
	if hardDur == nil {
		t.Error("hard_lock_duration_seconds is NULL in the seed: the shipped default must EXPIRE, " +
			"otherwise ten unauthenticated requests disable an account until an operator intervenes")
	} else if got := time.Duration(*hardDur) * time.Second; got != d.HardLockDuration {
		t.Errorf("hard_lock_duration: seed %s, DefaultLockoutPolicy %s", got, d.HardLockDuration)
	}
	if got := time.Duration(window) * time.Second; got != d.FailureWindow {
		t.Errorf("failure_window: seed %s, DefaultLockoutPolicy %s", got, d.FailureWindow)
	}
	if spike != d.TenantSpikeThreshold {
		t.Errorf("tenant_spike_threshold: seed %d, DefaultLockoutPolicy %d", spike, d.TenantSpikeThreshold)
	}
}

// TestDefaultLockoutPolicyEscalates checks the shipped default satisfies the
// ordering the CHECK constraints require, so a bad edit to DefaultLockoutPolicy is
// caught here rather than as a constraint violation at runtime.
func TestDefaultLockoutPolicyEscalates(t *testing.T) {
	d := DefaultLockoutPolicy
	if d.SoftLockThreshold >= d.HardLockThreshold {
		t.Errorf("soft threshold %d must be below hard threshold %d, or the soft tier is unreachable",
			d.SoftLockThreshold, d.HardLockThreshold)
	}
	if d.NotifyUserThreshold > d.SoftLockThreshold {
		t.Errorf("notify threshold %d must not exceed soft threshold %d, or the user is warned only after being locked out",
			d.NotifyUserThreshold, d.SoftLockThreshold)
	}
	if d.HardLockDuration <= 0 {
		t.Error("DefaultLockoutPolicy.HardLockDuration must be positive: a permanent lock by default is a denial-of-service primitive")
	}
}

func TestHardLockExpiresAt(t *testing.T) {
	base := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)

	t.Run("expiring policy reports a deadline", func(t *testing.T) {
		p := LockoutPolicy{HardLockDuration: 30 * time.Minute}
		at, ok := p.HardLockExpiresAt(base)
		if !ok {
			t.Fatal("expected ok for a policy with a duration")
		}
		if want := base.Add(30 * time.Minute); !at.Equal(want) {
			t.Errorf("got %s, want %s", at, want)
		}
	})

	// The important half: a caller that treated the zero time as "already expired"
	// would unlock every permanently locked account in the tenant.
	t.Run("permanent policy reports no deadline", func(t *testing.T) {
		p := LockoutPolicy{HardLockDuration: 0}
		if _, ok := p.HardLockExpiresAt(base); ok {
			t.Error("expected ok=false for a permanent lock")
		}
	})
}

func TestSoftLockErrorHidesLockState(t *testing.T) {
	// The message must be indistinguishable from any other credential failure:
	// revealing that an account is locked also reveals that it exists.
	e := &SoftLockError{RetryAfter: 5 * time.Minute}
	if got := e.Error(); got != "invalid credentials" {
		t.Errorf("SoftLockError.Error() = %q, want %q — a distinct message is an account-enumeration oracle", got, "invalid credentials")
	}

	// containsMsg in the handlers matches on this string, so the 401 path depends
	// on it staying exactly this.
	if !errorsIs(e, ErrSoftLocked) {
		t.Error("SoftLockError must match ErrSoftLocked via errors.Is")
	}

	t.Run("retry-after floors at 1", func(t *testing.T) {
		// A Retry-After of 0 invites an immediate retry that would be refused again.
		if got := (&SoftLockError{RetryAfter: 0}).RetryAfterSeconds(); got != 1 {
			t.Errorf("RetryAfterSeconds() = %d, want 1", got)
		}
		if got := (&SoftLockError{RetryAfter: 90 * time.Second}).RetryAfterSeconds(); got != 90 {
			t.Errorf("RetryAfterSeconds() = %d, want 90", got)
		}
	})
}

// errorsIs is a tiny local shim so this file does not import errors solely for
// one call in one assertion.
func errorsIs(err, target error) bool {
	type isser interface{ Is(error) bool }
	if i, ok := err.(isser); ok {
		return i.Is(target)
	}
	return err == target
}

func TestLockoutOverridesFromEnv(t *testing.T) {
	// Every LOCKOUT_* key this test touches, cleared before each case so a value
	// set by one subtest cannot leak into the next.
	keys := []string{
		"LOCKOUT_NOTIFY_THRESHOLD", "LOCKOUT_SOFT_THRESHOLD", "LOCKOUT_SOFT_TTL",
		"LOCKOUT_HARD_THRESHOLD", "LOCKOUT_HARD_TTL", "LOCKOUT_WINDOW",
		"LOCKOUT_SPIKE_THRESHOLD",
	}
	clear := func(t *testing.T) {
		t.Helper()
		for _, k := range keys {
			t.Setenv(k, "")
			_ = os.Unsetenv(k)
		}
	}

	t.Run("unset yields an empty override set", func(t *testing.T) {
		clear(t)
		ov, err := LockoutOverridesFromEnv()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !ov.Empty() {
			t.Error("expected Empty() with nothing set — a non-empty set would rewrite the seeded row on every boot")
		}
	})

	t.Run("durations and thresholds parse", func(t *testing.T) {
		clear(t)
		t.Setenv("LOCKOUT_SOFT_TTL", "10m")
		t.Setenv("LOCKOUT_HARD_THRESHOLD", "8")
		ov, err := LockoutOverridesFromEnv()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ov.SoftDuration == nil || *ov.SoftDuration != 10*time.Minute {
			t.Errorf("SoftDuration = %v, want 10m", ov.SoftDuration)
		}
		if ov.HardThreshold == nil || *ov.HardThreshold != 8 {
			t.Errorf("HardThreshold = %v, want 8", ov.HardThreshold)
		}
		if ov.Empty() {
			t.Error("expected non-empty override set")
		}
	})

	t.Run("hard TTL off means permanent", func(t *testing.T) {
		clear(t)
		t.Setenv("LOCKOUT_HARD_TTL", "off")
		ov, err := LockoutOverridesFromEnv()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !ov.HardLockDisabled {
			t.Error("expected HardLockDisabled for LOCKOUT_HARD_TTL=off")
		}
		if ov.HardDuration != nil {
			t.Error("HardDuration must stay nil when permanence was requested")
		}
	})

	// Malformed input must fail loudly. A deployment that meant 15 minutes and
	// typo'd the unit should hear about it at boot, not discover months later that
	// the seeded default was in force the whole time.
	t.Run("malformed values are rejected", func(t *testing.T) {
		for _, tc := range []struct{ key, val string }{
			{"LOCKOUT_SOFT_TTL", "15"},         // no unit
			{"LOCKOUT_SOFT_TTL", "-5m"},        // negative
			{"LOCKOUT_HARD_TTL", "sometimes"},  // neither duration nor "off"
			{"LOCKOUT_HARD_THRESHOLD", "many"}, // not an integer
			{"LOCKOUT_SOFT_THRESHOLD", "-1"},   // negative
		} {
			t.Run(tc.key+"="+tc.val, func(t *testing.T) {
				clear(t)
				t.Setenv(tc.key, tc.val)
				if _, err := LockoutOverridesFromEnv(); err == nil {
					t.Errorf("expected an error for %s=%q", tc.key, tc.val)
				}
			})
		}
	})
}
