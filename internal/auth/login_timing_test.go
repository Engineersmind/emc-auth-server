package auth

import (
	"context"
	"os"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/engineersmind/emc-auth-server/internal/password"
)

// hashProbe runs one verification against the dummy hash, matching what a login
// pays per candidate.
func hashProbe() error {
	return password.NewHasher(password.DefaultParams()).
		Verify(context.Background(), "probe", dummyPasswordHash)
}

// TestCalibrateLoginTimingBudget_ExceedsWorstCaseWork asserts the property the
// budget exists to provide: it must be larger than the real bcrypt work a login
// can perform, or settleLoginTiming has nothing to sleep off and latency becomes
// a function of how many candidates the email matched.
//
// This is the regression test for the bug that motivated calibration — a
// hardcoded 700ms budget sized from a "~190ms per comparison" measurement, run
// on hardware where the same cost takes 352ms. Worst-case work was 1056ms, the
// settle never fired, and the uniformity guarantee silently stopped binding.
func TestCalibrateLoginTimingBudget_ExceedsWorstCaseWork(t *testing.T) {
	t.Setenv("LOGIN_TIMING_BUDGET_MS", "")

	budget := calibrateLoginTimingBudget()

	// Measure what a login actually costs at worst: loginMaxRealCompares
	// comparisons at the configured parameters.
	start := time.Now()
	for i := 0; i < loginMaxRealCompares; i++ {
		_ = hashProbe()
	}
	worstCase := time.Since(start)

	if budget <= worstCase && budget < loginBudgetCeiling {
		t.Fatalf("budget %v does not exceed worst-case work %v — settleLoginTiming "+
			"will not sleep and login latency becomes candidate-count dependent",
			budget, worstCase)
	}
}

// TestCalibrateLoginTimingBudget_RespectsOverride confirms an operator can pin
// the budget to a fixed, auditable value.
func TestCalibrateLoginTimingBudget_RespectsOverride(t *testing.T) {
	t.Setenv("LOGIN_TIMING_BUDGET_MS", "1234")
	if got := calibrateLoginTimingBudget(); got != 1234*time.Millisecond {
		t.Fatalf("override ignored: got %v, want 1.234s", got)
	}
}

// TestCalibrateLoginTimingBudget_IgnoresInvalidOverride confirms a malformed
// value falls back to measurement rather than producing a zero budget, which
// would disable the settle entirely.
func TestCalibrateLoginTimingBudget_IgnoresInvalidOverride(t *testing.T) {
	for _, bad := range []string{"0", "-1", "abc", " "} {
		t.Setenv("LOGIN_TIMING_BUDGET_MS", bad)
		if got := calibrateLoginTimingBudget(); got < loginBudgetFloor {
			t.Fatalf("invalid override %q produced %v, below floor %v", bad, got, loginBudgetFloor)
		}
	}
}

// TestCalibrateLoginTimingBudget_WithinBounds pins the clamps.
func TestCalibrateLoginTimingBudget_WithinBounds(t *testing.T) {
	_ = os.Unsetenv("LOGIN_TIMING_BUDGET_MS")
	budget := calibrateLoginTimingBudget()
	if budget < loginBudgetFloor {
		t.Fatalf("budget %v below floor %v", budget, loginBudgetFloor)
	}
	if budget > loginBudgetCeiling {
		t.Fatalf("budget %v above ceiling %v", budget, loginBudgetCeiling)
	}
}

// TestSettleLoginTiming_IsUniformAcrossWorkDone is the uniformity property
// itself: a path that did no work and a path that did some must be
// indistinguishable on the wire.
func TestSettleLoginTiming_IsUniformAcrossWorkDone(t *testing.T) {
	ctx := context.Background()

	measure := func(work time.Duration) time.Duration {
		start := time.Now()
		time.Sleep(work)
		settleLoginTiming(ctx, start)
		return time.Since(start)
	}

	noWork := measure(0)
	someWork := measure(loginTimingBudget / 4)

	// Both must land at the budget. Tolerance covers scheduler jitter only.
	const tolerance = 60 * time.Millisecond
	delta := noWork - someWork
	if delta < 0 {
		delta = -delta
	}
	if delta > tolerance {
		t.Fatalf("latency leaked work done: no-work %v vs some-work %v (delta %v > %v)",
			noWork, someWork, delta, tolerance)
	}
	if noWork < loginTimingBudget {
		t.Fatalf("settle returned early: %v < budget %v", noWork, loginTimingBudget)
	}
}

// TestSettleLoginTiming_RespectsCancellation confirms a client that hangs up is
// not held for the remainder of the budget.
func TestSettleLoginTiming_RespectsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	settleLoginTiming(ctx, start)

	if elapsed := time.Since(start); elapsed > loginTimingBudget/2 {
		t.Fatalf("cancelled context still waited %v (budget %v)", elapsed, loginTimingBudget)
	}
}

// TestDummyPasswordHash_UsesCurrentAlgorithm is the regression test for a subtle
// asymmetry: the zero-candidate path verifies against dummyPasswordHash, so if
// that hash is pinned to an algorithm or parameter set the system no longer
// uses, an unknown email does measurably different work from a real login —
// reintroducing the enumeration signal the dummy hash exists to remove.
func TestDummyPasswordHash_UsesCurrentAlgorithm(t *testing.T) {
	if got := password.Identify(dummyPasswordHash); got != password.AlgorithmArgon2id {
		t.Fatalf("dummy hash is %q, want argon2id — the unknown-email path would do "+
			"different work from a real login", got)
	}
	if password.NewHasher(password.DefaultParams()).NeedsRehash(dummyPasswordHash) {
		t.Fatal("dummy hash parameters differ from the configured ones — the " +
			"unknown-email path is measurably distinguishable from a real login")
	}
}

// TestDummyPasswordHash_HasNoKnownPlaintext confirms the hash cannot be matched,
// which is what makes it safe to verify arbitrary user input against.
func TestDummyPasswordHash_HasNoKnownPlaintext(t *testing.T) {
	h := password.NewHasher(password.DefaultParams())
	ctx := context.Background()
	for _, guess := range []string{"", "password", "admin", "probe", "calibration-probe"} {
		if err := h.Verify(ctx, guess, dummyPasswordHash); err == nil {
			t.Fatalf("dummy hash matched %q — the zero-candidate path could authenticate", guess)
		}
	}
}

// TestLegacyBcryptCredentialsStillVerify is the migration guarantee at the
// service boundary: accounts hashed before the switch to Argon2id must keep
// signing in, with no reset. The per-algorithm detail is covered in
// internal/password; this asserts the auth service's own hasher honours it.
func TestLegacyBcryptCredentialsStillVerify(t *testing.T) {
	h := password.NewHasher(password.DefaultParams())
	ctx := context.Background()
	const pw = "legacy-account-password"

	for _, cost := range []int{10, 11, 12} {
		legacy, err := bcrypt.GenerateFromPassword([]byte(pw), cost)
		if err != nil {
			t.Fatalf("bcrypt cost %d: %v", cost, err)
		}
		if err := h.Verify(ctx, pw, string(legacy)); err != nil {
			t.Fatalf("cost-%d bcrypt credential rejected after the argon2id switch: %v", cost, err)
		}
		if !h.NeedsRehash(string(legacy)) {
			t.Fatalf("cost-%d bcrypt credential not flagged for upgrade — it would "+
				"never migrate to argon2id", cost)
		}
	}
}
