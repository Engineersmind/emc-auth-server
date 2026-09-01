package auth

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
)

// ---------------------------------------------------------------------------
// Account-lockout policy (issue #72).
//
// Three escalating tiers over one windowed failure counter:
//
//	NotifyUserThreshold  — email the account owner. Nothing is blocked. The point
//	                       is that a victim hears about an attack while it is
//	                       still running, not after they cannot sign in.
//	SoftLockThreshold    — refuse authentication for SoftLockDuration, holding the
//	                       state in Redis and leaving the users row untouched.
//	HardLockThreshold    — disable the account (the pre-existing behaviour), now
//	                       with an expiry so it stops being a permanent DoS.
//
// See migration 00086 for why these are per-tenant data rather than constants.
// ---------------------------------------------------------------------------

// LockoutPolicy is the resolved lockout policy for one (tenant, application) pair.
type LockoutPolicy struct {
	// NotifyUserThreshold is how many failures warn the account owner by email.
	// Zero disables the tier.
	NotifyUserThreshold int

	// SoftLockThreshold is how many failures trigger a temporary refusal, and
	// SoftLockDuration is how long it lasts. Soft locks live in Redis and never
	// touch account state.
	SoftLockThreshold int
	SoftLockDuration  time.Duration

	// HardLockThreshold is how many failures disable the account.
	HardLockThreshold int

	// HardLockDuration is how long a hard lock holds before the account admits
	// logins again. Zero means "until an administrator acts" — see
	// migration 00086 for why that is available but not the default.
	HardLockDuration time.Duration

	// FailureWindow is how long a failed attempt counts toward the thresholds.
	FailureWindow time.Duration

	// TenantSpikeThreshold is how many distinct accounts must hard-lock inside
	// FailureWindow before the tenant's administrators are emailed once about a
	// suspected attack. Zero disables the alert.
	TenantSpikeThreshold int
}

// DefaultLockoutPolicy mirrors the platform-default row seeded by migration 00086.
//
// It is the value used when the policy table cannot be read — see
// LockoutPolicyService.Resolve for why that degrades to a default rather than
// failing the login. Kept in sync with the migration by
// TestDefaultLockoutPolicyMatchesSeed.
var DefaultLockoutPolicy = LockoutPolicy{
	NotifyUserThreshold:  3,
	SoftLockThreshold:    5,
	SoftLockDuration:     15 * time.Minute,
	HardLockThreshold:    MaxFailedLogins, // 10 — unchanged from the pre-#72 constant
	HardLockDuration:     30 * time.Minute,
	FailureWindow:        FailedLoginWindow, // 15m — unchanged
	TenantSpikeThreshold: 10,
}

// minHardLockDurationSeconds is the shortest hard-lock expiry any scope may
// configure, mirroring the lockout_policies_hard_duration_range CHECK in
// migration 00086.
//
// The login path uses it as the admit-window floor for the auto-expiry predicate:
// it must let in any account whose lock could have elapsed under ANY tenant's
// policy, because in generic mode the tenant is not known until after the query.
// Keep it in step with the migration — a value above the constraint's floor would
// leave accounts in a tenant with a shorter expiry locked past their deadline.
const minHardLockDurationSeconds = 60

// SoftLockError is returned by Login when an account is temporarily locked.
//
// It carries RetryAfter so the handler can set the Retry-After header, and its
// Error() string is deliberately the same "invalid credentials" every other
// credential failure returns: the response body must not reveal that an account
// exists, let alone that it is locked. The header is the one intentional
// disclosure, and issue #72 asks for it explicitly — it tells a legitimate user
// when to come back without telling an attacker whether they found a real account,
// since a soft lock can only be reached by an attempt that already failed.
type SoftLockError struct {
	RetryAfter time.Duration
}

func (e *SoftLockError) Error() string { return "invalid credentials" }

// ErrSoftLocked is the sentinel for errors.Is matching. Handlers should use
// errors.As with a *SoftLockError to recover the retry duration.
var ErrSoftLocked = &SoftLockError{}

// Is makes every SoftLockError match ErrSoftLocked regardless of duration.
func (e *SoftLockError) Is(target error) bool {
	_, ok := target.(*SoftLockError)
	return ok
}

// RetryAfterSeconds is the value for the Retry-After header, floored at 1: a
// header of "0" invites an immediate retry that would be refused again.
func (e *SoftLockError) RetryAfterSeconds() int {
	s := int(e.RetryAfter.Seconds())
	if s < 1 {
		return 1
	}
	return s
}

// HardLockExpiresAt returns when a hard lock stamped at blockedAt lifts, and
// whether it lifts at all. Callers must branch on ok rather than treating the
// zero time as "already expired": a policy with no duration means the lock holds
// until an operator clears it, and reading that as expiry would silently undo
// every permanent lock in the tenant.
func (p LockoutPolicy) HardLockExpiresAt(blockedAt time.Time) (at time.Time, ok bool) {
	if p.HardLockDuration <= 0 {
		return time.Time{}, false
	}
	return blockedAt.Add(p.HardLockDuration), true
}

// LockoutPolicyService resolves and caches lockout policy.
//
// Resolution is most-specific-wins: an application row, else the tenant row,
// else the platform default. Cached because Resolve sits on the failure path of
// every login attempt, which is precisely the path an attacker drives hardest —
// an uncached lookup would let a brute-force attempt also become a load
// amplifier against the policy table.
type LockoutPolicyService struct {
	pool   *pgxpool.Pool
	logger zerolog.Logger

	mu    sync.RWMutex
	cache map[lockoutPolicyKey]cachedLockoutPolicy
	ttl   time.Duration
}

type lockoutPolicyKey struct {
	tenantID      int64
	applicationID int64 // 0 = no application scope
}

type cachedLockoutPolicy struct {
	policy   LockoutPolicy
	cachedAt time.Time
}

// lockoutPolicyCacheTTL is how long a resolved policy is reused. Short enough
// that an operator tightening a threshold during an incident sees it take effect
// while they are still looking at the screen.
const lockoutPolicyCacheTTL = 60 * time.Second

// NewLockoutPolicyService creates a lockout-policy resolver over the given pool.
func NewLockoutPolicyService(pool *pgxpool.Pool, logger zerolog.Logger) *LockoutPolicyService {
	return &LockoutPolicyService{
		pool:   pool,
		logger: logger,
		cache:  make(map[lockoutPolicyKey]cachedLockoutPolicy),
		ttl:    lockoutPolicyCacheTTL,
	}
}

// Resolve returns the policy in force for the given scope. applicationID may be
// nil for tenant-level users.
//
// Never returns an error. A lookup failure falls back to DefaultLockoutPolicy and
// logs at warn: this sits on the login path, and refusing to authenticate anybody
// because a settings table is briefly unreadable trades a configuration problem
// for an outage. The fallback is the platform default, so the failure mode is
// "thresholds revert to shipped defaults", not "lockout stops working".
func (s *LockoutPolicyService) Resolve(ctx context.Context, tenantID int64, applicationID *int64) LockoutPolicy {
	if s == nil || s.pool == nil {
		return DefaultLockoutPolicy
	}

	key := lockoutPolicyKey{tenantID: tenantID}
	if applicationID != nil {
		key.applicationID = *applicationID
	}

	s.mu.RLock()
	entry, ok := s.cache[key]
	s.mu.RUnlock()
	if ok && time.Since(entry.cachedAt) < s.ttl {
		return entry.policy
	}

	policy, err := s.load(ctx, tenantID, applicationID)
	if err != nil {
		s.logger.Warn().Err(err).
			Int64("tenant_id", tenantID).
			Msg("lockout policy: resolve failed, using platform defaults")
		return DefaultLockoutPolicy
	}

	s.mu.Lock()
	s.cache[key] = cachedLockoutPolicy{policy: policy, cachedAt: time.Now()}
	s.mu.Unlock()
	return policy
}

// load reads the most specific matching policy row.
//
// ORDER BY places the application row first, then the tenant row, then the
// platform default, and LIMIT 1 takes the winner — one indexed query instead of
// up to three round trips.
func (s *LockoutPolicyService) load(ctx context.Context, tenantID int64, applicationID *int64) (LockoutPolicy, error) {
	var notify, soft, softDur, hard, window, spike int
	var hardDur *int // nullable: NULL means "until an administrator acts"

	err := s.pool.QueryRow(ctx, `
		SELECT notify_user_threshold,
		       soft_lock_threshold, soft_lock_duration_seconds,
		       hard_lock_threshold, hard_lock_duration_seconds,
		       failure_window_seconds, tenant_spike_threshold
		FROM lockout_policies
		WHERE (application_id = $2 AND tenant_id = $1)
		   OR (application_id IS NULL AND tenant_id = $1)
		   OR (application_id IS NULL AND tenant_id IS NULL)
		ORDER BY application_id NULLS LAST, tenant_id NULLS LAST
		LIMIT 1
	`, tenantID, applicationID).Scan(&notify, &soft, &softDur, &hard, &hardDur, &window, &spike)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// The platform-default row is seeded by migration 00086, so this
			// means somebody deleted it. Defaults still apply; say so loudly
			// rather than inventing a policy silently.
			return DefaultLockoutPolicy, fmt.Errorf("no lockout policy row matched (platform default missing?)")
		}
		return DefaultLockoutPolicy, fmt.Errorf("load lockout policy: %w", err)
	}

	p := LockoutPolicy{
		NotifyUserThreshold:  notify,
		SoftLockThreshold:    soft,
		SoftLockDuration:     time.Duration(softDur) * time.Second,
		HardLockThreshold:    hard,
		FailureWindow:        time.Duration(window) * time.Second,
		TenantSpikeThreshold: spike,
	}
	if hardDur != nil {
		p.HardLockDuration = time.Duration(*hardDur) * time.Second
	}
	return p, nil
}

// InvalidateCache drops cached policy for every scope. Called by the admin write
// path so an operator who changes a threshold does not have to wait out
// lockoutPolicyCacheTTL to see it — and, more importantly, so loosening a
// threshold to let a locked-out user back in takes effect immediately.
//
// Drops the whole cache rather than one key: a tenant-level change affects every
// application key under that tenant, and the set of those keys is not tracked.
func (s *LockoutPolicyService) InvalidateCache() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.cache = make(map[lockoutPolicyKey]cachedLockoutPolicy)
	s.mu.Unlock()
}

// ---------------------------------------------------------------------------
// Environment overrides for the platform default
// ---------------------------------------------------------------------------

// LockoutEnvOverrides are the platform-default thresholds read from the
// environment. A nil field means "not set — leave the seeded value alone".
//
// These tune the PLATFORM DEFAULT row only; per-tenant and per-application rows
// are never touched. That split is deliberate: an env var is the natural place
// for a deployment-wide default, but it cannot express "admins get a mandatory
// expiry while end users may opt into a permanent lock", which is two values at
// once. The table remains the source of truth and the only thing that can carry
// per-scope policy.
type LockoutEnvOverrides struct {
	NotifyThreshold  *int
	SoftThreshold    *int
	SoftDuration     *time.Duration
	HardThreshold    *int
	HardDuration     *time.Duration // a zero duration means "permanent"
	FailureWindow    *time.Duration
	SpikeThreshold   *int
	HardLockDisabled bool // LOCKOUT_HARD_TTL=off — permanent locks
}

// LockoutOverridesFromEnv reads the LOCKOUT_* variables.
//
//	LOCKOUT_NOTIFY_THRESHOLD   integer, 0 disables the warn-the-user tier
//	LOCKOUT_SOFT_THRESHOLD     integer
//	LOCKOUT_SOFT_TTL           duration ("15m", "900s")
//	LOCKOUT_HARD_THRESHOLD     integer
//	LOCKOUT_HARD_TTL           duration, or "off"/"never" for a permanent lock
//	LOCKOUT_WINDOW             duration
//	LOCKOUT_SPIKE_THRESHOLD    integer, 0 disables the tenant spike alert
//
// Malformed values are reported as errors rather than ignored: a deployment that
// meant to set a 15-minute lock and typo'd the unit should hear about it at boot,
// not discover months later that the seeded default was in force all along.
func LockoutOverridesFromEnv() (LockoutEnvOverrides, error) {
	var ov LockoutEnvOverrides

	intVar := func(key string, dst **int) error {
		raw := os.Getenv(key)
		if raw == "" {
			return nil
		}
		n, err := strconv.Atoi(raw)
		if err != nil {
			return fmt.Errorf("%s: %q is not an integer", key, raw)
		}
		if n < 0 {
			return fmt.Errorf("%s: must not be negative (got %d)", key, n)
		}
		*dst = &n
		return nil
	}
	durVar := func(key string, dst **time.Duration) error {
		raw := os.Getenv(key)
		if raw == "" {
			return nil
		}
		d, err := time.ParseDuration(raw)
		if err != nil {
			return fmt.Errorf("%s: %q is not a duration (try \"15m\" or \"900s\")", key, raw)
		}
		if d <= 0 {
			return fmt.Errorf("%s: must be positive (got %s)", key, d)
		}
		*dst = &d
		return nil
	}

	for _, f := range []func() error{
		func() error { return intVar("LOCKOUT_NOTIFY_THRESHOLD", &ov.NotifyThreshold) },
		func() error { return intVar("LOCKOUT_SOFT_THRESHOLD", &ov.SoftThreshold) },
		func() error { return durVar("LOCKOUT_SOFT_TTL", &ov.SoftDuration) },
		func() error { return intVar("LOCKOUT_HARD_THRESHOLD", &ov.HardThreshold) },
		func() error { return durVar("LOCKOUT_WINDOW", &ov.FailureWindow) },
		func() error { return intVar("LOCKOUT_SPIKE_THRESHOLD", &ov.SpikeThreshold) },
	} {
		if err := f(); err != nil {
			return ov, err
		}
	}

	// LOCKOUT_HARD_TTL takes "off"/"never" in addition to a duration, so a
	// deployment can opt into the pre-#72 permanent lock explicitly rather than
	// by leaving something blank. Requiring the word makes it a decision in the
	// deployment config rather than an accident.
	switch raw := os.Getenv("LOCKOUT_HARD_TTL"); raw {
	case "":
	case "off", "never", "permanent":
		ov.HardLockDisabled = true
	default:
		d, err := time.ParseDuration(raw)
		if err != nil {
			return ov, fmt.Errorf("LOCKOUT_HARD_TTL: %q is neither a duration nor \"off\"", raw)
		}
		if d <= 0 {
			return ov, fmt.Errorf("LOCKOUT_HARD_TTL: must be positive, or \"off\" for a permanent lock (got %s)", d)
		}
		ov.HardDuration = &d
	}

	return ov, nil
}

// Empty reports whether no override was set, so the caller can skip the write
// entirely and leave the seeded row exactly as the migration left it.
func (o LockoutEnvOverrides) Empty() bool {
	return o.NotifyThreshold == nil && o.SoftThreshold == nil && o.SoftDuration == nil &&
		o.HardThreshold == nil && o.HardDuration == nil && o.FailureWindow == nil &&
		o.SpikeThreshold == nil && !o.HardLockDisabled
}

// ApplyLockoutEnvOverrides writes the environment overrides onto the
// platform-default policy row at boot.
//
// COALESCE per column so an unset variable leaves the seeded value untouched
// rather than resetting it — otherwise setting one variable would silently
// revert every other column to whatever this build thinks the default is.
//
// Returns an error rather than logging it: a deployment that asked for a
// specific lockout posture and did not get it should fail to start, not run with
// a policy the operator did not choose. The CHECK constraints in migration 00086
// are what reject an escalation order that does not make sense, so a bad
// combination surfaces here as a constraint violation.
func ApplyLockoutEnvOverrides(ctx context.Context, pool *pgxpool.Pool, ov LockoutEnvOverrides, logger zerolog.Logger) error {
	if pool == nil || ov.Empty() {
		return nil
	}

	secs := func(d *time.Duration) *int {
		if d == nil {
			return nil
		}
		n := int(d.Seconds())
		return &n
	}

	// hardDur carries three states, which is why it cannot be a plain *int:
	// unset (leave the row alone), a duration, or explicitly permanent (NULL).
	var hardDur *int
	if ov.HardDuration != nil {
		hardDur = secs(ov.HardDuration)
	}

	ct, err := pool.Exec(ctx, `
		UPDATE lockout_policies
		SET notify_user_threshold      = COALESCE($1, notify_user_threshold),
		    soft_lock_threshold        = COALESCE($2, soft_lock_threshold),
		    soft_lock_duration_seconds = COALESCE($3, soft_lock_duration_seconds),
		    hard_lock_threshold        = COALESCE($4, hard_lock_threshold),
		    hard_lock_duration_seconds = CASE
		        WHEN $5::BOOLEAN THEN NULL
		        ELSE COALESCE($6, hard_lock_duration_seconds)
		    END,
		    failure_window_seconds     = COALESCE($7, failure_window_seconds),
		    tenant_spike_threshold     = COALESCE($8, tenant_spike_threshold),
		    updated_at = NOW()
		WHERE tenant_id IS NULL AND application_id IS NULL
	`,
		ov.NotifyThreshold, ov.SoftThreshold, secs(ov.SoftDuration),
		ov.HardThreshold, ov.HardLockDisabled, hardDur,
		secs(ov.FailureWindow), ov.SpikeThreshold,
	)
	if err != nil {
		// The tier-escalation CHECK is the one an operator trips in practice, and
		// it is easy to trip by accident: setting only LOCKOUT_SOFT_THRESHOLD
		// leaves the notify threshold at its previous value, which may now be
		// above it. A bare SQLSTATE 23514 at boot does not tell anybody that, and
		// this path is fatal, so the message has to name the fix.
		if strings.Contains(err.Error(), "lockout_policies_tiers_escalate") {
			return fmt.Errorf("apply LOCKOUT_* environment overrides: the resulting thresholds do not escalate — "+
				"they must satisfy notify <= soft < hard. Set the LOCKOUT_*_THRESHOLD variables together rather than "+
				"individually, since an unset one keeps its previous value: %w", err)
		}
		return fmt.Errorf("apply LOCKOUT_* environment overrides: %w", err)
	}
	if ct.RowsAffected() == 0 {
		// RunSeed restores this row on every start, so reaching here means the
		// override ran before the seed — an ordering bug in the caller, not a
		// configuration problem.
		return fmt.Errorf("apply LOCKOUT_* environment overrides: platform-default lockout policy row is missing " +
			"(overrides must be applied after migrations and seed)")
	}

	ev := logger.Info()
	if ov.HardLockDisabled {
		// Worth its own line at boot: this reinstates the permanent lock, which
		// is the DoS-prone posture migration 00086 exists to move away from.
		ev = ev.Bool("hard_lock_permanent", true)
	}
	ev.Msg("lockout policy: platform defaults overridden from environment")
	return nil
}
