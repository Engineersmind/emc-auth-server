package auth

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/engineersmind/emc-auth-server/internal/audit"
	"github.com/engineersmind/emc-auth-server/internal/metrics"
)

// Per-account password brute-force lockout (issue #72).
//
// Two tiers sit on ONE Redis counter of consecutive failed attempts per email:
//
//	soft — counter >= SoftThreshold: every further attempt is refused for the
//	       rest of the window, including one carrying the correct password.
//	       Nothing is written to the database; the lock evaporates with the key.
//	hard — counter >= HardThreshold: users.locked_until is stamped on every
//	       account owning that email, so the lock survives a Redis restart and
//	       outlives the (short) counter window.
//
// Three deliberate departures from a naive reading of the issue, each of which
// would otherwise be a security or availability regression:
//
//  1. The counter key is NOT tenant-scoped. On a FAILED login no tenant is
//     known — Login resolves the tenant by finding which tenant's stored hash
//     the password matches (see the Login doc comment), so a tenant-scoped
//     failure counter could only ever be written after a SUCCESSFUL password
//     check, which is exactly when a brute-force counter is pointless. The key
//     is therefore keyed on the email's hash alone. Consequence, accepted
//     knowingly: when one address owns accounts in several tenants (or both a
//     tenant-level and an app-scoped account) they share one counter, so an
//     attack on one locks the others too. Bounded by the fact that a lock is
//     temporary, revokes nothing, and leaves is_active alone.
//
//  2. A hard lock is TEMPORARY and never touches is_active. Permanently
//     disabling the account (admin-unlock-only) would hand anyone who knows a
//     victim's email a denial of service: ten unauthenticated requests to take
//     someone offline until a human intervenes. locked_until self-heals; an
//     admin can still clear it early.
//
//  3. Neither tier revokes existing sessions or bumps token_version. Failed
//     attempts do not compromise sessions that are already established, so
//     killing them would only hand the same attacker a way to forcibly sign a
//     victim out of every device at will. Administrative blocking
//     (admin.SetUserActive) remains the tool that terminates sessions.
//
// Every rejection returns ErrInvalidCredentials — byte-identical to a wrong
// password — and pays the same dummy-bcrypt floor, so lock state leaks through
// neither the response body nor the response time. That is also why no
// Retry-After header is emitted on this path: its mere presence would be the
// oracle the generic error exists to prevent. The per-IP/per-email 429 limiter
// (middleware.LoginRateLimiter) owns Retry-After semantics and is unaffected.

// lockReasonBruteForce is the users.locked_reason tag for an automatic lockout.
const lockReasonBruteForce = "brute_force"

// LockoutConfig is the per-account lockout policy, normalized from config.
type LockoutConfig struct {
	// SoftThreshold is the failure count at which attempts start being refused.
	// 0 disables lockout entirely.
	SoftThreshold int
	// HardThreshold is the failure count at which users.locked_until is set.
	// 0 disables the hard tier, leaving soft locks only.
	HardThreshold int
	// Window is the failure-counter TTL and the soft-lock duration.
	Window time.Duration
	// HardDuration is how long a hard lock holds before expiring on its own.
	HardDuration time.Duration
}

// NewLockoutConfig builds a policy from raw (env-derived) values, clamping
// nonsense rather than trusting it: negative counts disable the feature, a hard
// threshold below the soft one is raised to it (a hard tier that trips first
// would make the soft tier unreachable), and non-positive durations fall back
// to the defaults so a typo cannot produce a zero-length or eternal lock.
func NewLockoutConfig(soft, hard, windowMinutes, hardMinutes int) LockoutConfig {
	c := LockoutConfig{
		SoftThreshold: soft,
		HardThreshold: hard,
		Window:        time.Duration(windowMinutes) * time.Minute,
		HardDuration:  time.Duration(hardMinutes) * time.Minute,
	}
	if c.SoftThreshold < 0 {
		c.SoftThreshold = 0
	}
	if c.HardThreshold < 0 {
		c.HardThreshold = 0
	}
	if c.HardThreshold > 0 && c.HardThreshold < c.SoftThreshold {
		c.HardThreshold = c.SoftThreshold
	}
	if c.Window <= 0 {
		c.Window = 15 * time.Minute
	}
	if c.HardDuration <= 0 {
		c.HardDuration = time.Hour
	}
	return c
}

// enabled reports whether lockout is configured AND has a Redis client to count
// with. Without Redis the feature fails OPEN by design: the alternative — fail
// closed — turns a cache outage into a total authentication outage, and the
// per-IP rate limiter still provides a floor of brute-force protection.
func (s *AuthService) lockoutEnabled() bool {
	return s.lockout.SoftThreshold > 0 && s.lockoutRedis != nil
}

// loginFailKey is the Redis key holding the consecutive-failure count for an
// email. The email is lower-cased before hashing so that varying the case of
// an address cannot mint a fresh counter, and hashed so a Redis dump (or a
// KEYS/MONITOR session) does not become a list of who has been attacked.
func loginFailKey(email string) string {
	return "login:fail:" + HashToken(strings.ToLower(strings.TrimSpace(email)))
}

// loginFailBump increments the failure counter and returns {count, ttl_ms}.
//
// The TTL is refreshed only while the count is at or below the soft threshold,
// which makes the window "N failures within Window of each other" up to the
// lock, and then stops sliding: an attacker who keeps hammering an
// already-locked account must not be able to extend that lock indefinitely and
// so hold a victim out for as long as they care to keep sending requests.
// A key found without a TTL (only reachable if a previous process died between
// INCR and PEXPIRE) is re-armed rather than left to lock the account forever.
var loginFailBump = redis.NewScript(`
local n = redis.call("INCR", KEYS[1])
local ttl = redis.call("PTTL", KEYS[1])
if n <= tonumber(ARGV[2]) or ttl < 0 then
	redis.call("PEXPIRE", KEYS[1], ARGV[1])
	ttl = tonumber(ARGV[1])
end
return {n, ttl}
`)

// loginFailureCount returns the current consecutive-failure count for email.
// The bool reports whether the count is trustworthy — false on any Redis error
// (fail open, see lockoutEnabled) so callers skip the gate rather than deny.
func (s *AuthService) loginFailureCount(ctx context.Context, email string) (int, bool) {
	if !s.lockoutEnabled() {
		return 0, false
	}
	n, err := s.lockoutRedis.Get(ctx, loginFailKey(email)).Int()
	if err == redis.Nil {
		return 0, true
	}
	if err != nil {
		s.logger.Warn().Err(err).Msg("lockout: failure-count read failed, allowing attempt")
		return 0, false
	}
	return n, true
}

// clearLoginFailures resets the counter after a correct password. Called before
// the MFA gate on purpose: once the password is right the password-brute-force
// window is over, and MFA enforces its own attempt budget (bumpOTPAttempts), so
// leaving this counter armed would let a user who fumbles an OTP code several
// times get locked out of their password instead.
func (s *AuthService) clearLoginFailures(ctx context.Context, email string) {
	if !s.lockoutEnabled() {
		return
	}
	if err := s.lockoutRedis.Del(ctx, loginFailKey(email)).Err(); err != nil {
		s.logger.Warn().Err(err).Msg("lockout: failed to clear failure counter after successful login")
	}
}

// ResetLoginFailures clears the failure counter for an email. Exported for the
// admin unlock endpoint (admin.LoginFailureResetter), which must clear the
// counter as well as users.locked_until — the counter alone IS the soft lock.
// Returns nil when lockout is not configured: there is nothing to reset, and an
// error would make an otherwise-successful unlock look like a failure.
func (s *AuthService) ResetLoginFailures(ctx context.Context, email string) error {
	if !s.lockoutEnabled() {
		return nil
	}
	return s.lockoutRedis.Del(ctx, loginFailKey(email)).Err()
}

// recordLoginFailure counts one failed attempt against email and applies
// whichever tier the new count crosses.
//
// candidates is every account owning the email (nil when it matched none). The
// counter advances for an unknown email too: skipping it would make "no such
// account" cheaper than "wrong password" in Redis round-trips, and would let an
// attacker enumerate addresses by probing for which ones can be locked.
//
// Best-effort throughout — a Redis or database failure here must never convert
// a plain failed login into a 500, so every error is logged and swallowed.
func (s *AuthService) recordLoginFailure(ctx context.Context, email string, candidates []loginCandidate) {
	if !s.lockoutEnabled() {
		return
	}

	res, err := loginFailBump.Run(ctx, s.lockoutRedis,
		[]string{loginFailKey(email)},
		s.lockout.Window.Milliseconds(),
		s.lockout.SoftThreshold,
	).Int64Slice()
	if err != nil || len(res) != 2 {
		s.logger.Warn().Err(err).Msg("lockout: failure-counter increment failed, attempt not counted")
		return
	}
	count, ttlMS := int(res[0]), res[1]

	// Tiers fire on the exact crossing, not on every subsequent attempt, so the
	// audit trail and the metric each carry one row per lockout rather than one
	// per request. Attempts that arrive while a lock is already in force are
	// recorded separately by auditLoginBlocked.
	switch {
	case s.lockout.HardThreshold > 0 && count == s.lockout.HardThreshold:
		metrics.AccountLockouts.WithLabelValues("hard").Inc()
		s.hardLockAccounts(ctx, email, candidates, count)
	case count == s.lockout.SoftThreshold:
		metrics.AccountLockouts.WithLabelValues("soft").Inc()
		s.auditLockEvent(ctx, audit.ActionAuthAccountSoftLocked, email, candidates, map[string]any{
			"reason":          lockReasonBruteForce,
			"failed_attempts": count,
			"threshold":       s.lockout.SoftThreshold,
			"unlocks_in_sec":  ttlMS / 1000,
			"tier":            "soft",
		})
	}
}

// hardLockAccounts stamps locked_until on every account owning the email and
// audits one event per account. Does NOT touch is_active, token_version, or
// live sessions — see the tier-3 note in this file's header comment.
func (s *AuthService) hardLockAccounts(ctx context.Context, email string, candidates []loginCandidate, count int) {
	until := time.Now().Add(s.lockout.HardDuration)

	// An email nobody owns has nothing to lock; the counter still holds the
	// soft lock, so continued probing of a non-existent address stays refused.
	if len(candidates) > 0 {
		ids := make([]int64, 0, len(candidates))
		for i := range candidates {
			ids = append(ids, candidates[i].userID)
		}
		// GREATEST keeps the longer of an existing and the new expiry so a
		// second burst that lands while a lock is already running can only
		// extend it, never shorten one an admin has not cleared.
		if _, err := s.pool.Exec(ctx, `
			UPDATE users
			SET locked_until = GREATEST(COALESCE(locked_until, $1), $1),
			    locked_reason = $2,
			    updated_at = NOW()
			WHERE id = ANY($3) AND deleted_at IS NULL
		`, until, lockReasonBruteForce, ids); err != nil {
			s.logger.Error().Err(err).
				Msg("lockout: hard lock write failed, soft lock still in force")
			return
		}
		s.logger.Warn().
			Int("failed_attempts", count).
			Int("accounts_locked", len(ids)).
			Time("locked_until", until).
			Msg("lockout: account hard-locked after repeated failed logins")
	}

	s.auditLockEvent(ctx, audit.ActionAuthAccountHardLocked, email, candidates, map[string]any{
		"reason":          lockReasonBruteForce,
		"failed_attempts": count,
		"threshold":       s.lockout.HardThreshold,
		"locked_until":    until.UTC().Format(time.RFC3339),
		"tier":            "hard",
	})
}

// auditLoginBlocked records an attempt refused because a lock was already in
// force, so the trail shows how long an attack kept running after it tripped.
// tier is "soft" (counter window) or "hard" (users.locked_until).
func (s *AuthService) auditLoginBlocked(ctx context.Context, tier, email string, candidates []loginCandidate) {
	metrics.LoginsBlockedByLockout.WithLabelValues(tier).Inc()
	s.auditLockEvent(ctx, audit.ActionAuthLoginBlocked, email, candidates, map[string]any{
		"reason": lockReasonBruteForce,
		"tier":   tier,
	})
}

// auditLockEvent writes one lockout audit row per affected account, or a single
// account-less row when the email owns none (so a probed-but-nonexistent
// address still leaves a trail). Nil-safe: no audit logger means no rows.
func (s *AuthService) auditLockEvent(ctx context.Context, action, email string, candidates []loginCandidate, meta map[string]any) {
	if s.audit == nil {
		return
	}
	if len(candidates) == 0 {
		s.audit.Log(ctx, audit.Event{
			ActorEmail:   email,
			Action:       action,
			ResourceType: "user",
			Status:       audit.StatusFailure,
			AuthMethod:   audit.AuthMethodPassword,
			Metadata:     meta,
		})
		return
	}
	for i := range candidates {
		tenantID, userID := candidates[i].tenantID, candidates[i].userID
		s.audit.Log(ctx, audit.Event{
			TenantID:     &tenantID,
			UserID:       &userID,
			ActorEmail:   candidates[i].email,
			Action:       action,
			ResourceType: "user",
			ResourceID:   strconv.FormatInt(userID, 10),
			Status:       audit.StatusFailure,
			AuthMethod:   audit.AuthMethodPassword,
			Metadata:     meta,
		})
	}
}
