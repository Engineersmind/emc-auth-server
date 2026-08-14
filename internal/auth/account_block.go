package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"

	"github.com/engineersmind/emc-auth-server/internal/audit"
	"github.com/engineersmind/emc-auth-server/internal/mailer"
)

// ---------------------------------------------------------------------------
// Account blocking and suspicious-activity alerts (the blocked_account email).
//
// Five distinct events reach one template, distinguished by Reason:
//
//	failed_attempts_warning — repeated failures, nothing locked yet (issue #72).
//	                   Sent once per window so a victim hears about an attack
//	                   while it is still running. Link is a password reset.
//	soft_locked      — a TEMPORARY refusal that lifts by itself (issue #72). No
//	                   account state changed, so no operator can or need do
//	                   anything about it.
//	failed_attempts  — automatic lockout at the hard threshold. The user may lift
//	                   it themselves via a single-use link, and unless the tenant
//	                   opted into a permanent lock it also expires on its own.
//	admin            — an operator disabled the account. No self-unblock link:
//	                   letting the user undo an admin action would defeat it, so
//	                   the link is a password reset and access needs an admin.
//	suspicious_login — a high-risk sign-in SUCCEEDED. Nothing is blocked; this is
//	                   a "was this you?" alert with a password-reset link.
//
// Only the hard-lock path mints an unblock token. Brute-force counting is
// per-account (users.failed_login_attempts), reset on any successful sign-in, so
// a user's own typos never accumulate toward a lockout across sessions.
//
// Administrators are never emailed about a single account — see lockout_notify.go
// for why that would be a denial-of-service primitive aimed at the alert channel.
// ---------------------------------------------------------------------------

const (
	// MaxFailedLogins is the DEFAULT hard-lock threshold, retained as the value
	// DefaultLockoutPolicy is built from and as the fallback when no policy row
	// can be read. Per-tenant policy (migration 00070) is the live setting —
	// resolve it through LockoutPolicyService rather than reading this directly.
	MaxFailedLogins = 10

	// FailedLoginWindow is the DEFAULT window over which failed attempts count.
	// Per-tenant policy overrides it; see MaxFailedLogins above.
	FailedLoginWindow = 15 * time.Minute

	// UnblockTokenTTL is how long a self-service unblock link stays valid.
	UnblockTokenTTL = 1 * time.Hour
)

// ErrInvalidUnblockToken is returned when an unblock token is unknown, expired,
// or already used.
var ErrInvalidUnblockToken = errors.New("invalid or expired unblock token")

// riskAlertTimeout bounds the detached risk assessment + send, which no longer
// has a request context to inherit a deadline from.
const riskAlertTimeout = 20 * time.Second

// notifySendTimeout bounds one detached blocked_account delivery: a template
// lookup, a sender lookup, and an SMTP handshake.
//
// Its own constant rather than reusing riskAlertTimeout, which is sized for a
// risk assessment's history queries — the two are unrelated work, and a change to
// either bound should not silently move the other. Generous because a remote relay
// legitimately takes seconds, and nothing is waiting on this; the goroutine must
// still be bounded so a hung relay cannot leak them one per failed login.
const notifySendTimeout = 30 * time.Second

// AccountBlockService owns lockout state and the blocked_account notifications.
type AccountBlockService struct {
	pool       *pgxpool.Pool
	notify     EmailNotifier
	risk       audit.RiskAssessor // nil when risk assessment is not configured
	appBaseURL string
	logger     zerolog.Logger

	// redis holds the ephemeral tiers (soft lock, warning marker, spike counter).
	// Nil degrades to hard-lock-only — see WithRedis in lockout_notify.go.
	redis *redis.Client
	// policySvc resolves per-tenant thresholds. Nil falls back to
	// DefaultLockoutPolicy, which mirrors the pre-#72 constants.
	policySvc *LockoutPolicyService
	// dashboardURL is where the spike alert sends an operator to act.
	dashboardURL string
}

// NewAccountBlockService creates an AccountBlockService.
func NewAccountBlockService(pool *pgxpool.Pool, m mailer.Mailer, appBaseURL string, logger zerolog.Logger) *AccountBlockService {
	return &AccountBlockService{
		pool:       pool,
		notify:     EmailNotifier{mailer: m, logger: logger},
		appBaseURL: appBaseURL,
		logger:     logger,
	}
}

// WithDashboardURL sets the console origin used by the lockout spike alert, whose
// call to action is a filtered users page rather than an API endpoint.
func (s *AccountBlockService) WithDashboardURL(u string) *AccountBlockService {
	s.dashboardURL = u
	return s
}

// policyFor resolves the lockout policy for an account's scope.
func (s *AccountBlockService) policyFor(ctx context.Context, tenantID int64, appRowID *int64) LockoutPolicy {
	if s.policySvc == nil {
		return DefaultLockoutPolicy
	}
	return s.policySvc.Resolve(ctx, tenantID, appRowID)
}

// WithSenders wires the white-label sender resolver.
func (s *AccountBlockService) WithSenders(senderSvc *EmailSenderService) *AccountBlockService {
	s.notify.senderSvc = senderSvc
	return s
}

// WithTemplates wires the per-scope template resolver.
func (s *AccountBlockService) WithTemplates(tmplSvc *EmailTemplateService) *AccountBlockService {
	s.notify.tmplSvc = tmplSvc
	return s
}

// WithAudit wires the audit logger so suppressed sends are recorded.
func (s *AccountBlockService) WithAudit(a *audit.Logger) *AccountBlockService {
	s.notify.audit = a
	return s
}

// WithRiskAssessor wires the security-signal assessor so a successful but
// high-risk sign-in raises a suspicious-activity alert. Optional: without it,
// only the failed-attempt and admin paths send blocked_account mail.
func (s *AccountBlockService) WithRiskAssessor(r audit.RiskAssessor) *AccountBlockService {
	s.risk = r
	return s
}

// NotifyIfRisky assesses a sign-in that has just succeeded and, when it looks
// unusual for this user, emails a "was this you?" alert. It returns immediately
// and works on a detached context: the assessment runs history queries, and a
// notification must never sit between the user and their tokens.
//
// Deliberately alert-only — see NotifySuspiciousLogin for why a risk signal does
// not block. It reuses the same assessor as the audit pipeline, so the email and
// the audit record agree on what "risky" means.
func (s *AccountBlockService) NotifyIfRisky(ctx context.Context, tenantID int64, appRowID *int64, userID int64, email, ip, userAgent string) {
	if s == nil || s.risk == nil || email == "" {
		return
	}
	detached := context.WithoutCancel(ctx)
	go func() {
		ctx, cancel := context.WithTimeout(detached, riskAlertTimeout)
		defer cancel()

		signals := s.risk.Assess(ctx, audit.RiskInput{
			UserID:    &userID,
			TenantID:  &tenantID,
			Action:    audit.ActionAuthLogin,
			IPAddress: ip,
			UserAgent: userAgent,
		})
		if len(signals) == 0 {
			return
		}
		// Anything above "low" is worth telling the user about: a first sign-in
		// from a new device is exactly the event a victim needs to see, even
		// though on its own it is only medium.
		level, _ := signals["score"].(string)
		if level != "high" && level != "medium" {
			return
		}

		s.logger.Info().
			Int64("user_id", userID).
			Str("risk", level).
			Msg("risky sign-in — alerting account owner")
		// An ALERT, not a block: the sign-in succeeded and the account is untouched.
		// This used to be recorded as auth.account_blocked, which put "account
		// blocked" in the activity feed one second after "login succeeded" on an
		// account that was never blocked.
		s.notify.auditUserEvent(ctx, audit.ActionAuthSuspiciousLogin, tenantID, appRowID, userID, map[string]any{
			"reason": mailer.BlockReasonSuspiciousLogin,
			"risk":   signals,
		})
		s.notifyAlert(ctx, tenantID, appRowID, email, mailer.BlockReasonSuspiciousLogin)
	}()
}

// RecordFailedLogin advances the account's consecutive-failure counter and
// applies whichever lockout tier the count has reached. Attempts older than the
// policy's failure window do not count: the counter restarts at 1 when the
// previous failure has aged out.
//
// The three tiers escalate (see migration 00070 for why they are per-tenant data):
//
//	NotifyUserThreshold  email the account owner; nothing is blocked
//	SoftLockThreshold    temporary refusal held in Redis; no account state changes
//	HardLockThreshold    disable the account, revoke everything, email an unblock link
//
// Best-effort and nil-safe — it is called from the login path, where a bookkeeping
// error must never turn a plain "invalid credentials" into a 500. It reports
// whether the account ended up HARD locked, for the caller's audit metadata; the
// soft tier is reported through SoftLockedFor instead, because the caller has to
// consult that on every attempt rather than only on the one that crossed.
func (s *AccountBlockService) RecordFailedLogin(ctx context.Context, tenantID, userID int64) bool {
	if s == nil {
		return false
	}

	// Resolved before the counter write so one policy reading drives every tier
	// decision below: re-resolving per tier could straddle an operator's edit and
	// apply a soft threshold from the old policy against a hard one from the new.
	//
	// Scope note: policy is resolved at tenant scope here rather than for the
	// account's application, because application_id is only known after the
	// UPDATE below returns it. Tenant scope is the right default — an attacker
	// cannot pick which policy applies — and the app-scoped row still governs the
	// soft-lock check on the login path, where the scope is known up front.
	policy := s.policyFor(ctx, tenantID, nil)

	var attempts int
	var email string
	var appRowID *int64
	err := s.pool.QueryRow(ctx, `
		UPDATE users
		SET failed_login_attempts = CASE
				WHEN last_failed_login_at IS NULL OR last_failed_login_at < NOW() - make_interval(secs => $3) THEN 1
				ELSE failed_login_attempts + 1
			END,
			last_failed_login_at = NOW(),
			updated_at = NOW()
		WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL
		RETURNING failed_login_attempts, email, application_id
	`, userID, tenantID, int(policy.FailureWindow.Seconds())).Scan(&attempts, &email, &appRowID)
	if err != nil {
		s.logger.Warn().Err(err).Int64("user_id", userID).Msg("lockout: could not record failed login")
		return false
	}

	// Tier 3 first: the thresholds escalate, so the most severe reachable tier is
	// the one that should apply. Checking notify or soft first would let an account
	// well past the hard threshold keep re-arming a soft lock instead of being
	// disabled.
	if attempts >= policy.HardLockThreshold {
		return s.blockForFailedAttempts(ctx, tenantID, appRowID, userID, email, policy)
	}

	// Tier 2: soft lock. Applied before the warning email so a user who crosses
	// both thresholds on the same attempt is told about the lock rather than only
	// about the failures.
	if attempts >= policy.SoftLockThreshold {
		if s.applySoftLock(ctx, tenantID, userID, policy.SoftLockDuration) {
			s.logger.Info().
				Int64("user_id", userID).Int64("tenant_id", tenantID).
				Int("attempts", attempts).
				Dur("duration", policy.SoftLockDuration).
				Msg("account soft-locked after repeated failed sign-ins")
			s.notify.auditUserEvent(ctx, audit.ActionAuthAccountSoftLocked, tenantID, appRowID, userID, map[string]any{
				"attempts":         attempts,
				"threshold":        policy.SoftLockThreshold,
				"duration_seconds": int(policy.SoftLockDuration.Seconds()),
			})
			s.notifySoftLock(ctx, tenantID, appRowID, userID, email, policy)
		}
		return false
	}

	// Tier 1: warn the account owner, once per window.
	if policy.NotifyUserThreshold > 0 && attempts >= policy.NotifyUserThreshold {
		if s.markWarned(ctx, tenantID, userID, policy.FailureWindow) {
			s.notify.auditUserEvent(ctx, audit.ActionAuthLoginFailedThreshold, tenantID, appRowID, userID, map[string]any{
				"attempts":  attempts,
				"threshold": policy.NotifyUserThreshold,
			})
			s.notifyFailureWarning(ctx, tenantID, appRowID, userID, email)
		}
	}
	return false
}

// sendBlockedAccountAsync delivers one blocked_account variant on a DETACHED
// context and returns immediately.
//
// Safe to call from a goroutine that is itself about to return and cancel its
// context — NotifyIfRisky does exactly that. context.WithoutCancel below severs
// the parent, so the send is not killed by a `defer cancel()` firing the moment
// the caller finishes.
//
// Detached for the same reason NotifyIfRisky is (see its doc comment): a
// notification must never sit between the user and their response. An SMTP
// handshake to a remote relay measured in seconds, on the request path, would be
// three separate faults at once:
//
//   - the user waits seconds for a 401 that should be instant;
//   - the wait is a TIMING ORACLE. If attempts 1-2 return in milliseconds and
//     attempt 3 takes nine seconds, an attacker has been told exactly which
//     addresses have accounts and precisely when a threshold was crossed. That
//     dwarfs the leak loginCompareFloor exists to prevent, so leaving the send
//     inline would undo deliberate work elsewhere in this package;
//   - a slow or unreachable mail relay would throttle every login in the system.
//
// Best-effort by construction: the tier has already been applied and audited
// before this runs, so a failed send costs the user a notification, never the
// enforcement.
func (s *AccountBlockService) sendBlockedAccountAsync(ctx context.Context, tenantID int64, appRowID *int64, userID int64, msg mailer.BlockedAccountEmail) {
	if msg.To == "" {
		return
	}
	detached := context.WithoutCancel(ctx)
	go func() {
		ctx, cancel := context.WithTimeout(detached, notifySendTimeout)
		defer cancel()

		// Resolved in here rather than by the caller: it is a database round trip,
		// and the whole point of this function is that the caller waits for nothing.
		msg.AppName = appNameByRowID(ctx, s.pool, appRowID)

		if _, err := s.notify.Send(ctx, tenantID, appRowID, mailer.TemplateBlockedAccount,
			func(sender *mailer.SMTPConfig, tmpl *mailer.Template) error {
				return s.notify.mailer.SendBlockedAccount(ctx, sender, tmpl, msg)
			}); err != nil {
			s.logger.Warn().Err(err).
				Str("email", msg.To).Str("reason", msg.Reason).Int64("user_id", userID).
				Msg("lockout: notification could not be delivered")
		}
	}()
}

// notifyFailureWarning tells the account owner that somebody has been failing to
// sign in as them. The link is a password reset: nothing is locked, so there is
// nothing to unblock, and a user who has genuinely forgotten their password
// should be able to act on the email rather than keep guessing toward a lockout.
func (s *AccountBlockService) notifyFailureWarning(ctx context.Context, tenantID int64, appRowID *int64, userID int64, email string) {
	s.sendBlockedAccountAsync(ctx, tenantID, appRowID, userID, mailer.BlockedAccountEmail{
		To:     email,
		Link:   fmt.Sprintf("%s/forgot-password", s.appBaseURL),
		Reason: mailer.BlockReasonFailedAttemptsWarning,
	})
}

// notifySoftLock tells the account owner that sign-ins are paused and will resume
// on their own. TTLMinutes carries the wait so the email can say how long, and the
// wording deliberately avoids sending the user to an administrator: there is
// nothing an operator can usefully do about a state that clears itself.
func (s *AccountBlockService) notifySoftLock(ctx context.Context, tenantID int64, appRowID *int64, userID int64, email string, policy LockoutPolicy) {
	// Rounded up: a "try again in 0 minutes" that still refuses the next attempt
	// reads as a broken promise.
	mins := int((policy.SoftLockDuration + time.Minute - 1) / time.Minute)
	s.sendBlockedAccountAsync(ctx, tenantID, appRowID, userID, mailer.BlockedAccountEmail{
		To:         email,
		Link:       fmt.Sprintf("%s/forgot-password", s.appBaseURL),
		Reason:     mailer.BlockReasonSoftLocked,
		TTLMinutes: mins,
	})
}

// blockForFailedAttempts performs the automatic lockout: clear is_active, stamp
// the reason, bump token_version so any issued access token stops validating,
// revoke refresh tokens, then email the unblock link.
func (s *AccountBlockService) blockForFailedAttempts(ctx context.Context, tenantID int64, appRowID *int64, userID int64, email string, policy LockoutPolicy) bool {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		s.logger.Warn().Err(err).Int64("user_id", userID).Msg("lockout: begin block tx failed")
		return false
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// Only block an account that is still active: a concurrent second failure
	// must not re-block (and re-notify) an already-blocked account.
	var blocked bool
	err = tx.QueryRow(ctx, `
		UPDATE users
		SET is_active = false, blocked_at = NOW(), block_reason = $3,
		    token_version = token_version + 1, updated_at = NOW()
		WHERE id = $1 AND tenant_id = $2 AND is_active = true AND deleted_at IS NULL
		RETURNING true
	`, userID, tenantID, mailer.BlockReasonFailedAttempts).Scan(&blocked)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			s.logger.Warn().Err(err).Int64("user_id", userID).Msg("lockout: block update failed")
		}
		return false // already blocked, or gone — nothing to notify about
	}
	if err := RevokeAllSessionsTx(ctx, tx, userID, tenantID, RevokeReasonCredentialChange); err != nil {
		s.logger.Warn().Err(err).Int64("user_id", userID).Msg("lockout: session revocation failed")
		return false
	}

	rawToken, err := GenerateRefreshToken()
	if err != nil {
		s.logger.Warn().Err(err).Msg("lockout: unblock token generation failed")
		return false
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO account_unblock_tokens (user_id, tenant_id, token_hash, expires_at)
		VALUES ($1, $2, $3, $4)
	`, userID, tenantID, HashToken(rawToken), time.Now().UTC().Add(UnblockTokenTTL)); err != nil {
		s.logger.Warn().Err(err).Int64("user_id", userID).Msg("lockout: unblock token persist failed")
		return false
	}
	if err := tx.Commit(ctx); err != nil {
		s.logger.Warn().Err(err).Int64("user_id", userID).Msg("lockout: commit failed")
		return false
	}

	// Refuse the outstanding access tokens too, now that the block is committed.
	// Revoking the refresh rows only stops renewal, so without this a locked-out
	// account keeps working for the remaining life of the token it already holds —
	// the opposite of a lockout. After the commit because a Redis entry cannot be
	// rolled back: denying on a block that failed to commit would sign a user out on
	// the strength of a write that never landed.
	DenyAccountSessions(ctx, s.logger, userID, tenantID)

	// The soft-lock key has served its purpose once the account is disabled, and
	// leaving it behind would outlive an admin unlock and refuse a user the
	// operator just restored.
	s.ClearSoftLock(ctx, tenantID, userID)

	// retryMins is 0 for a policy with no expiry, which suppresses the "or just
	// wait" wording rather than promising a release that never arrives.
	retryMins := 0
	if policy.HardLockDuration > 0 {
		retryMins = int((policy.HardLockDuration + time.Minute - 1) / time.Minute)
	}

	s.logger.Warn().
		Int64("user_id", userID).Int64("tenant_id", tenantID).
		Int("hard_lock_threshold", policy.HardLockThreshold).
		Int("expires_in_minutes", retryMins).
		Msg("account blocked after repeated failed sign-ins")
	s.notify.auditUserEvent(ctx, audit.ActionAuthAccountBlocked, tenantID, appRowID, userID, map[string]any{
		"reason":       mailer.BlockReasonFailedAttempts,
		"max_attempts": policy.HardLockThreshold,
		// Recorded so the feed distinguishes a lock that lifts by itself from one
		// waiting on an operator — the two need different responses.
		"expires_in_seconds": int(policy.HardLockDuration.Seconds()),
		"permanent":          policy.HardLockDuration <= 0,
	})

	// Count this lock toward the tenant's window and alert administrators only if
	// it is the one that crossed the spike threshold. Per-account locks
	// deliberately do not email staff — see lockout_notify.go for why.
	if s.recordSpike(ctx, tenantID, policy.TenantSpikeThreshold, policy.FailureWindow) {
		s.notifyLockoutSpike(ctx, tenantID, appRowID, s.spikeCount(ctx, tenantID), policy.FailureWindow)
	}

	// Detached, like the other two tiers. This is the attempt that crosses the hard
	// threshold, so an inline SMTP handshake would put its full latency on exactly
	// the request an attacker is watching — see sendBlockedAccountAsync for why that
	// is a timing oracle as well as a slow response.
	//
	// The block itself is already committed, so a send that fails or is still in
	// flight cannot affect enforcement; it only costs the user their unblock link,
	// which is logged.
	s.sendBlockedAccountAsync(ctx, tenantID, appRowID, userID, mailer.BlockedAccountEmail{
		To:           email,
		Link:         fmt.Sprintf("%s/api/v1/auth/unblock-account?token=%s", s.appBaseURL, rawToken),
		Reason:       mailer.BlockReasonFailedAttempts,
		TTLMinutes:   int(UnblockTokenTTL.Minutes()),
		RetryMinutes: retryMins,
	})
	return true
}

// ResetFailedLogins clears the counter after a successful sign-in. Best-effort
// and nil-safe: a failure here can only cost a user a spurious future lockout,
// never a failed login, so it is logged rather than returned.
func (s *AccountBlockService) ResetFailedLogins(ctx context.Context, tenantID, userID int64) {
	if s == nil {
		return
	}
	if _, err := s.pool.Exec(ctx, `
		UPDATE users SET failed_login_attempts = 0, last_failed_login_at = NULL
		WHERE id = $1 AND tenant_id = $2 AND failed_login_attempts <> 0
	`, userID, tenantID); err != nil {
		s.logger.Warn().Err(err).Int64("user_id", userID).Msg("lockout: could not reset failed-login counter")
	}
	// The warning marker goes with the counter: a user who signs in successfully
	// has started a fresh window, and keeping the marker would suppress the next
	// window's warning — silencing exactly the alert a returning attacker should
	// trigger.
	s.ClearSoftLock(ctx, tenantID, userID)
}

// ExpireHardLock lifts an automatic lockout whose duration has elapsed, and
// reports whether it lifted one.
//
// Called from the login path when the candidate query has matched an account that
// is disabled but past its expiry (see the auto-expiry predicate in
// AuthService.Login). Doing it lazily, on the next attempt, rather than from a
// background reaper is deliberate: there is no window in which an expired lock is
// still enforced, and no periodic job to be running for the guarantee to hold.
//
// Scoped tightly to block_reason = 'failed_attempts'. An administrator's block
// carries block_reason = 'admin' and must never be lifted by a clock — an
// operator's decision that quietly undoes itself is worse than no control at all.
// The predicate also re-checks the elapsed time in SQL rather than trusting the
// caller, so a stale policy read cannot unlock an account early.
func (s *AccountBlockService) ExpireHardLock(ctx context.Context, tenantID, userID int64, after time.Duration) bool {
	if s == nil || after <= 0 {
		return false
	}
	var appRowID *int64
	err := s.pool.QueryRow(ctx, `
		UPDATE users
		SET is_active = true, blocked_at = NULL, block_reason = NULL,
		    failed_login_attempts = 0, last_failed_login_at = NULL,
		    updated_at = NOW()
		WHERE id = $1 AND tenant_id = $2
		  AND deleted_at IS NULL
		  AND is_active = false
		  AND block_reason = $3
		  AND blocked_at IS NOT NULL
		  AND blocked_at < NOW() - make_interval(secs => $4)
		RETURNING application_id
	`, userID, tenantID, mailer.BlockReasonFailedAttempts, int(after.Seconds())).Scan(&appRowID)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			s.logger.Warn().Err(err).Int64("user_id", userID).Msg("lockout: could not expire hard lock")
		}
		return false // not locked, not expired yet, or an admin block — all no-ops
	}

	// Any unblock token minted for the lock we just lifted is now pointless, and
	// leaving it live means an old email could "unblock" an account that a later
	// admin block has since disabled again.
	if _, err := s.pool.Exec(ctx, `
		UPDATE account_unblock_tokens SET used_at = NOW()
		WHERE user_id = $1 AND tenant_id = $2 AND used_at IS NULL
	`, userID, tenantID); err != nil {
		s.logger.Warn().Err(err).Int64("user_id", userID).Msg("lockout: could not retire unblock tokens after expiry")
	}

	s.ClearSoftLock(ctx, tenantID, userID)
	s.logger.Info().Int64("user_id", userID).Int64("tenant_id", tenantID).
		Dur("after", after).Msg("automatic account lock expired")
	// Audited because a re-enabled account must never be a silent state change:
	// "why is this account active again?" needs an answer better than an assumption
	// that it timed out.
	s.notify.auditUserEvent(ctx, audit.ActionAuthHardLockExpired, tenantID, appRowID, userID, map[string]any{
		"reason":         mailer.BlockReasonFailedAttempts,
		"locked_seconds": int(after.Seconds()),
		"lifted_by":      "expiry",
	})
	return true
}

// NotifyAdminBlock emails the user that an administrator blocked their account.
// The link is a password reset, not an unblock — only an admin can restore
// access. Nil-safe and best-effort; the block itself has already been applied by
// the admin service.
func (s *AccountBlockService) NotifyAdminBlock(ctx context.Context, tenantID int64, appRowID *int64, userID int64, email string) {
	if s == nil {
		return
	}
	if _, err := s.pool.Exec(ctx, `
		UPDATE users SET blocked_at = NOW(), block_reason = $3 WHERE id = $1 AND tenant_id = $2
	`, userID, tenantID, mailer.BlockReasonAdmin); err != nil {
		s.logger.Warn().Err(err).Int64("user_id", userID).Msg("block: could not stamp admin block reason")
	}
	s.notifyAlert(ctx, tenantID, appRowID, email, mailer.BlockReasonAdmin)
}

// NotifySuspiciousLogin alerts the user that a high-risk sign-in succeeded from
// an unrecognised device or location. Nothing is blocked — an automatic block on
// a risk signal would lock users out whenever they travel or buy a laptop, so
// this is a notification with a password-reset link. Nil-safe, best-effort.
func (s *AccountBlockService) NotifySuspiciousLogin(ctx context.Context, tenantID int64, appRowID *int64, email string) {
	if s == nil {
		return
	}
	s.notifyAlert(ctx, tenantID, appRowID, email, mailer.BlockReasonSuspiciousLogin)
}

// notifyAlert sends a blocked_account variant whose call to action is a password
// reset rather than an unblock link.
//
// Asynchronous for the same reason as every other send here: NotifyAdminBlock
// reaches this from the admin API, where an operator disabling a compromised
// account should not wait on a mail relay to see their action confirmed — the
// block is already committed by the time this runs.
func (s *AccountBlockService) notifyAlert(ctx context.Context, tenantID int64, appRowID *int64, email, reason string) {
	s.sendBlockedAccountAsync(ctx, tenantID, appRowID, 0, mailer.BlockedAccountEmail{
		To:     email,
		Link:   fmt.Sprintf("%s/forgot-password", s.appBaseURL),
		Reason: reason,
	})
}

// Unblock consumes a self-service unblock token and restores the account. It
// only ever lifts an automatic lockout: the token is bound to the user, and an
// admin block never issues one, so an admin's decision cannot be undone here.
// Any unblock token issued before an admin block is rejected for the same reason.
func (s *AccountBlockService) Unblock(ctx context.Context, rawToken string) error {
	var tokenID, userID, tenantID int64
	err := s.pool.QueryRow(ctx, `
		SELECT t.id, t.user_id, t.tenant_id
		FROM account_unblock_tokens t
		JOIN users u ON u.id = t.user_id
		WHERE t.token_hash = $1 AND t.used_at IS NULL AND t.expires_at > NOW()
		  AND u.deleted_at IS NULL
		  AND u.block_reason = $2
	`, HashToken(rawToken), mailer.BlockReasonFailedAttempts).Scan(&tokenID, &userID, &tenantID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrInvalidUnblockToken
		}
		return fmt.Errorf("lookup unblock token: %w", err)
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin unblock tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if _, err := tx.Exec(ctx, `UPDATE account_unblock_tokens SET used_at = NOW() WHERE id = $1`, tokenID); err != nil {
		return fmt.Errorf("mark unblock token used: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE users
		SET is_active = true, blocked_at = NULL, block_reason = NULL,
		    failed_login_attempts = 0, last_failed_login_at = NULL, updated_at = NOW()
		WHERE id = $1 AND tenant_id = $2
	`, userID, tenantID); err != nil {
		return fmt.Errorf("unblock user: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit unblock: %w", err)
	}

	s.logger.Info().Int64("user_id", userID).Msg("account unblocked via emailed link")
	s.notify.auditUserEvent(ctx, audit.ActionAuthAccountUnblocked, tenantID, nil, userID, map[string]any{"method": "self_service_link"})
	return nil
}
