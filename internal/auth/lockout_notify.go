package auth

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/engineersmind/emc-auth-server/internal/audit"
	"github.com/engineersmind/emc-auth-server/internal/mailer"
)

// ---------------------------------------------------------------------------
// Lockout notification routing (issue #72).
//
// Two audiences, deliberately treated differently:
//
//	THE ACCOUNT OWNER hears about their own account at every tier. "Someone tried
//	to sign in as you" is always actionable for the person it happened to, and a
//	victim who learns about an attack at attempt three can change their password
//	before attempt ten locks them out.
//
//	ADMINISTRATORS hear only about AGGREGATES. A per-lock email to owners and
//	co-owners looks helpful and is actively harmful: 200 accounts × 3 attempts is
//	600 cheap unauthenticated requests that generate several hundred emails to a
//	tenant's operators, with nothing ever locked. That is a denial-of-service
//	primitive aimed at the alert channel itself — and worse, most single-account
//	lockouts are somebody forgetting a password, so the flood trains operators to
//	filter the sender. The one alert that mattered then lands in a spam folder.
//
//	So per-account locks surface in-app (the locked badge and the audit feed), and
//	email is reserved for the tenant-level spike: many accounts locking inside one
//	window, which is the credential-stuffing signal and is worth an interrupt.
//	Email volume is then bounded by attacks, not by attempts.
// ---------------------------------------------------------------------------

// lockoutRecipient is one administrator who should hear about a tenant-wide
// lockout event.
type lockoutRecipient struct {
	email string
	role  string
}

// lockoutSpikeRecipients returns the administrators to alert about a lockout
// spike in one tenant: the tenant's owners, plus the co-owners scoped to the
// affected application.
//
// appRowID is the locked account's application. When it is nil the co-owner join
// cannot match — `sc.application_id = NULL` is never true in SQL — so only owners
// are returned. That is the correct reading rather than an accident of
// three-valued logic: an account with no application is either a tenant-level
// user or an administrator, and in both cases a co-owner scoped to some unrelated
// application has no standing to be told. For an administrator's own lockout it
// also avoids broadcasting "your owner's account is under attack" to people who
// cannot act on it.
func (s *AccountBlockService) lockoutSpikeRecipients(ctx context.Context, tenantID int64, appRowID *int64) ([]lockoutRecipient, string, error) {
	// The activated_at / is_active / blocked_at filters mirror
	// admin.platformAdminStatus's definition of an administrator who can actually
	// act: an invitation nobody accepted has no mailbox expectation behind it, and
	// a blocked administrator cannot log in to do anything about the alert.
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT u.email, ta.admin_role
		FROM tenant_admins ta
		JOIN users u ON u.id = ta.user_id
		LEFT JOIN tenant_admin_app_scopes sc ON sc.admin_id = ta.id
		WHERE ta.tenant_id = $1
		  AND ta.deleted_at IS NULL
		  AND ta.activated_at IS NOT NULL
		  AND u.deleted_at IS NULL
		  AND u.is_active
		  AND u.blocked_at IS NULL
		  AND u.email <> ''
		  AND (ta.admin_role = $3 OR sc.application_id = $2)
	`, tenantID, appRowID, AdminRoleOwner)
	if err != nil {
		return nil, "", fmt.Errorf("resolve lockout alert recipients: %w", err)
	}
	defer rows.Close()

	var out []lockoutRecipient
	for rows.Next() {
		var r lockoutRecipient
		if err := rows.Scan(&r.email, &r.role); err != nil {
			return nil, "", fmt.Errorf("scan lockout alert recipient: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, "", fmt.Errorf("iterate lockout alert recipients: %w", err)
	}

	var tenantName string
	if err := s.pool.QueryRow(ctx, `
		SELECT COALESCE(NULLIF(display_name, ''), name) FROM tenants WHERE id = $1
	`, tenantID).Scan(&tenantName); err != nil {
		// A missing name costs the email a nicety, not its meaning.
		s.logger.Warn().Err(err).Int64("tenant_id", tenantID).Msg("lockout: could not resolve tenant name for alert")
	}
	return out, tenantName, nil
}

// Redis key shapes for the tiers that hold ephemeral state.
//
// Keyed on user_id rather than a hash of the email, which is what issue #72
// originally proposed. One email address can hold separate accounts in several
// tenants and in several application user bases, and the failure counter already
// fans out across every candidate account — a {tenant, email_hash} key cannot
// express that, and for the no-such-user case there is no tenant to key on at
// all.
func softLockKey(tenantID, userID int64) string {
	return "login:soft:" + strconv.FormatInt(tenantID, 10) + ":" + strconv.FormatInt(userID, 10)
}

func notifyWarnKey(tenantID, userID int64) string {
	return "login:warned:" + strconv.FormatInt(tenantID, 10) + ":" + strconv.FormatInt(userID, 10)
}

func spikeCountKey(tenantID int64) string {
	return "lockout:spike:" + strconv.FormatInt(tenantID, 10)
}

func spikeSentKey(tenantID int64) string {
	return "lockout:spike:sent:" + strconv.FormatInt(tenantID, 10)
}

// spikeAlertDebounce is the minimum gap between two spike alerts for one tenant.
// An attack that keeps running must not keep mailing: the operator has been told,
// and the second email adds nothing the first did not say.
const spikeAlertDebounce = 1 * time.Hour

// WithRedis wires the ephemeral half of the lockout state: soft locks, the
// once-per-window warning marker, and the spike counter.
//
// Optional by design, following the established pattern for Redis in this
// codebase (see AuthService.WithTOTP). Without it the SOFT tier and the spike
// alert are skipped while the HARD tier keeps working, because the hard tier is a
// pure Postgres transaction. That asymmetry is deliberate: losing a temporary
// speed bump when Redis is down is acceptable, whereas losing the control that
// actually disables a compromised account is not — which is the reason the hard
// counter was not moved to Redis as issue #72 proposed.
func (s *AccountBlockService) WithRedis(rdb *redis.Client) *AccountBlockService {
	s.redis = rdb
	return s
}

// WithLockoutPolicy wires per-tenant thresholds. Without it the service falls
// back to DefaultLockoutPolicy, which mirrors the pre-#72 constants.
func (s *AccountBlockService) WithLockoutPolicy(svc *LockoutPolicyService) *AccountBlockService {
	s.policySvc = svc
	return s
}

// SoftLockedFor reports how long an account is soft-locked for, and whether it is
// locked at all.
//
// Returns (0, false) when Redis is not configured: no soft state can exist
// without somewhere to hold it, and failing open here is what keeps the tier a
// speed bump rather than a dependency the login path cannot survive.
//
// A Redis error is also treated as "not locked" and logged. The alternative —
// refusing logins when the cache is unreachable — converts a Redis blip into a
// tenant-wide outage, and the hard tier still backs this up.
func (s *AccountBlockService) SoftLockedFor(ctx context.Context, tenantID, userID int64) (time.Duration, bool) {
	if s == nil || s.redis == nil {
		return 0, false
	}
	ttl, err := s.redis.TTL(ctx, softLockKey(tenantID, userID)).Result()
	if err != nil {
		s.logger.Warn().Err(err).Int64("user_id", userID).Msg("lockout: soft-lock check failed, allowing attempt")
		return 0, false
	}
	// Redis returns -2 for a missing key and -1 for a key with no expiry. Neither
	// is a live soft lock: every soft lock is written with a TTL, so a key without
	// one is a bug or a manual edit and is safer read as absent than as an
	// indefinite lock nothing will ever clear.
	if ttl <= 0 {
		return 0, false
	}
	return ttl, true
}

// applySoftLock starts a soft lock, and returns whether this call was the one
// that started it.
//
// SetNX rather than Set: re-arming on every subsequent failure would extend the
// lock indefinitely, so a user who keeps retrying while locked could never get
// back in — the tier would stop being temporary. Only the first crossing sets the
// clock.
func (s *AccountBlockService) applySoftLock(ctx context.Context, tenantID, userID int64, d time.Duration) bool {
	if s == nil || s.redis == nil || d <= 0 {
		return false
	}
	ok, err := s.redis.SetNX(ctx, softLockKey(tenantID, userID), "1", d).Result()
	if err != nil {
		s.logger.Warn().Err(err).Int64("user_id", userID).Msg("lockout: could not apply soft lock")
		return false
	}
	return ok
}

// ClearSoftLock drops the soft lock and the warning marker for an account.
// Called on a successful sign-in and by the admin unlock path, so an operator's
// unlock is not silently undone by a Redis key nobody thought to clear.
func (s *AccountBlockService) ClearSoftLock(ctx context.Context, tenantID, userID int64) {
	if s == nil || s.redis == nil {
		return
	}
	if err := s.redis.Del(ctx,
		softLockKey(tenantID, userID),
		notifyWarnKey(tenantID, userID),
	).Err(); err != nil {
		s.logger.Warn().Err(err).Int64("user_id", userID).Msg("lockout: could not clear soft-lock state")
	}
}

// markWarned records that the account owner has been emailed about failures in
// this window, and reports whether this call was the first to do so.
//
// Without this gate the warning tier fires on attempt 3 and again on 4, 5, 6…,
// which rebuilds at the user the exact flood the aggregate-only staff policy
// exists to avoid. When Redis is absent it returns false — no marker means no way
// to tell a first warning from a fiftieth, and silence is the safer failure.
func (s *AccountBlockService) markWarned(ctx context.Context, tenantID, userID int64, window time.Duration) bool {
	if s == nil || s.redis == nil || window <= 0 {
		return false
	}
	ok, err := s.redis.SetNX(ctx, notifyWarnKey(tenantID, userID), "1", window).Result()
	if err != nil {
		s.logger.Warn().Err(err).Int64("user_id", userID).Msg("lockout: could not set warning marker")
		return false
	}
	return ok
}

// recordSpike counts one hard lock toward the tenant's window and reports whether
// this lock is the one that crossed the alert threshold.
//
// The counter is a plain INCR with a window TTL rather than a set of user ids:
// the alert only needs a magnitude, and a set would grow with the size of the
// attack. Deliberately >= rather than ==: two locks landing concurrently can skip
// the exact boundary value, and an alert that silently does not fire because of a
// race is worse than the debounce key having to suppress a duplicate.
func (s *AccountBlockService) recordSpike(ctx context.Context, tenantID int64, threshold int, window time.Duration) bool {
	if s == nil || s.redis == nil || threshold <= 0 || window <= 0 {
		return false
	}
	key := spikeCountKey(tenantID)
	n, err := s.redis.Incr(ctx, key).Result()
	if err != nil {
		s.logger.Warn().Err(err).Int64("tenant_id", tenantID).Msg("lockout: spike counter failed")
		return false
	}
	if n == 1 {
		// Only the first lock in a window sets the expiry, so the window is fixed
		// from the first lock rather than sliding forward with every new one — a
		// sliding window under sustained attack would never expire and the counter
		// would keep climbing across unrelated incidents.
		if err := s.redis.Expire(ctx, key, window).Err(); err != nil {
			s.logger.Warn().Err(err).Int64("tenant_id", tenantID).Msg("lockout: could not bound spike window")
		}
	}
	if n < int64(threshold) {
		return false
	}

	// Debounce: one alert per tenant per hour however long the attack runs.
	sent, err := s.redis.SetNX(ctx, spikeSentKey(tenantID), "1", spikeAlertDebounce).Result()
	if err != nil {
		s.logger.Warn().Err(err).Int64("tenant_id", tenantID).Msg("lockout: spike debounce check failed")
		return false
	}
	return sent
}

// spikeCount reads the current window's lock count for the alert body.
func (s *AccountBlockService) spikeCount(ctx context.Context, tenantID int64) int {
	if s == nil || s.redis == nil {
		return 0
	}
	n, err := s.redis.Get(ctx, spikeCountKey(tenantID)).Int()
	if err != nil {
		return 0
	}
	return n
}

// notifyLockoutSpike emails the tenant's owners and the affected application's
// co-owners that many accounts locked inside one window.
//
// Runs detached with its own timeout: it resolves recipients and sends mail, and
// none of that may sit between a failed login attempt and its response. The
// attempt has already been refused by the time this runs.
func (s *AccountBlockService) notifyLockoutSpike(ctx context.Context, tenantID int64, appRowID *int64, count int, window time.Duration) {
	if s == nil {
		return
	}
	detached := context.WithoutCancel(ctx)
	go func() {
		ctx, cancel := context.WithTimeout(detached, riskAlertTimeout)
		defer cancel()

		recipients, tenantName, err := s.lockoutSpikeRecipients(ctx, tenantID, appRowID)
		if err != nil {
			s.logger.Error().Err(err).Int64("tenant_id", tenantID).
				Msg("lockout: could not resolve spike alert recipients")
			return
		}

		s.logger.Warn().
			Int64("tenant_id", tenantID).
			Int("accounts_locked", count).
			Int("recipients", len(recipients)).
			Msg("lockout spike detected — alerting tenant administrators")

		// Audited whether or not anybody could be mailed. A tenant with no
		// reachable administrator is precisely the case where the audit trail is
		// the only record that an attack was detected.
		s.notify.auditTenantEvent(ctx, audit.ActionAuthTenantLockoutSpike, tenantID, appRowID, map[string]any{
			"accounts_locked": count,
			"window_seconds":  int(window.Seconds()),
			"recipients":      len(recipients),
		})
		if len(recipients) == 0 {
			s.logger.Error().Int64("tenant_id", tenantID).
				Msg("lockout spike: no reachable administrator to alert")
			return
		}

		appName := appNameByRowID(ctx, s.pool, appRowID)
		for _, r := range recipients {
			msg := mailer.TenantLockoutAlertEmail{
				To:            r.email,
				Link:          fmt.Sprintf("%s/users?status=blocked", s.dashboardBaseURL()),
				TenantName:    tenantName,
				AppName:       appName,
				Count:         count,
				WindowMinutes: int(window.Minutes()),
			}
			if _, err := s.notify.Send(ctx, tenantID, appRowID, mailer.TemplateTenantLockoutAlert,
				func(sender *mailer.SMTPConfig, tmpl *mailer.Template) error {
					return s.notify.mailer.SendTenantLockoutAlert(ctx, sender, tmpl, msg)
				}); err != nil {
				s.logger.Warn().Err(err).Str("email", r.email).Str("role", r.role).
					Msg("lockout: spike alert could not be delivered")
			}
		}
	}()
}

// dashboardBaseURL is where an operator goes to act on the alert. Falls back to
// appBaseURL so the link is never empty — a dead link is still better than an
// email that tells somebody to go somewhere and does not say where.
func (s *AccountBlockService) dashboardBaseURL() string {
	if s.dashboardURL != "" {
		return s.dashboardURL
	}
	return s.appBaseURL
}
