package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	"github.com/engineersmind/emc-auth-server/internal/audit"
	"github.com/engineersmind/emc-auth-server/internal/mailer"
)

// ---------------------------------------------------------------------------
// Account blocking and suspicious-activity alerts (the blocked_account email).
//
// Three distinct events reach one template, distinguished by Reason:
//
//	failed_attempts  — automatic lockout after MaxFailedLogins wrong passwords.
//	                   The user may lift it themselves via a single-use link.
//	admin            — an operator disabled the account. No self-unblock link:
//	                   letting the user undo an admin action would defeat it, so
//	                   the link is a password reset and access needs an admin.
//	suspicious_login — a high-risk sign-in SUCCEEDED. Nothing is blocked; this is
//	                   a "was this you?" alert with a password-reset link.
//
// Only the automatic path mints an unblock token. Brute-force counting is
// per-account (users.failed_login_attempts), reset on any successful sign-in, so
// a user's own typos never accumulate toward a lockout across sessions.
// ---------------------------------------------------------------------------

const (
	// MaxFailedLogins is how many consecutive failed password attempts block an
	// account. Chosen to sit well above realistic typo counts and far below what
	// an online guessing attack needs; the per-IP rate limiter is the first line
	// of defence, this is the per-account backstop.
	MaxFailedLogins = 10

	// FailedLoginWindow is how long a failed attempt counts toward a lockout. A
	// user who mistypes twice today and once next week is never locked out.
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

// AccountBlockService owns lockout state and the blocked_account notifications.
type AccountBlockService struct {
	pool       *pgxpool.Pool
	notify     EmailNotifier
	risk       audit.RiskAssessor // nil when risk assessment is not configured
	appBaseURL string
	logger     zerolog.Logger
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
		s.notify.auditUserEvent(ctx, audit.ActionAuthAccountBlocked, tenantID, appRowID, userID, map[string]any{
			"reason": mailer.BlockReasonSuspiciousLogin,
			"risk":   signals,
		})
		s.notifyAlert(ctx, tenantID, appRowID, email, mailer.BlockReasonSuspiciousLogin)
	}()
}

// RecordFailedLogin increments the account's consecutive-failure counter and, on
// reaching MaxFailedLogins, blocks the account and emails a single-use unblock
// link. Attempts older than FailedLoginWindow do not count: the counter restarts
// at 1 when the previous failure has aged out.
//
// Best-effort and nil-safe — it is called from the login path, where a bookkeeping
// error must never turn a plain "invalid credentials" into a 500. It reports
// whether the account ended up blocked, for the caller's audit metadata.
func (s *AccountBlockService) RecordFailedLogin(ctx context.Context, tenantID, userID int64) bool {
	if s == nil {
		return false
	}
	var attempts int
	var email string
	var appRowID *int64
	err := s.pool.QueryRow(ctx, `
		UPDATE users
		SET failed_login_attempts = CASE
				WHEN last_failed_login_at IS NULL OR last_failed_login_at < NOW() - make_interval(mins => $3) THEN 1
				ELSE failed_login_attempts + 1
			END,
			last_failed_login_at = NOW(),
			updated_at = NOW()
		WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL
		RETURNING failed_login_attempts, email, application_id
	`, userID, tenantID, int(FailedLoginWindow.Minutes())).Scan(&attempts, &email, &appRowID)
	if err != nil {
		s.logger.Warn().Err(err).Int64("user_id", userID).Msg("lockout: could not record failed login")
		return false
	}
	if attempts < MaxFailedLogins {
		return false
	}
	return s.blockForFailedAttempts(ctx, tenantID, appRowID, userID, email)
}

// blockForFailedAttempts performs the automatic lockout: clear is_active, stamp
// the reason, bump token_version so any issued access token stops validating,
// revoke refresh tokens, then email the unblock link.
func (s *AccountBlockService) blockForFailedAttempts(ctx context.Context, tenantID int64, appRowID *int64, userID int64, email string) bool {
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
	if _, err := tx.Exec(ctx, `
		UPDATE refresh_tokens SET revoked_at = NOW()
		WHERE user_id = $1 AND tenant_id = $2 AND revoked_at IS NULL
	`, userID, tenantID); err != nil {
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

	s.logger.Warn().Int64("user_id", userID).Int64("tenant_id", tenantID).Msg("account blocked after repeated failed sign-ins")
	s.notify.auditUserEvent(ctx, audit.ActionAuthAccountBlocked, tenantID, appRowID, userID, map[string]any{
		"reason":       mailer.BlockReasonFailedAttempts,
		"max_attempts": MaxFailedLogins,
	})

	msg := mailer.BlockedAccountEmail{
		To:         email,
		Link:       fmt.Sprintf("%s/api/v1/auth/unblock-account?token=%s", s.appBaseURL, rawToken),
		AppName:    appNameByRowID(ctx, s.pool, appRowID),
		Reason:     mailer.BlockReasonFailedAttempts,
		TTLMinutes: int(UnblockTokenTTL.Minutes()),
	}
	if _, err := s.notify.Send(ctx, tenantID, appRowID, mailer.TemplateBlockedAccount,
		func(sender *mailer.SMTPConfig, tmpl *mailer.Template) error {
			return s.notify.mailer.SendBlockedAccount(ctx, sender, tmpl, msg)
		}); err != nil {
		s.logger.Warn().Err(err).Str("email", email).Msg("lockout: blocked-account email could not be delivered")
	}
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
func (s *AccountBlockService) notifyAlert(ctx context.Context, tenantID int64, appRowID *int64, email, reason string) {
	msg := mailer.BlockedAccountEmail{
		To:      email,
		Link:    fmt.Sprintf("%s/forgot-password", s.appBaseURL),
		AppName: appNameByRowID(ctx, s.pool, appRowID),
		Reason:  reason,
	}
	if _, err := s.notify.Send(ctx, tenantID, appRowID, mailer.TemplateBlockedAccount,
		func(sender *mailer.SMTPConfig, tmpl *mailer.Template) error {
			return s.notify.mailer.SendBlockedAccount(ctx, sender, tmpl, msg)
		}); err != nil {
		s.logger.Warn().Err(err).Str("email", email).Str("reason", reason).Msg("blocked-account alert could not be delivered")
	}
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
