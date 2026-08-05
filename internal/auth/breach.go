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
	"github.com/engineersmind/emc-auth-server/internal/security/breach"
)

// ---------------------------------------------------------------------------
// Breached-password detection (the password_breach email).
//
// After a successful sign-in the submitted password is checked against the Have
// I Been Pwned corpus (k-anonymous — see internal/security/breach). A hit sends
// the user a warning with a reset link; it does NOT block the login. Rejecting a
// credential that has been valid until now would lock people out of their own
// accounts on an advisory third-party signal, so detection is decoupled from
// enforcement, matching the built-in template's wording ("please choose a new
// password now").
//
// The check runs off the request path: the caller hands it to Notify, which
// returns immediately and does the lookup on a detached context. A user is
// warned once per password (users.breach_notified_at), so keeping a breached
// password does not mean a warning on every sign-in.
// ---------------------------------------------------------------------------

// breachCheckTimeout bounds the whole detached check (HTTP lookup + DB writes +
// send), since it no longer has a request context to inherit a deadline from.
const breachCheckTimeout = 20 * time.Second

// BreachService warns users whose password appears in a known breach.
type BreachService struct {
	pool       *pgxpool.Pool
	checker    *breach.Checker
	notify     EmailNotifier
	appBaseURL string
	logger     zerolog.Logger
}

// NewBreachService creates a BreachService. A nil checker (feature disabled)
// yields a service whose Notify is a no-op, so call sites need no branch.
func NewBreachService(pool *pgxpool.Pool, checker *breach.Checker, m mailer.Mailer, appBaseURL string, logger zerolog.Logger) *BreachService {
	return &BreachService{
		pool:       pool,
		checker:    checker,
		notify:     EmailNotifier{mailer: m, logger: logger},
		appBaseURL: appBaseURL,
		logger:     logger,
	}
}

// WithSenders wires the white-label sender resolver.
func (s *BreachService) WithSenders(senderSvc *EmailSenderService) *BreachService {
	s.notify.senderSvc = senderSvc
	return s
}

// WithTemplates wires the per-scope template resolver.
func (s *BreachService) WithTemplates(tmplSvc *EmailTemplateService) *BreachService {
	s.notify.tmplSvc = tmplSvc
	return s
}

// WithAudit wires the audit logger so suppressed sends are recorded.
func (s *BreachService) WithAudit(a *audit.Logger) *BreachService {
	s.notify.audit = a
	return s
}

// Enabled reports whether breach checking is configured.
func (s *BreachService) Enabled() bool { return s != nil && s.checker != nil }

// Notify starts a detached breach check for a password that has just been used
// or set, and warns the user if it is breached. It returns immediately: the
// lookup is a third-party HTTP call and must never sit on the login path.
//
// The goroutine deliberately does not inherit the request's cancellation — the
// response is sent long before the check finishes — but it does carry a hard
// timeout of its own.
func (s *BreachService) Notify(ctx context.Context, tenantID int64, appRowID *int64, userID int64, email, password string) {
	if !s.Enabled() || password == "" {
		return
	}
	detached := context.WithoutCancel(ctx)
	go func() {
		ctx, cancel := context.WithTimeout(detached, breachCheckTimeout)
		defer cancel()
		if err := s.CheckNow(ctx, tenantID, appRowID, userID, email, password); err != nil {
			s.logger.Warn().Err(err).Int64("user_id", userID).Msg("breach: detached check failed")
		}
	}()
}

// CheckNow performs the lookup inline and, on a hit, claims the
// one-warning-per-password slot and sends the alert. Notify is the normal entry
// point; this is exported for callers that need the check to complete before
// they continue (and for tests, which cannot join a detached goroutine).
//
// A nil return means "nothing more to do" — including the common cases of a
// clean password and an already-warned user.
func (s *BreachService) CheckNow(ctx context.Context, tenantID int64, appRowID *int64, userID int64, email, password string) error {
	if !s.Enabled() || password == "" {
		return nil
	}
	count := s.checker.Count(ctx, password)
	if count <= 0 {
		return nil
	}

	// Claim the slot before sending. The conditional UPDATE is the lock: two
	// concurrent sign-ins with the same breached password produce exactly one
	// warning, because only one of them observes a NULL breach_notified_at.
	var claimed bool
	err := s.pool.QueryRow(ctx, `
		UPDATE users SET breach_notified_at = NOW()
		WHERE id = $1 AND tenant_id = $2 AND breach_notified_at IS NULL AND deleted_at IS NULL
		RETURNING true
	`, userID, tenantID).Scan(&claimed)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			s.logger.Warn().Err(err).Int64("user_id", userID).Msg("breach: could not claim notification slot")
		}
		return nil // already warned for this password, or the row is gone
	}

	s.logger.Warn().
		Int64("user_id", userID).
		Int64("tenant_id", tenantID).
		Int("breach_count", count).
		Msg("password found in known breach corpus — warning user")
	// The count is recorded, never the password or its hash.
	s.notify.auditUserEvent(ctx, audit.ActionAuthPasswordBreachFound, tenantID, appRowID, userID, map[string]any{
		"breach_count": count,
		"source":       "pwnedpasswords",
	})

	msg := mailer.PasswordBreachEmail{
		To:      email,
		Link:    fmt.Sprintf("%s/forgot-password", s.appBaseURL),
		AppName: appNameByRowID(ctx, s.pool, appRowID),
	}
	if _, err := s.notify.Send(ctx, tenantID, appRowID, mailer.TemplatePasswordBreach,
		func(sender *mailer.SMTPConfig, tmpl *mailer.Template) error {
			return s.notify.mailer.SendPasswordBreach(ctx, sender, tmpl, msg)
		}); err != nil {
		// Release the slot so the next sign-in retries rather than swallowing the
		// only warning the user was ever going to get.
		if _, rbErr := s.pool.Exec(ctx, `UPDATE users SET breach_notified_at = NULL WHERE id = $1 AND tenant_id = $2`, userID, tenantID); rbErr != nil {
			s.logger.Warn().Err(rbErr).Int64("user_id", userID).Msg("breach: could not release notification slot")
		}
		return fmt.Errorf("send breach warning: %w", err)
	}
	return nil
}

// ClearNotified resets the one-warning-per-password marker. Callers invoke it
// whenever a password changes, so a user who ignores the warning and later
// changes to another breached password is warned again. Best-effort.
func (s *BreachService) ClearNotified(ctx context.Context, tenantID, userID int64) {
	if s == nil {
		return
	}
	if _, err := s.pool.Exec(ctx, `UPDATE users SET breach_notified_at = NULL WHERE id = $1 AND tenant_id = $2`, userID, tenantID); err != nil {
		s.logger.Warn().Err(err).Int64("user_id", userID).Msg("breach: could not clear notification marker")
	}
}
