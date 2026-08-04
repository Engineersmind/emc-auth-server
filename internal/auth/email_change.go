package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	"github.com/engineersmind/emc-auth-server/internal/audit"
	"github.com/engineersmind/emc-auth-server/internal/mailer"
)

// ---------------------------------------------------------------------------
// Self-service email change (Auth0-style). The new address is held in
// email_change_requests until the user proves control of it by following a
// single-use link; only then does users.email move. Holding it out of the users
// row is the whole point: a typo'd or attacker-supplied address can never take
// over the account, because the change never lands until the NEW inbox confirms.
//
// The confirmation link goes to the new address only — sending it to the old one
// would defeat the proof-of-control check. The old address is told after the fact
// instead: once the change applies it receives a security notice naming the new
// address, so a silent takeover is impossible even for someone holding a valid
// session.
// ---------------------------------------------------------------------------

// EmailChangeTTL is how long a pending email-change confirmation stays valid.
const EmailChangeTTL = 1 * time.Hour

var (
	// ErrInvalidEmailChange is returned when a token is unknown, expired, or used.
	ErrInvalidEmailChange = errors.New("invalid or expired email change token")
	// ErrEmailTaken is returned when the requested address already belongs to
	// another account in the same scope.
	ErrEmailTaken = errors.New("email address is already in use")
	// ErrSameEmail is returned when the requested address is the current one.
	ErrSameEmail = errors.New("new email matches the current address")
)

// EmailChangeService implements the request/confirm email-change flow.
type EmailChangeService struct {
	pool       *pgxpool.Pool
	notify     EmailNotifier
	appBaseURL string
	logger     zerolog.Logger
}

// NewEmailChangeService creates an EmailChangeService.
func NewEmailChangeService(pool *pgxpool.Pool, m mailer.Mailer, appBaseURL string, logger zerolog.Logger) *EmailChangeService {
	return &EmailChangeService{
		pool:       pool,
		notify:     EmailNotifier{mailer: m, logger: logger},
		appBaseURL: appBaseURL,
		logger:     logger,
	}
}

// WithSenders wires the white-label sender resolver.
func (s *EmailChangeService) WithSenders(senderSvc *EmailSenderService) *EmailChangeService {
	s.notify.senderSvc = senderSvc
	return s
}

// WithTemplates wires the per-scope template resolver.
func (s *EmailChangeService) WithTemplates(tmplSvc *EmailTemplateService) *EmailChangeService {
	s.notify.tmplSvc = tmplSvc
	return s
}

// WithAudit wires the audit logger so suppressed sends are recorded.
func (s *EmailChangeService) WithAudit(a *audit.Logger) *EmailChangeService {
	s.notify.audit = a
	return s
}

// Request starts an email change for an authenticated user: it records the
// pending address and emails a confirmation link to it. The caller supplies the
// user identity from verified JWT claims — this flow never accepts a user id
// from the request body.
func (s *EmailChangeService) Request(ctx context.Context, tenantID, userID int64, newEmail string) error {
	newEmail = strings.ToLower(strings.TrimSpace(newEmail))
	if newEmail == "" || !strings.Contains(newEmail, "@") {
		return fmt.Errorf("a valid email address is required")
	}

	var currentEmail string
	var appRowID *int64
	err := s.pool.QueryRow(ctx, `
		SELECT email, application_id FROM users
		WHERE id = $1 AND tenant_id = $2 AND is_active = true AND deleted_at IS NULL
	`, userID, tenantID).Scan(&currentEmail, &appRowID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("user not found")
		}
		return fmt.Errorf("lookup user for email change: %w", err)
	}
	if strings.EqualFold(currentEmail, newEmail) {
		return ErrSameEmail
	}

	// Uniqueness is per (tenant, application) user base, matching the users
	// table's scoping — the same address may hold separate accounts in different
	// applications of one tenant.
	var taken bool
	if err := s.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM users
			WHERE tenant_id = $1 AND email = $2 AND application_id IS NOT DISTINCT FROM $3
			  AND deleted_at IS NULL AND id <> $4
		)
	`, tenantID, newEmail, appRowID, userID).Scan(&taken); err != nil {
		return fmt.Errorf("check email availability: %w", err)
	}
	if taken {
		return ErrEmailTaken
	}

	rawToken, err := GenerateRefreshToken()
	if err != nil {
		return fmt.Errorf("generate email change token: %w", err)
	}

	// One pending change per user: a new request supersedes the previous one.
	if _, err := s.pool.Exec(ctx, `
		UPDATE email_change_requests SET used_at = NOW()
		WHERE user_id = $1 AND used_at IS NULL
	`, userID); err != nil {
		return fmt.Errorf("supersede prior email change: %w", err)
	}
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO email_change_requests (user_id, tenant_id, new_email, token_hash, expires_at)
		VALUES ($1, $2, $3, $4, $5)
	`, userID, tenantID, newEmail, HashToken(rawToken), time.Now().UTC().Add(EmailChangeTTL)); err != nil {
		return fmt.Errorf("persist email change request: %w", err)
	}

	msg := mailer.ChangeEmailEmail{
		To:         newEmail,
		Link:       fmt.Sprintf("%s/api/v1/auth/confirm-email-change?token=%s", s.appBaseURL, rawToken),
		AppName:    appNameByRowID(ctx, s.pool, appRowID),
		TTLMinutes: int(EmailChangeTTL.Minutes()),
	}
	sent, err := s.notify.Send(ctx, tenantID, appRowID, mailer.TemplateChangeEmail,
		func(sender *mailer.SMTPConfig, tmpl *mailer.Template) error {
			return s.notify.mailer.SendChangeEmail(ctx, sender, tmpl, msg)
		})
	if err != nil {
		return fmt.Errorf("send email change confirmation: %w", err)
	}
	if !sent {
		if _, delErr := s.pool.Exec(ctx, `UPDATE email_change_requests SET used_at = NOW() WHERE user_id = $1 AND used_at IS NULL`, userID); delErr != nil {
			s.logger.Warn().Err(delErr).Int64("user_id", userID).Msg("email change: could not retire unsent token")
		}
		return nil
	}
	s.logger.Info().Int64("user_id", userID).Msg("email change confirmation sent to new address")
	return nil
}

// EmailChangeResult describes an applied email change. It carries the identity
// the caller needs for a complete audit record — the handler has no session to
// read it from, because the confirmation link is followed unauthenticated.
type EmailChangeResult struct {
	UserID   int64
	TenantID int64
	OldEmail string
	NewEmail string
}

// Confirm consumes an email-change token and moves users.email to the confirmed
// address, marking it verified. The identity on the account has changed, so this
// is treated like any other credential change: token_version is bumped and every
// refresh token revoked, so sessions carrying the old email claim cannot outlive
// it. The previous address is then told what happened.
func (s *EmailChangeService) Confirm(ctx context.Context, rawToken string) (*EmailChangeResult, error) {
	var res EmailChangeResult
	var reqID int64
	var appRowID *int64
	err := s.pool.QueryRow(ctx, `
		SELECT r.id, r.user_id, r.tenant_id, r.new_email, u.email, u.application_id
		FROM email_change_requests r
		JOIN users u ON u.id = r.user_id
		WHERE r.token_hash = $1 AND r.used_at IS NULL AND r.expires_at > NOW()
		  AND u.deleted_at IS NULL
	`, HashToken(rawToken)).Scan(&reqID, &res.UserID, &res.TenantID, &res.NewEmail, &res.OldEmail, &appRowID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrInvalidEmailChange
		}
		return nil, fmt.Errorf("lookup email change request: %w", err)
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin confirm-email-change tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if _, err := tx.Exec(ctx, `UPDATE email_change_requests SET used_at = NOW() WHERE id = $1`, reqID); err != nil {
		return nil, fmt.Errorf("mark email change used: %w", err)
	}
	// The address may have been claimed between request and confirmation, so the
	// unique constraint is the authority here, not the earlier availability check.
	if _, err := tx.Exec(ctx, `
		UPDATE users SET email = $1, email_verified = true,
		    token_version = token_version + 1, updated_at = NOW()
		WHERE id = $2 AND tenant_id = $3
	`, res.NewEmail, res.UserID, res.TenantID); err != nil {
		if isUniqueViolation(err) {
			return nil, ErrEmailTaken
		}
		return nil, fmt.Errorf("apply email change: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE refresh_tokens SET revoked_at = NOW()
		WHERE user_id = $1 AND tenant_id = $2 AND revoked_at IS NULL
	`, res.UserID, res.TenantID); err != nil {
		return nil, fmt.Errorf("revoke sessions on email change: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit confirm-email-change: %w", err)
	}

	s.logger.Info().Int64("user_id", res.UserID).Msg("email change confirmed")
	s.notifyOldAddress(ctx, res.TenantID, appRowID, res.OldEmail, res.NewEmail)
	return &res, nil
}

// notifyOldAddress tells the previous address that the account moved. Without it
// an attacker holding a captured access token could reroute an account silently,
// and the original owner would have no signal at all. Best-effort and after
// commit: the change stands whether or not this mail is delivered.
func (s *EmailChangeService) notifyOldAddress(ctx context.Context, tenantID int64, appRowID *int64, oldEmail, newEmail string) {
	if oldEmail == "" {
		return
	}
	msg := mailer.ChangeEmailEmail{
		To:       oldEmail,
		Link:     fmt.Sprintf("%s/forgot-password", s.appBaseURL),
		AppName:  appNameByRowID(ctx, s.pool, appRowID),
		Reason:   mailer.EmailChangeApplied,
		NewEmail: newEmail,
	}
	if _, err := s.notify.Send(ctx, tenantID, appRowID, mailer.TemplateChangeEmail,
		func(sender *mailer.SMTPConfig, tmpl *mailer.Template) error {
			return s.notify.mailer.SendChangeEmail(ctx, sender, tmpl, msg)
		}); err != nil {
		s.logger.Warn().Err(err).Msg("email change: could not alert the previous address")
	}
}
