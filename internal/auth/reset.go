// Package auth provides authentication and session management for emc-auth-server.
package auth

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/engineersmind/emc-auth-server/internal/emailaddr"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/bcrypt"

	"github.com/engineersmind/emc-auth-server/internal/audit"
	"github.com/engineersmind/emc-auth-server/internal/mailer"
)

// ResetTokenTTL is the expiry window for password reset tokens (RESET-01: 15 minutes).
const ResetTokenTTL = 15 * time.Minute

// ResetService implements the forgot-password and reset-password flows.
type ResetService struct {
	pool       *pgxpool.Pool
	mailer     mailer.Mailer
	senderSvc  *EmailSenderService
	tmplSvc    *EmailTemplateService
	audit      *audit.Logger
	appBaseURL string
	logger     zerolog.Logger
}

// NewResetService creates a ResetService.
func NewResetService(pool *pgxpool.Pool, m mailer.Mailer, appBaseURL string, logger zerolog.Logger) *ResetService {
	return &ResetService{
		pool:       pool,
		mailer:     m,
		appBaseURL: appBaseURL,
		logger:     logger,
	}
}

// WithSenders wires the white-label sender resolver so reset emails use the
// tenant's configured sender/branding. Optional: without it, reset always uses
// the global sender (today's behaviour).
func (s *ResetService) WithSenders(senderSvc *EmailSenderService) *ResetService {
	s.senderSvc = senderSvc
	return s
}

// WithTemplates wires the per-scope template resolver so reset emails use the
// tenant's/application's customized template when one is configured. Optional.
func (s *ResetService) WithTemplates(tmplSvc *EmailTemplateService) *ResetService {
	s.tmplSvc = tmplSvc
	return s
}

// WithAudit wires the audit logger so suppressed sends are recorded. Optional.
func (s *ResetService) WithAudit(a *audit.Logger) *ResetService {
	s.audit = a
	return s
}

// auditEmailSuppressed records that a transactional email was not sent because
// its template is disabled at the resolved scope. Nil-safe.
func auditEmailSuppressed(ctx context.Context, a *audit.Logger, tenantID int64, appRowID *int64, tt mailer.TemplateType) {
	if a == nil {
		return
	}
	a.Log(ctx, audit.Event{
		TenantID:      &tenantID,
		ApplicationID: appRowID,
		Action:        audit.ActionAuthEmailSuppressed,
		ResourceType:  "email_template",
		ResourceID:    string(tt),
		Metadata:      map[string]any{"template_type": string(tt)},
	})
}

// ForgotPassword generates a time-limited reset token and emails it to the
// user, scoped to the authenticated application (appRowID). The caller
// authenticates the application via client_id/client_secret and passes the
// resolved tenant + application. ALWAYS returns nil to prevent email
// enumeration (RESET-03).
func (s *ResetService) ForgotPassword(ctx context.Context, tenantID int64, appRowID *int64, email string) error {
	return s.forgotPassword(ctx, tenantID, appRowID, email, true)
}

// ForgotPasswordForced is the admin-initiated variant (ForcePasswordReset): it
// ignores the template disable flag so a super-admin force-reset always sends,
// regardless of the tenant/app template configuration.
func (s *ResetService) ForgotPasswordForced(ctx context.Context, tenantID int64, appRowID *int64, email string) error {
	return s.forgotPassword(ctx, tenantID, appRowID, email, false)
}

func (s *ResetService) forgotPassword(ctx context.Context, tenantID int64, appRowID *int64, email string, honorSuppression bool) error {
	email = emailaddr.Normalize(email)

	// Suppression: if the reset template is disabled at this scope, don't send —
	// unless this is an admin-forced reset (honorSuppression=false).
	if honorSuppression && !s.tmplSvc.IsTypeEnabled(ctx, tenantID, appRowID, mailer.TemplatePasswordReset) {
		s.logger.Info().Int64("tenant_id", tenantID).Msg("forgot-password: reset template disabled at this scope — not sending")
		auditEmailSuppressed(ctx, s.audit, tenantID, appRowID, mailer.TemplatePasswordReset)
		return nil
	}

	// Scope the lookup to the authenticated application: an email may hold
	// independent accounts in different applications of the same tenant, so the
	// application_id disambiguates which account to reset.
	var userID int64
	err := s.pool.QueryRow(ctx,
		`SELECT id FROM users WHERE tenant_id = $1 AND email = $2 AND application_id IS NOT DISTINCT FROM $3 AND is_active = true AND deleted_at IS NULL`,
		tenantID, email, appRowID,
	).Scan(&userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			s.logger.Debug().Str("email", email).Msg("forgot-password: user not found, silently succeeding")
			return nil
		}
		return fmt.Errorf("lookup user for forgot-password: %w", err)
	}

	rawToken, err := GenerateRefreshToken()
	if err != nil {
		return fmt.Errorf("generate reset token: %w", err)
	}
	tokenHash := HashToken(rawToken)

	_, err = s.pool.Exec(ctx, `
		INSERT INTO password_reset_tokens (user_id, tenant_id, token_hash, expires_at)
		VALUES ($1, $2, $3, $4)
	`, userID, tenantID, tokenHash, time.Now().UTC().Add(ResetTokenTTL))
	if err != nil {
		return fmt.Errorf("persist reset token: %w", err)
	}

	resetLink := fmt.Sprintf("%s/api/v1/auth/reset-password?token=%s", s.appBaseURL, rawToken)
	msg := mailer.ResetEmail{
		To:        email,
		ResetLink: resetLink,
		// State the real window so the body can never contradict the token's
		// actual expiry if ResetTokenTTL changes.
		TTLMinutes: int(ResetTokenTTL.Minutes()),
	}

	// Resolve the sender for this application (application → tenant → global). A
	// broken sender must never block a password reset, so fall back to the global
	// sender and log — same policy as the MFA/magic-link paths.
	var sender *mailer.SMTPConfig
	if s.senderSvc != nil {
		sender, err = s.senderSvc.Resolve(ctx, tenantID, appRowID)
		if err != nil {
			s.logger.Warn().Err(err).Int64("tenant_id", tenantID).Msg("forgot-password: sender resolution failed — using global sender")
			sender = nil
		}
	}
	tmpl := s.tmplSvc.ResolveTemplate(ctx, tenantID, appRowID, mailer.TemplatePasswordReset)

	sendErr := s.mailer.SendReset(ctx, sender, tmpl, msg)
	if sendErr != nil && sender != nil {
		s.logger.Warn().Err(sendErr).Str("from", sender.From).Msg("forgot-password: white-label sender failed — retrying via global sender")
		sendErr = s.mailer.SendReset(ctx, nil, tmpl, msg)
	}
	if sendErr != nil {
		s.logger.Error().Err(sendErr).Str("email", email).Msg("forgot-password: email dispatch failed")
		return nil
	}

	s.logger.Info().
		Int64("tenant_id", tenantID).
		Str("user_id", strconv.FormatInt(userID, 10)).
		Msg("forgot-password: reset token issued")

	return nil
}

// ResetPasswordInput is the payload for the reset-password endpoint.
type ResetPasswordInput struct {
	RawToken    string
	NewPassword string
}

// ErrInvalidResetToken is returned when the reset token is invalid, expired, or already used.
var ErrInvalidResetToken = errors.New("invalid or expired reset token")

// ResetPassword validates the reset token and updates the user's password.
func (s *ResetService) ResetPassword(ctx context.Context, in ResetPasswordInput) error {
	if len(in.NewPassword) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}

	tokenHash := HashToken(in.RawToken)

	var tokenID, userID, tenantID int64
	var email string
	var appRowID *int64
	err := s.pool.QueryRow(ctx, `
		SELECT t.id, t.user_id, t.tenant_id, u.email, u.application_id
		FROM password_reset_tokens t
		JOIN users u ON u.id = t.user_id
		WHERE t.token_hash = $1
		  AND t.used_at IS NULL
		  AND t.expires_at > NOW()
	`, tokenHash).Scan(&tokenID, &userID, &tenantID, &email, &appRowID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrInvalidResetToken
		}
		return fmt.Errorf("lookup reset token: %w", err)
	}

	newHash, err := bcrypt.GenerateFromPassword([]byte(in.NewPassword), BcryptCost)
	if err != nil {
		return fmt.Errorf("hash new password: %w", err)
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin reset-password tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	_, err = tx.Exec(ctx, `
		UPDATE password_reset_tokens SET used_at = NOW() WHERE id = $1
	`, tokenID)
	if err != nil {
		return fmt.Errorf("mark reset token used: %w", err)
	}

	_, err = tx.Exec(ctx, `
		UPDATE user_credentials SET password_hash = $1, updated_at = NOW()
		WHERE user_id = $2 AND tenant_id = $3
	`, string(newHash), userID, tenantID)
	if err != nil {
		return fmt.Errorf("update password hash: %w", err)
	}

	_, err = tx.Exec(ctx, `
		UPDATE refresh_tokens SET revoked_at = NOW()
		WHERE user_id = $1 AND tenant_id = $2 AND revoked_at IS NULL
	`, userID, tenantID)
	if err != nil {
		return fmt.Errorf("revoke refresh tokens on password reset: %w", err)
	}

	// The breach warning is per-password: clearing the marker means a user who
	// resets to another breached password is warned again on their next sign-in.
	_, err = tx.Exec(ctx, `UPDATE users SET breach_notified_at = NULL WHERE id = $1 AND tenant_id = $2`, userID, tenantID)
	if err != nil {
		return fmt.Errorf("clear breach marker on password reset: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit reset-password tx: %w", err)
	}

	s.logger.Info().
		Str("user_id", strconv.FormatInt(userID, 10)).
		Str("tenant_id", strconv.FormatInt(tenantID, 10)).
		Msg("password reset completed; all sessions revoked")

	// Confirm the change to the account owner. Best-effort: the password is
	// already changed, so a mail failure must not fail the request — but it is a
	// security notification, so it is logged at warn level when it does fail.
	s.NotifyPasswordChanged(ctx, tenantID, appRowID, email)

	return nil
}

// NotifyPasswordChanged sends the password-changed confirmation for an
// out-of-band password change (reset completion, admin change, self-service
// change). Best-effort and never returns an error: the change has already
// happened by the time this runs.
func (s *ResetService) NotifyPasswordChanged(ctx context.Context, tenantID int64, appRowID *int64, email string) {
	n := EmailNotifier{mailer: s.mailer, senderSvc: s.senderSvc, tmplSvc: s.tmplSvc, audit: s.audit, logger: s.logger}
	_, err := n.Send(ctx, tenantID, appRowID, mailer.TemplatePasswordChanged,
		func(sender *mailer.SMTPConfig, tmpl *mailer.Template) error {
			return s.mailer.SendPasswordChanged(ctx, sender, tmpl, mailer.PasswordChangedEmail{To: email})
		})
	if err != nil {
		s.logger.Warn().Err(err).Str("email", email).Msg("password-changed confirmation could not be delivered")
	}
}
