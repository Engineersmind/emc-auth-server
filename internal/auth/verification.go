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
// Email verification (Auth0-style). On self-service registration a signed,
// single-use verification link is emailed; clicking it flips
// users.email_verified to true and triggers a welcome email. Enforcement (are
// unverified users blocked at login?) is a separate opt-in policy — this flow
// only establishes verified state.
//
// Tokens live in the email_verification_tokens table (user_id, tenant_id,
// token_hash, expires_at, used_at). Only the SHA-256 hash is stored; the raw
// token is emailed and never persisted.
// ---------------------------------------------------------------------------

// VerificationTokenTTL is how long a verification link stays valid.
const VerificationTokenTTL = 24 * time.Hour

// ErrInvalidVerificationToken is returned when a token is unknown, expired, or
// already used.
var ErrInvalidVerificationToken = errors.New("invalid or expired verification token")

// VerificationService implements the send/verify/resend email-verification flow.
type VerificationService struct {
	pool       *pgxpool.Pool
	mailer     mailer.Mailer
	senderSvc  *EmailSenderService
	tmplSvc    *EmailTemplateService
	audit      *audit.Logger
	appBaseURL string
	logger     zerolog.Logger
}

// NewVerificationService creates a VerificationService.
func NewVerificationService(pool *pgxpool.Pool, m mailer.Mailer, appBaseURL string, logger zerolog.Logger) *VerificationService {
	return &VerificationService{pool: pool, mailer: m, appBaseURL: appBaseURL, logger: logger}
}

// WithSenders wires the white-label sender resolver.
func (s *VerificationService) WithSenders(senderSvc *EmailSenderService) *VerificationService {
	s.senderSvc = senderSvc
	return s
}

// WithTemplates wires the per-scope template resolver.
func (s *VerificationService) WithTemplates(tmplSvc *EmailTemplateService) *VerificationService {
	s.tmplSvc = tmplSvc
	return s
}

// WithAudit wires the audit logger so suppressed sends are recorded. Optional.
func (s *VerificationService) WithAudit(a *audit.Logger) *VerificationService {
	s.audit = a
	return s
}

// resolveSender resolves the white-label sender chain, degrading to the global
// sender (nil) on any error — a broken tenant sender must never block a send.
func (s *VerificationService) resolveSender(ctx context.Context, tenantID int64, appRowID *int64) *mailer.SMTPConfig {
	if s.senderSvc == nil {
		return nil
	}
	sender, err := s.senderSvc.Resolve(ctx, tenantID, appRowID)
	if err != nil {
		s.logger.Warn().Err(err).Int64("tenant_id", tenantID).Msg("verification: sender resolution failed — using global sender")
		return nil
	}
	return sender
}

// SendVerification issues a fresh verification token for a user and emails the
// link. Best-effort: a send failure is logged, not returned, so it never blocks
// the registration that triggered it. Called on registration.
func (s *VerificationService) SendVerification(ctx context.Context, tenantID int64, appRowID *int64, userID int64, email, appName string) {
	// Suppression: if the verification template is disabled at this scope, skip.
	if !s.tmplSvc.IsTypeEnabled(ctx, tenantID, appRowID, mailer.TemplateEmailVerification) {
		s.logger.Info().Int64("tenant_id", tenantID).Msg("verification template disabled at this scope — not sending")
		auditEmailSuppressed(ctx, s.audit, tenantID, appRowID, mailer.TemplateEmailVerification)
		return
	}

	rawToken, err := GenerateRefreshToken()
	if err != nil {
		s.logger.Error().Err(err).Msg("verification: generate token failed")
		return
	}
	tokenHash := HashToken(rawToken)

	_, err = s.pool.Exec(ctx, `
		INSERT INTO email_verification_tokens (user_id, tenant_id, token_hash, expires_at)
		VALUES ($1, $2, $3, $4)
	`, userID, tenantID, tokenHash, time.Now().UTC().Add(VerificationTokenTTL))
	if err != nil {
		s.logger.Error().Err(err).Int64("user_id", userID).Msg("verification: persist token failed")
		return
	}

	link := fmt.Sprintf("%s/api/v1/auth/verify-email?token=%s", s.appBaseURL, rawToken)
	msg := mailer.VerificationEmail{To: email, Link: link, AppName: appName, TTLMinutes: int(VerificationTokenTTL.Minutes())}

	sender := s.resolveSender(ctx, tenantID, appRowID)
	tmpl := s.tmplSvc.ResolveTemplate(ctx, tenantID, appRowID, mailer.TemplateEmailVerification)

	sendErr := s.mailer.SendVerification(ctx, sender, tmpl, msg)
	if sendErr != nil && sender != nil {
		s.logger.Warn().Err(sendErr).Msg("verification: white-label sender failed — retrying via global sender")
		sendErr = s.mailer.SendVerification(ctx, nil, tmpl, msg)
	}
	if sendErr != nil {
		s.logger.Error().Err(sendErr).Str("email", email).Msg("verification: email dispatch failed")
		return
	}
	s.logger.Info().Str("email", email).Int64("user_id", userID).Msg("verification email sent")
}

// VerifyEmail consumes a verification token: it marks the token used and sets
// users.email_verified = true in one transaction, then sends a welcome email
// (best-effort). Idempotency: a token is single-use; a second click reports the
// token invalid.
func (s *VerificationService) VerifyEmail(ctx context.Context, rawToken string) error {
	tokenHash := HashToken(rawToken)

	var tokenID, userID, tenantID int64
	err := s.pool.QueryRow(ctx, `
		SELECT id, user_id, tenant_id
		FROM email_verification_tokens
		WHERE token_hash = $1 AND used_at IS NULL AND expires_at > NOW()
	`, tokenHash).Scan(&tokenID, &userID, &tenantID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrInvalidVerificationToken
		}
		return fmt.Errorf("lookup verification token: %w", err)
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin verify-email tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if _, err = tx.Exec(ctx, `UPDATE email_verification_tokens SET used_at = NOW() WHERE id = $1`, tokenID); err != nil {
		return fmt.Errorf("mark verification token used: %w", err)
	}
	var email string
	var appRowID *int64
	err = tx.QueryRow(ctx, `
		UPDATE users SET email_verified = true, updated_at = NOW()
		WHERE id = $1 AND tenant_id = $2
		RETURNING email, application_id
	`, userID, tenantID).Scan(&email, &appRowID)
	if err != nil {
		return fmt.Errorf("mark email verified: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit verify-email: %w", err)
	}

	s.logger.Info().Int64("user_id", userID).Msg("email verified")

	// Welcome email (best-effort, never fails the verification).
	appName := ""
	if appRowID != nil {
		_ = s.pool.QueryRow(ctx, `SELECT name FROM oauth_clients WHERE id = $1`, *appRowID).Scan(&appName)
	}
	if s.tmplSvc.IsTypeEnabled(ctx, tenantID, appRowID, mailer.TemplateWelcome) {
		sender := s.resolveSender(ctx, tenantID, appRowID)
		tmpl := s.tmplSvc.ResolveTemplate(ctx, tenantID, appRowID, mailer.TemplateWelcome)
		if err := s.mailer.SendWelcome(ctx, sender, tmpl, mailer.WelcomeEmail{To: email, AppName: appName}); err != nil {
			if sender != nil {
				_ = s.mailer.SendWelcome(ctx, nil, tmpl, mailer.WelcomeEmail{To: email, AppName: appName})
			}
		}
	} else {
		s.logger.Info().Int64("tenant_id", tenantID).Msg("welcome template disabled at this scope — not sending")
		auditEmailSuppressed(ctx, s.audit, tenantID, appRowID, mailer.TemplateWelcome)
	}
	return nil
}

// ResendVerification re-issues a verification link for a tenant-level user.
// ALWAYS returns nil to prevent email enumeration, mirroring ForgotPassword.
// Already-verified or unknown emails silently succeed.
func (s *VerificationService) ResendVerification(ctx context.Context, tenantSlug, email string) error {
	var tenantID int64
	err := s.pool.QueryRow(ctx,
		`SELECT id FROM tenants WHERE slug = $1 AND is_active = true`, tenantSlug,
	).Scan(&tenantID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return fmt.Errorf("resolve tenant for resend-verification: %w", err)
	}

	var userID int64
	err = s.pool.QueryRow(ctx, `
		SELECT id FROM users
		WHERE tenant_id = $1 AND email = $2 AND application_id IS NULL
		  AND is_active = true AND deleted_at IS NULL AND email_verified = false
	`, tenantID, email).Scan(&userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			s.logger.Debug().Str("email", email).Msg("resend-verification: no unverified user, silently succeeding")
			return nil
		}
		return fmt.Errorf("lookup user for resend-verification: %w", err)
	}

	s.SendVerification(ctx, tenantID, nil, userID, email, "")
	return nil
}
