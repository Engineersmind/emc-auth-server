// Package auth provides authentication and session management for emc-auth-server.
package auth

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/bcrypt"

	"github.com/engineersmind/emc-auth-server/internal/mailer"
)

// ResetTokenTTL is the expiry window for password reset tokens (RESET-01: 15 minutes).
const ResetTokenTTL = 15 * time.Minute

// ResetService implements the forgot-password and reset-password flows.
type ResetService struct {
	pool       *pgxpool.Pool
	mailer     mailer.Mailer
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

// ForgotPassword generates a time-limited reset token and emails it to the user.
// ALWAYS returns nil to prevent email enumeration (RESET-03).
func (s *ResetService) ForgotPassword(ctx context.Context, tenantSlug, email string) error {
	var tenantID int64
	err := s.pool.QueryRow(ctx,
		`SELECT id FROM tenants WHERE slug = $1 AND is_active = true`,
		tenantSlug,
	).Scan(&tenantID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			s.logger.Debug().Str("tenant_slug", tenantSlug).Msg("forgot-password: tenant not found, silently succeeding")
			return nil
		}
		return fmt.Errorf("resolve tenant for forgot-password: %w", err)
	}

	var userID int64
	err = s.pool.QueryRow(ctx,
		`SELECT id FROM users WHERE tenant_id = $1 AND email = $2 AND is_active = true AND deleted_at IS NULL`,
		tenantID, email,
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

	if err := s.mailer.SendReset(ctx, mailer.ResetEmail{
		To:         email,
		ResetLink:  resetLink,
		TenantSlug: tenantSlug,
	}); err != nil {
		s.logger.Error().Err(err).Str("email", email).Msg("forgot-password: email dispatch failed")
		return nil
	}

	s.logger.Info().
		Str("tenant", tenantSlug).
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
	err := s.pool.QueryRow(ctx, `
		SELECT id, user_id, tenant_id
		FROM password_reset_tokens
		WHERE token_hash = $1
		  AND used_at IS NULL
		  AND expires_at > NOW()
	`, tokenHash).Scan(&tokenID, &userID, &tenantID)
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

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit reset-password tx: %w", err)
	}

	s.logger.Info().
		Str("user_id", strconv.FormatInt(userID, 10)).
		Str("tenant_id", strconv.FormatInt(tenantID, 10)).
		Msg("password reset completed; all sessions revoked")

	return nil
}
