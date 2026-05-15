// Package auth provides authentication and session management for emc-auth-server.
package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
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
// appBaseURL is prefixed to the reset link, e.g. "https://auth.emc.local".
func NewResetService(pool *pgxpool.Pool, m mailer.Mailer, appBaseURL string, logger zerolog.Logger) *ResetService {
	return &ResetService{
		pool:       pool,
		mailer:     m,
		appBaseURL: appBaseURL,
		logger:     logger,
	}
}

// ForgotPassword generates a time-limited reset token and emails it to the user.
//
// Security (RESET-03): This function ALWAYS returns nil (success) even if the email
// is not registered. The handler must return HTTP 200 regardless to prevent
// email enumeration attacks. Logging is suppressed for "user not found" cases.
//
// Token storage (RESET-04, NFR-05):
// - Generate 32 random bytes via crypto/rand -> hex string (raw token)
// - Compute SHA-256 hash of raw token -> store only the hash in DB
// - Send raw token in the reset link (never stored)
func (s *ResetService) ForgotPassword(ctx context.Context, tenantSlug, email string) error {
	// 1. Resolve tenant.
	var tenantID uuid.UUID
	err := s.pool.QueryRow(ctx,
		`SELECT id FROM tenants WHERE slug = $1 AND is_active = true`,
		tenantSlug,
	).Scan(&tenantID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Tenant not found — silently succeed (RESET-03).
			s.logger.Debug().Str("tenant_slug", tenantSlug).Msg("forgot-password: tenant not found, silently succeeding")
			return nil
		}
		return fmt.Errorf("resolve tenant for forgot-password: %w", err)
	}

	// 2. Look up user by email in this tenant.
	var userID uuid.UUID
	err = s.pool.QueryRow(ctx,
		`SELECT id FROM users WHERE tenant_id = $1 AND email = $2 AND is_active = true AND is_deleted = false`,
		tenantID, email,
	).Scan(&userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// User not found — silently succeed (RESET-03).
			s.logger.Debug().Str("email", email).Msg("forgot-password: user not found, silently succeeding")
			return nil
		}
		return fmt.Errorf("lookup user for forgot-password: %w", err)
	}

	// 3. Generate raw token (32 bytes -> hex) and its SHA-256 hash (RESET-04, NFR-05).
	// Reuse GenerateRefreshToken() — same 32-byte crypto/rand pattern.
	rawToken, err := GenerateRefreshToken()
	if err != nil {
		return fmt.Errorf("generate reset token: %w", err)
	}
	tokenHash := HashToken(rawToken)

	// 4. Persist token hash with 15-minute expiry.
	// Any pre-existing unused reset tokens for this user remain valid (don't invalidate on re-request).
	_, err = s.pool.Exec(ctx, `
		INSERT INTO password_reset_tokens (id, user_id, tenant_id, token_hash, expires_at)
		VALUES (gen_random_uuid(), $1, $2, $3, $4)
	`, userID, tenantID, tokenHash, time.Now().UTC().Add(ResetTokenTTL))
	if err != nil {
		return fmt.Errorf("persist reset token: %w", err)
	}

	// 5. Compose reset link with raw token in query param.
	// The client (or admin UI) handles this URL and posts to /reset-password.
	resetLink := fmt.Sprintf("%s/api/v1/auth/reset-password?token=%s", s.appBaseURL, rawToken)

	// 6. Send email (dev: logs to console; prod: SMTP).
	if err := s.mailer.SendReset(ctx, mailer.ResetEmail{
		To:         email,
		ResetLink:  resetLink,
		TenantSlug: tenantSlug,
	}); err != nil {
		// Log the error but still return nil — the token is persisted.
		// The user can retry; we don't expose email send failures to the caller (RESET-03).
		s.logger.Error().Err(err).Str("email", email).Msg("forgot-password: email dispatch failed")
		return nil
	}

	s.logger.Info().
		Str("tenant", tenantSlug).
		Str("user_id", userID.String()).
		Msg("forgot-password: reset token issued")

	return nil
}

// ResetPasswordInput is the payload for the reset-password endpoint.
type ResetPasswordInput struct {
	// RawToken is the token from the reset link query parameter.
	RawToken string
	// NewPassword is the desired new plaintext password.
	NewPassword string
}

// ErrInvalidResetToken is returned when the reset token is invalid, expired, or already used.
var ErrInvalidResetToken = errors.New("invalid or expired reset token")

// ResetPassword validates the reset token and updates the user's password.
//
// Algorithm (RESET-02):
//  1. Hash the incoming raw token -> look up in password_reset_tokens WHERE used_at IS NULL AND expires_at > NOW().
//  2. If not found -> ErrInvalidResetToken (400).
//  3. Mark the token as used (SET used_at = NOW()).
//  4. Hash the new password with bcrypt cost 12.
//  5. UPDATE user_credentials SET password_hash = <new_hash>.
//  6. Revoke ALL active refresh_tokens for this user (SET revoked_at = NOW()).
//  7. Return nil.
//
// Steps 3-6 run in a single transaction so a partial failure leaves the
// token unused and the password unchanged.
func (s *ResetService) ResetPassword(ctx context.Context, in ResetPasswordInput) error {
	if len(in.NewPassword) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}

	tokenHash := HashToken(in.RawToken)

	// 1. Look up token — must be unused and not expired.
	var tokenID, userID, tenantID uuid.UUID
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

	// 2. Hash the new password.
	newHash, err := bcrypt.GenerateFromPassword([]byte(in.NewPassword), BcryptCost)
	if err != nil {
		return fmt.Errorf("hash new password: %w", err)
	}

	// 3. Atomic transaction: mark token used, update password, revoke all refresh tokens.
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin reset-password tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// Mark token used.
	_, err = tx.Exec(ctx, `
		UPDATE password_reset_tokens SET used_at = NOW() WHERE id = $1
	`, tokenID)
	if err != nil {
		return fmt.Errorf("mark reset token used: %w", err)
	}

	// Update password hash.
	_, err = tx.Exec(ctx, `
		UPDATE user_credentials SET password_hash = $1, updated_at = NOW()
		WHERE user_id = $2 AND tenant_id = $3
	`, string(newHash), userID, tenantID)
	if err != nil {
		return fmt.Errorf("update password hash: %w", err)
	}

	// Revoke ALL active refresh tokens for this user (session invalidation on password reset).
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
		Str("user_id", userID.String()).
		Str("tenant_id", tenantID.String()).
		Msg("password reset completed; all sessions revoked")

	return nil
}
