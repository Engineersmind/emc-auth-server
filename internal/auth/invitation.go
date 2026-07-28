package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/bcrypt"

	"github.com/engineersmind/emc-auth-server/internal/audit"
	"github.com/engineersmind/emc-auth-server/internal/mailer"
)

// ---------------------------------------------------------------------------
// User invitations (Auth0-style). An admin creates an account the user has not
// chosen a password for; the user receives a single-use link, sets a password,
// and the address is treated as verified (they proved control of the inbox by
// following the link).
//
// The account exists and is active from creation — the invitation only gates the
// password. That keeps admin listings, role assignment, and RBAC unchanged for
// pending users, and matches the built-in user_invitation template's wording
// ("Accept the invitation to set up your account").
// ---------------------------------------------------------------------------

// InvitationTTL is how long an invitation link stays valid. Longer than a reset
// link: invitations are often sent ahead of an onboarding date.
const InvitationTTL = 72 * time.Hour

// ErrInvalidInvitation is returned when a token is unknown, expired, or used.
var ErrInvalidInvitation = errors.New("invalid or expired invitation")

// ErrWeakPassword is returned when a chosen password is shorter than the
// minimum length enforced everywhere a password is set.
var ErrWeakPassword = errors.New("password must be at least 8 characters")

// ErrInvitationBlocked is returned when the token is valid but the account has
// since been blocked by an administrator. Distinct from ErrInvalidInvitation so
// the handler can answer 403 rather than 400: nothing is wrong with the link,
// the account state is what forbids acceptance.
var ErrInvitationBlocked = errors.New("account is blocked by an administrator")

// InvitationService issues and consumes user invitations.
type InvitationService struct {
	pool       *pgxpool.Pool
	notify     emailNotifier
	appBaseURL string
	logger     zerolog.Logger
}

// NewInvitationService creates an InvitationService.
func NewInvitationService(pool *pgxpool.Pool, m mailer.Mailer, appBaseURL string, logger zerolog.Logger) *InvitationService {
	return &InvitationService{
		pool:       pool,
		notify:     emailNotifier{mailer: m, logger: logger},
		appBaseURL: appBaseURL,
		logger:     logger,
	}
}

// WithSenders wires the white-label sender resolver.
func (s *InvitationService) WithSenders(senderSvc *EmailSenderService) *InvitationService {
	s.notify.senderSvc = senderSvc
	return s
}

// WithTemplates wires the per-scope template resolver.
func (s *InvitationService) WithTemplates(tmplSvc *EmailTemplateService) *InvitationService {
	s.notify.tmplSvc = tmplSvc
	return s
}

// WithAudit wires the audit logger so suppressed sends are recorded.
func (s *InvitationService) WithAudit(a *audit.Logger) *InvitationService {
	s.notify.audit = a
	return s
}

// Invite issues a fresh invitation for an existing user row and emails the link.
// Re-inviting is allowed and simply supersedes any unused invitation, so an
// admin can resend when the first mail is lost. inviterID/inviterName describe
// the admin who triggered it (both optional).
func (s *InvitationService) Invite(ctx context.Context, tenantID int64, appRowID *int64, userID int64, email, inviterName string, inviterID *int64) error {
	rawToken, err := GenerateRefreshToken()
	if err != nil {
		return fmt.Errorf("generate invitation token: %w", err)
	}

	// Invalidate any outstanding invitation first: two live links for one account
	// would let a leaked older mail still claim it after a resend.
	if _, err := s.pool.Exec(ctx, `
		UPDATE user_invitations SET used_at = NOW()
		WHERE user_id = $1 AND used_at IS NULL
	`, userID); err != nil {
		return fmt.Errorf("supersede prior invitations: %w", err)
	}

	if _, err := s.pool.Exec(ctx, `
		INSERT INTO user_invitations (user_id, tenant_id, token_hash, invited_by, expires_at)
		VALUES ($1, $2, $3, $4, $5)
	`, userID, tenantID, HashToken(rawToken), inviterID, time.Now().UTC().Add(InvitationTTL)); err != nil {
		return fmt.Errorf("persist invitation: %w", err)
	}

	var name string
	_ = s.pool.QueryRow(ctx, `SELECT TRIM(CONCAT(first_name, ' ', last_name)) FROM users WHERE id = $1`, userID).Scan(&name)

	msg := mailer.InvitationEmail{
		To:          email,
		Link:        fmt.Sprintf("%s/api/v1/auth/accept-invitation?token=%s", s.appBaseURL, rawToken),
		AppName:     appNameByRowID(ctx, s.pool, appRowID),
		InviterName: inviterName,
		Name:        name,
		TTLMinutes:  int(InvitationTTL.Minutes()),
	}
	sent, err := s.notify.send(ctx, tenantID, appRowID, mailer.TemplateUserInvitation,
		func(sender *mailer.SMTPConfig, tmpl *mailer.Template) error {
			return s.notify.mailer.SendInvitation(ctx, sender, tmpl, msg)
		})
	if err != nil {
		return fmt.Errorf("send invitation: %w", err)
	}
	if !sent {
		// Suppressed by configuration: drop the token rather than leave a live
		// link nobody was told about.
		if _, delErr := s.pool.Exec(ctx, `UPDATE user_invitations SET used_at = NOW() WHERE user_id = $1 AND used_at IS NULL`, userID); delErr != nil {
			s.logger.Warn().Err(delErr).Int64("user_id", userID).Msg("invitation: could not retire unsent token")
		}
		return nil
	}
	s.logger.Info().Int64("user_id", userID).Str("email", email).Msg("invitation sent")
	return nil
}

// InvitationTarget describes the account behind a valid invitation token.
type InvitationTarget struct {
	UserID   int64
	TenantID int64
	Email    string
}

// Accept consumes an invitation: it sets the user's password, marks the email
// verified, and burns the token — all in one transaction, so a failure part-way
// cannot leave a used token with an unchanged password.
func (s *InvitationService) Accept(ctx context.Context, rawToken, newPassword string) (*InvitationTarget, error) {
	if len(newPassword) < 8 {
		return nil, ErrWeakPassword
	}

	var invID int64
	var t InvitationTarget
	var blockReason *string
	err := s.pool.QueryRow(ctx, `
		SELECT i.id, i.user_id, i.tenant_id, u.email, u.block_reason
		FROM user_invitations i
		JOIN users u ON u.id = i.user_id
		WHERE i.token_hash = $1 AND i.used_at IS NULL AND i.expires_at > NOW()
		  AND u.deleted_at IS NULL
	`, HashToken(rawToken)).Scan(&invID, &t.UserID, &t.TenantID, &t.Email, &blockReason)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrInvalidInvitation
		}
		return nil, fmt.Errorf("lookup invitation: %w", err)
	}
	// An admin who blocks an account after inviting it must not be overridden by
	// the still-live invitation link: accepting it would set a password and
	// re-activate the row, silently undoing the operator's decision. Only an
	// automatic failed-attempt lockout may be cleared this way — the same rule the
	// self-service unblock endpoint applies.
	if blockReason != nil && *blockReason != mailer.BlockReasonFailedAttempts {
		return nil, ErrInvitationBlocked
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), BcryptCost)
	if err != nil {
		return nil, fmt.Errorf("hash invitation password: %w", err)
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin accept-invitation tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if _, err := tx.Exec(ctx, `UPDATE user_invitations SET used_at = NOW() WHERE id = $1`, invID); err != nil {
		return nil, fmt.Errorf("mark invitation used: %w", err)
	}
	// Upsert: an invited account normally has a credentials row (created with a
	// throwaway password), but an invitation for an account created by another
	// path may not.
	if _, err := tx.Exec(ctx, `
		INSERT INTO user_credentials (user_id, tenant_id, password_hash)
		VALUES ($1, $2, $3)
		ON CONFLICT (user_id) DO UPDATE SET password_hash = EXCLUDED.password_hash, updated_at = NOW()
	`, t.UserID, t.TenantID, string(hash)); err != nil {
		return nil, fmt.Errorf("set invitation password: %w", err)
	}
	// is_active reflects actual state rather than being forced true: an account
	// carrying a lockout stays inactive until that lockout is lifted through its
	// own path. Only an account with no block at all is activated here.
	if _, err := tx.Exec(ctx, `
		UPDATE users
		SET email_verified = true, is_active = (blocked_at IS NULL),
		    token_version = token_version + 1, updated_at = NOW()
		WHERE id = $1 AND tenant_id = $2
	`, t.UserID, t.TenantID); err != nil {
		return nil, fmt.Errorf("mark invited user verified: %w", err)
	}
	// Setting a password through an invitation is a credential change, so it ends
	// any session that existed beforehand — the case that matters is a user who
	// already had a password and was re-invited.
	if _, err := tx.Exec(ctx, `
		UPDATE refresh_tokens SET revoked_at = NOW()
		WHERE user_id = $1 AND tenant_id = $2 AND revoked_at IS NULL
	`, t.UserID, t.TenantID); err != nil {
		return nil, fmt.Errorf("revoke sessions on invitation accept: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit accept-invitation: %w", err)
	}

	s.logger.Info().Int64("user_id", t.UserID).Msg("invitation accepted")
	return &t, nil
}

// appNameByRowID resolves an application's display name for email bodies. A nil
// scope (tenant-level user) or a lookup miss yields "", which every template
// renders as the generic wording.
func appNameByRowID(ctx context.Context, pool *pgxpool.Pool, appRowID *int64) string {
	if appRowID == nil {
		return ""
	}
	var name string
	if err := pool.QueryRow(ctx, `SELECT name FROM oauth_clients WHERE id = $1`, *appRowID).Scan(&name); err != nil {
		return ""
	}
	return name
}
