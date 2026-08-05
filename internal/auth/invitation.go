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
	pool   *pgxpool.Pool
	notify EmailNotifier
	// dashboardBaseURL, not appBaseURL: the invitation link must open the admin
	// console page that collects a password. POST /api/v1/auth/accept-invitation
	// cannot serve a browser GET — it answers "authorization required" — because
	// the token alone is not enough to complete the flow.
	dashboardBaseURL string
	logger           zerolog.Logger
}

// NewInvitationService creates an InvitationService. dashboardBaseURL is the
// admin console origin, not the API origin — see the struct field.
func NewInvitationService(pool *pgxpool.Pool, m mailer.Mailer, dashboardBaseURL string, logger zerolog.Logger) *InvitationService {
	return &InvitationService{
		pool:             pool,
		notify:           EmailNotifier{mailer: m, logger: logger},
		dashboardBaseURL: dashboardBaseURL,
		logger:           logger,
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

// ErrInvitationSuppressed reports that no invitation was sent because the
// user_invitation template is disabled at the target scope. Invite treats that
// as success — an admin who turned the template off got what they asked for.
// InviteRequired does not: for an account that has no other way to obtain a
// password, "suppressed" and "delivered" are not interchangeable outcomes.
var ErrInvitationSuppressed = errors.New("invitation email is disabled at this scope")

// Invite issues a fresh invitation for an existing user row and emails the link.
// Re-inviting is allowed and simply supersedes any unused invitation, so an
// admin can resend when the first mail is lost. inviterID/inviterName describe
// the admin who triggered it (both optional).
//
// A send suppressed by template configuration returns nil. Callers that cannot
// tolerate a silently-unsent invitation should use InviteRequired.
func (s *InvitationService) Invite(ctx context.Context, tenantID int64, appRowID *int64, userID int64, email, inviterName string, inviterID *int64) error {
	err := s.invite(ctx, tenantID, appRowID, userID, email, inviterName, inviterID)
	if errors.Is(err, ErrInvitationSuppressed) {
		return nil
	}
	return err
}

// InviteRequired is Invite for accounts whose only route to a password is the
// invitation link — a newly seeded tenant owner above all. It reports
// ErrInvitationSuppressed instead of swallowing it, so the caller can tell the
// operator that the account exists but nobody was told how to claim it.
func (s *InvitationService) InviteRequired(ctx context.Context, tenantID int64, appRowID *int64, userID int64, email, inviterName string, inviterID *int64) error {
	return s.invite(ctx, tenantID, appRowID, userID, email, inviterName, inviterID)
}

func (s *InvitationService) invite(ctx context.Context, tenantID int64, appRowID *int64, userID int64, email, inviterName string, inviterID *int64) error {
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
		Link:        fmt.Sprintf("%s/accept-invitation?token=%s", s.dashboardBaseURL, rawToken),
		AppName:     appNameByRowID(ctx, s.pool, appRowID),
		InviterName: inviterName,
		Name:        name,
		TTLMinutes:  int(InvitationTTL.Minutes()),
	}
	sent, err := s.notify.Send(ctx, tenantID, appRowID, mailer.TemplateUserInvitation,
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
		return ErrInvitationSuppressed
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

// InvitationPreview describes a live invitation token without consuming it, so
// the landing page can ask for a password only when there is one to set.
//
// RequiresPassword is false for an account that already has credentials — an
// existing tenant user being made an administrator, or an administrator being
// re-instated. For them the link is a confirmation, not an onboarding: it must
// not reset a working password or end their sessions.
type InvitationPreview struct {
	Email            string `json:"email"`
	RequiresPassword bool   `json:"requires_password"`
	// GrantsAdmin reports that accepting will also activate a pending
	// administrative grant, so the page can say what is being confirmed.
	GrantsAdmin bool `json:"grants_admin"`
}

// Preview resolves a live invitation token for display. It reports
// ErrInvalidInvitation for an unknown, expired or spent token, and never
// consumes it.
func (s *InvitationService) Preview(ctx context.Context, rawToken string) (*InvitationPreview, error) {
	var p InvitationPreview
	err := s.pool.QueryRow(ctx, `
		SELECT u.email,
		       NOT EXISTS (SELECT 1 FROM user_credentials c WHERE c.user_id = u.id),
		       -- ta.tenant_id = i.tenant_id, or a pending grant in ANOTHER tenant
		       -- reads as one this invitation would activate. Accept resolves the
		       -- grant by (user, invitation tenant); this predicate is what keeps
		       -- the two answering the same question.
		       EXISTS (
		           SELECT 1 FROM tenant_admins ta
		           WHERE ta.user_id = u.id AND ta.tenant_id = i.tenant_id
		             AND ta.deleted_at IS NULL AND ta.activated_at IS NULL
		       )
		FROM user_invitations i
		JOIN users u ON u.id = i.user_id
		WHERE i.token_hash = $1 AND i.used_at IS NULL AND i.expires_at > NOW()
		  AND u.deleted_at IS NULL
	`, HashToken(rawToken)).Scan(&p.Email, &p.RequiresPassword, &p.GrantsAdmin)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrInvalidInvitation
		}
		return nil, fmt.Errorf("preview invitation: %w", err)
	}
	return &p, nil
}

// ErrCurrentPasswordMismatch is returned when someone confirms an invitation by
// keeping their existing password but supplies the wrong one. Distinct from
// ErrInvalidInvitation so the caller can say which of the two is wrong — the
// link is fine, the password is not — and so a mistyped password does not read
// as an expired link.
var ErrCurrentPasswordMismatch = errors.New("current password is incorrect")

// AcceptOptions carries the three ways an invitation can be accepted. Which one
// applies is decided by the account, not by the caller:
//
//	no credentials yet   NewPassword is required. Onboarding.
//	credentials exist    exactly one of CurrentPassword (keep it) or NewPassword
//	                     (replace it) must be supplied.
//
// Requiring one of them for an existing account is deliberate. Accepting used to
// need nothing but the link, so anyone holding the inbox could activate an
// administrative grant; now they must also demonstrate they can operate the
// account. Note this is a consent step rather than an impassable barrier — an
// attacker with the inbox could still choose NewPassword, exactly as they could
// already run the forgot-password flow. It raises the bar for the ordinary
// mis-click, not for someone who owns the mailbox.
type AcceptOptions struct {
	NewPassword     string
	CurrentPassword string
}

// Accept consumes an invitation: it marks the email verified, activates any
// pending administrative grant, and burns the token — all in one transaction,
// so a failure part-way cannot leave a used token with nothing applied.
//
// Keeping the existing password leaves it and every live session alone. That
// matters because promoting someone already working in the tenant is the
// ordinary case, and charging them a credential reset for it buys nothing.
func (s *InvitationService) Accept(ctx context.Context, rawToken string, opts AcceptOptions) (*InvitationTarget, error) {
	var invID int64
	var t InvitationTarget
	var blockReason *string
	var existingHash *string
	err := s.pool.QueryRow(ctx, `
		SELECT i.id, i.user_id, i.tenant_id, u.email, u.block_reason,
		       (SELECT c.password_hash FROM user_credentials c WHERE c.user_id = u.id)
		FROM user_invitations i
		JOIN users u ON u.id = i.user_id
		WHERE i.token_hash = $1 AND i.used_at IS NULL AND i.expires_at > NOW()
		  AND u.deleted_at IS NULL
	`, HashToken(rawToken)).Scan(&invID, &t.UserID, &t.TenantID, &t.Email, &blockReason, &existingHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrInvalidInvitation
		}
		return nil, fmt.Errorf("lookup invitation: %w", err)
	}

	hasPassword := existingHash != nil && *existingHash != ""
	setPassword := !hasPassword || opts.NewPassword != ""
	if setPassword && len(opts.NewPassword) < 8 {
		return nil, ErrWeakPassword
	}
	if hasPassword && !setPassword {
		// Keeping the existing password: prove it. Verified BEFORE the
		// transaction opens, so a wrong password cannot burn the token — the
		// recipient gets to try again with the same link.
		if opts.CurrentPassword == "" {
			return nil, ErrCurrentPasswordMismatch
		}
		if bcrypt.CompareHashAndPassword([]byte(*existingHash), []byte(opts.CurrentPassword)) != nil {
			return nil, ErrCurrentPasswordMismatch
		}
	}
	// An admin who blocks an account after inviting it must not be overridden by
	// the still-live invitation link: accepting it would set a password and
	// re-activate the row, silently undoing the operator's decision. Only an
	// automatic failed-attempt lockout may be cleared this way — the same rule the
	// self-service unblock endpoint applies.
	if blockReason != nil && *blockReason != mailer.BlockReasonFailedAttempts {
		return nil, ErrInvitationBlocked
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin accept-invitation tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if _, err := tx.Exec(ctx, `UPDATE user_invitations SET used_at = NOW() WHERE id = $1`, invID); err != nil {
		return nil, fmt.Errorf("mark invitation used: %w", err)
	}

	if setPassword {
		hash, hashErr := bcrypt.GenerateFromPassword([]byte(opts.NewPassword), BcryptCost)
		if hashErr != nil {
			return nil, fmt.Errorf("hash invitation password: %w", hashErr)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO user_credentials (user_id, tenant_id, password_hash)
			VALUES ($1, $2, $3)
			ON CONFLICT (user_id) DO UPDATE SET password_hash = EXCLUDED.password_hash, updated_at = NOW()
		`, t.UserID, t.TenantID, string(hash)); err != nil {
			return nil, fmt.Errorf("set invitation password: %w", err)
		}
		// A credential change ends any session that existed beforehand. Confined
		// to the branch where the password actually changed: a bare confirmation
		// must not sign the person out of work they are in the middle of.
		//
		// Activating an administrative grant revokes unconditionally — see
		// activatePendingAdminGrant. The distinction is what changed: a
		// confirmation that raises nothing leaves sessions alone, one that raises
		// authority does not.
		if _, err := tx.Exec(ctx, `
			UPDATE refresh_tokens SET revoked_at = NOW()
			WHERE user_id = $1 AND tenant_id = $2 AND revoked_at IS NULL
		`, t.UserID, t.TenantID); err != nil {
			return nil, fmt.Errorf("revoke sessions on invitation accept: %w", err)
		}
	}

	// is_active reflects actual state rather than being forced true: an account
	// carrying a lockout stays inactive until that lockout is lifted through its
	// own path. Only an account with no block at all is activated here.
	//
	// token_version is bumped either way: an activated administrative grant
	// changes what the account may do, so tokens issued a moment ago must not
	// keep asserting the old reach.
	if _, err := tx.Exec(ctx, `
		UPDATE users
		SET email_verified = true, is_active = (blocked_at IS NULL),
		    token_version = token_version + 1, updated_at = NOW()
		WHERE id = $1 AND tenant_id = $2
	`, t.UserID, t.TenantID); err != nil {
		return nil, fmt.Errorf("mark invited user verified: %w", err)
	}

	if err := activatePendingAdminGrant(ctx, tx, t.UserID, t.TenantID); err != nil {
		return nil, err
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
