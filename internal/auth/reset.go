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

	"github.com/engineersmind/emc-auth-server/internal/audit"
	"github.com/engineersmind/emc-auth-server/internal/mailer"
	"github.com/engineersmind/emc-auth-server/internal/password"
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
	// dashboardBaseURL is the admin-console origin used for the emailed reset
	// link (GHSA-2267-r48x-9fh2). The link must open the reset-password PAGE,
	// not the API endpoint: the page reads the token out of the URL and POSTs
	// it in the request body, so the credential never transits an API access
	// log, proxy log, or Referer header as a query parameter. Unset keeps the
	// legacy API-path link for deployments without a console.
	dashboardBaseURL string
	// hasher writes the new credential on a completed reset. Defaulted by the
	// constructor so a caller that forgets WithHasher still writes a correctly
	// hashed password.
	hasher *password.Hasher
	logger zerolog.Logger
}

// NewResetService creates a ResetService.
func NewResetService(pool *pgxpool.Pool, m mailer.Mailer, appBaseURL string, logger zerolog.Logger) *ResetService {
	return &ResetService{
		pool:       pool,
		mailer:     m,
		appBaseURL: appBaseURL,
		hasher:     password.NewHasher(password.DefaultParams()),
		logger:     logger,
	}
}

// WithHasher shares the process-wide hasher so a reset writes the credential
// under the same parameters, and against the same concurrency cap, as every
// other credential path.
func (s *ResetService) WithHasher(h *password.Hasher) *ResetService {
	if h != nil {
		s.hasher = h
	}
	return s
}

// WithDashboardURL points emailed reset links at the admin console's reset
// page rather than the API (see the dashboardBaseURL field comment).
func (s *ResetService) WithDashboardURL(base string) *ResetService {
	if base != "" {
		s.dashboardBaseURL = base
	}
	return s
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

// MaxConsoleResetFanOut caps how many first-party accounts one console
// forgot-password request may issue reset tokens for. An email holds at most
// one first-party account per tenant, so this is a cap on tenants. It bounds
// the work and the mail one unauthenticated request can cause; accounts past
// the cap are skipped and logged, never reported to the caller.
const MaxConsoleResetFanOut = 10

// ConsoleResetCooldown is how long a first-party account that was just sent a
// reset link is skipped by ForgotPasswordFirstParty.
//
// The per-email rate limit counts requests, but one request mails every
// account the address owns. Without a per-account cooldown an address with
// accounts in ten tenants would receive ten emails per allowed request. With
// it, one inbox gets at most one email per account per cooldown, whatever the
// request rate.
const ConsoleResetCooldown = time.Minute

// ForgotPasswordFirstParty is the console variant of ForgotPassword (issue
// #179). The console is a browser and holds no client credentials, so there is
// no application to scope the lookup to and no tenant slug to pick a tenant.
// Unlike Login it has no password to tell same-email accounts apart, so it
// issues one token per first-party account (application_id IS NULL) the email
// owns, each in its own email naming its tenant. A token resolves to exactly
// one user, so each link resets only its own account.
//
// These are platform console accounts, not a tenant's end users, so the
// tenant's template suppression, custom template and white-label sender do not
// apply: the email always goes out with the platform template and sender.
//
// Returns the tenant ids a token was issued for, for the caller to audit. The
// caller must not let the result change its response (RESET-03).
func (s *ResetService) ForgotPasswordFirstParty(ctx context.Context, email string) ([]int64, error) {
	email = emailaddr.Normalize(email)

	// One row past the cap, so an overflow can be logged rather than silently
	// truncated. Same tenant and account filters as console Login, minus any
	// account still inside its cooldown.
	rows, err := s.pool.Query(ctx, `
		SELECT u.id, u.tenant_id, t.name
		FROM users u
		JOIN tenants t ON t.id = u.tenant_id
		WHERE u.email = $1
		  AND u.application_id IS NULL
		  AND u.is_active = true
		  AND u.deleted_at IS NULL
		  AND t.is_active = true
		  AND t.deleted_at IS NULL
		  AND NOT EXISTS (
		      SELECT 1 FROM password_reset_tokens p
		      WHERE p.user_id = u.id
		        AND p.created_at > NOW() - $3 * INTERVAL '1 second'
		  )
		ORDER BY u.tenant_id
		LIMIT $2
	`, email, MaxConsoleResetFanOut+1, int64(ConsoleResetCooldown/time.Second))
	if err != nil {
		return nil, fmt.Errorf("lookup first-party accounts for forgot-password: %w", err)
	}
	type account struct {
		userID, tenantID int64
		tenantName       string
	}
	var accounts []account
	for rows.Next() {
		var a account
		if err := rows.Scan(&a.userID, &a.tenantID, &a.tenantName); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan first-party accounts for forgot-password: %w", err)
		}
		accounts = append(accounts, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("scan first-party accounts for forgot-password: %w", err)
	}
	if len(accounts) > MaxConsoleResetFanOut {
		s.logger.Warn().Int("cap", MaxConsoleResetFanOut).Msg("forgot-password: first-party accounts exceed the fan-out cap — skipping the rest")
		accounts = accounts[:MaxConsoleResetFanOut]
	}

	var issued []int64
	for _, a := range accounts {
		// One account failing must not stop the others: each is independent.
		if err := s.issueReset(ctx, a.userID, a.tenantID, nil, email, resetMail{platform: true, tenantName: a.tenantName}); err != nil {
			s.logger.Error().Err(err).Int64("tenant_id", a.tenantID).Msg("forgot-password: first-party reset failed")
			continue
		}
		issued = append(issued, a.tenantID)
	}
	return issued, nil
}

// forgotPassword resets the account the email holds in one application scope.
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

	return s.issueReset(ctx, userID, tenantID, appRowID, email, resetMail{})
}

// resetMail says how issueReset's email is sent.
type resetMail struct {
	// platform sends with the platform template and sender instead of the
	// tenant's or application's.
	platform bool
	// tenantName, when set, names the account's tenant in the email, so an
	// address with accounts in several tenants can tell the links apart.
	tenantName string
}

// issueReset stores a reset token for one user and emails the link.
//
// A nil error means the token was stored, even if the email then failed: the
// token is redeemable, so callers that audit issuance must still record it.
// The send failure is logged here.
func (s *ResetService) issueReset(ctx context.Context, userID, tenantID int64, appRowID *int64, email string, how resetMail) error {
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

	// The link goes to the dashboard reset page, not the API endpoint — a query
	// param on the API URL would land the token in access/proxy logs and
	// Referer headers (GHSA-2267-r48x-9fh2). The page POSTs it in the body.
	// Deployments without a console keep the legacy API-path link unchanged.
	resetLink := fmt.Sprintf("%s/api/v1/auth/reset-password?token=%s", s.appBaseURL, rawToken)
	if s.dashboardBaseURL != "" {
		resetLink = fmt.Sprintf("%s/reset-password?token=%s", s.dashboardBaseURL, rawToken)
	}
	msg := mailer.ResetEmail{
		To:         email,
		ResetLink:  resetLink,
		TenantName: how.tenantName,
		// State the real window so the body can never contradict the token's
		// actual expiry if ResetTokenTTL changes.
		TTLMinutes: int(ResetTokenTTL.Minutes()),
	}

	// Resolve the sender for this application (application → tenant → global). A
	// broken sender must never block a password reset, so fall back to the global
	// sender and log — same policy as the MFA/magic-link paths. A platform email
	// skips both lookups: nil is the global sender and the built-in template.
	var sender *mailer.SMTPConfig
	var tmpl *mailer.Template
	if !how.platform {
		if s.senderSvc != nil {
			sender, err = s.senderSvc.Resolve(ctx, tenantID, appRowID)
			if err != nil {
				s.logger.Warn().Err(err).Int64("tenant_id", tenantID).Msg("forgot-password: sender resolution failed — using global sender")
				sender = nil
			}
		}
		tmpl = s.tmplSvc.ResolveTemplate(ctx, tenantID, appRowID, mailer.TemplatePasswordReset)
	}

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
	// ScopeTenantID and ScopeApplicationID, when set, restrict the token to
	// users of that tenant and application. Set when an application's backend
	// redeems the token on its users' behalf: it may only redeem its own
	// users' tokens, so a tenant holding valid credentials cannot use its own
	// (higher, per-application) limits to guess another tenant's tokens. Zero
	// / nil means unscoped, as for a browser calling directly.
	ScopeTenantID      int64
	ScopeApplicationID *int64
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
		  AND ($2::bigint = 0 OR t.tenant_id = $2)
		  AND ($3::bigint IS NULL OR u.application_id = $3)
	`, tokenHash, in.ScopeTenantID, in.ScopeApplicationID).Scan(&tokenID, &userID, &tenantID, &email, &appRowID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrInvalidResetToken
		}
		return fmt.Errorf("lookup reset token: %w", err)
	}

	newHash, err := s.hasher.Hash(ctx, in.NewPassword)
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

	if err := RevokeAllSessionsTx(ctx, tx, userID, tenantID, RevokeReasonCredentialChange); err != nil {
		return fmt.Errorf("revoke sessions on password reset: %w", err)
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

	// Refuse the access tokens already in circulation.
	//
	// After the commit, so a Redis entry is never written for a transaction that
	// rolled back. The refresh-token revocation above only stops RENEWAL, so
	// without this a password reset left whoever held the old session — including
	// an attacker the reset was meant to evict — working normally until their
	// access token expired.
	DenyAccountSessions(ctx, s.logger, userID, tenantID)

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
