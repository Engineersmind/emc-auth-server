package auth

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ---------------------------------------------------------------------------
// Application-scoped MFA policy (issue #63)
//
// Every application inside a tenant carries its own MFA mode and its own set
// of allowed second-factor methods, configured by the tenant owner or a
// super_admin. Users registered through an application (users.application_id
// set) are governed by that application's policy; tenant-level users
// (application_id IS NULL) are always 'optional' with every method allowed.
// ---------------------------------------------------------------------------

// MFA modes. Stored in application_mfa_settings.mode; the CHECK constraint
// mirrors this set.
const (
	MFAModeDisabled = "disabled"
	MFAModeOptional = "optional"
	MFAModeRequired = "required"
)

// MFA methods. Stored in application_mfa_settings.allowed_methods; the CHECK
// constraint mirrors this set.
const (
	MFAMethodTOTP  = "totp"
	MFAMethodEmail = "email"
)

// ValidMFAMode reports whether mode is one of the accepted policy values.
func ValidMFAMode(mode string) bool {
	return mode == MFAModeDisabled || mode == MFAModeOptional || mode == MFAModeRequired
}

// ValidMFAMethods reports whether methods is a non-empty subset of the
// supported method set.
func ValidMFAMethods(methods []string) bool {
	if len(methods) == 0 {
		return false
	}
	for _, m := range methods {
		if m != MFAMethodTOTP && m != MFAMethodEmail {
			return false
		}
	}
	return true
}

// methodAllowed reports whether method appears in methods.
func methodAllowed(methods []string, method string) bool {
	for _, m := range methods {
		if m == method {
			return true
		}
	}
	return false
}

// defaultMFAMethods is the implicit method set when no policy row exists and
// the pre-00047 default for existing rows.
func defaultMFAMethods() []string { return []string{MFAMethodTOTP} }

// ErrInvalidMFAMode is returned when a policy update carries an unknown mode.
var ErrInvalidMFAMode = errors.New("mode must be one of: disabled, optional, required")

// ErrInvalidMFAMethods is returned when a policy update carries an unknown or
// empty method set.
var ErrInvalidMFAMethods = errors.New("allowed_methods must be a non-empty subset of: totp, email")

// ErrMFAEnrollmentDisabled is returned when a user of an application whose MFA
// mode is 'disabled' attempts to enroll.
var ErrMFAEnrollmentDisabled = errors.New("MFA is disabled for this application")

// ErrMFAMethodNotAllowed is returned when a user attempts to enroll a method
// the application's policy does not permit.
var ErrMFAMethodNotAllowed = errors.New("this MFA method is not allowed for this application")

// ErrMFARequiredByPolicy is returned when a user attempts to remove their last
// active second factor while their application's MFA mode is 'required'.
var ErrMFARequiredByPolicy = errors.New("MFA is required by this application's policy and cannot be disabled")

// ErrTOTPReenrollProof is returned when a user with an active enrollment
// attempts to re-enroll without proving control of the current second factor —
// otherwise a stolen access token alone could rotate the victim's MFA secret.
var ErrTOTPReenrollProof = errors.New("TOTP is already active — a valid current TOTP or backup code is required to re-enroll")

// ErrTOTPProofRequired is returned when an MFA self-service action (e.g.
// regenerating backup codes) is attempted without a valid current TOTP or
// backup code.
var ErrTOTPProofRequired = errors.New("a valid current TOTP or backup code is required")

// ErrTooManyOTPAttempts is returned when an OTP challenge or pending-enrollment
// session exceeds its attempt budget; the session is invalidated and the user
// must restart from the password step.
var ErrTooManyOTPAttempts = errors.New("too many incorrect codes — restart login")

// ErrUserNotFound is returned by admin MFA operations when the target user does
// not exist within the resolved tenant/application scope.
var ErrUserNotFound = errors.New("user not found")

// MFAPolicy is the persisted per-application policy returned by admin reads.
type MFAPolicy struct {
	ApplicationID  string   `json:"application_id"`
	Mode           string   `json:"mode"`
	AllowedMethods []string `json:"allowed_methods"`
	// Passwordless magic-link sign-in (opt-in; the redirect URL is the
	// application frontend that receives ?token=…).
	MagicLinkEnabled     bool   `json:"magic_link_enabled"`
	MagicLinkRedirectURL string `json:"magic_link_redirect_url"`
	// UpdatedAt is nil when no explicit policy row exists (implicit 'optional').
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
	// Enrollment stats over the application's own isolated user base — for the
	// owner dashboard. Pending = TOTP enrolled but never activated.
	EnrolledUsers      int64 `json:"enrolled_users"`
	PendingEnrollments int64 `json:"pending_enrollments"`
	EmailEnrolledUsers int64 `json:"email_enrolled_users"`
	TotalUsers         int64 `json:"total_users"`
}

// GetAppMFAConfig returns the effective MFA mode and allowed methods for an
// application. Absence of a policy row means 'optional' + TOTP-only
// (pre-feature behaviour). This is the login hot-path read — one PK lookup.
func (s *TOTPService) GetAppMFAConfig(ctx context.Context, appRowID int64) (mode string, methods []string, err error) {
	err = s.pool.QueryRow(ctx, `
		SELECT mode, allowed_methods FROM application_mfa_settings WHERE application_id = $1
	`, appRowID).Scan(&mode, &methods)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return MFAModeOptional, defaultMFAMethods(), nil
		}
		return "", nil, fmt.Errorf("load app MFA config: %w", err)
	}
	if len(methods) == 0 {
		methods = defaultMFAMethods()
	}
	return mode, methods, nil
}

// GetAppMFAMode returns just the effective MFA mode for an application.
func (s *TOTPService) GetAppMFAMode(ctx context.Context, appRowID int64) (string, error) {
	mode, _, err := s.GetAppMFAConfig(ctx, appRowID)
	return mode, err
}

// GetAppMFAPolicy returns the application's policy plus enrollment stats for
// the admin/owner dashboard. The caller must have verified that appRowID
// belongs to tenantID (handlers use applicationOwnedByTenant).
func (s *TOTPService) GetAppMFAPolicy(ctx context.Context, tenantID, appRowID int64) (*MFAPolicy, error) {
	p := &MFAPolicy{
		ApplicationID:  strconv.FormatInt(appRowID, 10),
		Mode:           MFAModeOptional,
		AllowedMethods: defaultMFAMethods(),
	}

	var updatedAt time.Time
	err := s.pool.QueryRow(ctx, `
		SELECT mode, allowed_methods, magic_link_enabled, magic_link_redirect_url, updated_at
		FROM application_mfa_settings
		WHERE application_id = $1 AND tenant_id = $2
	`, appRowID, tenantID).Scan(&p.Mode, &p.AllowedMethods, &p.MagicLinkEnabled, &p.MagicLinkRedirectURL, &updatedAt)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("load app MFA policy: %w", err)
	}
	if err == nil {
		p.UpdatedAt = &updatedAt
		if len(p.AllowedMethods) == 0 {
			p.AllowedMethods = defaultMFAMethods()
		}
	}

	err = s.pool.QueryRow(ctx, `
		SELECT
			COUNT(*) FILTER (WHERE ts.is_active),
			COUNT(ts.user_id) FILTER (WHERE NOT ts.is_active),
			COUNT(*) FILTER (WHERE ems.is_active),
			COUNT(u.id)
		FROM users u
		LEFT JOIN totp_secrets ts ON ts.user_id = u.id
		LEFT JOIN email_mfa_settings ems ON ems.user_id = u.id
		WHERE u.tenant_id = $1 AND u.application_id = $2
		  AND u.is_active = true AND u.deleted_at IS NULL
	`, tenantID, appRowID).Scan(&p.EnrolledUsers, &p.PendingEnrollments, &p.EmailEnrolledUsers, &p.TotalUsers)
	if err != nil {
		return nil, fmt.Errorf("load app MFA stats: %w", err)
	}
	return p, nil
}

// SetAppMFAPolicy upserts the application's MFA mode and allowed methods.
// methods == nil keeps the existing method set (or the TOTP-only default on
// first insert). The caller must have verified tenant ownership of appRowID;
// tenant_id is still pinned in the upsert so a policy row can never point at
// a foreign tenant.
func (s *TOTPService) SetAppMFAPolicy(ctx context.Context, tenantID, appRowID int64, mode string, methods []string, updatedBy *int64) error {
	if !ValidMFAMode(mode) {
		return ErrInvalidMFAMode
	}
	if methods != nil && !ValidMFAMethods(methods) {
		return ErrInvalidMFAMethods
	}
	tag, err := s.pool.Exec(ctx, `
		INSERT INTO application_mfa_settings (application_id, tenant_id, mode, allowed_methods, updated_by, updated_at)
		VALUES ($1, $2, $3, COALESCE($4, '{totp}'::TEXT[]), $5, NOW())
		ON CONFLICT (application_id) DO UPDATE
		SET mode            = EXCLUDED.mode,
		    allowed_methods = COALESCE($4, application_mfa_settings.allowed_methods),
		    updated_by      = EXCLUDED.updated_by,
		    updated_at      = NOW()
		WHERE application_mfa_settings.tenant_id = EXCLUDED.tenant_id
	`, appRowID, tenantID, mode, methods, updatedBy)
	if err != nil {
		return fmt.Errorf("upsert app MFA policy: %w", err)
	}
	// The DO UPDATE is tenant-pinned: a conflicting row owned by another
	// tenant filters the update down to zero rows. Surface that instead of
	// reporting success on a write that never happened.
	if tag.RowsAffected() == 0 {
		return ErrAppNotFound
	}
	return nil
}

// SetAppMagicLink upserts the application's passwordless magic-link settings.
// nil fields keep the stored values. Enabling requires a redirect URL (stored
// or provided); the URL must be absolute https (http is allowed for loopback
// hosts only — sign-in tokens must not transit cleartext).
func (s *TOTPService) SetAppMagicLink(ctx context.Context, tenantID, appRowID int64, enabled *bool, redirectURL *string, updatedBy *int64) error {
	if redirectURL != nil && *redirectURL != "" {
		if !validMagicRedirectURL(*redirectURL) {
			return ErrMagicLinkNotConfigured
		}
	}

	// Enabling without any redirect URL (stored or incoming) is a config error
	// surfaced now rather than at the first user's login attempt.
	if enabled != nil && *enabled {
		incoming := redirectURL != nil && *redirectURL != ""
		if !incoming {
			var stored string
			err := s.pool.QueryRow(ctx,
				`SELECT magic_link_redirect_url FROM application_mfa_settings WHERE application_id = $1`,
				appRowID,
			).Scan(&stored)
			if err != nil || stored == "" {
				return ErrMagicLinkNotConfigured
			}
		}
	}

	tag, err := s.pool.Exec(ctx, `
		INSERT INTO application_mfa_settings (application_id, tenant_id, magic_link_enabled, magic_link_redirect_url, updated_by, updated_at)
		VALUES ($1, $2, COALESCE($3, false), COALESCE($4, ''), $5, NOW())
		ON CONFLICT (application_id) DO UPDATE
		SET magic_link_enabled      = COALESCE($3, application_mfa_settings.magic_link_enabled),
		    magic_link_redirect_url = COALESCE($4, application_mfa_settings.magic_link_redirect_url),
		    updated_by              = EXCLUDED.updated_by,
		    updated_at              = NOW()
		WHERE application_mfa_settings.tenant_id = EXCLUDED.tenant_id
	`, appRowID, tenantID, enabled, redirectURL, updatedBy)
	if err != nil {
		return fmt.Errorf("upsert magic link settings: %w", err)
	}
	// Tenant-pinned DO UPDATE — see SetAppMFAPolicy.
	if tag.RowsAffected() == 0 {
		return ErrAppNotFound
	}
	return nil
}

// ResetUserMFA removes a user's second factors — TOTP enrollment, email MFA,
// AND passkeys — on behalf of an admin (lost phone + backup codes, lost mailbox
// access, lost laptop). The target user must belong to the tenant and, when
// appRowID is non-nil, to that application's isolated user base — a foreign user
// is reported as not found, never touched. Idempotent: resetting a user with no
// enrollment succeeds.
//
// Passkeys are included because leaving them out made this endpoint lie. An
// operator resetting a user who lost their laptop cleared TOTP and email and
// left the laptop's passkey usable — a factor still live on the device the reset
// was performed BECAUSE of. The API reported success; the credential kept
// working. Deactivating them here is what makes "reset this user's MFA" mean
// what its name says.
//
// Soft-deactivated rather than deleted, like every other passkey revocation:
// which credential an operator removed and when is the audit-relevant part.
//
// SCOPE NOTE — the reset is TENANT-wide, not application-wide. appRowID narrows
// the existence check above (an operator with rights over one application cannot
// reset a user outside it), but every mutation below is keyed on
// (user_id, tenant_id) and therefore clears the user's factors across every
// application under that tenant. That is deliberate and it is what the lost-laptop
// case requires — a factor left live on the lost device because it was enrolled
// through a different application is exactly the hole this endpoint is supposed
// to close, and it matches how TOTP and email MFA have always behaved here. It IS
// an over-reach relative to an application-scoped caller's other powers, so it is
// written down rather than left to be discovered: anyone narrowing this to one
// application must decide what happens to the credentials outside it.
//
// All three mutations run in ONE transaction. Sequential statements meant a
// failure on the passkey UPDATE returned an error having already deleted TOTP and
// email MFA — leaving the account with the lost device's passkey as its only
// remaining factor, which is the precise state this function exists to prevent.
func (s *TOTPService) ResetUserMFA(ctx context.Context, tenantID int64, appRowID *int64, userID int64) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin user MFA reset: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// Inside the transaction with the writes, so a user who is deleted or moved
	// out of scope concurrently cannot have their factors cleared by a check that
	// passed a moment earlier.
	var exists bool
	if err = tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM users
			WHERE id = $1 AND tenant_id = $2
			  AND ($3::BIGINT IS NULL OR application_id = $3)
			  AND deleted_at IS NULL
		)
	`, userID, tenantID, appRowID).Scan(&exists); err != nil {
		return fmt.Errorf("verify user scope: %w", err)
	}
	if !exists {
		return ErrUserNotFound
	}

	if _, err = tx.Exec(ctx, `DELETE FROM totp_secrets WHERE user_id = $1`, userID); err != nil {
		return fmt.Errorf("reset user TOTP: %w", err)
	}
	if _, err = tx.Exec(ctx, `DELETE FROM email_mfa_settings WHERE user_id = $1`, userID); err != nil {
		return fmt.Errorf("reset user email MFA: %w", err)
	}
	// revoked_by_admin, because that is what happened, and because the user's own
	// settings list reads that column to say "removed by your administrator"
	// rather than leaving them to wonder where their passkey went.
	if _, err = tx.Exec(ctx, `
		UPDATE webauthn_credentials
		SET is_active = false, revoked_at = NOW(), revoked_by_admin = true
		WHERE user_id = $1 AND tenant_id = $2 AND is_active
	`, userID, tenantID); err != nil {
		return fmt.Errorf("reset user passkeys: %w", err)
	}

	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit user MFA reset: %w", err)
	}
	return nil
}

// userMFAContext resolves the MFA-relevant application context for one user:
// the owning application (nil for tenant-level users), its display name (used
// as the otpauth:// issuer and in code emails), its effective MFA mode, and
// its allowed method set.
type userMFAContext struct {
	appRowID       *int64
	appName        string
	mode           string
	allowedMethods []string
}

// methodPermitted reports whether the user may use the given MFA method:
// tenant-level users may use everything; application users are bound to the
// application's allowed_methods.
func (uc *userMFAContext) methodPermitted(method string) bool {
	if uc.appRowID == nil {
		return true
	}
	return methodAllowed(uc.allowedMethods, method)
}

// loadUserMFAContext is shared by the TOTP and email MFA services.
func loadUserMFAContext(ctx context.Context, pool *pgxpool.Pool, userID, tenantID int64) (*userMFAContext, error) {
	uc := &userMFAContext{mode: MFAModeOptional, allowedMethods: defaultMFAMethods()}
	var appName *string
	var mode *string
	var methods []string
	err := pool.QueryRow(ctx, `
		SELECT u.application_id, oc.name, ams.mode, ams.allowed_methods
		FROM users u
		LEFT JOIN oauth_clients oc ON oc.id = u.application_id
		LEFT JOIN application_mfa_settings ams ON ams.application_id = u.application_id
		WHERE u.id = $1 AND u.tenant_id = $2 AND u.deleted_at IS NULL
	`, userID, tenantID).Scan(&uc.appRowID, &appName, &mode, &methods)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("load user MFA context: %w", err)
	}
	if appName != nil {
		uc.appName = *appName
	}
	if mode != nil {
		uc.mode = *mode
	}
	if len(methods) > 0 {
		uc.allowedMethods = methods
	}
	return uc, nil
}

func (s *TOTPService) loadUserMFAContext(ctx context.Context, userID, tenantID int64) (*userMFAContext, error) {
	return loadUserMFAContext(ctx, s.pool, userID, tenantID)
}

// EnrollUser is the user-initiated (JWT-authenticated) TOTP enrollment path.
// It applies the application policy (mode and method set) and the
// re-enrollment proof requirement, then generates the secret with the
// application's name as the authenticator issuer:
//
//   - application mode 'disabled' → rejected;
//   - 'totp' missing from the application's allowed_methods → rejected;
//   - an already-ACTIVE enrollment requires currentCode (valid TOTP or backup
//     code) before the secret is rotated — a bare stolen JWT is not enough;
//   - the otpauth:// issuer is the owning application's name, so the entry in
//     the user's authenticator is labelled per application (tenant-level users
//     fall back to the server-wide issuer).
func (s *TOTPService) EnrollUser(ctx context.Context, userID, tenantID int64, email, currentCode string) (*EnrollResult, error) {
	uc, err := s.loadUserMFAContext(ctx, userID, tenantID)
	if err != nil {
		return nil, err
	}
	if uc.appRowID != nil && uc.mode == MFAModeDisabled {
		return nil, ErrMFAEnrollmentDisabled
	}
	if !uc.methodPermitted(MFAMethodTOTP) {
		return nil, ErrMFAMethodNotAllowed
	}

	active, err := s.IsActive(ctx, userID)
	if err != nil {
		return nil, err
	}
	if active {
		if currentCode == "" {
			return nil, ErrTOTPReenrollProof
		}
		if err := s.Verify(ctx, userID, currentCode); err != nil {
			if err2 := s.VerifyBackupCode(ctx, userID, currentCode); err2 != nil {
				return nil, ErrTOTPReenrollProof
			}
		}
	}

	issuer := TOTPIssuer
	if uc.appName != "" {
		issuer = uc.appName
	}
	return s.Enroll(ctx, userID, tenantID, email, issuer)
}

// emailMFAActive reports whether the user has active email MFA (used for
// last-factor checks inside the TOTP service).
func emailMFAActive(ctx context.Context, pool *pgxpool.Pool, userID int64) (bool, error) {
	var active bool
	err := pool.QueryRow(ctx, `
		SELECT is_active FROM email_mfa_settings WHERE user_id = $1
	`, userID).Scan(&active)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("check email MFA active: %w", err)
	}
	return active, nil
}

// DisableUser is the user-initiated TOTP disable path: policy-checked, then
// code-verified via Disable. Users of a 'required' application may only
// remove TOTP while another active second factor (email MFA) remains — the
// last factor cannot be removed under a mandate.
func (s *TOTPService) DisableUser(ctx context.Context, userID, tenantID int64, code string) error {
	uc, err := s.loadUserMFAContext(ctx, userID, tenantID)
	if err != nil {
		return err
	}
	if uc.appRowID != nil && uc.mode == MFAModeRequired {
		emailActive, err := emailMFAActive(ctx, s.pool, userID)
		if err != nil {
			return err
		}
		if !emailActive {
			return ErrMFARequiredByPolicy
		}
	}
	return s.Disable(ctx, userID, code)
}
