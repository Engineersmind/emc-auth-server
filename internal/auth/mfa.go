package auth

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
)

// ---------------------------------------------------------------------------
// Application-scoped MFA policy (issue #63)
//
// Every application inside a tenant carries its own MFA mode, configured by
// the tenant owner or a super_admin. Users registered through an application
// (users.application_id set) are governed by that application's policy;
// tenant-level users (application_id IS NULL) are always 'optional'.
// ---------------------------------------------------------------------------

// MFA modes. Stored in application_mfa_settings.mode; the CHECK constraint
// mirrors this set.
const (
	MFAModeDisabled = "disabled"
	MFAModeOptional = "optional"
	MFAModeRequired = "required"
)

// ValidMFAMode reports whether mode is one of the accepted policy values.
func ValidMFAMode(mode string) bool {
	return mode == MFAModeDisabled || mode == MFAModeOptional || mode == MFAModeRequired
}

// ErrInvalidMFAMode is returned when a policy update carries an unknown mode.
var ErrInvalidMFAMode = errors.New("mode must be one of: disabled, optional, required")

// ErrMFAEnrollmentDisabled is returned when a user of an application whose MFA
// mode is 'disabled' attempts to enroll.
var ErrMFAEnrollmentDisabled = errors.New("MFA is disabled for this application")

// ErrMFARequiredByPolicy is returned when a user attempts to disable TOTP while
// their application's MFA mode is 'required'.
var ErrMFARequiredByPolicy = errors.New("MFA is required by this application's policy and cannot be disabled")

// ErrTOTPReenrollProof is returned when a user with an active enrollment
// attempts to re-enroll without proving control of the current second factor —
// otherwise a stolen access token alone could rotate the victim's MFA secret.
var ErrTOTPReenrollProof = errors.New("TOTP is already active — a valid current TOTP or backup code is required to re-enroll")

// ErrTooManyOTPAttempts is returned when an OTP challenge or pending-enrollment
// session exceeds its attempt budget; the session is invalidated and the user
// must restart from the password step.
var ErrTooManyOTPAttempts = errors.New("too many incorrect codes — restart login")

// ErrUserNotFound is returned by admin MFA operations when the target user does
// not exist within the resolved tenant/application scope.
var ErrUserNotFound = errors.New("user not found")

// MFAPolicy is the persisted per-application policy returned by admin reads.
type MFAPolicy struct {
	ApplicationID string     `json:"application_id"`
	Mode          string     `json:"mode"`
	// UpdatedAt is nil when no explicit policy row exists (implicit 'optional').
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
	// Enrollment stats over the application's own isolated user base — for the
	// owner dashboard. Pending = enrolled but never activated.
	EnrolledUsers      int64 `json:"enrolled_users"`
	PendingEnrollments int64 `json:"pending_enrollments"`
	TotalUsers         int64 `json:"total_users"`
}

// GetAppMFAMode returns the effective MFA mode for an application. Absence of
// a policy row means 'optional' (pre-feature behaviour). This is the login
// hot-path read — a single PK lookup.
func (s *TOTPService) GetAppMFAMode(ctx context.Context, appRowID int64) (string, error) {
	var mode string
	err := s.pool.QueryRow(ctx, `
		SELECT mode FROM application_mfa_settings WHERE application_id = $1
	`, appRowID).Scan(&mode)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return MFAModeOptional, nil
		}
		return "", fmt.Errorf("load app MFA mode: %w", err)
	}
	return mode, nil
}

// GetAppMFAPolicy returns the application's policy plus enrollment stats for
// the admin/owner dashboard. The caller must have verified that appRowID
// belongs to tenantID (handlers use applicationOwnedByTenant).
func (s *TOTPService) GetAppMFAPolicy(ctx context.Context, tenantID, appRowID int64) (*MFAPolicy, error) {
	p := &MFAPolicy{
		ApplicationID: strconv.FormatInt(appRowID, 10),
		Mode:          MFAModeOptional,
	}

	var updatedAt time.Time
	err := s.pool.QueryRow(ctx, `
		SELECT mode, updated_at FROM application_mfa_settings
		WHERE application_id = $1 AND tenant_id = $2
	`, appRowID, tenantID).Scan(&p.Mode, &updatedAt)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("load app MFA policy: %w", err)
	}
	if err == nil {
		p.UpdatedAt = &updatedAt
	}

	err = s.pool.QueryRow(ctx, `
		SELECT
			COUNT(*) FILTER (WHERE ts.is_active),
			COUNT(ts.user_id) FILTER (WHERE NOT ts.is_active),
			COUNT(u.id)
		FROM users u
		LEFT JOIN totp_secrets ts ON ts.user_id = u.id
		WHERE u.tenant_id = $1 AND u.application_id = $2
		  AND u.is_active = true AND u.deleted_at IS NULL
	`, tenantID, appRowID).Scan(&p.EnrolledUsers, &p.PendingEnrollments, &p.TotalUsers)
	if err != nil {
		return nil, fmt.Errorf("load app MFA stats: %w", err)
	}
	return p, nil
}

// SetAppMFAPolicy upserts the application's MFA mode. The caller must have
// verified tenant ownership of appRowID; tenant_id is still pinned in the
// upsert so a policy row can never point at a foreign tenant.
func (s *TOTPService) SetAppMFAPolicy(ctx context.Context, tenantID, appRowID int64, mode string, updatedBy *int64) error {
	if !ValidMFAMode(mode) {
		return ErrInvalidMFAMode
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO application_mfa_settings (application_id, tenant_id, mode, updated_by, updated_at)
		VALUES ($1, $2, $3, $4, NOW())
		ON CONFLICT (application_id) DO UPDATE
		SET mode       = EXCLUDED.mode,
		    updated_by = EXCLUDED.updated_by,
		    updated_at = NOW()
		WHERE application_mfa_settings.tenant_id = EXCLUDED.tenant_id
	`, appRowID, tenantID, mode, updatedBy)
	if err != nil {
		return fmt.Errorf("upsert app MFA policy: %w", err)
	}
	return nil
}

// ResetUserMFA removes a user's TOTP enrollment on behalf of an admin (lost
// phone + backup codes). The target user must belong to the tenant and, when
// appRowID is non-nil, to that application's isolated user base — a foreign
// user is reported as not found, never touched. Idempotent: resetting a user
// with no enrollment succeeds.
func (s *TOTPService) ResetUserMFA(ctx context.Context, tenantID int64, appRowID *int64, userID int64) error {
	var exists bool
	err := s.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM users
			WHERE id = $1 AND tenant_id = $2
			  AND ($3::BIGINT IS NULL OR application_id = $3)
			  AND deleted_at IS NULL
		)
	`, userID, tenantID, appRowID).Scan(&exists)
	if err != nil {
		return fmt.Errorf("verify user scope: %w", err)
	}
	if !exists {
		return ErrUserNotFound
	}

	_, err = s.pool.Exec(ctx, `DELETE FROM totp_secrets WHERE user_id = $1`, userID)
	if err != nil {
		return fmt.Errorf("reset user MFA: %w", err)
	}
	return nil
}

// userMFAContext resolves the MFA-relevant application context for one user:
// the owning application (nil for tenant-level users), its display name (used
// as the otpauth:// issuer), and its effective MFA mode.
type userMFAContext struct {
	appRowID *int64
	appName  string
	mode     string
}

func (s *TOTPService) loadUserMFAContext(ctx context.Context, userID, tenantID int64) (*userMFAContext, error) {
	uc := &userMFAContext{mode: MFAModeOptional}
	var appName *string
	var mode *string
	err := s.pool.QueryRow(ctx, `
		SELECT u.application_id, oc.name, ams.mode
		FROM users u
		LEFT JOIN oauth_clients oc ON oc.id = u.application_id
		LEFT JOIN application_mfa_settings ams ON ams.application_id = u.application_id
		WHERE u.id = $1 AND u.tenant_id = $2 AND u.deleted_at IS NULL
	`, userID, tenantID).Scan(&uc.appRowID, &appName, &mode)
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
	return uc, nil
}

// EnrollUser is the user-initiated (JWT-authenticated) enrollment path. It
// applies the application policy and the re-enrollment proof requirement, then
// generates the secret with the application's name as the authenticator issuer:
//
//   - application mode 'disabled' → rejected;
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

// DisableUser is the user-initiated disable path: policy-checked (users of a
// 'required' application cannot opt out), then code-verified via Disable.
func (s *TOTPService) DisableUser(ctx context.Context, userID, tenantID int64, code string) error {
	uc, err := s.loadUserMFAContext(ctx, userID, tenantID)
	if err != nil {
		return err
	}
	if uc.appRowID != nil && uc.mode == MFAModeRequired {
		return ErrMFARequiredByPolicy
	}
	return s.Disable(ctx, userID, code)
}
