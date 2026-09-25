package admin

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// ---------------------------------------------------------------------------
// Administrator MFA policy (migration 00094)
//
// MFA is mandatory for administrators and cannot be switched off here. These
// endpoints only choose WHICH methods satisfy it, and at least one must always
// remain allowed.
// ---------------------------------------------------------------------------

// AdminMFAPolicyView is the API representation of an administrator MFA policy.
type AdminMFAPolicyView struct {
	// Scope is "platform" or "tenant" — which row answered the request.
	Scope string `json:"scope"`
	// Inherited is true when the tenant has no row of its own and the values
	// came from the platform policy.
	Inherited bool `json:"inherited"`
	// MFARequired is always true. Reported so a client never has to assume it.
	MFARequired bool `json:"mfa_required"`
	// AllowedMethods, in presentation order (passkey, totp, email).
	AllowedMethods []string `json:"allowed_methods"`
	// SupportedMethods is every method a policy may name.
	SupportedMethods []string `json:"supported_methods"`
}

// AdminMFAPolicyInput is the writable body.
type AdminMFAPolicyInput struct {
	AllowedMethods []string `json:"allowed_methods"`
}

// WithAdminMFAPolicy wires the resolver so writes invalidate it immediately.
func (s *Service) WithAdminMFAPolicy(p *auth.AdminMFAPolicyService) *Service {
	s.adminMFAPolicy = p
	return s
}

// GetAdminMFAPolicy returns the policy for a tenant (tenantID > 0) or the
// platform policy (tenantID 0).
func (s *Service) GetAdminMFAPolicy(ctx context.Context, tenantID int64) (*AdminMFAPolicyView, error) {
	var methods []string
	var isPlatform bool
	err := s.pool.QueryRow(ctx, `
		SELECT allowed_methods, tenant_id IS NULL
		FROM admin_mfa_policies
		WHERE tenant_id = $1 OR tenant_id IS NULL
		ORDER BY tenant_id NULLS LAST
		LIMIT 1
	`, tenantID).Scan(&methods, &isPlatform)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("load admin MFA policy: %w", err)
	}
	view := &AdminMFAPolicyView{
		MFARequired:      true,
		SupportedMethods: append([]string(nil), auth.AdminMFAMethods...),
	}
	if errors.Is(err, pgx.ErrNoRows) {
		// The platform row is seeded by migration 00094; report what the login
		// path falls back to so the API and the running behaviour agree.
		view.Scope, view.Inherited = "platform", tenantID != 0
		view.AllowedMethods = auth.DefaultAdminMFAMethods()
		return view, nil
	}
	view.AllowedMethods = auth.OrderAdminMFAMethods(methods)
	if isPlatform {
		view.Scope = "platform"
		view.Inherited = tenantID != 0
	} else {
		view.Scope = "tenant"
	}
	return view, nil
}

// SetAdminMFAPolicy upserts the policy for a tenant (tenantID > 0) or the
// platform (tenantID 0).
func (s *Service) SetAdminMFAPolicy(ctx context.Context, tenantID int64, actorUserID *int64, in AdminMFAPolicyInput) (*AdminMFAPolicyView, error) {
	if err := auth.ValidateAdminMFAMethods(in.AllowedMethods); err != nil {
		return nil, err // wraps ErrInvalidAdminMFAPolicy with the offending value
	}
	methods := auth.OrderAdminMFAMethods(in.AllowedMethods)

	var err error
	if tenantID == 0 {
		_, err = s.pool.Exec(ctx, `
			UPDATE admin_mfa_policies
			SET allowed_methods = $1, updated_by = $2, updated_at = NOW()
			WHERE tenant_id IS NULL
		`, methods, actorUserID)
		if err == nil {
			_, err = s.pool.Exec(ctx, `
				INSERT INTO admin_mfa_policies (tenant_id, allowed_methods, updated_by)
				SELECT NULL, $1, $2
				WHERE NOT EXISTS (SELECT 1 FROM admin_mfa_policies WHERE tenant_id IS NULL)
			`, methods, actorUserID)
		}
	} else {
		_, err = s.pool.Exec(ctx, `
			INSERT INTO admin_mfa_policies (tenant_id, allowed_methods, updated_by)
			VALUES ($1, $2, $3)
			ON CONFLICT (tenant_id) WHERE tenant_id IS NOT NULL
			DO UPDATE SET allowed_methods = EXCLUDED.allowed_methods,
			              updated_by      = EXCLUDED.updated_by,
			              updated_at      = NOW()
		`, tenantID, methods, actorUserID)
	}
	if err != nil {
		return nil, fmt.Errorf("save admin MFA policy: %w", err)
	}
	s.adminMFAPolicy.InvalidateCache()
	return s.GetAdminMFAPolicy(ctx, tenantID)
}

// DeleteAdminMFAPolicy removes a tenant's own row so it inherits the platform
// policy. The platform row itself cannot be deleted: it is what every tenant
// without a row resolves to.
func (s *Service) DeleteAdminMFAPolicy(ctx context.Context, tenantID int64) error {
	if tenantID == 0 {
		return fmt.Errorf("%w: the platform policy cannot be deleted", ErrInvalidAdminMFAPolicy)
	}
	tag, err := s.pool.Exec(ctx, `DELETE FROM admin_mfa_policies WHERE tenant_id = $1`, tenantID)
	if err != nil {
		return fmt.Errorf("delete admin MFA policy: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	s.adminMFAPolicy.InvalidateCache()
	return nil
}

// ErrInvalidAdminMFAPolicy is returned when a policy update is invalid. The same
// sentinel as the auth package's, so one errors.Is serves both layers.
var ErrInvalidAdminMFAPolicy = auth.ErrInvalidAdminMFAPolicy

// AdministratorForReset resolves a tenant administrator record (tenant_admins
// id, the id the admin API already uses) to the account behind it: its user id
// and its home tenant, where its factors and sessions live. A tenant
// administrator's account is often homed in a different tenant from the one
// granting them access. Removed records are not found.
func (s *Service) AdministratorForReset(ctx context.Context, tenantID, adminID int64) (userID, homeTenant int64, err error) {
	err = s.pool.QueryRow(ctx, `
		SELECT u.id, u.tenant_id
		FROM tenant_admins ta
		JOIN users u ON u.id = ta.user_id
		WHERE ta.id = $1 AND ta.tenant_id = $2
		  AND ta.deleted_at IS NULL AND u.deleted_at IS NULL
	`, adminID, tenantID).Scan(&userID, &homeTenant)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, 0, ErrNotFound
		}
		return 0, 0, fmt.Errorf("resolve administrator: %w", err)
	}
	return userID, homeTenant, nil
}
