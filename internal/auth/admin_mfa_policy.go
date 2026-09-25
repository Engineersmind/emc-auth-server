package auth

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
)

// ---------------------------------------------------------------------------
// Mandatory administrator MFA (migration 00094)
//
// Every administrator — tenant owner, co-owner, platform administrator — must
// complete a second factor before a console session exists. The requirement
// itself is not configurable; only the set of factors that satisfy it is, per
// tenant, with a platform row governing platform administrators and every
// tenant that has not chosen.
//
// Two ways into the console, as in GitHub and Microsoft Entra:
//
//   - password, then a SECOND FACTOR — an authenticator app (TOTP, with its
//     backup codes) or an emailed one-time code; and
//   - a passkey on the sign-in page, which is phishing-resistant and — with
//     user verification (biometric or PIN) — already two factors on its own,
//     so it needs no second step. Passkeys are therefore a sign-in method, not
//     a second factor, and are not part of this policy.
// ---------------------------------------------------------------------------

// AdminMFAMethods is every second factor an administrator MFA policy may allow,
// in the order a client should present them.
var AdminMFAMethods = []string{MFAMethodTOTP, MFAMethodEmail}

// DefaultAdminMFAMethods is the shipped policy: both second factors, so an
// administrator always has another one to fall back on when one is not to hand.
//
// Email is included deliberately, although NIST SP 800-63B §5.1.3.1 does not
// accept it as an out-of-band authenticator — it is the one factor every
// administrator already has. A tenant that wants AAL2-strict factors removes
// it from its own policy.
//
// Must match the column default and platform seed in migrations 00094/00096.
func DefaultAdminMFAMethods() []string {
	return []string{MFAMethodTOTP, MFAMethodEmail}
}

// AdminMFAPolicy is the set of factors that satisfy the administrator MFA
// requirement in one scope.
type AdminMFAPolicy struct {
	AllowedMethods []string `json:"allowed_methods"`
	// Source names where the policy came from: "tenant", "platform", or
	// "default" when no row could be read.
	Source string `json:"source"`
}

// Allows reports whether method satisfies this policy.
func (p AdminMFAPolicy) Allows(method string) bool {
	return methodAllowed(p.AllowedMethods, method)
}

var (
	// ErrAdminMFAUnavailable means no factor the policy allows can be used on
	// this deployment (e.g. TOTP is not configured and passkeys are off). The
	// login is refused rather than let through: the requirement is mandatory,
	// and failing open on a configuration gap would make it optional in exactly
	// the deployments least likely to notice.
	ErrAdminMFAUnavailable = errors.New("no administrator MFA method is available on this server")
	// ErrAdminMFAMethodNotAllowed means the factor presented is not one the
	// administrator's MFA policy accepts.
	ErrAdminMFAMethodNotAllowed = errors.New("this MFA method is not allowed for administrators")
	// ErrMFAStepUpRequired means the session was not established with MFA, so it
	// may not be carried into a tenant that requires it.
	ErrMFAStepUpRequired = errors.New("this session was not established with multi-factor authentication")
	// ErrInvalidAdminMFAPolicy is a validation failure on write.
	ErrInvalidAdminMFAPolicy = errors.New("invalid administrator MFA policy")
)

// ValidateAdminMFAMethods checks a proposed allowed-method set: at least one
// method, each one known, none repeated. The at-least-one rule is what keeps a
// mandatory requirement satisfiable — an empty set would lock every
// administrator of the scope out.
func ValidateAdminMFAMethods(methods []string) error {
	if len(methods) == 0 {
		return fmt.Errorf("%w: at least one MFA method must be allowed", ErrInvalidAdminMFAPolicy)
	}
	seen := make(map[string]bool, len(methods))
	for _, m := range methods {
		if !slices.Contains(AdminMFAMethods, m) {
			return fmt.Errorf("%w: unknown MFA method %q", ErrInvalidAdminMFAPolicy, m)
		}
		if seen[m] {
			return fmt.Errorf("%w: MFA method %q is listed twice", ErrInvalidAdminMFAPolicy, m)
		}
		seen[m] = true
	}
	return nil
}

// OrderAdminMFAMethods returns methods in presentation order (AdminMFAMethods),
// so every surface lists them the same way regardless of how they were stored.
func OrderAdminMFAMethods(methods []string) []string {
	out := make([]string, 0, len(methods))
	for _, m := range AdminMFAMethods {
		if methodAllowed(methods, m) {
			out = append(out, m)
		}
	}
	return out
}

// AdminMFAPolicyService resolves administrator MFA policy.
type AdminMFAPolicyService struct {
	pool   *pgxpool.Pool
	logger zerolog.Logger

	mu    sync.RWMutex
	cache map[int64]cachedAdminMFAPolicy // key: tenant id, 0 = platform
	ttl   time.Duration
}

type cachedAdminMFAPolicy struct {
	policy   AdminMFAPolicy
	cachedAt time.Time
}

// adminMFAPolicyCacheTTL bounds how long a resolved policy is reused. Writes
// invalidate immediately; the TTL only covers other replicas.
const adminMFAPolicyCacheTTL = 60 * time.Second

// NewAdminMFAPolicyService creates the resolver.
func NewAdminMFAPolicyService(pool *pgxpool.Pool, logger zerolog.Logger) *AdminMFAPolicyService {
	return &AdminMFAPolicyService{
		pool:   pool,
		logger: logger,
		cache:  make(map[int64]cachedAdminMFAPolicy),
		ttl:    adminMFAPolicyCacheTTL,
	}
}

// Resolve returns the policy for a tenant's administrators, or for platform
// administrators when tenantID is 0.
//
// Never fails. A read error falls back to the shipped default and logs: the
// requirement is mandatory whatever this returns, so the fallback only decides
// WHICH factors satisfy it, never WHETHER one is needed. Refusing every
// administrator sign-in because a settings table was briefly unreadable would
// turn a transient fault into an outage with no security benefit.
func (s *AdminMFAPolicyService) Resolve(ctx context.Context, tenantID int64) AdminMFAPolicy {
	if s == nil || s.pool == nil {
		return AdminMFAPolicy{AllowedMethods: DefaultAdminMFAMethods(), Source: "default"}
	}

	s.mu.RLock()
	entry, ok := s.cache[tenantID]
	s.mu.RUnlock()
	if ok && time.Since(entry.cachedAt) < s.ttl {
		return entry.policy
	}

	policy, err := s.load(ctx, tenantID)
	if err != nil {
		s.logger.Warn().Err(err).Int64("tenant_id", tenantID).
			Msg("admin MFA policy: resolve failed, using the shipped default methods")
		return AdminMFAPolicy{AllowedMethods: DefaultAdminMFAMethods(), Source: "default"}
	}

	s.mu.Lock()
	s.cache[tenantID] = cachedAdminMFAPolicy{policy: policy, cachedAt: time.Now()}
	s.mu.Unlock()
	return policy
}

// load reads the most specific row: the tenant's own, else the platform row.
func (s *AdminMFAPolicyService) load(ctx context.Context, tenantID int64) (AdminMFAPolicy, error) {
	var methods []string
	var isPlatform bool
	err := s.pool.QueryRow(ctx, `
		SELECT allowed_methods, tenant_id IS NULL
		FROM admin_mfa_policies
		WHERE tenant_id = $1 OR tenant_id IS NULL
		ORDER BY tenant_id NULLS LAST
		LIMIT 1
	`, tenantID).Scan(&methods, &isPlatform)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return AdminMFAPolicy{}, fmt.Errorf("no admin MFA policy row matched (platform row missing?)")
		}
		return AdminMFAPolicy{}, fmt.Errorf("load admin MFA policy: %w", err)
	}
	source := "tenant"
	if isPlatform {
		source = "platform"
	}
	return AdminMFAPolicy{AllowedMethods: OrderAdminMFAMethods(methods), Source: source}, nil
}

// InvalidateCache drops every cached policy. A platform-row change affects every
// tenant without its own row, and those keys are not tracked individually.
func (s *AdminMFAPolicyService) InvalidateCache() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.cache = make(map[int64]cachedAdminMFAPolicy)
	s.mu.Unlock()
}

// ---------------------------------------------------------------------------
// AuthService integration
// ---------------------------------------------------------------------------

// WithAdminMFAPolicy turns on mandatory administrator MFA. Without it the login
// path behaves as it always has; with it, every administrator sign-in must
// complete a factor the resolved policy allows.
func (s *AuthService) WithAdminMFAPolicy(svc *AdminMFAPolicyService) *AuthService {
	s.adminMFA = svc
	return s
}

// AdminMFAPolicy exposes the resolver to handlers that report policy state.
func (s *AuthService) AdminMFAPolicy() *AdminMFAPolicyService { return s.adminMFA }

// AdminMFAEnforced reports whether mandatory administrator MFA is on.
func (s *AuthService) AdminMFAEnforced() bool { return s.adminMFA != nil }

// administratorKind reports whether a user is an administrator and, if so,
// whether a platform one. Platform administrators hold tenant:manage; tenant
// administrators hold an activated admin grant (owner or co-owner) in any
// tenant, or the legacy admin:access permission.
//
// Fails closed: a read error is returned rather than read as "not an
// administrator", because that reading would skip a mandatory control.
func (s *AuthService) administratorKind(ctx context.Context, userID int64, perms []string) (admin, platform bool, err error) {
	for _, p := range perms {
		if p == "tenant:manage" {
			return true, true, nil
		}
		if p == "admin:access" {
			admin = true
		}
	}
	if admin {
		return true, false, nil
	}
	if err := s.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM admin_grants
			WHERE user_id = $1 AND deleted_at IS NULL AND activated_at IS NOT NULL
		)
	`, userID).Scan(&admin); err != nil {
		return false, false, fmt.Errorf("check administrator grants: %w", err)
	}
	return admin, false, nil
}

// AdminMFAPolicyFor resolves the policy governing one administrator: the
// platform policy for a platform administrator, else their tenant's.
func (s *AuthService) AdminMFAPolicyFor(ctx context.Context, tenantID int64, platform bool) AdminMFAPolicy {
	if platform {
		return s.adminMFA.Resolve(ctx, 0)
	}
	return s.adminMFA.Resolve(ctx, tenantID)
}

// adminMethodUsable reports whether this deployment can actually run a second
// factor: its backing service is configured. A policy may allow a method the
// deployment cannot run; such a method is simply never offered.
func (s *AuthService) adminMethodUsable(_ context.Context, _ int64, method string) bool {
	switch method {
	case MFAMethodTOTP:
		return s.totpSvc != nil
	case MFAMethodEmail:
		return s.emailSvc != nil
	}
	return false
}

// adminMFAGate is mfaGate for administrators: MFA is mandatory, and the
// factors that satisfy it come from the administrator MFA policy rather than
// an application's.
//
//   - an active factor the policy allows → OTP challenge listing every one, so
//     the client can offer the authenticator app and email side by side;
//   - none → forced enrollment in a method the policy allows and the
//     deployment can run;
//   - no such method at all → ErrAdminMFAUnavailable. Never tokens.
//
// Every read error fails closed.
func (s *AuthService) adminMFAGate(ctx context.Context, userID, tenantID int64, platform bool, appID, email, roleName string, perms []string, persistent bool, activeRoles []string) (*LoginResult, error) {
	if s.redisCli == nil {
		return nil, ErrAdminMFAUnavailable
	}
	policy := s.AdminMFAPolicyFor(ctx, tenantID, platform)

	var usable []string
	for _, m := range policy.AllowedMethods {
		if s.adminMethodUsable(ctx, tenantID, m) {
			usable = append(usable, m)
		}
	}
	if len(usable) == 0 {
		s.logger.Error().Int64("tenant_id", tenantID).Strs("allowed", policy.AllowedMethods).
			Msg("admin MFA: no allowed method is configured on this deployment — administrator sign-in refused")
		return nil, ErrAdminMFAUnavailable
	}

	var methods []string
	for _, m := range usable {
		active, err := s.factorActive(ctx, userID, tenantID, m)
		if err != nil {
			return nil, err
		}
		if active {
			methods = append(methods, m)
		}
	}

	if len(methods) > 0 {
		// Once the administrator has set up any factor, an email code is also
		// offered whenever the policy allows email — even if they never turned
		// email on. It is the "try another way" for a lost or reset phone: the
		// code goes to the address the account signs in with, and is bound to
		// this challenge, so no enrollment is needed for it. A policy that drops
		// email removes the fallback, leaving backup codes and an admin reset.
		//
		// Email is mailed up front only when it is the sole method the account
		// has set up; as a fallback it is sent only when chosen, so an
		// authenticator-app sign-in never also drops a code in the inbox.
		sendEmailNow := len(methods) == 1 && methods[0] == MFAMethodEmail
		if !slices.Contains(methods, MFAMethodEmail) && slices.Contains(usable, MFAMethodEmail) {
			methods = append(methods, MFAMethodEmail)
		}
		challenge, err := s.createOTPSessionWith(ctx, userID, tenantID, email, roleName, perms, appID, methods, persistent, activeRoles, sendEmailNow)
		if err != nil {
			return nil, fmt.Errorf("create OTP session: %w", err)
		}
		return &LoginResult{OTPChallenge: challenge}, nil
	}

	challenge, err := s.createMFAEnrollmentSession(ctx, userID, tenantID, email, roleName, perms, appID, usable, persistent, activeRoles)
	if err != nil {
		return nil, fmt.Errorf("create MFA enrollment session: %w", err)
	}
	return &LoginResult{MFAEnrollment: challenge}, nil
}

// factorActive reports whether the administrator has set method up.
//
// Both second factors are opt-in: a new administrator has neither, chooses one
// at their first sign-in (the forced-enrollment step), and may add the other
// from Settings. Email counts only once its address has been confirmed with a
// code — the same enrollment every other email-MFA user goes through.
func (s *AuthService) factorActive(ctx context.Context, userID, _ int64, method string) (bool, error) {
	switch method {
	case MFAMethodTOTP:
		return s.totpSvc.IsActive(ctx, userID)
	case MFAMethodEmail:
		return s.emailSvc.IsActive(ctx, userID)
	}
	return false, nil
}

// requireAdminPasskeyMFA applies mandatory administrator MFA to a passwordless
// passkey sign-in: it satisfies the requirement only when the authenticator
// performed user verification (a biometric or PIN), which is what makes one
// passkey two factors — possession of the device and the person using it.
func (s *AuthService) requireAdminPasskeyMFA(ctx context.Context, id *WebAuthnIdentity, perms []string) error {
	if s.adminMFA == nil {
		return nil
	}
	admin, _, err := s.administratorKind(ctx, id.UserID, perms)
	if err != nil || !admin {
		return err
	}
	if !id.UserVerified {
		return ErrUserVerificationRequired
	}
	return nil
}

// sessionHasMFA reports whether a session was established with MFA, read from
// the amr recorded when it was created.
func (s *AuthService) sessionHasMFA(ctx context.Context, sessionID int64, userID int64) (bool, error) {
	var ok bool
	err := s.pool.QueryRow(ctx, `
		SELECT $3 = ANY (amr)
		FROM user_sessions
		WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL
	`, sessionID, userID, AMRMFA).Scan(&ok)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("read session amr: %w", err)
	}
	return ok, nil
}

// ---------------------------------------------------------------------------
// Self-service: what an administrator may enroll and remove
// ---------------------------------------------------------------------------

// MFAMethodStatus is one method's state for the caller's settings page.
type MFAMethodStatus struct {
	Method string `json:"method"`
	// Allowed: the caller's policy accepts this method. Always true for a
	// non-administrator, whose methods are not governed by the admin policy.
	Allowed bool `json:"allowed"`
	// Available: this deployment can run the method at all.
	Available bool `json:"available"`
	// Active: the caller has it enrolled.
	Active bool `json:"active"`
	// BackupCodesRemaining is the number of unused backup codes (totp only).
	BackupCodesRemaining int `json:"backup_codes_remaining,omitempty"`
}

// MFAStatus is the caller's complete MFA picture.
type MFAStatus struct {
	// MFARequired is true when the caller is an administrator and MFA is
	// therefore mandatory for them.
	MFARequired  bool              `json:"mfa_required"`
	PolicySource string            `json:"policy_source,omitempty"`
	Methods      []MFAMethodStatus `json:"methods"`
}

// MyMFAStatus reports the caller's MFA state across every method.
func (s *AuthService) MyMFAStatus(ctx context.Context, userID, tenantID int64, perms []string) (*MFAStatus, error) {
	out := &MFAStatus{}
	var policy *AdminMFAPolicy
	if s.adminMFA != nil {
		admin, platform, err := s.administratorKind(ctx, userID, perms)
		if err != nil {
			return nil, err
		}
		if admin {
			p := s.AdminMFAPolicyFor(ctx, tenantID, platform)
			policy = &p
			out.MFARequired = true
			out.PolicySource = p.Source
		}
	}

	for _, m := range AdminMFAMethods {
		st := MFAMethodStatus{Method: m, Allowed: policy == nil || policy.Allows(m)}
		st.Available = s.adminMethodUsable(ctx, tenantID, m)
		if st.Available {
			switch m {
			case MFAMethodTOTP:
				ts, err := s.totpSvc.Status(ctx, userID)
				if err != nil {
					return nil, err
				}
				st.Active = ts.Active
				if ts.Active {
					st.BackupCodesRemaining = ts.BackupCodesRemaining
				}
			case MFAMethodEmail:
				active, err := s.emailSvc.IsActive(ctx, userID)
				if err != nil {
					return nil, err
				}
				st.Active = active
			}
		}
		out.Methods = append(out.Methods, st)
	}
	return out, nil
}

// AdminMethodEnrollable refuses self-service enrollment of a method the
// caller's administrator policy does not accept. A factor that can never
// satisfy the requirement would only mislead its owner into thinking they are
// covered. A no-op for non-administrators.
func (s *AuthService) AdminMethodEnrollable(ctx context.Context, userID, tenantID int64, perms []string, method string) error {
	if s.adminMFA == nil {
		return nil
	}
	admin, platform, err := s.administratorKind(ctx, userID, perms)
	if err != nil || !admin {
		return err
	}
	if !s.AdminMFAPolicyFor(ctx, tenantID, platform).Allows(method) {
		return ErrAdminMFAMethodNotAllowed
	}
	return nil
}

// AdminFactorRemovalAllowed refuses turning off an administrator's last second
// factor that satisfies their policy. Only factors the policy accepts count as
// remaining: keeping one it no longer accepts does not keep the administrator
// able to sign in. An authenticator app can still be REPLACED (set up again on
// a new phone with a current code) whatever else the account holds.
func (s *AuthService) AdminFactorRemovalAllowed(ctx context.Context, userID, tenantID int64, perms []string, method string) error {
	if s.adminMFA == nil {
		return nil
	}
	admin, platform, err := s.administratorKind(ctx, userID, perms)
	if err != nil || !admin {
		return err
	}
	policy := s.AdminMFAPolicyFor(ctx, tenantID, platform)
	for _, m := range policy.AllowedMethods {
		if m == method || !s.adminMethodUsable(ctx, tenantID, m) {
			continue
		}
		active, err := s.factorActive(ctx, userID, tenantID, m)
		if err != nil {
			return err
		}
		if active {
			return nil
		}
	}
	return ErrMFARequiredByPolicy
}
