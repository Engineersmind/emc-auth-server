package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/engineersmind/emc-auth-server/internal/audit"
)

// ---------------------------------------------------------------------------
// Passwordless administration (issue #203, plan section 7.3): the impact
// preview, usage statistics and the per-user recovery actions. The policy itself
// is edited through PasswordlessPolicyService.
// ---------------------------------------------------------------------------

// PasswordlessAdminService answers the read-mostly questions an administrator
// asks around the policy.
type PasswordlessAdminService struct {
	pool   *pgxpool.Pool
	policy *PasswordlessPolicyService
}

// NewPasswordlessAdminService creates the service.
func NewPasswordlessAdminService(pool *pgxpool.Pool, policy *PasswordlessPolicyService) *PasswordlessAdminService {
	return &PasswordlessAdminService{pool: pool, policy: policy}
}

// PasswordlessImpact is the dry-run answer to "what would this change do".
type PasswordlessImpact struct {
	ModeBefore string `json:"mode_before"`
	ModeAfter  string `json:"mode_after"`

	// ActiveUsers is the number of active users in the application.
	ActiveUsers int `json:"active_users"`
	// UsersWithPassword keep their stored password whatever the mode: it is never
	// deleted, only closed in passwordless-only mode.
	UsersWithPassword    int `json:"users_with_password"`
	UsersWithoutPassword int `json:"users_without_password"`
	// UsersUnverifiedEmail will have their address verified by their first code.
	UsersUnverifiedEmail int `json:"users_unverified_email"`
	// PasswordSignIns are successful password sign-ins in the window, with the
	// number of distinct users: the figure that should fall toward zero before the
	// password flow is closed.
	PasswordSignIns7d         int `json:"password_sign_ins_7d"`
	PasswordSignInUsers7d     int `json:"password_sign_in_users_7d"`
	PasswordSignIns30d        int `json:"password_sign_ins_30d"`
	PasswordSignInUsers30d    int `json:"password_sign_in_users_30d"`
	PasswordRefusalsSinceHour int `json:"-"`
	// UsersNeedingTOTPEnrolment have email as their only second factor while the
	// application requires MFA: after an emailed first factor they would be asked
	// to enrol an authenticator app.
	UsersNeedingTOTPEnrolment int `json:"users_needing_totp_enrolment"`
	// SelfRegistrationRemains reports whether new accounts can still appear
	// without an administrator: by password sign-up or by code sign-up.
	SelfRegistrationRemains bool `json:"self_registration_remains"`
	// RequiresOverride is true when the change would strand active users that
	// have no stored password (a switch to password only).
	RequiresOverride bool     `json:"requires_override"`
	Warnings         []string `json:"warnings"`
	// Risky is true when the change needs the application name typed to confirm:
	// password flow closed, or sign-up opened with no domain list.
	Risky bool `json:"risky"`
}

// Impact computes the effect of replacing the overrides at an application scope
// with proposed. It writes nothing.
func (s *PasswordlessAdminService) Impact(ctx context.Context, tenantID, appID int64, proposed PasswordlessPolicyRow) (*PasswordlessImpact, error) {
	sc := PasswordlessScope{TenantID: &tenantID, ApplicationID: &appID}
	current, err := s.policy.View(ctx, sc)
	if err != nil {
		return nil, err
	}
	after, vErr := s.policy.Validate(ctx, sc, &proposed)
	if vErr != nil && !isAdvisoryPasswordlessErr(vErr) {
		return nil, vErr
	}

	im := &PasswordlessImpact{
		ModeBefore: current.Effective.Mode(), ModeAfter: after.Mode(), Warnings: []string{},
	}
	if vErr != nil {
		im.Warnings = append(im.Warnings, vErr.Error())
	}
	if err := s.pool.QueryRow(ctx, `
		SELECT
		  count(*) FILTER (WHERE u.is_active),
		  count(*) FILTER (WHERE u.is_active AND EXISTS (SELECT 1 FROM user_credentials c WHERE c.user_id = u.id)),
		  count(*) FILTER (WHERE u.is_active AND NOT EXISTS (SELECT 1 FROM user_credentials c WHERE c.user_id = u.id)),
		  count(*) FILTER (WHERE u.is_active AND NOT u.email_verified)
		FROM users u
		WHERE u.tenant_id = $1 AND u.application_id = $2 AND u.deleted_at IS NULL`,
		tenantID, appID).Scan(&im.ActiveUsers, &im.UsersWithPassword, &im.UsersWithoutPassword, &im.UsersUnverifiedEmail); err != nil {
		return nil, fmt.Errorf("count users: %w", err)
	}
	for _, w := range []struct {
		days         int
		signIns, usr *int
	}{{7, &im.PasswordSignIns7d, &im.PasswordSignInUsers7d}, {30, &im.PasswordSignIns30d, &im.PasswordSignInUsers30d}} {
		if err := s.pool.QueryRow(ctx, `
			SELECT count(*), count(DISTINCT user_id) FROM audit_logs
			WHERE tenant_id = $1 AND application_id = $2 AND action = $3
			  AND auth_method = $4 AND status = 'success'
			  AND created_at > NOW() - make_interval(days => $5)`,
			tenantID, appID, audit.ActionAuthLogin, audit.AuthMethodPassword, w.days).Scan(w.signIns, w.usr); err != nil {
			return nil, fmt.Errorf("count password sign-ins: %w", err)
		}
	}

	mode, methods, mErr := s.mfaMode(ctx, appID)
	if mErr == nil && mode == MFAModeRequired && after.EmailOTPEnabled {
		var n int
		if err := s.pool.QueryRow(ctx, `
			SELECT count(*) FROM users u
			WHERE u.tenant_id = $1 AND u.application_id = $2 AND u.is_active AND u.deleted_at IS NULL
			  AND EXISTS (SELECT 1 FROM email_mfa_settings e WHERE e.user_id = u.id AND e.is_active)
			  AND NOT EXISTS (SELECT 1 FROM totp_secrets t WHERE t.user_id = u.id AND t.is_active)`,
			tenantID, appID).Scan(&n); err == nil {
			im.UsersNeedingTOTPEnrolment = n
		}
		_ = methods
	}

	im.SelfRegistrationRemains = after.PasswordEnabled || after.SignupEnabled
	if !im.SelfRegistrationRemains {
		im.Warnings = append(im.Warnings, "Nobody can sign up by themselves after this change: accounts will come only from an administrator, an invitation or an import.")
	}
	if after.Mode() == PasswordlessModePasswordOnly && im.UsersWithoutPassword > 0 && current.Effective.EmailOTPEnabled {
		im.RequiresOverride = true
		im.Warnings = append(im.Warnings, fmt.Sprintf("%d active users have no password and could not sign in under password only.", im.UsersWithoutPassword))
	}
	if after.Mode() == PasswordlessModeOnly && current.Effective.PasswordEnabled {
		im.Risky = true
		im.Warnings = append(im.Warnings, "Integrations that send passwords to /apps/login will stop working at once. Stored passwords are kept.")
	}
	if after.SignupEnabled && !current.Effective.SignupEnabled && len(after.AllowedEmailDomains) == 0 {
		im.Risky = true
		im.Warnings = append(im.Warnings, "Anyone with an email address will be able to create an account. Consider an allowed-domain list.")
	}
	return im, nil
}

// isAdvisoryPasswordlessErr reports validation errors that an impact preview
// should show as warnings rather than fail on.
func isAdvisoryPasswordlessErr(err error) bool {
	return errors.Is(err, ErrPasswordlessNoFirstFactor) || errors.Is(err, ErrPasswordlessMFAConflict) ||
		errors.Is(err, ErrPasswordlessTemplateDisabled) || errors.Is(err, ErrPasswordlessCeiling)
}

func (s *PasswordlessAdminService) mfaMode(ctx context.Context, appID int64) (string, []string, error) {
	if s.policy == nil || s.policy.mfaConfig == nil {
		return "", nil, errors.New("no MFA reader")
	}
	return s.policy.mfaConfig(ctx, appID)
}

// SwitchGuard enforces the one hard guardrail on a change of mode: moving to
// password only while active users have no stored password is refused unless the
// administrator explicitly overrides, because those users could not sign in.
func (s *PasswordlessAdminService) SwitchGuard(ctx context.Context, tenantID, appID int64, proposed PasswordlessPolicyRow, override bool) error {
	im, err := s.Impact(ctx, tenantID, appID, proposed)
	if err != nil {
		return err
	}
	if im.RequiresOverride && !override {
		return ErrPasswordlessNoPasswordUsers
	}
	return nil
}

// SwitchGuardScope applies SwitchGuard to every application a write at sc would
// change, using each one's resolved policy: an application, a tenant default, the
// platform default, a delete (in == nil) or a restore. Without override it
// refuses when any application would become password only while it has active
// users with no stored password.
func (s *PasswordlessAdminService) SwitchGuardScope(ctx context.Context, sc PasswordlessScope, in *PasswordlessPolicyRow, override bool) error {
	if override {
		return nil
	}
	apps, err := s.policy.AppsInScope(ctx, sc)
	if err != nil {
		return err
	}
	for appID, tenantID := range apps {
		before, after, err := s.policy.ProjectApp(ctx, sc, in, tenantID, appID)
		if err != nil {
			return err
		}
		if after.Mode() != PasswordlessModePasswordOnly || !before.EmailOTPEnabled {
			continue
		}
		var n int
		if err := s.pool.QueryRow(ctx, `
			SELECT count(*) FROM users u
			WHERE u.tenant_id = $1 AND u.application_id = $2 AND u.is_active AND u.deleted_at IS NULL
			  AND NOT EXISTS (SELECT 1 FROM user_credentials c WHERE c.user_id = u.id)`,
			tenantID, appID).Scan(&n); err != nil {
			return fmt.Errorf("count users without a password: %w", err)
		}
		if n > 0 {
			return ErrPasswordlessNoPasswordUsers
		}
	}
	return nil
}

// PasswordlessStats are usage counters over a window, read from the audit log.
type PasswordlessStats struct {
	Window            string `json:"window"`
	CodesRequested    int    `json:"codes_requested"`
	CodesThrottled    int    `json:"codes_throttled"`
	SignInsByCode     int    `json:"sign_ins_by_code"`
	FailedVerifies    int    `json:"failed_verifies"`
	VerifySuccessRate string `json:"verify_success_rate"`
	AccountsCreated   int    `json:"accounts_created"`
	AccountsSecured   int    `json:"accounts_secured"`
	PasswordRefusals  int    `json:"password_refusals"`
}

// Stats counts passwordless activity for an application over 24h, 7d or 30d.
func (s *PasswordlessAdminService) Stats(ctx context.Context, tenantID, appID int64, window string) (*PasswordlessStats, error) {
	d := map[string]time.Duration{"24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour, "30d": 30 * 24 * time.Hour}[window]
	if d == 0 {
		window, d = "24h", 24*time.Hour
	}
	st := &PasswordlessStats{Window: window, VerifySuccessRate: "n/a"}
	err := s.pool.QueryRow(ctx, `
		SELECT
		  count(*) FILTER (WHERE action = $3),
		  count(*) FILTER (WHERE action = $4),
		  count(*) FILTER (WHERE action = $5 AND auth_method = $9 AND status = 'success'),
		  count(*) FILTER (WHERE action = $6 AND auth_method = $9),
		  count(*) FILTER (WHERE action = $7),
		  count(*) FILTER (WHERE action = $8),
		  count(*) FILTER (WHERE action = $6 AND auth_method = $10 AND metadata->>'reason' = 'password_auth_disabled')
		FROM audit_logs
		WHERE tenant_id = $1 AND application_id = $2 AND created_at > NOW() - $11::interval`,
		tenantID, appID,
		audit.ActionAuthPasswordlessStarted, audit.ActionAuthPasswordlessThrottled,
		audit.ActionAuthLogin, audit.ActionAuthLoginFailed,
		audit.ActionUserCreatedPasswordless, audit.ActionAuthPreverificationNeutralized,
		audit.AuthMethodEmailOTP, audit.AuthMethodPassword, fmt.Sprintf("%d seconds", int(d.Seconds())),
	).Scan(&st.CodesRequested, &st.CodesThrottled, &st.SignInsByCode, &st.FailedVerifies,
		&st.AccountsCreated, &st.AccountsSecured, &st.PasswordRefusals)
	if err != nil {
		return nil, fmt.Errorf("passwordless stats: %w", err)
	}
	if total := st.SignInsByCode + st.FailedVerifies; total > 0 {
		st.VerifySuccessRate = fmt.Sprintf("%.1f%%", 100*float64(st.SignInsByCode)/float64(total))
	}
	return st, nil
}

// UserAuthMethod is one way a user can sign in.
type UserAuthMethod struct {
	Method   string     `json:"method"`
	Enabled  bool       `json:"enabled"`
	Detail   string     `json:"detail,omitempty"`
	AddedAt  *time.Time `json:"added_at,omitempty"`
	LastUsed *time.Time `json:"last_used,omitempty"`
}

// PasswordlessUserMethods is a user's sign-in methods card.
type PasswordlessUserMethods struct {
	UserID        int64            `json:"user_id"`
	Email         string           `json:"email"`
	EmailVerified bool             `json:"email_verified"`
	Methods       []UserAuthMethod `json:"methods"`
	// ThrottleBlocked reports the per-address verify block, if one is active.
	Mode string `json:"mode"`
}

// UserAuthMethods lists how a user can sign in, with last use from the audit log.
func (s *PasswordlessAdminService) UserAuthMethods(ctx context.Context, tenantID, appID, userID int64) (*PasswordlessUserMethods, error) {
	out := &PasswordlessUserMethods{UserID: userID, Methods: []UserAuthMethod{}}
	var hasPassword bool
	var pwAdded *time.Time
	err := s.pool.QueryRow(ctx, `
		SELECT u.email, u.email_verified,
		       EXISTS (SELECT 1 FROM user_credentials c WHERE c.user_id = u.id),
		       (SELECT created_at FROM user_credentials c WHERE c.user_id = u.id)
		FROM users u
		WHERE u.id = $1 AND u.tenant_id = $2 AND u.application_id = $3 AND u.deleted_at IS NULL`,
		userID, tenantID, appID).Scan(&out.Email, &out.EmailVerified, &hasPassword, &pwAdded)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrPasswordlessPolicyNotFound
	}
	if err != nil {
		return nil, err
	}
	eff := s.policy.Resolve(ctx, tenantID, &appID)
	out.Mode = eff.Mode()

	last := func(method string) *time.Time {
		var t *time.Time
		_ = s.pool.QueryRow(ctx, `
			SELECT max(created_at) FROM audit_logs
			WHERE user_id = $1 AND action = $2 AND auth_method = $3 AND status = 'success'`,
			userID, audit.ActionAuthLogin, method).Scan(&t)
		return t
	}
	out.Methods = append(out.Methods,
		UserAuthMethod{Method: "password", Enabled: hasPassword, Detail: passwordDetail(hasPassword, eff.PasswordEnabled), AddedAt: pwAdded, LastUsed: last(audit.AuthMethodPassword)},
		UserAuthMethod{Method: "email_code", Enabled: eff.EmailOTPEnabled, LastUsed: last(audit.AuthMethodEmailOTP)},
	)
	var passkeys int
	_ = s.pool.QueryRow(ctx, `SELECT count(*) FROM webauthn_credentials WHERE user_id = $1 AND is_active`, userID).Scan(&passkeys)
	out.Methods = append(out.Methods, UserAuthMethod{Method: "passkey", Enabled: passkeys > 0, Detail: fmt.Sprintf("%d registered", passkeys), LastUsed: last(audit.AuthMethodPasskey)})

	rows, err := s.pool.Query(ctx, `SELECT provider, created_at FROM user_identities WHERE user_id = $1`, userID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var p string
			var at time.Time
			if rows.Scan(&p, &at) == nil {
				a := at
				out.Methods = append(out.Methods, UserAuthMethod{Method: p, Enabled: true, AddedAt: &a, LastUsed: last(audit.SocialAuthMethod(p))})
			}
		}
	}
	var totp, emailMFA bool
	_ = s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM totp_secrets WHERE user_id = $1 AND is_active)`, userID).Scan(&totp)
	_ = s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM email_mfa_settings WHERE user_id = $1 AND is_active)`, userID).Scan(&emailMFA)
	out.Methods = append(out.Methods,
		UserAuthMethod{Method: "mfa_totp", Enabled: totp},
		UserAuthMethod{Method: "mfa_email", Enabled: emailMFA})
	return out, nil
}

func passwordDetail(has, open bool) string {
	switch {
	case has && !open:
		return "stored, flow closed for this application"
	case has:
		return "stored"
	default:
		return "none"
	}
}

// MarkEmailVerified sets email_verified on a user of the application. Returns
// whether anything changed.
func (s *PasswordlessAdminService) MarkEmailVerified(ctx context.Context, tenantID, appID, userID int64) (bool, error) {
	ct, err := s.pool.Exec(ctx, `
		UPDATE users SET email_verified = true, updated_at = NOW()
		WHERE id = $1 AND tenant_id = $2 AND application_id = $3 AND deleted_at IS NULL AND NOT email_verified`,
		userID, tenantID, appID)
	if err != nil {
		return false, err
	}
	return ct.RowsAffected() > 0, nil
}

// UserEmail returns a user's address within an application, for throttle clearing.
func (s *PasswordlessAdminService) UserEmail(ctx context.Context, tenantID, appID, userID int64) (string, error) {
	var email string
	err := s.pool.QueryRow(ctx, `SELECT email FROM users WHERE id = $1 AND tenant_id = $2 AND application_id = $3 AND deleted_at IS NULL`,
		userID, tenantID, appID).Scan(&email)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrPasswordlessPolicyNotFound
	}
	return email, err
}

// UserApplication returns the application an application user belongs to, so a
// tenant-level route can act on the user without the caller naming it. A user
// that is not an application user (a console administrator) is not found: the
// passwordless flow never applies to them.
func (s *PasswordlessAdminService) UserApplication(ctx context.Context, tenantID, userID int64) (int64, error) {
	var app *int64
	err := s.pool.QueryRow(ctx, `SELECT application_id FROM users WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL`,
		userID, tenantID).Scan(&app)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return 0, ErrPasswordlessPolicyNotFound
	case err != nil:
		return 0, err
	case app == nil:
		return 0, ErrPasswordlessPolicyNotFound
	}
	return *app, nil
}
