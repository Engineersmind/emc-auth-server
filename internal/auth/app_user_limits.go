package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
)

// Per-application overrides of the per-user rate limits.
//
// The application end-user routes limit each end user separately (see
// middleware.AppS2S.UserLimit). The defaults are server-wide configuration
// (RATE_LIMIT_APP_*); an administrator can raise or lower them for one
// application here — a product with a high-traffic "forgot password" flow, or
// one that wants a stricter login limit than the platform's.
//
// Raising is capped. These limits are what bound password guessing on one
// account, OTP guessing, and how much mail one address can be sent, so a tenant
// may not lift them arbitrarily: UserLimitDef.Max is the ceiling for each.
//
// Like AppTrustService, the request path reads an in-memory snapshot refreshed
// every AppTrustRefreshInterval, never the database.

// ErrInvalidUserLimit is returned by SetUserLimits for an unknown key or a
// value out of range. The wrapped message says which and why.
var ErrInvalidUserLimit = errors.New("invalid user limit")

// UserLimitDef describes one per-user limit an administrator can override.
type UserLimitDef struct {
	// Key names the limit in the API and in app_user_rate_limits.limits.
	Key string `json:"key"`
	// Name is the human label shown in the admin console.
	Name string `json:"name"`
	// KeyedBy says what one bucket is: whose requests share the allowance.
	KeyedBy string `json:"keyed_by"`
	// Endpoints are the routes the limit applies to.
	Endpoints []string `json:"endpoints"`
	// Max is the highest override accepted, per minute.
	Max int `json:"max"`
}

// Limit keys. Stable: they are stored in the database and sent by clients.
const (
	UserLimitRegister           = "register"
	UserLimitLogin              = "login"
	UserLimitMagicLink          = "magic_link"
	UserLimitMagicLinkVerify    = "magic_link_verify"
	UserLimitForgotPassword     = "forgot_password"
	UserLimitResetPassword      = "reset_password"
	UserLimitRoles              = "roles"
	UserLimitMe                 = "me"
	UserLimitMFAChallenge       = "mfa_challenge"
	UserLimitOAuthExchange      = "oauth_exchange"
	UserLimitPasskeyLogin       = "passkey_login"
	UserLimitResendVerification = "resend_verification"
)

// UserLimitDefs lists every overridable per-user limit, in display order.
//
// Ceilings: limits that bound guessing a secret the user holds (password, OTP)
// stay low; limits that send mail stay low so one address cannot be flooded;
// token redemption is higher because the tokens are unguessable and the bucket
// is per end-user address; read-only routes are highest.
var UserLimitDefs = []UserLimitDef{
	{Key: UserLimitLogin, Name: "Sign in", KeyedBy: "email (+ user IP when forwarded)",
		Endpoints: []string{"POST /api/v1/auth/apps/login"}, Max: 20},
	{Key: UserLimitRegister, Name: "Sign up", KeyedBy: "email",
		Endpoints: []string{"POST /api/v1/auth/apps/register"}, Max: 30},
	{Key: UserLimitMFAChallenge, Name: "MFA / OTP challenge", KeyedBy: "user IP (forwarded)",
		Endpoints: []string{"POST /api/v1/auth/login/otp", "POST /api/v1/auth/login/otp/resend", "POST /api/v1/auth/login/mfa/*"}, Max: 30},
	{Key: UserLimitPasskeyLogin, Name: "Passkey sign in", KeyedBy: "user IP (forwarded)",
		Endpoints: []string{"POST /api/v1/auth/passkey/login/complete"}, Max: 60},
	{Key: UserLimitMagicLink, Name: "Magic link email", KeyedBy: "email",
		Endpoints: []string{"POST /api/v1/auth/apps/login/magic"}, Max: 10},
	{Key: UserLimitMagicLinkVerify, Name: "Magic link verify", KeyedBy: "user IP (forwarded)",
		Endpoints: []string{"POST /api/v1/auth/apps/login/magic/verify"}, Max: 60},
	{Key: UserLimitForgotPassword, Name: "Forgot password email", KeyedBy: "email",
		Endpoints: []string{"POST /api/v1/auth/forgot-password"}, Max: 10},
	{Key: UserLimitResetPassword, Name: "Reset password", KeyedBy: "user IP (forwarded)",
		Endpoints: []string{"POST /api/v1/auth/reset-password"}, Max: 60},
	{Key: UserLimitResendVerification, Name: "Resend verification email", KeyedBy: "email",
		Endpoints: []string{"POST /api/v1/auth/resend-verification"}, Max: 10},
	{Key: UserLimitOAuthExchange, Name: "Social login code exchange", KeyedBy: "user IP (forwarded)",
		Endpoints: []string{"POST /api/v1/auth/oauth/exchange"}, Max: 60},
	{Key: UserLimitRoles, Name: "User roles", KeyedBy: "user id",
		Endpoints: []string{"POST /api/v1/auth/apps/users/roles"}, Max: 300},
	{Key: UserLimitMe, Name: "Current user (/me)", KeyedBy: "signed-in user",
		Endpoints: []string{"GET /api/v1/auth/apps/me"}, Max: 600},
}

// UserLimitDefByKey returns the definition for key.
func UserLimitDefByKey(key string) (UserLimitDef, bool) {
	for _, d := range UserLimitDefs {
		if d.Key == key {
			return d, true
		}
	}
	return UserLimitDef{}, false
}

// AppUserLimitService manages per-application per-user limit overrides.
type AppUserLimitService struct {
	pool   *pgxpool.Pool
	logger zerolog.Logger
	// snapshot maps application id → overrides, for active applications that
	// have any. Swapped whole on reload, so readers never lock.
	snapshot atomic.Pointer[map[int64]map[string]int]
}

// NewAppUserLimitService creates the service with an empty snapshot. Call Start
// to load it and keep it fresh.
func NewAppUserLimitService(pool *pgxpool.Pool, logger zerolog.Logger) *AppUserLimitService {
	s := &AppUserLimitService{pool: pool, logger: logger}
	empty := map[int64]map[string]int{}
	s.snapshot.Store(&empty)
	return s
}

// UserLimitOverride returns the application's override for key from the
// in-memory snapshot. It never touches the database.
func (s *AppUserLimitService) UserLimitOverride(applicationID int64, key string) (int, bool) {
	if s == nil || applicationID <= 0 {
		return 0, false
	}
	m := s.snapshot.Load()
	if m == nil {
		return 0, false
	}
	v, ok := (*m)[applicationID][key]
	return v, ok
}

// Start loads the snapshot and refreshes it every AppTrustRefreshInterval until
// the returned stop function is called. A failed load keeps the previous
// snapshot, so a database blip does not drop every application to the defaults.
func (s *AppUserLimitService) Start(ctx context.Context) (stop func()) {
	ctx, cancel := context.WithCancel(ctx)
	if err := s.Reload(ctx); err != nil {
		s.logger.Warn().Err(err).Msg("app user limits: initial load failed — server defaults apply until the next refresh")
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(AppTrustRefreshInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := s.Reload(ctx); err != nil && ctx.Err() == nil {
					s.logger.Warn().Err(err).Msg("app user limits: refresh failed — keeping the previous snapshot")
				}
			}
		}
	}()
	return func() {
		cancel()
		<-done
	}
}

// Reload rebuilds the snapshot. Suspended and deleted applications are left
// out. Stored values are re-validated, so a row edited by hand cannot lift a
// limit past its ceiling.
func (s *AppUserLimitService) Reload(ctx context.Context) error {
	rows, err := s.pool.Query(ctx, `
		SELECT l.application_id, l.limits
		FROM app_user_rate_limits l
		JOIN oauth_clients c ON c.id = l.application_id
		WHERE c.deleted_at IS NULL AND c.is_active
	`)
	if err != nil {
		return fmt.Errorf("load app user limits: %w", err)
	}
	defer rows.Close()

	next := map[int64]map[string]int{}
	for rows.Next() {
		var (
			appID int64
			raw   []byte
		)
		if err := rows.Scan(&appID, &raw); err != nil {
			return fmt.Errorf("scan app user limits: %w", err)
		}
		var stored map[string]int
		if err := json.Unmarshal(raw, &stored); err != nil {
			s.logger.Warn().Err(err).Int64("application_id", appID).Msg("app user limits: unreadable row skipped")
			continue
		}
		valid := map[string]int{}
		for k, v := range stored {
			if validateUserLimit(k, v) == nil {
				valid[k] = v
			}
		}
		if len(valid) > 0 {
			next[appID] = valid
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read app user limits: %w", err)
	}
	s.snapshot.Store(&next)
	return nil
}

// GetUserLimits returns the application's overrides (empty when it has none).
// ErrAppNotFound when the application does not exist in the tenant.
func (s *AppUserLimitService) GetUserLimits(ctx context.Context, tenantID, applicationID int64) (map[string]int, error) {
	var raw []byte
	err := s.pool.QueryRow(ctx, `
		SELECT COALESCE(l.limits, '{}'::jsonb)
		FROM oauth_clients c
		LEFT JOIN app_user_rate_limits l ON l.application_id = c.id
		WHERE c.id = $1 AND c.tenant_id = $2 AND c.deleted_at IS NULL
	`, applicationID, tenantID).Scan(&raw)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrAppNotFound
		}
		return nil, fmt.Errorf("get app user limits: %w", err)
	}
	out := map[string]int{}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decode app user limits: %w", err)
	}
	return out, nil
}

// SetUserLimits replaces the application's overrides. An empty map removes them
// all, returning every limit to the server default.
func (s *AppUserLimitService) SetUserLimits(ctx context.Context, tenantID, applicationID int64, overrides map[string]int) (map[string]int, error) {
	for k, v := range overrides {
		if err := validateUserLimit(k, v); err != nil {
			return nil, err
		}
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin app user limits update: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// Ownership check that also locks the application row, so two concurrent
	// replacements serialise.
	tag, err := tx.Exec(ctx, `
		SELECT 1 FROM oauth_clients
		WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL
		FOR UPDATE
	`, applicationID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("lock application: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrAppNotFound
	}

	if len(overrides) == 0 {
		if _, err := tx.Exec(ctx, `DELETE FROM app_user_rate_limits WHERE application_id = $1`, applicationID); err != nil {
			return nil, fmt.Errorf("clear app user limits: %w", err)
		}
	} else {
		encoded, err := json.Marshal(overrides)
		if err != nil {
			return nil, fmt.Errorf("encode app user limits: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO app_user_rate_limits (application_id, tenant_id, limits, updated_at)
			VALUES ($1, $2, $3, NOW())
			ON CONFLICT (application_id) DO UPDATE
			SET limits = EXCLUDED.limits, updated_at = NOW()
		`, applicationID, tenantID, encoded); err != nil {
			return nil, fmt.Errorf("save app user limits: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit app user limits update: %w", err)
	}

	// Apply on this instance now; the others pick it up on their next refresh.
	if err := s.Reload(ctx); err != nil {
		s.logger.Warn().Err(err).Msg("app user limits: reload after update failed — change applies at the next refresh")
	}
	return s.GetUserLimits(ctx, tenantID, applicationID)
}

func validateUserLimit(key string, v int) error {
	def, ok := UserLimitDefByKey(key)
	if !ok {
		return fmt.Errorf("%w: unknown limit %q", ErrInvalidUserLimit, key)
	}
	if v < 1 || v > def.Max {
		return fmt.Errorf("%w: %s must be between 1 and %d per minute", ErrInvalidUserLimit, key, def.Max)
	}
	return nil
}
