package admin

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// LockoutPolicyView is the API representation of an account-lockout policy
// (issue #72).
type LockoutPolicyView struct {
	// Scope is "platform", "tenant", or "application" — which row actually
	// answered the request. Without it a caller cannot tell a policy they have set
	// from an inherited default, and would have no way to know that editing it
	// creates a new row rather than changing an existing one.
	Scope string `json:"scope"`
	// Inherited is true when no row exists at the requested scope and these
	// values came from a broader one.
	Inherited bool `json:"inherited"`

	NotifyUserThreshold     int `json:"notify_user_threshold"`
	SoftLockThreshold       int `json:"soft_lock_threshold"`
	SoftLockDurationSeconds int `json:"soft_lock_duration_seconds"`
	HardLockThreshold       int `json:"hard_lock_threshold"`
	// HardLockDurationSeconds is nil when a hard lock does NOT expire on its own
	// and only an operator can restore access. Nullable rather than zero because
	// "never expires" is a deliberate choice a tenant makes, and encoding it as 0
	// would make it indistinguishable from an unset field.
	HardLockDurationSeconds *int `json:"hard_lock_duration_seconds"`
	FailureWindowSeconds    int  `json:"failure_window_seconds"`
	TenantSpikeThreshold    int  `json:"tenant_spike_threshold"`
}

// LockoutPolicyInput is the writable body of a policy update. Every field is a
// pointer so an omitted field means "leave as is" rather than "set to zero" — a
// PUT that reset hard_lock_threshold to 0 because the caller only wanted to change
// the window would lock out a tenant's entire user base.
type LockoutPolicyInput struct {
	NotifyUserThreshold     *int `json:"notify_user_threshold"`
	SoftLockThreshold       *int `json:"soft_lock_threshold"`
	SoftLockDurationSeconds *int `json:"soft_lock_duration_seconds"`
	HardLockThreshold       *int `json:"hard_lock_threshold"`
	FailureWindowSeconds    *int `json:"failure_window_seconds"`
	TenantSpikeThreshold    *int `json:"tenant_spike_threshold"`

	// RawHardLockDuration sets how long a hard lock holds. Omitted leaves the
	// current setting alone.
	RawHardLockDuration *int `json:"hard_lock_duration_seconds"`
	// HardLockPermanent:true makes hard locks last until an operator intervenes.
	//
	// A separate explicit flag rather than a null duration, because this is the
	// most consequential setting in the table — it is what turns ten
	// unauthenticated requests into an account disabled indefinitely — and it must
	// never be reachable by an omitted, misspelled, or null-coerced field. An
	// operator choosing it has to say so.
	HardLockPermanent *bool `json:"hard_lock_permanent"`
}

// Policy bounds, mirrored from the CHECK constraints in migration 00086.
//
// Duplicated in Go so the caller gets a readable 400 naming the offending field
// instead of a 500 wrapping a constraint-violation string. The database keeps its
// own copy because the table is also reachable by hand during incident response,
// and that is exactly when a mistyped value does the most damage.
const (
	minLockoutThreshold    = 1
	maxLockoutThreshold    = 1000
	minSoftLockSeconds     = 30
	maxSoftLockSeconds     = 86400
	minHardLockSeconds     = 60
	maxHardLockSeconds     = 2592000
	minLockoutWindowSecs   = 60
	maxLockoutWindowSecs   = 86400
	maxLockoutSpikeAccount = 100000
)

// ErrInvalidLockoutPolicy is returned when a policy update violates its bounds.
var ErrInvalidLockoutPolicy = errors.New("invalid lockout policy")

// GetLockoutPolicy returns the policy in force at the given scope, reporting
// whether it was inherited from a broader one.
func (s *Service) GetLockoutPolicy(ctx context.Context, tenantID int64, applicationID *int64) (*LockoutPolicyView, error) {
	var view LockoutPolicyView
	var rowTenant, rowApp *int64

	err := s.pool.QueryRow(ctx, `
		SELECT tenant_id, application_id, notify_user_threshold,
		       soft_lock_threshold, soft_lock_duration_seconds,
		       hard_lock_threshold, hard_lock_duration_seconds,
		       failure_window_seconds, tenant_spike_threshold
		FROM lockout_policies
		WHERE (application_id = $2 AND tenant_id = $1)
		   OR (application_id IS NULL AND tenant_id = $1)
		   OR (application_id IS NULL AND tenant_id IS NULL)
		ORDER BY application_id NULLS LAST, tenant_id NULLS LAST
		LIMIT 1
	`, tenantID, applicationID).Scan(&rowTenant, &rowApp,
		&view.NotifyUserThreshold, &view.SoftLockThreshold, &view.SoftLockDurationSeconds,
		&view.HardLockThreshold, &view.HardLockDurationSeconds,
		&view.FailureWindowSeconds, &view.TenantSpikeThreshold)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// The platform default is seeded by migration 00086; its absence means
			// somebody deleted it. Report the compiled-in defaults, which are what
			// the auth service is also falling back to, so the API and the running
			// behaviour agree.
			return platformFallbackLockoutView(), nil
		}
		return nil, fmt.Errorf("get lockout policy: %w", err)
	}

	switch {
	case rowApp != nil:
		view.Scope = "application"
	case rowTenant != nil:
		view.Scope = "tenant"
	default:
		view.Scope = "platform"
	}
	view.Inherited = (applicationID != nil && rowApp == nil) || rowTenant == nil
	return &view, nil
}

// platformFallbackLockoutView renders auth.DefaultLockoutPolicy as an API response.
func platformFallbackLockoutView() *LockoutPolicyView {
	d := auth.DefaultLockoutPolicy
	v := &LockoutPolicyView{
		Scope:                   "platform",
		Inherited:               true,
		NotifyUserThreshold:     d.NotifyUserThreshold,
		SoftLockThreshold:       d.SoftLockThreshold,
		SoftLockDurationSeconds: int(d.SoftLockDuration.Seconds()),
		HardLockThreshold:       d.HardLockThreshold,
		FailureWindowSeconds:    int(d.FailureWindow.Seconds()),
		TenantSpikeThreshold:    d.TenantSpikeThreshold,
	}
	if d.HardLockDuration > 0 {
		secs := int(d.HardLockDuration.Seconds())
		v.HardLockDurationSeconds = &secs
	}
	return v
}

// SetLockoutPolicy creates or updates the policy at the given scope.
//
// Reads the currently effective policy first and applies the caller's partial
// input on top, so a PUT that sets one field inherits the rest from what was
// actually in force rather than from compiled-in defaults. Without that, setting a
// tenant's failure window would silently reset its thresholds to platform values —
// a change the caller never asked for and would not see in their own request body.
func (s *Service) SetLockoutPolicy(ctx context.Context, tenantID int64, applicationID *int64, in LockoutPolicyInput) (*LockoutPolicyView, error) {
	current, err := s.GetLockoutPolicy(ctx, tenantID, applicationID)
	if err != nil {
		return nil, err
	}

	next := *current
	if in.NotifyUserThreshold != nil {
		next.NotifyUserThreshold = *in.NotifyUserThreshold
	}
	if in.SoftLockThreshold != nil {
		next.SoftLockThreshold = *in.SoftLockThreshold
	}
	if in.SoftLockDurationSeconds != nil {
		next.SoftLockDurationSeconds = *in.SoftLockDurationSeconds
	}
	if in.HardLockThreshold != nil {
		next.HardLockThreshold = *in.HardLockThreshold
	}
	if in.FailureWindowSeconds != nil {
		next.FailureWindowSeconds = *in.FailureWindowSeconds
	}
	if in.TenantSpikeThreshold != nil {
		next.TenantSpikeThreshold = *in.TenantSpikeThreshold
	}
	// Permanence is checked before the duration so an explicit
	// hard_lock_permanent:true wins over a duration sent in the same body — the
	// more conservative reading of a contradictory request.
	switch {
	case in.HardLockPermanent != nil && *in.HardLockPermanent:
		next.HardLockDurationSeconds = nil
	case in.RawHardLockDuration != nil:
		next.HardLockDurationSeconds = in.RawHardLockDuration
	case in.HardLockPermanent != nil && !*in.HardLockPermanent && next.HardLockDurationSeconds == nil:
		// Turning permanence off with no duration supplied: fall back to the
		// platform default rather than leaving the row in a state whose meaning
		// ("not permanent, but no expiry either") the login path cannot honour.
		next.HardLockDurationSeconds = platformFallbackLockoutView().HardLockDurationSeconds
	}

	if err := validateLockoutPolicy(next); err != nil {
		return nil, err
	}

	// ON CONFLICT cannot be used here: the uniqueness of a scope is expressed by
	// three partial indexes (see migration 00086), and ON CONFLICT requires a
	// single named constraint or index. An UPDATE-then-INSERT under one transaction
	// is the portable equivalent; concurrent writes to the same scope are settled by
	// the partial unique index, which turns the loser into an error rather than a
	// duplicate row.
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin lockout policy tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	ct, err := tx.Exec(ctx, `
		UPDATE lockout_policies
		SET notify_user_threshold = $3, soft_lock_threshold = $4,
		    soft_lock_duration_seconds = $5, hard_lock_threshold = $6,
		    hard_lock_duration_seconds = $7, failure_window_seconds = $8,
		    tenant_spike_threshold = $9, updated_at = NOW()
		WHERE tenant_id = $1 AND application_id IS NOT DISTINCT FROM $2
	`, tenantID, applicationID, next.NotifyUserThreshold, next.SoftLockThreshold,
		next.SoftLockDurationSeconds, next.HardLockThreshold, next.HardLockDurationSeconds,
		next.FailureWindowSeconds, next.TenantSpikeThreshold)
	if err != nil {
		return nil, fmt.Errorf("update lockout policy: %w", err)
	}
	if ct.RowsAffected() == 0 {
		if _, err := tx.Exec(ctx, `
			INSERT INTO lockout_policies
			    (tenant_id, application_id, notify_user_threshold, soft_lock_threshold,
			     soft_lock_duration_seconds, hard_lock_threshold, hard_lock_duration_seconds,
			     failure_window_seconds, tenant_spike_threshold)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		`, tenantID, applicationID, next.NotifyUserThreshold, next.SoftLockThreshold,
			next.SoftLockDurationSeconds, next.HardLockThreshold, next.HardLockDurationSeconds,
			next.FailureWindowSeconds, next.TenantSpikeThreshold); err != nil {
			return nil, fmt.Errorf("insert lockout policy: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit lockout policy: %w", err)
	}

	// Drop the resolver's cache immediately. Waiting out the cache TTL would be
	// acceptable for a routine change but not for the case that matters: an
	// operator RAISING a threshold to let a locked-out user back in needs it to
	// apply to the next attempt, not the one after the cache expires.
	s.invalidateLockoutCache()

	next.Inherited = false
	if applicationID != nil {
		next.Scope = "application"
	} else {
		next.Scope = "tenant"
	}
	return &next, nil
}

// DeleteLockoutPolicy removes the policy row at the given scope so the scope
// inherits again. Returns ErrNotFound when there was nothing to delete —
// distinguishable from success because "you had no override" and "your override is
// gone" mean different things to a caller reconciling desired state.
func (s *Service) DeleteLockoutPolicy(ctx context.Context, tenantID int64, applicationID *int64) error {
	ct, err := s.pool.Exec(ctx, `
		DELETE FROM lockout_policies
		WHERE tenant_id = $1 AND application_id IS NOT DISTINCT FROM $2
	`, tenantID, applicationID)
	if err != nil {
		return fmt.Errorf("delete lockout policy: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	s.invalidateLockoutCache()
	return nil
}

// invalidateLockoutCache clears the auth service's resolver cache when one is
// wired. A nil auth service is not an error — see Service.authSvc — but it does
// mean policy changes take up to lockoutPolicyCacheTTL to apply.
func (s *Service) invalidateLockoutCache() {
	if s.authSvc == nil {
		return
	}
	s.authSvc.LockoutPolicy().InvalidateCache()
}

// validateLockoutPolicy enforces the same bounds as the table's CHECK
// constraints, naming the offending field.
func validateLockoutPolicy(p LockoutPolicyView) error {
	switch {
	// Zero is legal for the notify tier — it disables the warning email — so this
	// one is bounded only above.
	case p.NotifyUserThreshold < 0 || p.NotifyUserThreshold > maxLockoutThreshold:
		return fmt.Errorf("%w: notify_user_threshold must be between 0 and %d",
			ErrInvalidLockoutPolicy, maxLockoutThreshold)
	case p.SoftLockThreshold < minLockoutThreshold || p.SoftLockThreshold > maxLockoutThreshold:
		return fmt.Errorf("%w: soft_lock_threshold must be between %d and %d",
			ErrInvalidLockoutPolicy, minLockoutThreshold, maxLockoutThreshold)
	case p.HardLockThreshold < minLockoutThreshold || p.HardLockThreshold > maxLockoutThreshold:
		return fmt.Errorf("%w: hard_lock_threshold must be between %d and %d",
			ErrInvalidLockoutPolicy, minLockoutThreshold, maxLockoutThreshold)
	case p.SoftLockDurationSeconds < minSoftLockSeconds || p.SoftLockDurationSeconds > maxSoftLockSeconds:
		return fmt.Errorf("%w: soft_lock_duration_seconds must be between %d and %d",
			ErrInvalidLockoutPolicy, minSoftLockSeconds, maxSoftLockSeconds)
	case p.HardLockDurationSeconds != nil &&
		(*p.HardLockDurationSeconds < minHardLockSeconds || *p.HardLockDurationSeconds > maxHardLockSeconds):
		return fmt.Errorf("%w: hard_lock_duration_seconds must be between %d and %d, or null for a permanent lock",
			ErrInvalidLockoutPolicy, minHardLockSeconds, maxHardLockSeconds)
	case p.FailureWindowSeconds < minLockoutWindowSecs || p.FailureWindowSeconds > maxLockoutWindowSecs:
		return fmt.Errorf("%w: failure_window_seconds must be between %d and %d",
			ErrInvalidLockoutPolicy, minLockoutWindowSecs, maxLockoutWindowSecs)
	case p.TenantSpikeThreshold < 0 || p.TenantSpikeThreshold > maxLockoutSpikeAccount:
		return fmt.Errorf("%w: tenant_spike_threshold must be between 0 and %d",
			ErrInvalidLockoutPolicy, maxLockoutSpikeAccount)

	// The tiers must escalate. Rejected rather than clamped: silently altering a
	// number the operator typed is how a policy comes to differ from what the
	// console displays.
	//
	// A soft threshold at or above the hard one makes the soft tier unreachable —
	// the account is disabled before the temporary lock can ever apply — which
	// silently removes the self-healing tier and sends every fumbled password
	// straight to a hard lock.
	case p.SoftLockThreshold >= p.HardLockThreshold:
		return fmt.Errorf("%w: soft_lock_threshold must be below hard_lock_threshold", ErrInvalidLockoutPolicy)
	// A notify threshold above the soft one warns the user only after they are
	// already locked out, which defeats the point of an early warning.
	case p.NotifyUserThreshold > 0 && p.NotifyUserThreshold > p.SoftLockThreshold:
		return fmt.Errorf("%w: notify_user_threshold cannot exceed soft_lock_threshold", ErrInvalidLockoutPolicy)
	}
	return nil
}
