package admin

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// SessionPolicyView is the API representation of a session policy.
//
// TTLs are exposed in seconds rather than as a duration string because this is a
// machine-consumed settings API and seconds are unambiguous; a human-facing unit
// belongs in the UI, not on the wire.
type SessionPolicyView struct {
	// Scope is "platform", "tenant", or "application" — which row actually
	// answered the request. Without it a caller cannot tell a policy they have set
	// from an inherited default, and would have no way to know that editing it
	// creates a new row rather than changing an existing one.
	Scope string `json:"scope"`
	// Inherited is true when no row exists at the requested scope and these
	// values came from a broader one.
	Inherited bool `json:"inherited"`

	IdleTTLSeconds              int  `json:"idle_ttl_seconds"`
	NonPersistentIdleTTLSeconds int  `json:"non_persistent_idle_ttl_seconds"`
	AbsoluteTTLSeconds          int  `json:"absolute_ttl_seconds"`
	MaxConcurrentSessions       int  `json:"max_concurrent_sessions"`
	AllowPersistent             bool `json:"allow_persistent"`
}

// SessionPolicyInput is the writable body of a policy update. Every field is a
// pointer so an omitted field means "leave as is" rather than "set to zero" — a
// PUT that silently reset max_concurrent_sessions to 0 because the caller only
// wanted to change the idle timeout would be a very expensive surprise.
type SessionPolicyInput struct {
	IdleTTLSeconds              *int  `json:"idle_ttl_seconds"`
	NonPersistentIdleTTLSeconds *int  `json:"non_persistent_idle_ttl_seconds"`
	AbsoluteTTLSeconds          *int  `json:"absolute_ttl_seconds"`
	MaxConcurrentSessions       *int  `json:"max_concurrent_sessions"`
	AllowPersistent             *bool `json:"allow_persistent"`
}

// Policy bounds, mirrored from the CHECK constraints in migration 00067.
//
// Duplicated in Go so the caller gets a readable 400 naming the offending field
// instead of a 500 wrapping a constraint-violation string. The database keeps its
// own copy because the table is also reachable by hand during incident response,
// and that is exactly when a mistyped value does the most damage.
const (
	minTTLSeconds         = 60
	minAbsoluteTTLSeconds = 300
	maxTTLSeconds         = 90 * 24 * 3600
	minSessionCap         = 1
	maxSessionCap         = 1000
)

// ErrInvalidSessionPolicy is returned when a policy update violates its bounds.
var ErrInvalidSessionPolicy = errors.New("invalid session policy")

// GetSessionPolicy returns the policy in force at the given scope, reporting
// whether it was inherited from a broader one.
func (s *Service) GetSessionPolicy(ctx context.Context, tenantID int64, applicationID *int64) (*SessionPolicyView, error) {
	var view SessionPolicyView
	var rowTenant, rowApp *int64

	err := s.pool.QueryRow(ctx, `
		SELECT tenant_id, application_id, idle_ttl_seconds, non_persistent_idle_ttl_seconds,
		       absolute_ttl_seconds, max_concurrent_sessions, allow_persistent
		FROM session_policies
		WHERE (application_id = $2 AND tenant_id = $1)
		   OR (application_id IS NULL AND tenant_id = $1)
		   OR (application_id IS NULL AND tenant_id IS NULL)
		ORDER BY application_id NULLS LAST, tenant_id NULLS LAST
		LIMIT 1
	`, tenantID, applicationID).Scan(&rowTenant, &rowApp,
		&view.IdleTTLSeconds, &view.NonPersistentIdleTTLSeconds,
		&view.AbsoluteTTLSeconds, &view.MaxConcurrentSessions, &view.AllowPersistent)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// The platform default is seeded by migration 00067; its absence means
			// somebody deleted it. Report the compiled-in defaults, which are what
			// the auth service is also falling back to, so the API and the running
			// behaviour agree.
			return platformFallbackView(), nil
		}
		return nil, fmt.Errorf("get session policy: %w", err)
	}

	switch {
	case rowApp != nil:
		view.Scope = "application"
	case rowTenant != nil:
		view.Scope = "tenant"
	default:
		view.Scope = "platform"
	}
	// Inherited when the answering row is broader than what was asked for.
	view.Inherited = (applicationID != nil && rowApp == nil) || rowTenant == nil
	return &view, nil
}

// platformFallbackView renders auth.DefaultSessionPolicy as an API response.
func platformFallbackView() *SessionPolicyView {
	d := auth.DefaultSessionPolicy
	return &SessionPolicyView{
		Scope:                       "platform",
		Inherited:                   true,
		IdleTTLSeconds:              int(d.IdleTTL.Seconds()),
		NonPersistentIdleTTLSeconds: int(d.NonPersistentIdleTTL.Seconds()),
		AbsoluteTTLSeconds:          int(d.AbsoluteTTL.Seconds()),
		MaxConcurrentSessions:       d.MaxConcurrentSessions,
		AllowPersistent:             d.AllowPersistent,
	}
}

// SetSessionPolicy creates or updates the policy at the given scope.
//
// Reads the currently effective policy first and applies the caller's partial
// input on top, so a PUT that sets one field inherits the rest from what was
// actually in force rather than from compiled-in defaults. Without that, setting
// a tenant's idle timeout would silently reset its session cap to the platform
// value — a change the caller never asked for and would not see in their own
// request body.
func (s *Service) SetSessionPolicy(ctx context.Context, tenantID int64, applicationID *int64, in SessionPolicyInput) (*SessionPolicyView, error) {
	current, err := s.GetSessionPolicy(ctx, tenantID, applicationID)
	if err != nil {
		return nil, err
	}

	next := *current
	if in.IdleTTLSeconds != nil {
		next.IdleTTLSeconds = *in.IdleTTLSeconds
	}
	if in.NonPersistentIdleTTLSeconds != nil {
		next.NonPersistentIdleTTLSeconds = *in.NonPersistentIdleTTLSeconds
	}
	if in.AbsoluteTTLSeconds != nil {
		next.AbsoluteTTLSeconds = *in.AbsoluteTTLSeconds
	}
	if in.MaxConcurrentSessions != nil {
		next.MaxConcurrentSessions = *in.MaxConcurrentSessions
	}
	if in.AllowPersistent != nil {
		next.AllowPersistent = *in.AllowPersistent
	}

	if err := validateSessionPolicy(next); err != nil {
		return nil, err
	}

	// ON CONFLICT cannot be used here: the uniqueness of a scope is expressed by
	// three partial indexes (see migration 00067), and ON CONFLICT requires a
	// single named constraint or index. An UPDATE-then-INSERT under the caller's
	// transaction is the portable equivalent; concurrent writes to the same scope
	// are settled by the partial unique index, which turns the loser into an error
	// rather than a duplicate row.
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin session policy tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	ct, err := tx.Exec(ctx, `
		UPDATE session_policies
		SET idle_ttl_seconds = $3, non_persistent_idle_ttl_seconds = $4,
		    absolute_ttl_seconds = $5, max_concurrent_sessions = $6,
		    allow_persistent = $7, updated_at = NOW()
		WHERE tenant_id = $1 AND application_id IS NOT DISTINCT FROM $2
	`, tenantID, applicationID, next.IdleTTLSeconds, next.NonPersistentIdleTTLSeconds,
		next.AbsoluteTTLSeconds, next.MaxConcurrentSessions, next.AllowPersistent)
	if err != nil {
		return nil, fmt.Errorf("update session policy: %w", err)
	}
	if ct.RowsAffected() == 0 {
		if _, err := tx.Exec(ctx, `
			INSERT INTO session_policies
			    (tenant_id, application_id, idle_ttl_seconds, non_persistent_idle_ttl_seconds,
			     absolute_ttl_seconds, max_concurrent_sessions, allow_persistent)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
		`, tenantID, applicationID, next.IdleTTLSeconds, next.NonPersistentIdleTTLSeconds,
			next.AbsoluteTTLSeconds, next.MaxConcurrentSessions, next.AllowPersistent); err != nil {
			return nil, fmt.Errorf("insert session policy: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit session policy: %w", err)
	}

	// Drop the resolver's cache immediately. Waiting out the cache TTL would be
	// acceptable for a routine change but not for the case that matters: an
	// operator tightening session lifetimes during an incident needs the new value
	// to apply to the next refresh, not the one after the cache expires.
	s.invalidatePolicyCache()

	next.Inherited = false
	if applicationID != nil {
		next.Scope = "application"
	} else {
		next.Scope = "tenant"
	}
	return &next, nil
}

// DeleteSessionPolicy removes the policy row at the given scope so the scope
// inherits again. Returns ErrNotFound when there was nothing to delete —
// distinguishable from success because "you had no override" and "your override
// is gone" mean different things to a caller reconciling desired state.
func (s *Service) DeleteSessionPolicy(ctx context.Context, tenantID int64, applicationID *int64) error {
	ct, err := s.pool.Exec(ctx, `
		DELETE FROM session_policies
		WHERE tenant_id = $1 AND application_id IS NOT DISTINCT FROM $2
	`, tenantID, applicationID)
	if err != nil {
		return fmt.Errorf("delete session policy: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	s.invalidatePolicyCache()
	return nil
}

// invalidatePolicyCache clears the auth service's resolver cache when one is
// wired. A nil auth service is not an error — see Service.authSvc — but it does
// mean policy changes take up to policyCacheTTL to apply.
func (s *Service) invalidatePolicyCache() {
	if s.authSvc == nil {
		return
	}
	s.authSvc.SessionPolicy().InvalidateCache()
}

// validateSessionPolicy enforces the same bounds as the table's CHECK
// constraints, naming the offending field.
func validateSessionPolicy(p SessionPolicyView) error {
	switch {
	case p.IdleTTLSeconds < minTTLSeconds || p.IdleTTLSeconds > maxTTLSeconds:
		return fmt.Errorf("%w: idle_ttl_seconds must be between %d and %d",
			ErrInvalidSessionPolicy, minTTLSeconds, maxTTLSeconds)
	case p.NonPersistentIdleTTLSeconds < minTTLSeconds || p.NonPersistentIdleTTLSeconds > maxTTLSeconds:
		return fmt.Errorf("%w: non_persistent_idle_ttl_seconds must be between %d and %d",
			ErrInvalidSessionPolicy, minTTLSeconds, maxTTLSeconds)
	case p.AbsoluteTTLSeconds < minAbsoluteTTLSeconds || p.AbsoluteTTLSeconds > maxTTLSeconds:
		return fmt.Errorf("%w: absolute_ttl_seconds must be between %d and %d",
			ErrInvalidSessionPolicy, minAbsoluteTTLSeconds, maxTTLSeconds)
	case p.MaxConcurrentSessions < minSessionCap || p.MaxConcurrentSessions > maxSessionCap:
		return fmt.Errorf("%w: max_concurrent_sessions must be between %d and %d",
			ErrInvalidSessionPolicy, minSessionCap, maxSessionCap)
	// An idle clock longer than the absolute cap can never fire, which would
	// quietly restore the unbounded-session behaviour the idle clock exists to
	// fix. Rejected rather than clamped: silently altering a number the operator
	// typed is how a policy comes to differ from what the console displays.
	case p.IdleTTLSeconds > p.AbsoluteTTLSeconds:
		return fmt.Errorf("%w: idle_ttl_seconds cannot exceed absolute_ttl_seconds", ErrInvalidSessionPolicy)
	case p.NonPersistentIdleTTLSeconds > p.AbsoluteTTLSeconds:
		return fmt.Errorf("%w: non_persistent_idle_ttl_seconds cannot exceed absolute_ttl_seconds", ErrInvalidSessionPolicy)
	}
	return nil
}
