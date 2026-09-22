package admin

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// ---------------------------------------------------------------------------
// Admin: CAPTCHA policy (issue #145).
//
// Same shape as the lockout and session policy families — most-specific-wins
// resolution, partial updates, DELETE meaning "revert to inherit". See
// migration 00090 for the table.
// ---------------------------------------------------------------------------

// CaptchaPolicyView is the API representation of a captcha policy.
type CaptchaPolicyView struct {
	// Scope is "platform", "tenant", or "application" — which row actually
	// answered. Without it a caller cannot tell a policy they set from an
	// inherited default, and would have no way to know that editing it creates a
	// new row rather than changing an existing one.
	Scope string `json:"scope"`
	// Inherited is true when no row exists at the requested scope and these
	// values came from a broader one.
	//
	// The console renders "Reset to inherited" (a DELETE) next to "Off" (enabled
	// = false), and they do opposite things. This field is what lets it tell
	// them apart.
	Inherited bool `json:"inherited"`

	Enabled                 bool     `json:"enabled"`
	Provider                string   `json:"provider"`
	Mode                    string   `json:"mode"`
	ProtectedFlows          []string `json:"protected_flows"`
	TriggerAfterFailures    int      `json:"trigger_after_failures"`
	FailureWindowSeconds    int      `json:"failure_window_seconds"`
	CodeLength              int      `json:"code_length"`
	CaseSensitive           bool     `json:"case_sensitive"`
	TTLSeconds              int      `json:"ttl_seconds"`
	MaxAttemptsPerChallenge int      `json:"max_attempts_per_challenge"`
	NoiseLevel              string   `json:"noise_level"`
}

// CaptchaPolicyInput is the writable body of a policy update.
//
// Every field is a pointer so an omitted field means "leave as is" rather than
// "set to zero". Without that, a console sending its whole form to change one
// setting would write every inherited value as an identical explicit override —
// nothing would look wrong until somebody changed the tenant policy and this
// application quietly did not follow.
type CaptchaPolicyInput struct {
	Enabled                 *bool     `json:"enabled"`
	Mode                    *string   `json:"mode"`
	ProtectedFlows          *[]string `json:"protected_flows"`
	TriggerAfterFailures    *int      `json:"trigger_after_failures"`
	FailureWindowSeconds    *int      `json:"failure_window_seconds"`
	CodeLength              *int      `json:"code_length"`
	CaseSensitive           *bool     `json:"case_sensitive"`
	TTLSeconds              *int      `json:"ttl_seconds"`
	MaxAttemptsPerChallenge *int      `json:"max_attempts_per_challenge"`
	NoiseLevel              *string   `json:"noise_level"`

	// Provider is deliberately absent. Only 'internal' is implemented, so
	// accepting the field would let a tenant set a value that silently does
	// nothing — or, worse, that looks like third-party bot protection is in force
	// when no such code path exists.
}

// Policy bounds, mirrored from the CHECK constraints in migration 00090.
//
// Duplicated in Go so the caller gets a readable 400 naming the offending field
// instead of a 500 wrapping a constraint-violation string. The database keeps
// its own copy because the table is reachable by hand during support work, which
// is exactly when a mistyped value does the most damage.
const (
	minCaptchaTrigger    = 1
	maxCaptchaTrigger    = 100
	minCaptchaWindowSecs = 60
	maxCaptchaWindowSecs = 86400
	minCaptchaCodeLength = 4
	maxCaptchaCodeLength = 8
	minCaptchaTTLSecs    = 30
	maxCaptchaTTLSecs    = 600
	minCaptchaAttempts   = 1
	maxCaptchaAttempts   = 5
)

// ErrInvalidCaptchaPolicy is returned when a policy update violates its bounds.
var ErrInvalidCaptchaPolicy = errors.New("invalid captcha policy")

// GetCaptchaPolicy returns the policy in force at the given scope, reporting
// whether it was inherited from a broader one.
func (s *Service) GetCaptchaPolicy(ctx context.Context, tenantID int64, applicationID *int64) (*CaptchaPolicyView, error) {
	var view CaptchaPolicyView
	var rowTenant, rowApp *int64

	// Shared with the runtime resolver — see auth.CaptchaPolicyResolveSQL for
	// why this precedence rule lives in exactly one place.
	err := s.pool.QueryRow(ctx, auth.CaptchaPolicyResolveSQL, tenantID, applicationID).Scan(&rowTenant, &rowApp,
		&view.Enabled, &view.Provider, &view.Mode, &view.ProtectedFlows,
		&view.TriggerAfterFailures, &view.FailureWindowSeconds, &view.CodeLength,
		&view.CaseSensitive, &view.TTLSeconds, &view.MaxAttemptsPerChallenge,
		&view.NoiseLevel)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// The platform default is seeded by migration 00090; its absence means
			// somebody deleted it. Report the compiled-in defaults, which are what
			// the captcha service is also falling back to, so the API and the
			// running behaviour agree.
			return platformFallbackCaptchaView(), nil
		}
		return nil, fmt.Errorf("get captcha policy: %w", err)
	}

	switch {
	case rowApp != nil:
		view.Scope = "application"
	case rowTenant != nil:
		view.Scope = "tenant"
	default:
		view.Scope = "platform"
	}
	// Inherited means "no row exists at the scope that was ASKED FOR", which is
	// what tells the console whether editing creates a row and whether a
	// "reset to inherited" DELETE has anything to remove.
	//
	// The old one-liner — (applicationID != nil && rowApp == nil) || rowTenant == nil
	// — got the platform scope wrong. A platform request has rowTenant nil by
	// definition (the row's tenant_id IS NULL), so the second clause always fired
	// and GET /platform/captcha-policy reported inherited: true for a row that
	// plainly exists and has no DELETE endpoint at all. The console renders
	// "Reset to inherited" off this field, so it would have offered to remove
	// something unremovable. Reported by Copilot on PR #147; the symptom was
	// visible in a manual run before anyone read the formula.
	switch {
	case applicationID != nil:
		// Application scope: inherited unless an application row answered.
		view.Inherited = rowApp == nil
	case tenantID != 0:
		// Tenant scope: inherited unless a tenant row answered.
		view.Inherited = rowTenant == nil
	default:
		// Platform scope. Reaching here at all means a row answered — the
		// no-rows case returned platformFallbackCaptchaView above — and that row
		// IS the requested scope, so nothing was inherited.
		view.Inherited = false
	}
	return &view, nil
}

// platformFallbackCaptchaView renders auth.DefaultCaptchaPolicy as an API
// response.
func platformFallbackCaptchaView() *CaptchaPolicyView {
	d := auth.DefaultCaptchaPolicy
	return &CaptchaPolicyView{
		Scope:                   "platform",
		Inherited:               true,
		Enabled:                 d.Enabled,
		Provider:                d.Provider,
		Mode:                    d.Mode,
		ProtectedFlows:          append([]string(nil), d.ProtectedFlows...),
		TriggerAfterFailures:    d.TriggerAfterFailures,
		FailureWindowSeconds:    d.FailureWindowSeconds,
		CodeLength:              d.CodeLength,
		CaseSensitive:           d.CaseSensitive,
		TTLSeconds:              d.TTLSeconds,
		MaxAttemptsPerChallenge: d.MaxAttemptsPerChallenge,
		NoiseLevel:              d.NoiseLevel,
	}
}

// SetCaptchaPolicy creates or updates the policy at the given scope.
//
// Reads the currently effective policy first and applies the caller's partial
// input on top, so a PUT that sets one field inherits the rest from what was
// actually in force rather than from compiled-in defaults. Without that, turning
// a captcha on for a tenant would silently reset its thresholds to platform
// values — a change the caller never asked for and would not see in their own
// request body.
func (s *Service) SetCaptchaPolicy(ctx context.Context, tenantID int64, applicationID *int64, in CaptchaPolicyInput) (*CaptchaPolicyView, error) {
	current, err := s.GetCaptchaPolicy(ctx, tenantID, applicationID)
	if err != nil {
		return nil, err
	}

	next := applyCaptchaInput(*current, in)

	if err := validateCaptchaPolicy(next); err != nil {
		return nil, err
	}

	// ON CONFLICT cannot be used here: the uniqueness of a scope is expressed by
	// three partial indexes (see migration 00090), and ON CONFLICT requires a
	// single named constraint or index. An UPDATE-then-INSERT under one
	// transaction is the portable equivalent; concurrent writes to the same scope
	// are settled by the partial unique index, which turns the loser into an
	// error rather than a duplicate row.
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin captcha policy tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	ct, err := tx.Exec(ctx, `
		UPDATE captcha_policies
		SET enabled = $3, mode = $4, protected_flows = $5,
		    trigger_after_failures = $6, failure_window_seconds = $7,
		    code_length = $8, case_sensitive = $9, ttl_seconds = $10,
		    max_attempts_per_challenge = $11, noise_level = $12, updated_at = NOW()
		WHERE tenant_id = $1 AND application_id IS NOT DISTINCT FROM $2
	`, tenantID, applicationID, next.Enabled, next.Mode, next.ProtectedFlows,
		next.TriggerAfterFailures, next.FailureWindowSeconds, next.CodeLength,
		next.CaseSensitive, next.TTLSeconds, next.MaxAttemptsPerChallenge, next.NoiseLevel)
	if err != nil {
		return nil, fmt.Errorf("update captcha policy: %w", err)
	}
	if ct.RowsAffected() == 0 {
		if _, err := tx.Exec(ctx, `
			INSERT INTO captcha_policies
			    (tenant_id, application_id, enabled, provider, mode, protected_flows,
			     trigger_after_failures, failure_window_seconds, code_length,
			     case_sensitive, ttl_seconds, max_attempts_per_challenge, noise_level)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		`, tenantID, applicationID, next.Enabled, auth.CaptchaProviderInternal, next.Mode,
			next.ProtectedFlows, next.TriggerAfterFailures, next.FailureWindowSeconds,
			next.CodeLength, next.CaseSensitive, next.TTLSeconds,
			next.MaxAttemptsPerChallenge, next.NoiseLevel); err != nil {
			return nil, fmt.Errorf("insert captcha policy: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit captcha policy: %w", err)
	}

	// Drop the resolver's cache immediately. Waiting out the cache TTL would be
	// acceptable for a routine change but not for the case that matters: an
	// operator turning the feature OFF because it is misbehaving and blocking
	// real users needs it to apply to the next request, not the one after the
	// cache expires.
	s.invalidateCaptchaCache()

	next.Inherited = false
	if applicationID != nil {
		next.Scope = "application"
	} else {
		next.Scope = "tenant"
	}
	return &next, nil
}

// DeleteCaptchaPolicy removes the policy row at the given scope so the scope
// inherits again.
//
// Returns ErrNotFound when there was nothing to delete — distinguishable from
// success because "you had no override" and "your override is gone" mean
// different things to a caller reconciling desired state, and because the
// console renders this action next to a switch that merely turns the feature
// off.
func (s *Service) DeleteCaptchaPolicy(ctx context.Context, tenantID int64, applicationID *int64) error {
	ct, err := s.pool.Exec(ctx, `
		DELETE FROM captcha_policies
		WHERE tenant_id = $1 AND application_id IS NOT DISTINCT FROM $2
	`, tenantID, applicationID)
	if err != nil {
		return fmt.Errorf("delete captcha policy: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	s.invalidateCaptchaCache()
	return nil
}

// invalidateCaptchaCache clears the resolver cache when one is wired. A nil
// service is not an error — it does mean policy changes take up to
// captchaPolicyCacheTTL to apply.
func (s *Service) invalidateCaptchaCache() {
	if s.captchaPolicy == nil {
		return
	}
	s.captchaPolicy.InvalidateCache()
}

// validateCaptchaPolicy enforces the same bounds as the table's CHECK
// constraints, naming the offending field.
func validateCaptchaPolicy(p CaptchaPolicyView) error {
	switch p.Mode {
	case auth.CaptchaModeAdaptive, auth.CaptchaModeAlways:
	default:
		return fmt.Errorf("%w: mode must be %q or %q", ErrInvalidCaptchaPolicy,
			auth.CaptchaModeAdaptive, auth.CaptchaModeAlways)
	}

	switch p.NoiseLevel {
	case auth.CaptchaNoiseLow, auth.CaptchaNoiseMedium, auth.CaptchaNoiseHigh:
	default:
		return fmt.Errorf("%w: noise_level must be one of low, medium, high", ErrInvalidCaptchaPolicy)
	}

	// An unknown flow name is rejected rather than ignored. Silently dropping a
	// typo'd flow would leave an operator looking at a policy that says it
	// protects sign-up while nothing does.
	for _, f := range p.ProtectedFlows {
		if !auth.IsValidCaptchaFlow(f) {
			return fmt.Errorf("%w: protected_flows contains unknown flow %q", ErrInvalidCaptchaPolicy, f)
		}
	}
	// Mirrors the captcha_policies_flows_not_empty CHECK. Enabled with no flows
	// is a policy that says "on" and does nothing.
	if p.Enabled && len(p.ProtectedFlows) == 0 {
		return fmt.Errorf("%w: protected_flows must not be empty when enabled", ErrInvalidCaptchaPolicy)
	}

	if p.TriggerAfterFailures < minCaptchaTrigger || p.TriggerAfterFailures > maxCaptchaTrigger {
		return fmt.Errorf("%w: trigger_after_failures must be between %d and %d",
			ErrInvalidCaptchaPolicy, minCaptchaTrigger, maxCaptchaTrigger)
	}
	if p.FailureWindowSeconds < minCaptchaWindowSecs || p.FailureWindowSeconds > maxCaptchaWindowSecs {
		return fmt.Errorf("%w: failure_window_seconds must be between %d and %d",
			ErrInvalidCaptchaPolicy, minCaptchaWindowSecs, maxCaptchaWindowSecs)
	}
	if p.CodeLength < minCaptchaCodeLength || p.CodeLength > maxCaptchaCodeLength {
		return fmt.Errorf("%w: code_length must be between %d and %d",
			ErrInvalidCaptchaPolicy, minCaptchaCodeLength, maxCaptchaCodeLength)
	}
	if p.TTLSeconds < minCaptchaTTLSecs || p.TTLSeconds > maxCaptchaTTLSecs {
		return fmt.Errorf("%w: ttl_seconds must be between %d and %d",
			ErrInvalidCaptchaPolicy, minCaptchaTTLSecs, maxCaptchaTTLSecs)
	}
	if p.MaxAttemptsPerChallenge < minCaptchaAttempts || p.MaxAttemptsPerChallenge > maxCaptchaAttempts {
		return fmt.Errorf("%w: max_attempts_per_challenge must be between %d and %d",
			ErrInvalidCaptchaPolicy, minCaptchaAttempts, maxCaptchaAttempts)
	}
	return nil
}

// SetPlatformCaptchaPolicy updates the platform-default row (tenant_id NULL).
//
// Separate from SetCaptchaPolicy because that one keys on a tenant and the
// platform row has none: tenant_id NULL never matches tenant_id = $1, so the
// tenant path cannot reach this row however it is called. Keeping them apart
// also means a tenant-scoped handler cannot be talked into writing the platform
// row by passing a zero tenant id.
//
// There is no platform DELETE. The row is seeded by migration 00090 and every
// scope terminates resolution on it; removing it would make resolution come up
// empty and push each caller onto a compiled-in fallback. Disable it with
// enabled=false instead.
func (s *Service) SetPlatformCaptchaPolicy(ctx context.Context, in CaptchaPolicyInput) (*CaptchaPolicyView, error) {
	current, err := s.GetCaptchaPolicy(ctx, 0, nil)
	if err != nil {
		return nil, err
	}

	next := applyCaptchaInput(*current, in)
	if err := validateCaptchaPolicy(next); err != nil {
		return nil, err
	}

	// UPDATE-then-INSERT inside one transaction, matching SetCaptchaPolicy.
	//
	// The unique index on the platform row (migration 00090,
	// captcha_policies_platform_default) already means a lost race surfaces as a
	// clean 23505 rather than a duplicate row, and with no platform DELETE the
	// RowsAffected == 0 branch is unreachable today. The transaction is here so
	// the two near-identical writers do not rely on different guarantees — if a
	// platform delete is ever added, this becomes a live race, and the cheap
	// moment to close it is now rather than under time pressure. Raised on PR #147.
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin platform captcha policy update: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	ct, err := tx.Exec(ctx, `
		UPDATE captcha_policies
		SET enabled = $1, mode = $2, protected_flows = $3,
		    trigger_after_failures = $4, failure_window_seconds = $5,
		    code_length = $6, case_sensitive = $7, ttl_seconds = $8,
		    max_attempts_per_challenge = $9, noise_level = $10, updated_at = NOW()
		WHERE tenant_id IS NULL AND application_id IS NULL
	`, next.Enabled, next.Mode, next.ProtectedFlows, next.TriggerAfterFailures,
		next.FailureWindowSeconds, next.CodeLength, next.CaseSensitive,
		next.TTLSeconds, next.MaxAttemptsPerChallenge, next.NoiseLevel)
	if err != nil {
		return nil, fmt.Errorf("update platform captcha policy: %w", err)
	}
	if ct.RowsAffected() == 0 {
		// The seeded row is gone. Re-create it rather than failing: resolution
		// for every scope ends here, so its absence is worse than any value it
		// could hold.
		if _, err := tx.Exec(ctx, `
			INSERT INTO captcha_policies
			    (tenant_id, application_id, enabled, provider, mode, protected_flows,
			     trigger_after_failures, failure_window_seconds, code_length,
			     case_sensitive, ttl_seconds, max_attempts_per_challenge, noise_level)
			VALUES (NULL, NULL, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		`, next.Enabled, auth.CaptchaProviderInternal, next.Mode, next.ProtectedFlows,
			next.TriggerAfterFailures, next.FailureWindowSeconds, next.CodeLength,
			next.CaseSensitive, next.TTLSeconds, next.MaxAttemptsPerChallenge,
			next.NoiseLevel); err != nil {
			return nil, fmt.Errorf("recreate platform captcha policy: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit platform captcha policy update: %w", err)
	}

	s.invalidateCaptchaCache()
	next.Scope = "platform"
	next.Inherited = false
	return &next, nil
}

// applyCaptchaInput layers a partial update onto a resolved policy.
//
// Shared by the tenant and platform writers so the "omitted means leave alone"
// rule is implemented once. Two copies would be two places for the
// partial-update contract to drift, and the drift would be silent.
func applyCaptchaInput(next CaptchaPolicyView, in CaptchaPolicyInput) CaptchaPolicyView {
	if in.Enabled != nil {
		next.Enabled = *in.Enabled
	}
	if in.Mode != nil {
		next.Mode = *in.Mode
	}
	if in.ProtectedFlows != nil {
		next.ProtectedFlows = append([]string(nil), (*in.ProtectedFlows)...)
	}
	if in.TriggerAfterFailures != nil {
		next.TriggerAfterFailures = *in.TriggerAfterFailures
	}
	if in.FailureWindowSeconds != nil {
		next.FailureWindowSeconds = *in.FailureWindowSeconds
	}
	if in.CodeLength != nil {
		next.CodeLength = *in.CodeLength
	}
	if in.CaseSensitive != nil {
		next.CaseSensitive = *in.CaseSensitive
	}
	if in.TTLSeconds != nil {
		next.TTLSeconds = *in.TTLSeconds
	}
	if in.MaxAttemptsPerChallenge != nil {
		next.MaxAttemptsPerChallenge = *in.MaxAttemptsPerChallenge
	}
	if in.NoiseLevel != nil {
		next.NoiseLevel = *in.NoiseLevel
	}
	next.Provider = auth.CaptchaProviderInternal
	return next
}
