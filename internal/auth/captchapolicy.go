package auth

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"golang.org/x/sync/singleflight"
)

// ---------------------------------------------------------------------------
// CAPTCHA policy — per-tenant and per-application configuration (issue #145).
//
// Two questions live here and they are the same decision: WHETHER a captcha is
// demanded at all, and WHAT it looks like when it is. Keeping them together is
// what lets the gate answer "does this request need a challenge, and if so with
// which parameters" from one cached read on the login path.
//
// See migration 00090 for the table and for why the platform default is off.
// ---------------------------------------------------------------------------

// CaptchaFlow names an authentication flow the gate can protect. The values are
// the strings stored in captcha_policies.protected_flows, so they are part of
// the admin API contract and must not be renamed without a migration.
type CaptchaFlow string

const (
	// CaptchaFlowLogin covers POST /auth/login and POST /auth/apps/login.
	CaptchaFlowLogin CaptchaFlow = "login"
	// CaptchaFlowSession covers POST /auth/session — the admin console's own
	// sign-in. It is a separate flow from login because it is a separate
	// endpoint: the console posts here so credentials land in HttpOnly cookies
	// rather than in a response body, and gating only "login" would leave the
	// door holding the super-admin accounts open.
	CaptchaFlowSession CaptchaFlow = "session"
	// CaptchaFlowLoginOTP covers POST /auth/login/otp, where a brute-forcer
	// moves once the password step is gated.
	CaptchaFlowLoginOTP CaptchaFlow = "login_otp"
	// CaptchaFlowRegister covers POST /auth/register and /auth/apps/register.
	CaptchaFlowRegister CaptchaFlow = "register"
	// CaptchaFlowForgotPassword covers POST /auth/forgot-password.
	CaptchaFlowForgotPassword CaptchaFlow = "forgot_password"
)

// ValidCaptchaFlows is every flow the gate understands. A policy naming anything
// outside this set is rejected at the admin API rather than silently ignored: a
// typo'd flow name would otherwise read as configured protection that does not
// exist.
var ValidCaptchaFlows = []CaptchaFlow{
	CaptchaFlowLogin,
	CaptchaFlowSession,
	CaptchaFlowLoginOTP,
	CaptchaFlowRegister,
	CaptchaFlowForgotPassword,
}

// IsValidCaptchaFlow reports whether name is a flow the gate can enforce.
func IsValidCaptchaFlow(name string) bool {
	for _, f := range ValidCaptchaFlows {
		if string(f) == name {
			return true
		}
	}
	return false
}

// Captcha modes. See migration 00090 for why adaptive is the default.
const (
	// CaptchaModeAdaptive demands a challenge only after repeated failures from
	// the same origin.
	CaptchaModeAdaptive = "adaptive"
	// CaptchaModeAlways demands a challenge on every attempt.
	CaptchaModeAlways = "always"
)

// Noise levels, in rendering order of severity.
const (
	CaptchaNoiseLow    = "low"
	CaptchaNoiseMedium = "medium"
	CaptchaNoiseHigh   = "high"
)

// CaptchaProviderInternal is the only provider implemented. The column exists so
// that adding a hosted provider later does not require a migration against a
// live table.
const CaptchaProviderInternal = "internal"

// CaptchaPolicy is the resolved, ready-to-use policy for one scope. Every field
// is already merged, so a caller never has to decide whether a zero value means
// "inherit" — that is resolved here, once.
//
// Every field is tagged because this type is embedded as `effective` in the
// admin API response; untagged fields would ship Go identifiers on the wire
// instead of the snake_case names the console reads.
type CaptchaPolicy struct {
	// Enabled is the master switch. False short-circuits the gate before it does
	// any work.
	Enabled bool `json:"enabled"`
	// Provider names the implementation. Only CaptchaProviderInternal today.
	Provider string `json:"provider"`
	// Mode is CaptchaModeAdaptive or CaptchaModeAlways.
	Mode string `json:"mode"`
	// ProtectedFlows is the set of flows the gate applies to.
	ProtectedFlows []string `json:"protected_flows"`
	// TriggerAfterFailures is how many failures from one origin inside
	// FailureWindow arm the gate. Only consulted in adaptive mode.
	TriggerAfterFailures int `json:"trigger_after_failures"`
	// FailureWindow is how long a failure counts toward the trigger.
	FailureWindow time.Duration `json:"-"`
	// FailureWindowSeconds is FailureWindow on the wire.
	FailureWindowSeconds int `json:"failure_window_seconds"`
	// CodeLength is the number of characters in a challenge.
	CodeLength int `json:"code_length"`
	// CaseSensitive requires the typed answer to match case.
	CaseSensitive bool `json:"case_sensitive"`
	// TTL is how long a challenge stays solvable.
	TTL time.Duration `json:"-"`
	// TTLSeconds is TTL on the wire.
	TTLSeconds int `json:"ttl_seconds"`
	// MaxAttemptsPerChallenge is how many answers one challenge accepts before
	// it is burned.
	MaxAttemptsPerChallenge int `json:"max_attempts_per_challenge"`
	// NoiseLevel is the distortion strength.
	NoiseLevel string `json:"noise_level"`
	// Source records which row won resolution — "application", "tenant",
	// "platform", or "default" when no row matched at all. An operator debugging
	// "why is a captcha appearing here" needs that answer first, which is why it
	// is on the ADMIN response; it is never part of an end-user payload.
	Source string `json:"source"`
}

// Protects reports whether the policy is on and covers the given flow.
//
// One method rather than two checks at each call site: forgetting the Enabled
// half would turn a disabled policy's leftover flow list into live enforcement.
func (p CaptchaPolicy) Protects(flow CaptchaFlow) bool {
	if !p.Enabled {
		return false
	}
	for _, f := range p.ProtectedFlows {
		if f == string(flow) {
			return true
		}
	}
	return false
}

// DefaultCaptchaPolicy mirrors the platform-default row seeded by migration
// 00090. It is the value used when the policy table cannot be read — see
// CaptchaPolicyService.Resolve for why that degrades to a default rather than
// failing the request.
//
// Enabled is false, which is what makes the degraded path safe: an unreadable
// settings table cannot accidentally start demanding captchas nobody can obtain.
var DefaultCaptchaPolicy = CaptchaPolicy{
	Enabled:                 false,
	Provider:                CaptchaProviderInternal,
	Mode:                    CaptchaModeAdaptive,
	ProtectedFlows:          []string{"login", "session", "login_otp", "register", "forgot_password"},
	TriggerAfterFailures:    2,
	FailureWindow:           15 * time.Minute,
	FailureWindowSeconds:    900,
	CodeLength:              6,
	CaseSensitive:           false,
	TTL:                     2 * time.Minute,
	TTLSeconds:              120,
	MaxAttemptsPerChallenge: 1,
	NoiseLevel:              CaptchaNoiseMedium,
	Source:                  "default",
}

// CaptchaPolicyService resolves and caches captcha policy.
//
// Resolution is most-specific-wins: an application row, else the tenant row,
// else the platform default. Cached because Resolve sits on the failure path of
// every login attempt — precisely the path an attacker drives hardest — and an
// uncached lookup would let a brute-force attempt double as a load amplifier
// against the policy table.
type CaptchaPolicyService struct {
	pool   *pgxpool.Pool
	logger zerolog.Logger

	mu    sync.RWMutex
	cache map[captchaPolicyKey]cachedCaptchaPolicy
	ttl   time.Duration

	// reload collapses concurrent misses on the same scope into one query.
	//
	// Without it, InvalidateCache — which replaces the WHOLE cross-tenant map on
	// any single admin write, at any scope — left every scope cold at once, and
	// the next burst of login/register/otp/forgot-password traffic across all
	// tenants each issued its own SELECT. That is a stampede against the policy
	// table on the authentication hot path, triggered by one operator toggling
	// one unrelated tenant's setting. Reported on PR #147.
	reload singleflight.Group
}

type captchaPolicyKey struct {
	tenantID      int64
	applicationID int64 // 0 = no application scope
}

type cachedCaptchaPolicy struct {
	policy   CaptchaPolicy
	cachedAt time.Time
}

// captchaPolicyCacheTTL is how long a resolved policy is reused. Short enough
// that an operator turning the feature off during an incident — because it is
// misbehaving and blocking real users — sees it take effect while they are still
// looking at the screen.
const captchaPolicyCacheTTL = 60 * time.Second

// NewCaptchaPolicyService creates a captcha-policy resolver over the given pool.
func NewCaptchaPolicyService(pool *pgxpool.Pool, logger zerolog.Logger) *CaptchaPolicyService {
	return &CaptchaPolicyService{
		pool:   pool,
		logger: logger,
		cache:  make(map[captchaPolicyKey]cachedCaptchaPolicy),
		ttl:    captchaPolicyCacheTTL,
	}
}

// Resolve returns the policy in force for the given scope. applicationID may be
// nil for tenant-level callers.
//
// Never returns an error. A lookup failure falls back to DefaultCaptchaPolicy
// and logs at warn: this sits on the authentication path, and the fallback is
// "feature off", so the failure mode is losing a speed bump rather than refusing
// to authenticate anybody because a settings table is briefly unreadable.
func (s *CaptchaPolicyService) Resolve(ctx context.Context, tenantID int64, applicationID *int64) CaptchaPolicy {
	if s == nil {
		return DefaultCaptchaPolicy
	}

	key := captchaPolicyKey{tenantID: tenantID}
	if applicationID != nil {
		key.applicationID = *applicationID
	}

	// Cache before the pool check, not after. A cached policy is a resolved
	// answer and stays valid whether or not the pool is currently usable — and
	// consulting it first means a database that has gone away degrades to
	// "serve the last known policy until the entry ages out" rather than to
	// "revert every scope to platform defaults immediately".
	s.mu.RLock()
	entry, ok := s.cache[key]
	s.mu.RUnlock()
	if ok && time.Since(entry.cachedAt) < s.ttl {
		return entry.policy
	}

	if s.pool == nil {
		return DefaultCaptchaPolicy
	}

	// One query per scope per miss, however many callers arrive at once. The
	// followers block on the leader's result rather than each opening their own
	// — which is the whole point, because the callers here are concurrent login
	// attempts and the miss is usually cache-wide (see the reload field).
	//
	// The cache is written inside the shared function, so the followers do not
	// each re-take the write lock to store the same value.
	cacheKey := fmt.Sprintf("%d:%d", key.tenantID, key.applicationID)
	res, err, _ := s.reload.Do(cacheKey, func() (any, error) {
		policy, lErr := s.load(ctx, tenantID, applicationID)
		if lErr != nil {
			return nil, lErr
		}
		s.mu.Lock()
		s.cache[key] = cachedCaptchaPolicy{policy: policy, cachedAt: time.Now()}
		s.mu.Unlock()
		return policy, nil
	})
	if err != nil {
		s.logger.Warn().Err(err).
			Int64("tenant_id", tenantID).
			Msg("captcha policy: resolve failed, using platform defaults")
		return DefaultCaptchaPolicy
	}
	return res.(CaptchaPolicy)
}

// CaptchaPolicyResolveSQL is the "most-specific-wins" precedence query —
// application row, else tenant row, else the platform default — shared by the
// runtime resolver here and by the admin read path in internal/admin.
//
// Shared rather than written twice, because the two copies had already started
// to drift: this side derives Source from the returned ids while the admin side
// derives Scope and Inherited from the same shape, independently. A precedence
// change applied to one and missed in the other would let the console's
// "effective policy" disagree with what the gate actually enforces — a
// disagreement that shows up as a captcha appearing where the UI says it should
// not, with nothing in either file to explain it. Reported on PR #147.
//
// Parameters are $1 = tenant_id, $2 = application_id (nullable), in that order.
// Column order is part of the contract: both call sites Scan positionally.
const CaptchaPolicyResolveSQL = `
		SELECT tenant_id, application_id, enabled, provider, mode, protected_flows,
		       trigger_after_failures, failure_window_seconds, code_length,
		       case_sensitive, ttl_seconds, max_attempts_per_challenge, noise_level
		FROM captcha_policies
		WHERE (application_id = $2 AND tenant_id = $1)
		   OR (application_id IS NULL AND tenant_id = $1)
		   OR (application_id IS NULL AND tenant_id IS NULL)
		ORDER BY application_id NULLS LAST, tenant_id NULLS LAST
		LIMIT 1
	`

// load reads the most specific matching policy row.
//
// ORDER BY places the application row first, then the tenant row, then the
// platform default, and LIMIT 1 takes the winner — one indexed query instead of
// up to three round trips.
func (s *CaptchaPolicyService) load(ctx context.Context, tenantID int64, applicationID *int64) (CaptchaPolicy, error) {
	var p CaptchaPolicy
	var rowTenant, rowApp *int64
	var windowSecs, ttlSecs int

	err := s.pool.QueryRow(ctx, CaptchaPolicyResolveSQL, tenantID, applicationID).Scan(
		&rowTenant, &rowApp, &p.Enabled, &p.Provider, &p.Mode, &p.ProtectedFlows,
		&p.TriggerAfterFailures, &windowSecs, &p.CodeLength,
		&p.CaseSensitive, &ttlSecs, &p.MaxAttemptsPerChallenge, &p.NoiseLevel)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// The platform-default row is seeded by migration 00090, so this
			// means somebody deleted it. Defaults still apply; say so loudly
			// rather than inventing a policy silently.
			return DefaultCaptchaPolicy, fmt.Errorf("no captcha policy row matched (platform default missing?)")
		}
		return DefaultCaptchaPolicy, fmt.Errorf("load captcha policy: %w", err)
	}

	p.FailureWindowSeconds = windowSecs
	p.FailureWindow = time.Duration(windowSecs) * time.Second
	p.TTLSeconds = ttlSecs
	p.TTL = time.Duration(ttlSecs) * time.Second

	switch {
	case rowApp != nil:
		p.Source = "application"
	case rowTenant != nil:
		p.Source = "tenant"
	default:
		p.Source = "platform"
	}
	return p, nil
}

// InvalidateCache drops cached policy for every scope. Called by the admin write
// path so an operator who changes a setting does not have to wait out
// captchaPolicyCacheTTL to see it — and, more importantly, so turning the
// feature OFF because it is blocking real users takes effect immediately.
//
// Drops the whole cache rather than one key: a tenant-level change affects every
// application key under that tenant, and the set of those keys is not tracked.
func (s *CaptchaPolicyService) InvalidateCache() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.cache = make(map[captchaPolicyKey]cachedCaptchaPolicy)
	s.mu.Unlock()
}

// NewStaticCaptchaPolicyService returns a resolver that answers every scope with
// the same policy, bypassing the database.
//
// Exported for tests that need a captcha service without a Postgres pool — the
// gate's behaviour is worth testing on its own, and standing up a database to
// assert "a disabled policy refuses nothing" is disproportionate. It is not used
// by the server: RegisterRoutes always builds the real resolver.
func NewStaticCaptchaPolicyService(p CaptchaPolicy) *CaptchaPolicyService {
	s := &CaptchaPolicyService{
		cache: make(map[captchaPolicyKey]cachedCaptchaPolicy),
		// Far enough out that no test can age an entry out mid-run.
		ttl: 24 * time.Hour,
	}
	s.cache[captchaPolicyKey{}] = cachedCaptchaPolicy{policy: p, cachedAt: time.Now()}
	return s
}
