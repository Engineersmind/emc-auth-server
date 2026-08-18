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
)

// SessionPolicy is the resolved session-lifetime policy for one (tenant,
// application) pair. See migration 00067 for why these are per-tenant data
// rather than Go constants.
type SessionPolicy struct {
	// IdleTTL bounds how long a persistent session may go without a successful
	// refresh before it dies.
	IdleTTL time.Duration
	// NonPersistentIdleTTL is the same clock for a session the user did not ask
	// to be remembered — typically much shorter.
	NonPersistentIdleTTL time.Duration
	// AbsoluteTTL is the hard cap from first authentication. Never extended by a
	// refresh.
	AbsoluteTTL time.Duration
	// MaxConcurrentSessions is the per-user ceiling on live sessions; the oldest
	// is evicted when a new login would exceed it.
	MaxConcurrentSessions int
	// AllowPersistent gates "remember me". When false, every session uses
	// NonPersistentIdleTTL whatever the client asked for.
	AllowPersistent bool
}

// DefaultSessionPolicy mirrors the platform-default row seeded by migration
// 00067.
//
// It is the value used when the policy table cannot be read — see
// SessionPolicyService.Resolve for why that degrades to a default rather than
// failing the login. Kept in sync with the migration by TestDefaultPolicyMatchesSeed.
var DefaultSessionPolicy = SessionPolicy{
	IdleTTL:               7 * 24 * time.Hour,
	NonPersistentIdleTTL:  24 * time.Hour,
	AbsoluteTTL:           30 * 24 * time.Hour,
	MaxConcurrentSessions: 20,
	AllowPersistent:       true,
}

// IdleTTLFor returns the idle clock that applies to a session, honouring the
// policy's AllowPersistent gate. Callers must not branch on persistence
// themselves — routing both cases through here is what makes AllowPersistent=false
// actually binding rather than advisory.
func (p SessionPolicy) IdleTTLFor(persistent bool) time.Duration {
	if persistent && p.AllowPersistent {
		return p.IdleTTL
	}
	return p.NonPersistentIdleTTL
}

// Deadlines computes the two lifetime deadlines for a session authenticated at
// authTime. Returned together because they must be derived from one clock
// reading: computing them from separate time.Now() calls lets the idle deadline
// land after the absolute one on a slow path, and the clamp below would then
// silently do nothing.
//
// idle is clamped to absolute: an idle deadline beyond the hard cap can never
// fire, which would reinstate the unbounded behaviour the idle clock exists to
// prevent.
func (p SessionPolicy) Deadlines(authTime time.Time, persistent bool) (idle, absolute time.Time) {
	absolute = authTime.Add(p.AbsoluteTTL)
	idle = authTime.Add(p.IdleTTLFor(persistent))
	if idle.After(absolute) {
		idle = absolute
	}
	return idle, absolute
}

// SessionPolicyService resolves and caches session policy.
//
// Resolution is most-specific-wins: an application row, else the tenant row,
// else the platform default. Cached because Resolve is on the hot path of every
// login AND every token rotation — at a 15-minute access-token TTL that is one
// lookup per user per quarter hour, and policy changes measured in minutes are
// fast enough for a setting whose effect is measured in days.
type SessionPolicyService struct {
	pool   *pgxpool.Pool
	logger zerolog.Logger

	mu    sync.RWMutex
	cache map[policyKey]cachedPolicy
	ttl   time.Duration
}

type policyKey struct {
	tenantID      int64
	applicationID int64 // 0 = no application scope
}

type cachedPolicy struct {
	policy   SessionPolicy
	cachedAt time.Time
}

// policyCacheTTL is how long a resolved policy is reused. Short enough that an
// operator tightening a timeout sees it take effect while they are still looking
// at the screen, long enough to keep the refresh path off the policy table.
const policyCacheTTL = 60 * time.Second

// NewSessionPolicyService creates a policy resolver over the given pool.
func NewSessionPolicyService(pool *pgxpool.Pool, logger zerolog.Logger) *SessionPolicyService {
	return &SessionPolicyService{
		pool:   pool,
		logger: logger,
		cache:  make(map[policyKey]cachedPolicy),
		ttl:    policyCacheTTL,
	}
}

// Resolve returns the policy in force for the given scope. applicationID may be
// nil for tenant-level users.
//
// Never returns an error. A policy lookup failure falls back to
// DefaultSessionPolicy and logs at warn: this sits on the login and refresh
// paths, and refusing to authenticate anybody because a settings table is
// briefly unreadable trades a configuration problem for an outage. The fallback
// is the same conservative default the platform ships with, so the failure mode
// is "timeouts revert to platform defaults", not "sessions become unbounded".
func (s *SessionPolicyService) Resolve(ctx context.Context, tenantID int64, applicationID *int64) SessionPolicy {
	if s == nil || s.pool == nil {
		return DefaultSessionPolicy
	}

	key := policyKey{tenantID: tenantID}
	if applicationID != nil {
		key.applicationID = *applicationID
	}

	s.mu.RLock()
	entry, ok := s.cache[key]
	s.mu.RUnlock()
	if ok && time.Since(entry.cachedAt) < s.ttl {
		return entry.policy
	}

	policy, err := s.load(ctx, tenantID, applicationID)
	if err != nil {
		s.logger.Warn().Err(err).
			Int64("tenant_id", tenantID).
			Msg("session policy: resolve failed, using platform defaults")
		return DefaultSessionPolicy
	}

	s.mu.Lock()
	s.cache[key] = cachedPolicy{policy: policy, cachedAt: time.Now()}
	s.mu.Unlock()
	return policy
}

// load reads the most specific matching policy row.
//
// ORDER BY places the application row first, then the tenant row, then the
// platform default, and LIMIT 1 takes the winner — one indexed query instead of
// up to three round trips.
func (s *SessionPolicyService) load(ctx context.Context, tenantID int64, applicationID *int64) (SessionPolicy, error) {
	var idle, npIdle, absolute int
	var maxSessions int
	var allowPersistent bool

	err := s.pool.QueryRow(ctx, `
		SELECT idle_ttl_seconds, non_persistent_idle_ttl_seconds,
		       absolute_ttl_seconds, max_concurrent_sessions, allow_persistent
		FROM session_policies
		WHERE (application_id = $2 AND tenant_id = $1)
		   OR (application_id IS NULL AND tenant_id = $1)
		   OR (application_id IS NULL AND tenant_id IS NULL)
		ORDER BY application_id NULLS LAST, tenant_id NULLS LAST
		LIMIT 1
	`, tenantID, applicationID).Scan(&idle, &npIdle, &absolute, &maxSessions, &allowPersistent)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// The platform-default row is seeded by migration 00067, so this
			// means somebody deleted it. Defaults still apply; say so loudly
			// rather than inventing a policy silently.
			return DefaultSessionPolicy, fmt.Errorf("no session policy row matched (platform default missing?)")
		}
		return DefaultSessionPolicy, fmt.Errorf("load session policy: %w", err)
	}

	return SessionPolicy{
		IdleTTL:               time.Duration(idle) * time.Second,
		NonPersistentIdleTTL:  time.Duration(npIdle) * time.Second,
		AbsoluteTTL:           time.Duration(absolute) * time.Second,
		MaxConcurrentSessions: maxSessions,
		AllowPersistent:       allowPersistent,
	}, nil
}

// InvalidateCache drops cached policy for a scope. Called by the admin write path
// so an operator who changes a timeout does not have to wait out policyCacheTTL
// to see it — and, more importantly, so tightening a policy during an incident
// takes effect immediately.
//
// Drops the whole cache rather than one key: a tenant-level change affects every
// application key under that tenant, and the set of those keys is not tracked.
// The cache refills within one request, so precision here would buy nothing.
func (s *SessionPolicyService) InvalidateCache() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.cache = make(map[policyKey]cachedPolicy)
	s.mu.Unlock()
}
