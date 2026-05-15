// Package middleware provides Echo HTTP middleware for the emc-auth-server.
package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/labstack/echo/v4"
	"golang.org/x/time/rate"
)

// RateLimitConfig holds the parameters for the login rate limiter.
// AUTH-07: 5 attempts/min per IP, 10 attempts/min per tenant.
type RateLimitConfig struct {
	// PerIPRate is the number of requests allowed per minute per client IP.
	// Default: 5 (AUTH-07).
	PerIPRate int
	// PerTenantRate is the number of requests allowed per minute per tenant slug.
	// Default: 10 (AUTH-07).
	PerTenantRate int
}

// DefaultRateLimitConfig returns AUTH-07 compliant defaults.
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		PerIPRate:     5,
		PerTenantRate: 10,
	}
}

// limiterEntry wraps a rate.Limiter with a last-seen timestamp for TTL eviction.
type limiterEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// limiterStore is a sync.Map of key -> *limiterEntry.
// It is safe for concurrent use without external locking.
//
// NFR-04 Redis integration point:
// Replace this in-memory store with a Redis-backed sliding window counter
// (INCR + EXPIRE with Lua) in Phase 7. The LoginRateLimiter function signature
// and behaviour contract remain the same — only the Allow() implementation changes.
// Redis client can be injected via RateLimitConfig.RedisClient field (add it then).
type limiterStore struct {
	mu    sync.Mutex
	store sync.Map
}

// getOrCreate returns the *rate.Limiter for the given key, creating it if absent.
// r is requests per minute; burst is the token bucket burst size (= r for login).
func (s *limiterStore) getOrCreate(key string, r int) *rate.Limiter {
	ratePerSecond := rate.Every(time.Minute / time.Duration(r))
	entry, loaded := s.store.LoadOrStore(key, &limiterEntry{
		limiter:  rate.NewLimiter(ratePerSecond, r),
		lastSeen: time.Now(),
	})
	e := entry.(*limiterEntry)
	if loaded {
		e.lastSeen = time.Now()
	}
	return e.limiter
}

// cleanup removes entries not seen for more than ttl. Call periodically to prevent
// unbounded memory growth (one entry per unique IP/tenant slug ever seen).
func (s *limiterStore) cleanup(ttl time.Duration) {
	cutoff := time.Now().Add(-ttl)
	s.store.Range(func(key, value any) bool {
		e := value.(*limiterEntry)
		if e.lastSeen.Before(cutoff) {
			s.store.Delete(key)
		}
		return true
	})
}

// global stores — package-level singletons, one per key space.
// Using package-level vars ensures a single limiter map across all middleware
// instances (routes may call LoginRateLimiter multiple times during tests).
var (
	ipStore     = &limiterStore{}
	tenantStore = &limiterStore{}
	cleanupOnce sync.Once
)

// startCleanup starts a background goroutine that evicts stale limiter entries
// every 5 minutes. Called once via sync.Once.
func startCleanup() {
	cleanupOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(5 * time.Minute)
			defer ticker.Stop()
			for range ticker.C {
				// Evict entries not seen in 10 minutes — well beyond the 1-minute window.
				ipStore.cleanup(10 * time.Minute)
				tenantStore.cleanup(10 * time.Minute)
			}
		}()
	})
}

// LoginRateLimiter returns an Echo middleware that enforces two-level rate limiting
// on the login endpoint (AUTH-07):
//
//   - Per-IP: cfg.PerIPRate requests per minute (default 5)
//   - Per-tenant: cfg.PerTenantRate requests per minute (default 10), keyed by X-Tenant-Slug header
//
// Returns HTTP 429 with Retry-After header if either limit is exceeded.
//
// The limiter uses golang.org/x/time/rate (token bucket algorithm) backed by
// sync.Map per key space. This is correct for single-instance deployments.
//
// NFR-04 fallback note: This implementation IS the fallback — it runs entirely
// in-process with no Redis dependency. When Redis is available and a distributed
// rate limit is desired, replace the ipStore/tenantStore.getOrCreate calls with
// Redis INCR/EXPIRE atomic Lua script calls. The middleware signature stays the same.
func LoginRateLimiter(cfg RateLimitConfig) echo.MiddlewareFunc {
	// Start the background cleanup goroutine once at server startup.
	startCleanup()

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Determine client IP. Echo's RealIP() respects X-Real-IP and
			// X-Forwarded-For (set by reverse proxy). In production, ensure
			// the proxy is trusted (configure Echo's TrustProxies if needed).
			ip := c.RealIP()
			if ip == "" {
				ip = c.Request().RemoteAddr
			}

			// Per-IP rate check.
			ipLimiter := ipStore.getOrCreate("ip:"+ip, cfg.PerIPRate)
			if !ipLimiter.Allow() {
				c.Response().Header().Set("Retry-After", "60")
				return c.JSON(http.StatusTooManyRequests, map[string]string{
					"error":       "too many login attempts from your IP address",
					"retry_after": "60",
				})
			}

			// Per-tenant rate check (keyed by X-Tenant-Slug header value).
			// Always apply — use "unknown-tenant" as fallback key when header is absent
			// so the per-tenant limit cannot be bypassed by omitting the header (AUTH-07).
			tenantSlug := c.Request().Header.Get("X-Tenant-Slug")
			if tenantSlug == "" {
				tenantSlug = "unknown-tenant"
			}
			tenantLimiter := tenantStore.getOrCreate("tenant:"+tenantSlug, cfg.PerTenantRate)
			if !tenantLimiter.Allow() {
				c.Response().Header().Set("Retry-After", "60")
				return c.JSON(http.StatusTooManyRequests, map[string]string{
					"error":       "too many login attempts for this tenant",
					"retry_after": "60",
				})
			}

			return next(c)
		}
	}
}
