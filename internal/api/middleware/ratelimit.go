// Package middleware provides Echo HTTP middleware for the emc-auth-server.
package middleware

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/labstack/echo/v4"
	"golang.org/x/time/rate"
)

// RateLimitConfig holds the parameters for the login rate limiter.
// AUTH-07: 5 attempts/min per IP, 10 attempts/min per account.
type RateLimitConfig struct {
	// PerIPRate is the number of requests allowed per minute per client IP.
	// Default: 5 (AUTH-07).
	PerIPRate int
	// PerTenantRate is the number of requests allowed per minute per account
	// email. Named PerTenantRate for historical reasons (AUTH-07); since Login
	// no longer takes a tenant slug, this is keyed on the submitted email instead.
	// Default: 10 (AUTH-07).
	PerTenantRate int
}

// maxRateLimitEmailLen caps how much of a submitted "email" is used as part of
// a rate-limiter map key. RFC 5321 caps real addresses at 254 bytes; without
// this, a client submitting an arbitrarily long "email" string could inflate
// limiter-store memory with huge map keys.
const maxRateLimitEmailLen = 254

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
	e, _ := entry.(*limiterEntry)
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
		e, _ := value.(*limiterEntry)
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

// ResetStoresForTest clears all in-memory rate limiter state. It exists to allow
// tests to start from a clean bucket state so that running with -count=N or in
// a test suite that reuses the process does not pollute token buckets across runs.
// MUST NOT be called in production code.
func ResetStoresForTest() {
	ipStore.store.Range(func(k, _ any) bool { ipStore.store.Delete(k); return true })
	tenantStore.store.Range(func(k, _ any) bool { tenantStore.store.Delete(k); return true })
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

			// Per-account rate check, keyed on the submitted email — Login no
			// longer takes a tenant slug/client_id up front, so email is the only
			// stable identifier available before authentication succeeds.
			// "unknown-account" is the fallback key when the body can't be parsed,
			// so the limit cannot be bypassed by sending a malformed body (AUTH-07).
			// Trade-off vs. the old X-Tenant-Slug-keyed bucket: that capped *all*
			// attempts against one tenant at cfg.PerTenantRate regardless of which
			// email was tried; this one gives each email its own independent
			// bucket, so an attacker rotating through many known/guessed emails
			// against the same tenant faces no aggregate cap beyond the per-IP
			// limit above. There is no tenant identifier available before Login
			// resolves candidates, so a true per-tenant bucket isn't available
			// here — a coarser, tenant-aware limiter applied after resolution
			// would need to live in the service layer, not this middleware.
			//
			// Malformed/non-JSON bodies also share one "unknown-account" bucket
			// across every caller — a body-parse failure from one client can
			// count against unrelated callers hitting that same fallback key
			// within the window. Low severity: still bounded by the per-IP limit,
			// and only triggers when a client fails to send parseable JSON.
			email := loginEmailFromBody(c)
			if email == "" {
				email = "unknown-account"
			}
			if len(email) > maxRateLimitEmailLen {
				email = email[:maxRateLimitEmailLen]
			}
			accountLimiter := tenantStore.getOrCreate("account:"+email, cfg.PerTenantRate)
			if !accountLimiter.Allow() {
				c.Response().Header().Set("Retry-After", "60")
				return c.JSON(http.StatusTooManyRequests, map[string]string{
					"error":       "too many login attempts for this account",
					"retry_after": "60",
				})
			}

			return next(c)
		}
	}
}

// TokenRateLimiter rate-limits the client_credentials token endpoint.
// Unlike LoginRateLimiter it keys the per-account bucket on client_id — token
// requests carry no email, so reusing the login limiter would collapse every
// M2M client across all tenants into one shared "unknown-account" bucket,
// letting a single noisy client starve every other tenant's integration.
//
// client_id is read only from the Authorization: Basic header — the handler
// rejects body-sent credentials, so the body is never consulted here either.
// When no client_id can be determined (malformed request), only the per-IP
// limit applies — a shared fallback bucket would recreate the same
// cross-tenant collision.
func TokenRateLimiter(cfg RateLimitConfig) echo.MiddlewareFunc {
	startCleanup()

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			ip := c.RealIP()
			if ip == "" {
				ip = c.Request().RemoteAddr
			}

			ipLimiter := ipStore.getOrCreate("ip:"+ip, cfg.PerIPRate)
			if !ipLimiter.Allow() {
				c.Response().Header().Set("Retry-After", "60")
				return c.JSON(http.StatusTooManyRequests, map[string]string{
					"error":       "too many token requests from your IP address",
					"retry_after": "60",
				})
			}

			if clientID := tokenClientID(c); clientID != "" {
				if len(clientID) > maxRateLimitEmailLen {
					clientID = clientID[:maxRateLimitEmailLen]
				}
				clientLimiter := tenantStore.getOrCreate("client:"+clientID, cfg.PerTenantRate)
				if !clientLimiter.Allow() {
					c.Response().Header().Set("Retry-After", "60")
					return c.JSON(http.StatusTooManyRequests, map[string]string{
						"error":       "too many token requests for this client",
						"retry_after": "60",
					})
				}
			}

			return next(c)
		}
	}
}

// tokenClientID extracts the client_id from a token request for rate-limit
// keying. Client credentials are header-only (Authorization: Basic), matching
// the handler contract — body-sent credentials are rejected by the handler and
// never key a bucket. Returns "" when no well-formed header is present.
func tokenClientID(c echo.Context) string {
	header := c.Request().Header.Get(echo.HeaderAuthorization)
	if !strings.HasPrefix(header, "Basic ") {
		return ""
	}
	decoded, err := base64.StdEncoding.DecodeString(header[len("Basic "):])
	if err != nil {
		return ""
	}
	if id, _, found := strings.Cut(string(decoded), ":"); found && id != "" {
		return id
	}
	return ""
}

// loginEmailFromBody peeks the "email" field out of a login request body
// without consuming it, so the handler can still bind the full body afterward.
// Returns "" if the body is missing, unreadable, or not valid JSON.
func loginEmailFromBody(c echo.Context) string {
	req := c.Request()
	if req.Body == nil {
		return ""
	}
	data, err := io.ReadAll(io.LimitReader(req.Body, 1<<16)) // cap: login bodies are tiny
	_ = req.Body.Close()
	req.Body = io.NopCloser(bytes.NewReader(data))
	if err != nil {
		return ""
	}

	var payload struct {
		Email string `json:"email"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(payload.Email))
}
