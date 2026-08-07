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

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/metrics"
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

// getOrCreateEvery is getOrCreate for buckets slower than one token per minute,
// where the per-minute integer rate cannot express the interval. interval is the
// time to refill a single token; burst is how many may be spent at once.
func (s *limiterStore) getOrCreateEvery(key string, interval time.Duration, burst int) *rate.Limiter {
	entry, loaded := s.store.LoadOrStore(key, &limiterEntry{
		limiter:  rate.NewLimiter(rate.Every(interval), burst),
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
	// oauthClientStore is deliberately separate from tenantStore so OAuth
	// client_id keys can never collide with tenant/email keys — isolation is
	// structural, not dependent on a string prefix convention.
	oauthClientStore = &limiterStore{}
	// auditMaintStore buckets the expensive compliance endpoints (CSV export,
	// chain verify, GDPR erase) per tenant — each request can stream tens of
	// thousands of rows or recompute a 100k-row hash chain, so a tenant admin
	// must not be able to fan out concurrent calls against the DB.
	auditMaintStore = &limiterStore{}
	cleanupOnce     sync.Once
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
				oauthClientStore.cleanup(10 * time.Minute)
				auditMaintStore.cleanup(10 * time.Minute)
				jwksStore.cleanup(10 * time.Minute)
				// Safe at 10 min: UserInfo refills 60/min, i.e. one token per
				// second, so a bucket idle for ten minutes is already full and
				// evicting it grants nothing that waiting would not.
				userInfoStore.cleanup(10 * time.Minute)
				// Evicting a bucket resets it to full burst, so a store may not
				// be swept faster than its own refill interval or idling becomes
				// a way to skip the limit. Rotation refills one token every
				// signingKeyRotationInterval, hence the much longer TTL.
				signingKeyRotationStore.cleanup(time.Hour)
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
	oauthClientStore.store.Range(func(k, _ any) bool { oauthClientStore.store.Delete(k); return true })
	auditMaintStore.store.Range(func(k, _ any) bool { auditMaintStore.store.Delete(k); return true })
	jwksStore.store.Range(func(k, _ any) bool { jwksStore.store.Delete(k); return true })
	signingKeyRotationStore.store.Range(func(k, _ any) bool { signingKeyRotationStore.store.Delete(k); return true })
}

// defaultAuditMaintRate is the per-tenant per-minute cap on the expensive audit
// compliance endpoints when no explicit rate is supplied.
const defaultAuditMaintRate = 10

// AuditMaintenanceRateLimiter bounds the cost of the audit compliance endpoints
// (CSV export, chain verify, GDPR erase) per tenant. These are JWT-protected but
// individually expensive — a single export streams up to maxExportRows and holds
// a DB connection, and verify recomputes the whole hash chain — so unlimited
// concurrent calls from one tenant admin could exhaust the pool. The bucket is
// keyed on the caller's tenant (from JWT claims, set by JWTRequired which always
// runs first on these groups); it falls back to the client IP if claims are
// somehow absent. perMinute <= 0 uses defaultAuditMaintRate.
func AuditMaintenanceRateLimiter(perMinute int) echo.MiddlewareFunc {
	startCleanup()
	if perMinute <= 0 {
		perMinute = defaultAuditMaintRate
	}
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			key := "audit-maint:"
			if claims, ok := c.Get("user").(*auth.Claims); ok && claims != nil && claims.TenantID != "" {
				key += "tenant:" + claims.TenantID
			} else {
				ip := c.RealIP()
				if ip == "" {
					ip = c.Request().RemoteAddr
				}
				key += "ip:" + ip
			}
			if !auditMaintStore.getOrCreate(key, perMinute).Allow() {
				c.Response().Header().Set("Retry-After", "60")
				return c.JSON(http.StatusTooManyRequests, map[string]string{
					"error":       "too many audit compliance requests — slow down",
					"retry_after": "60",
				})
			}
			return next(c)
		}
	}
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

// OTPRateLimiter rate-limits the OTP-challenge completion endpoints
// (/auth/login/otp, /auth/login/mfa/enroll, /auth/login/mfa/activate).
// These carry no email and no client credentials — the only stable identifiers
// are the caller IP and the opaque session token from the body, so both get a
// bucket. The Redis-side per-session attempt cap (auth.MaxOTPAttempts) is the
// hard stop against single-session code brute force; this limiter bounds
// endpoint volume (many-session and token-guessing traffic) before it reaches
// Redis.
//
// The per-IP bucket is deliberately separate from LoginRateLimiter's ("ip:"
// vs "otp-ip:") — a legitimate two-step login spends password attempts and
// OTP attempts from independent budgets. Twice the login rate, because one
// login (1 request) legitimately fans out to enroll + activate + mistyped
// retries.
func OTPRateLimiter(cfg RateLimitConfig) echo.MiddlewareFunc {
	startCleanup()

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			ip := c.RealIP()
			if ip == "" {
				ip = c.Request().RemoteAddr
			}

			ipLimiter := ipStore.getOrCreate("otp-ip:"+ip, cfg.PerIPRate*2)
			if !ipLimiter.Allow() {
				c.Response().Header().Set("Retry-After", "60")
				return c.JSON(http.StatusTooManyRequests, map[string]string{
					"error":       "too many OTP attempts from your IP address",
					"retry_after": "60",
				})
			}

			if token := otpSessionTokenFromBody(c); token != "" {
				if len(token) > maxRateLimitEmailLen {
					token = token[:maxRateLimitEmailLen]
				}
				sessLimiter := tenantStore.getOrCreate("otpsess:"+token, cfg.PerTenantRate)
				if !sessLimiter.Allow() {
					c.Response().Header().Set("Retry-After", "60")
					return c.JSON(http.StatusTooManyRequests, map[string]string{
						"error":       "too many OTP attempts for this session",
						"retry_after": "60",
					})
				}
			}

			return next(c)
		}
	}
}

// OAuthRateLimiter rate-limits the social-login browser redirect endpoints
// (GET /oauth/:provider/login and /oauth/:provider/callback, issue #64).
// Neither LoginRateLimiter (JSON-body email key) nor TokenRateLimiter (Basic
// auth header key) fits a browser GET, so this variant keys the second bucket
// on the client_id query parameter. When no client_id is present (e.g. the
// callback, where only state identifies the attempt), only the per-IP limit
// applies — state itself is single-use, so callback replay is already dead.
func OAuthRateLimiter(cfg RateLimitConfig) echo.MiddlewareFunc {
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
					"error":       "too many login attempts from your IP address",
					"retry_after": "60",
				})
			}

			if clientID := c.QueryParam("client_id"); clientID != "" {
				if len(clientID) > maxRateLimitEmailLen {
					clientID = clientID[:maxRateLimitEmailLen]
				}
				clientLimiter := oauthClientStore.getOrCreate(clientID, cfg.PerTenantRate)
				if !clientLimiter.Allow() {
					c.Response().Header().Set("Retry-After", "60")
					return c.JSON(http.StatusTooManyRequests, map[string]string{
						"error":       "too many login attempts for this application",
						"retry_after": "60",
					})
				}
			}

			return next(c)
		}
	}
}

// otpSessionTokenFromBody peeks the pre-auth session token out of an OTP
// endpoint body without consuming it (same technique as loginEmailFromBody).
// Both field names are checked because /auth/login/otp uses
// otp_session_token and /auth/login/mfa/* use enrollment_token.
func otpSessionTokenFromBody(c echo.Context) string {
	req := c.Request()
	if req.Body == nil {
		return ""
	}
	data, err := io.ReadAll(io.LimitReader(req.Body, 1<<16))
	_ = req.Body.Close()
	req.Body = io.NopCloser(bytes.NewReader(data))
	if err != nil {
		return ""
	}

	var payload struct {
		OTPSessionToken string `json:"otp_session_token"`
		EnrollmentToken string `json:"enrollment_token"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return ""
	}
	if payload.OTPSessionToken != "" {
		return payload.OTPSessionToken
	}
	return payload.EnrollmentToken
}

// tokenClientID extracts the client_id from a token request for rate-limit
// keying. Client credentials are header-only (Authorization: Basic), matching
// the handler contract — body-sent credentials are rejected by the handler and
// never key a bucket. Returns "" when no well-formed header is present.
func tokenClientID(c echo.Context) string {
	if id := basicClientID(c.Request().Header.Get(echo.HeaderAuthorization)); id != "" {
		return id
	}
	// Routes that need BOTH a user Bearer token and application credentials
	// cannot put the latter in Authorization, so they carry it here (see
	// ClientAuthHeader). Without this fallback the per-application limiters read
	// an empty client_id on those routes and pass every request straight through
	// — the limiter is mounted but inert.
	return basicClientID(c.Request().Header.Get(ClientAuthHeader))
}

// ClientAuthHeader carries the calling application's credentials on endpoints
// that ALSO require a user Bearer token (currently GET /auth/apps/me).
//
// Why a second header: one header cannot hold two credentials, and Bearer has to
// stay in Authorization because that is where every HTTP client, proxy, and JWT
// library expects it. The value format is identical to the Authorization: Basic
// used by every other /apps/* route, so this adds a header name, not a third
// credential scheme.
//
// Defined here rather than in the handler package because the rate limiters read
// it too, and a limiter looking at a different header than the parser is exactly
// how the limiter ends up doing nothing.
const ClientAuthHeader = "X-Client-Authorization"

// basicClientID extracts the client_id from a "Basic base64(id:secret)" header
// value, or "" if the value is absent, not Basic, or malformed.
func basicClientID(header string) string {
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

// jwksStore holds the per-IP buckets for the public JWKS endpoint, kept separate
// from ipStore so JWKS traffic and login traffic cannot exhaust each other's
// budget — they have wildly different legitimate volumes.
var jwksStore = &limiterStore{}

// JWKSPerIPRate is the per-minute, per-IP allowance for the published JWKS.
//
// Deliberately far above the 5/min the login and OAuth limiters use, because the
// failure mode here is an OUTAGE for the consumer, not a slowed-down attacker.
// A tenant running 20 pods behind one NAT gateway presents as a single IP; if
// their JWKS caches expire together, a 5/min limit returns 429 and every one of
// those pods becomes unable to verify any token at all. JWKS is a hard dependency
// for every offline verifier we just told to depend on it, so it must fail open
// under legitimate load and only clamp genuine abuse.
//
// The response is also cheap and cacheable: a few hundred bytes of public key
// material served from an in-memory cache, with an ETag so well-behaved clients
// mostly get 304s. There is little to protect and much to break.
const JWKSPerIPRate = 120

// userInfoStore holds the per-user buckets for the OIDC UserInfo endpoint, kept
// separate from every other store for the same reason jwksStore is: UserInfo and
// login have different legitimate volumes and must not exhaust each other.
var userInfoStore = &limiterStore{}

// UserInfoPerSubjectRate is the per-minute allowance for /oauth/userinfo, keyed
// on the authenticated user.
//
// Keyed per user, not per IP, because unlike JWKS this endpoint is authenticated
// — the caller is known, so the bucket can be charged to the account rather than
// to a shared NAT address. That avoids the failure mode described for
// JWKSPerIPRate, where many pods behind one gateway starve each other.
//
// 60/min is generous for the intended use: a relying party calls UserInfo once
// per login to populate a profile, not on every request. It is low enough that a
// stolen token cannot be used to hammer the user lookup, and high enough that a
// client refreshing a profile on navigation will never notice it.
const UserInfoPerSubjectRate = 60

// UserInfoRateLimiter bounds /oauth/userinfo per authenticated subject (issue #7).
//
// This server attaches every limiter per route and has no global one, so a new
// route inherits no throttling whatsoever — the same gap JWKSRateLimiter exists to
// close, and the reason CLAUDE.md carries deferred item #14.
//
// Falls back to the client IP when no verified subject is present. That should be
// unreachable, since the route sits behind JWTRequired, but a limiter whose key can
// silently become the empty string collapses every caller into one shared bucket —
// which is either a global outage or no limit at all, depending on the order of
// arrival. Failing back to IP keeps it bounded either way.
func UserInfoRateLimiter() echo.MiddlewareFunc {
	startCleanup()

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			key := ""
			if claims, ok := c.Get("user").(*auth.Claims); ok && claims != nil && claims.UserID != "" {
				key = "userinfo:sub:" + claims.TenantID + ":" + claims.UserID
			} else {
				ip := c.RealIP()
				if ip == "" {
					ip = c.Request().RemoteAddr
				}
				key = "userinfo:ip:" + ip
			}

			if !userInfoStore.getOrCreate(key, UserInfoPerSubjectRate).Allow() {
				metrics.RateLimitHits.WithLabelValues("userinfo").Inc()
				c.Response().Header().Set("Retry-After", "60")
				return c.JSON(http.StatusTooManyRequests, map[string]string{
					"error":       "too many userinfo requests",
					"retry_after": "60",
				})
			}
			return next(c)
		}
	}
}

// JWKSRateLimiter rate-limits the public JWKS endpoint per client IP (issue #95).
//
// A new public route inherits no throttling at all — every limiter in this server
// is attached per route and there is no global one — so without this the endpoint
// would be completely unbounded.
//
// Conditional requests that result in 304 Not Modified are NOT counted. A verifier
// revalidating a cached key set is the behaviour we want to encourage, and charging
// it against the same budget as a full fetch would punish the well-behaved clients
// hardest — precisely the ones whose caches expire in lockstep across many pods.
func JWKSRateLimiter() echo.MiddlewareFunc {
	startCleanup()

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			ip := c.RealIP()
			if ip == "" {
				ip = c.Request().RemoteAddr
			}

			limiter := jwksStore.getOrCreate("jwks:"+ip, JWKSPerIPRate)

			// Reserve rather than Allow so the token can be handed back below.
			// A reservation that cannot proceed immediately means the bucket is
			// empty, which is the same condition Allow() reports as false.
			res := limiter.ReserveN(time.Now(), 1)
			if !res.OK() || res.Delay() > 0 {
				res.Cancel()
				metrics.RateLimitHits.WithLabelValues("jwks_ip").Inc()
				c.Response().Header().Set("Retry-After", "60")
				return c.JSON(http.StatusTooManyRequests, map[string]string{
					"error":       "too many JWKS requests from your IP address",
					"retry_after": "60",
				})
			}

			if err := next(c); err != nil {
				return err
			}

			// Give the token back when the response was a revalidation. Deciding
			// after the handler runs keeps the hot path free of response-shape
			// guesswork, and Cancel reverses the reservation's effect on the bucket.
			if c.Response().Status == http.StatusNotModified {
				res.Cancel()
			}
			return nil
		}
	}
}

// Signing-key rotation budget (issue #95 review). A rotation is a deliberate,
// rare operation — the runbook expects one per scheduled interval, not one per
// minute — so the bucket is sized for exactly that.
//
// The threat is not load. CompleteRotation retires the outgoing key, and a
// retired key drops out of the published set once RetiredKeyGrace elapses; an
// authorised-but-hostile (or scripted-and-buggy) caller cycling prepare→complete
// can therefore march a tenant through generations faster than outstanding
// tokens expire, and every token signed by a key pushed past its grace window
// fails verification. Rate limiting is what makes that take hours instead of
// seconds.
//
// Burst 2 so one honest rotation — prepare then complete, the two calls the
// two-step design requires — always goes through immediately.
const (
	signingKeyRotationInterval = 10 * time.Minute
	signingKeyRotationBurst    = 2
)

// signingKeyRotationStore is separate from every other store so a rotation
// bucket can never share a key with a tenant or IP bucket.
var signingKeyRotationStore = &limiterStore{}

// SigningKeyRotationRateLimiter bounds prepare/complete rotation calls per tenant.
//
// Keyed on the JWT tenant claim rather than the IP: the operation is tenant-wide,
// so an operator with two machines must still share one budget, and the endpoints
// sit behind JWTRequired + tenant:manage so claims are always present. It falls
// back to the IP only so a wiring mistake fails closed-ish rather than unlimited.
func SigningKeyRotationRateLimiter() echo.MiddlewareFunc {
	startCleanup()

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			key := "signing-key-rotation:"
			if claims, ok := c.Get("user").(*auth.Claims); ok && claims != nil && claims.TenantID != "" {
				key += "tenant:" + claims.TenantID
			} else {
				ip := c.RealIP()
				if ip == "" {
					ip = c.Request().RemoteAddr
				}
				key += "ip:" + ip
			}

			limiter := signingKeyRotationStore.getOrCreateEvery(
				key, signingKeyRotationInterval, signingKeyRotationBurst)
			if !limiter.Allow() {
				metrics.RateLimitHits.WithLabelValues("signing_key_rotation").Inc()
				c.Response().Header().Set("Retry-After", "600")
				return c.JSON(http.StatusTooManyRequests, map[string]string{
					"error":       "too many signing-key rotations for this tenant — rotation is rate limited to protect outstanding tokens",
					"retry_after": "600",
				})
			}
			return next(c)
		}
	}
}
