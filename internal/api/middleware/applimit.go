package middleware

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/go-redis/redis_rate/v10"
	"github.com/labstack/echo/v4"
	redisv9 "github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/metrics"
)

// AppRateLimiter returns middleware that enforces per-application rate limits.
//
// The calling application is identified from the validated JWT `app_id` claim
// (the numeric oauth_clients.id) and `tenant_id` claim — NOT from request
// headers. It therefore MUST be mounted AFTER a JWT middleware (JWTRequired /
// JWTRenew) that has stored *auth.Claims in the echo context; mounting it
// before auth is a no-op because no claims exist yet.
//
// Tokens with no app context (first-party admin/tenant tokens, where app_id is
// empty) are passed through unlimited — per-app limits only apply to
// application-scoped traffic. Applications with no custom config fall back to
// DefaultRequestsPerMinute / DefaultBurst.
//
// Enforcement counters live in Redis so the limit is global across replicas.
// If Redis errors, the request is allowed (fail-open) to avoid a Redis outage
// taking down all authenticated traffic.
func AppRateLimiter(svc *auth.AppRateLimitService, redisCli *redisv9.Client, logger zerolog.Logger) echo.MiddlewareFunc {
	limiter := redis_rate.NewLimiter(redisCli)

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			claims, ok := c.Get(userContextKey).(*auth.Claims)
			if !ok || claims == nil || claims.AppID == "" {
				return next(c) // no application context — skip per-app limiting
			}

			// Malformed claims fail open (a broken token must not take down all
			// authenticated traffic) but are logged: a misconfigured issuer or a
			// crafted claim silently bypassing per-app limits would otherwise be
			// invisible.
			appID, err := strconv.ParseInt(claims.AppID, 10, 64)
			if err != nil || appID <= 0 {
				metrics.RateLimitFailOpen.WithLabelValues("app", "malformed_app_id").Inc()
				logger.Warn().Str("app_id", claims.AppID).
					Msg("applimit: skipped — malformed app_id claim (fail-open)")
				return next(c)
			}
			tenantID, err := strconv.ParseInt(claims.TenantID, 10, 64)
			if err != nil {
				metrics.RateLimitFailOpen.WithLabelValues("app", "malformed_tenant_id").Inc()
				logger.Warn().Str("tenant_id", claims.TenantID).Int64("app_id", appID).
					Msg("applimit: skipped — malformed tenant_id claim (fail-open)")
				return next(c)
			}

			rpm, burst := svc.GetLimit(c.Request().Context(), tenantID, appID)
			return enforceAppLimit(c, next, limiter, logger, "app:", tenantID, appID, rpm, burst)
		}
	}
}

// AppClientRateLimiter is the pre-auth counterpart of AppRateLimiter for the
// Basic-auth application endpoints (client_credentials token, /auth/apps/*),
// where the caller is identified by the client_id in the Authorization: Basic
// header rather than a JWT, applying the application's configured limit to those
// auth calls.
//
// It uses a SEPARATE bucket namespace ("appauth:") from the JWT-authenticated
// API limiter ("app:"). The client_id is a public identifier read before the
// client_secret is verified, so sharing one bucket would let anyone who knows a
// client_id drain the application's authenticated API quota by sending bogus
// auth requests (a cross-surface DoS). With separate buckets, pre-auth guessing
// can at most throttle the auth endpoints — and that is already bounded per IP
// by TokenRateLimiter, which runs ahead of this middleware.
//
// Requests with no Basic client_id, or a client_id that maps to no live
// application, are passed through (the per-IP limits still apply).
//
// Behind AppS2S.Resolve (every application end-user route) it uses what Resolve
// learned instead of looking the client up again:
//
//   - Verified credentials spend the application's quota, which is the limit an
//     administrator sizes for the product's whole user base.
//   - Credentials that did NOT verify spend a separate bucket
//     ("appauth-unverified:") of the same size. The client_id is public, so
//     without this anyone who knew it could exhaust the product's quota with
//     bogus requests and lock out every real user — the same cross-surface DoS
//     the "appauth:"/"app:" split prevents, one level down.
func AppClientRateLimiter(svc *auth.AppRateLimitService, redisCli *redisv9.Client, logger zerolog.Logger) echo.MiddlewareFunc {
	limiter := redis_rate.NewLimiter(redisCli)

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			clientID := tokenClientID(c)
			if clientID == "" {
				return next(c)
			}
			if caller, ok := CallerFrom(c); ok && caller.ClientID == clientID && caller.HasCredentials {
				if caller.Verified {
					rpm, burst := svc.GetLimit(c.Request().Context(), caller.TenantID, caller.AppID)
					return enforceAppLimit(c, next, limiter, logger, "appauth:", caller.TenantID, caller.AppID, rpm, burst)
				}
				tenantID, appID, rpm, burst, ok := svc.GetLimitForClientID(c.Request().Context(), clientID)
				if !ok {
					return next(c)
				}
				return enforceAppLimit(c, next, limiter, logger, "appauth-unverified:", tenantID, appID, rpm, burst)
			}
			tenantID, appID, rpm, burst, ok := svc.GetLimitForClientID(c.Request().Context(), clientID)
			if !ok {
				return next(c)
			}
			return enforceAppLimit(c, next, limiter, logger, "appauth:", tenantID, appID, rpm, burst)
		}
	}
}

// enforceAppLimit applies one token-bucket check against the per-application
// Redis counter under keyPrefix (JWT API traffic and pre-auth client_id traffic
// use distinct prefixes so they never share a bucket), setting X-RateLimit-*
// headers and returning 429 when the bucket is empty. Redis errors fail open so
// an outage never blocks all traffic.
func enforceAppLimit(c echo.Context, next echo.HandlerFunc, limiter *redis_rate.Limiter, logger zerolog.Logger, keyPrefix string, tenantID, appID int64, rpm, burst int) error {
	// Metric label derived from the bucket namespace so the JWT-authenticated
	// limiter ("app:") and the pre-auth client_id limiter ("appauth:") stay
	// distinguishable in metrics, exactly as they are in Redis.
	limiterLabel := "app"
	switch keyPrefix {
	case "appauth:":
		limiterLabel = "app_client"
	case "appauth-unverified:":
		limiterLabel = "app_client_unverified"
	}

	rateKey := keyPrefix + strconv.FormatInt(tenantID, 10) + ":" + strconv.FormatInt(appID, 10)
	res, err := limiter.Allow(c.Request().Context(), rateKey, redis_rate.Limit{
		Rate:   rpm,
		Burst:  burst,
		Period: time.Minute,
	})
	if err != nil {
		// Redis unavailable — fail open, but count and log it. During a Redis
		// outage every tenant-configured quota silently stops being enforced;
		// without the counter that state is invisible outside warn-level logs.
		metrics.RateLimitFailOpen.WithLabelValues(limiterLabel, "redis_error").Inc()
		logger.Warn().Err(err).Int64("tenant_id", tenantID).Int64("application_id", appID).
			Msg("applimit: Redis error — allowing request (fail-open)")
		return next(c)
	}

	c.Response().Header().Set("X-RateLimit-Limit", strconv.Itoa(rpm))
	c.Response().Header().Set("X-RateLimit-Remaining", strconv.Itoa(res.Remaining))

	if res.Allowed == 0 {
		metrics.RateLimitHits.WithLabelValues(limiterLabel).Inc()
		retryAfter := int(res.RetryAfter.Seconds())
		c.Response().Header().Set("Retry-After", strconv.Itoa(retryAfter))
		return c.JSON(http.StatusTooManyRequests, map[string]string{
			"error": "rate limit exceeded for application " + strconv.FormatInt(appID, 10),
			// limiter tells an integrator which limit fired: "app" means the
			// whole product is over its quota, unlike "user" or "ip".
			"limiter":     "app",
			"retry_after": strconv.Itoa(retryAfter) + "s",
		})
	}

	return next(c)
}

// captchaBodyLimit caps how much of a request body the body-aware limiter will
// read looking for a client_id. The only route using it takes three short
// string fields; anything larger is not a challenge request and does not get to
// make the limiter allocate for it.
const captchaBodyLimit = 8 << 10 // 8 KiB

// AppCallerRateLimiter charges the application quota of the application that
// AppS2S's resolver identified — the one whose secret verified, or, for a
// client_id presented without a secret from that application's registered
// server IP, that application. Anything else passes through.
//
// For routes where the request may name an application in more than one place
// (a Basic header and a body client_id). Keying on what Resolve PROVED, rather
// than on whichever client_id a header or body carries, is what stops one
// tenant's valid credentials from spending another application's quota.
// Mount behind BackendsOnly, after a resolver.
func AppCallerRateLimiter(svc *auth.AppRateLimitService, redisCli *redisv9.Client, logger zerolog.Logger) echo.MiddlewareFunc {
	limiter := redis_rate.NewLimiter(redisCli)

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			caller, ok := CallerFrom(c)
			if !ok || caller.AppID <= 0 || caller.TenantID <= 0 || !TrustedBackend(c) {
				return next(c)
			}
			rpm, burst := svc.GetLimit(c.Request().Context(), caller.TenantID, caller.AppID)
			return enforceAppLimit(c, next, limiter, logger, "appauth:", caller.TenantID, caller.AppID, rpm, burst)
		}
	}
}

// AppClientBodyRateLimiter is AppClientRateLimiter for routes that carry
// client_id in the JSON BODY rather than in an Authorization: Basic header.
//
// It exists because mounting AppClientRateLimiter on POST /captcha/challenge was
// silently inert. That limiter keys on tokenClientID(c), which reads only the
// Authorization and X-Client-Authorization headers — and the challenge endpoint
// is called before sign-in, so it carries neither. The key was always "", the
// clientID == "" early return fired on every request, and the per-application
// bucket the route was documented as carrying never existed. Only the per-IP
// TokenRateLimiter was actually bounding the PNG render, so a known client_id
// flooded from many addresses got no per-application throttle at all.
//
// Reading the body in middleware is normally worth avoiding, which is why this
// is a separate constructor rather than a change to tokenClientID: it applies to
// exactly the routes that need it, and the handler still binds the body itself.
// The body is restored before next(c) so binding is unaffected.
//
// Same bucket namespace ("appauth:") as AppClientRateLimiter, deliberately —
// both identify a caller by an unverified, public client_id before any secret is
// checked, so they belong in the same pre-auth bucket and must stay out of the
// JWT-authenticated "app:" one.
//
// Fails OPEN on an unreadable or unparseable body: the handler is the component
// that owns rejecting a malformed request, and a limiter that 400s first would
// change the response an integrator sees for a bad payload.
func AppClientBodyRateLimiter(svc *auth.AppRateLimitService, redisCli *redisv9.Client, logger zerolog.Logger) echo.MiddlewareFunc {
	limiter := redis_rate.NewLimiter(redisCli)

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			clientID := clientIDFromBody(c)
			if clientID == "" {
				return next(c)
			}
			tenantID, appID, rpm, burst, ok := svc.GetLimitForClientID(c.Request().Context(), clientID)
			if !ok {
				return next(c)
			}
			return enforceAppLimit(c, next, limiter, logger, "appauth:", tenantID, appID, rpm, burst)
		}
	}
}

// clientIDFromBody peeks at the JSON body for a client_id and puts the body
// back, so the handler's own Bind still sees a complete request.
//
// Returns "" for anything it cannot read — no body, oversized body, malformed
// JSON, or no client_id field. Every one of those means "no per-client bucket
// applies", never "reject".
func clientIDFromBody(c echo.Context) string {
	req := c.Request()
	if req.Body == nil {
		return ""
	}
	raw, err := io.ReadAll(io.LimitReader(req.Body, captchaBodyLimit))
	// Restore unconditionally, including on a read error: the handler must get
	// whatever was readable rather than an already-consumed body.
	_ = req.Body.Close()
	req.Body = io.NopCloser(bytes.NewReader(raw))
	if err != nil || len(raw) == 0 {
		return ""
	}

	var probe struct {
		ClientID string `json:"client_id"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return ""
	}
	return probe.ClientID
}
