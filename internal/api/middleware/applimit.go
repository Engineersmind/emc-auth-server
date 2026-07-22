package middleware

import (
	"net/http"
	"strconv"
	"time"

	"github.com/go-redis/redis_rate/v10"
	"github.com/labstack/echo/v4"
	redisv9 "github.com/redis/go-redis/v9"

	"github.com/engineersmind/emc-auth-server/internal/auth"
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
func AppRateLimiter(svc *auth.AppRateLimitService, redisCli *redisv9.Client) echo.MiddlewareFunc {
	limiter := redis_rate.NewLimiter(redisCli)

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			claims, ok := c.Get(userContextKey).(*auth.Claims)
			if !ok || claims == nil || claims.AppID == "" {
				return next(c) // no application context — skip per-app limiting
			}

			appID, err := strconv.ParseInt(claims.AppID, 10, 64)
			if err != nil || appID <= 0 {
				return next(c) // malformed app_id claim — nothing to key on
			}
			tenantID, err := strconv.ParseInt(claims.TenantID, 10, 64)
			if err != nil {
				return next(c)
			}

			rpm, burst := svc.GetLimit(c.Request().Context(), tenantID, appID)
			return enforceAppLimit(c, next, limiter, "app:", tenantID, appID, rpm, burst)
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
// application, are passed through (the per-IP TokenRateLimiter still applies).
func AppClientRateLimiter(svc *auth.AppRateLimitService, redisCli *redisv9.Client) echo.MiddlewareFunc {
	limiter := redis_rate.NewLimiter(redisCli)

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			clientID := tokenClientID(c)
			if clientID == "" {
				return next(c)
			}
			tenantID, appID, rpm, burst, ok := svc.GetLimitForClientID(c.Request().Context(), clientID)
			if !ok {
				return next(c)
			}
			return enforceAppLimit(c, next, limiter, "appauth:", tenantID, appID, rpm, burst)
		}
	}
}

// enforceAppLimit applies one token-bucket check against the per-application
// Redis counter under keyPrefix (JWT API traffic and pre-auth client_id traffic
// use distinct prefixes so they never share a bucket), setting X-RateLimit-*
// headers and returning 429 when the bucket is empty. Redis errors fail open so
// an outage never blocks all traffic.
func enforceAppLimit(c echo.Context, next echo.HandlerFunc, limiter *redis_rate.Limiter, keyPrefix string, tenantID, appID int64, rpm, burst int) error {
	rateKey := keyPrefix + strconv.FormatInt(tenantID, 10) + ":" + strconv.FormatInt(appID, 10)
	res, err := limiter.Allow(c.Request().Context(), rateKey, redis_rate.Limit{
		Rate:   rpm,
		Burst:  burst,
		Period: time.Minute,
	})
	if err != nil {
		return next(c) // Redis unavailable — fail open.
	}

	c.Response().Header().Set("X-RateLimit-Limit", strconv.Itoa(rpm))
	c.Response().Header().Set("X-RateLimit-Remaining", strconv.Itoa(res.Remaining))

	if res.Allowed == 0 {
		retryAfter := int(res.RetryAfter.Seconds())
		c.Response().Header().Set("Retry-After", strconv.Itoa(retryAfter))
		return c.JSON(http.StatusTooManyRequests, map[string]string{
			"error":       "rate limit exceeded for application " + strconv.FormatInt(appID, 10),
			"retry_after": strconv.Itoa(retryAfter) + "s",
		})
	}

	return next(c)
}
