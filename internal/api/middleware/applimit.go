package middleware

import (
	"net/http"
	"strconv"

	"github.com/go-redis/redis_rate/v10"
	"github.com/labstack/echo/v4"
	redisv9 "github.com/redis/go-redis/v9"

	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// AppIDHeader is the request header used to identify the calling application.
const AppIDHeader = "X-App-ID"

// TenantSlugHeader is the request header used to identify the tenant.
const TenantSlugHeader = "X-Tenant-Slug"

// AppRateLimiter returns middleware that enforces per-application rate limits.
// Limits are loaded from the AppRateLimitService (DB-backed, Redis-cached, 60s TTL).
// Enforcement counters are stored in Redis so the limit is global across all replicas.
// Apps not in the DB fall back to DefaultRequestsPerMinute / DefaultBurst.
// Requests without X-App-ID are passed through without per-app limiting.
func AppRateLimiter(svc *auth.AppRateLimitService, redisCli *redisv9.Client) echo.MiddlewareFunc {
	limiter := redis_rate.NewLimiter(redisCli)

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			appID := c.Request().Header.Get(AppIDHeader)
			if appID == "" {
				return next(c) // no app ID — skip per-app limiting
			}

			tenantSlug := c.Request().Header.Get(TenantSlugHeader)
			rpm, _ := svc.GetLimit(c.Request().Context(), appID, tenantSlug)

			// Rate key includes tenant slug so the same app_id across tenants
			// does not share a counter.
			rateKey := "app:" + tenantSlug + ":" + appID
			res, err := limiter.Allow(c.Request().Context(), rateKey, redis_rate.PerMinute(rpm))
			if err != nil {
				// Redis unavailable — fail open to avoid blocking all traffic during an outage.
				// Log via the handler chain; rate limiting is best-effort when Redis is down.
				return next(c)
			}

			c.Response().Header().Set("X-RateLimit-Limit", strconv.Itoa(rpm))
			c.Response().Header().Set("X-RateLimit-Remaining", strconv.Itoa(res.Remaining))
			c.Response().Header().Set("X-App-ID", appID)

			if res.Allowed == 0 {
				retryAfter := int(res.RetryAfter.Seconds())
				c.Response().Header().Set("Retry-After", strconv.Itoa(retryAfter))
				return c.JSON(http.StatusTooManyRequests, map[string]string{
					"error":       "rate limit exceeded for app: " + appID,
					"retry_after": strconv.Itoa(retryAfter) + "s",
				})
			}

			return next(c)
		}
	}
}
