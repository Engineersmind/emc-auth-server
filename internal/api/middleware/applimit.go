package middleware

import (
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/labstack/echo/v4"
	"golang.org/x/time/rate"

	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// AppIDHeader is the request header used to identify the calling application.
const AppIDHeader = "X-App-ID"

// appLimiter holds a per-app token bucket rate limiter.
type appLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// AppRateLimiter returns middleware that enforces per-application rate limits.
// Limits are loaded from the AppRateLimitService (DB-backed, Redis-cached, 60s TTL).
// Apps not in the DB fall back to DefaultRequestsPerMinute / DefaultBurst.
// Requests without X-App-ID are passed through without per-app limiting.
func AppRateLimiter(svc *auth.AppRateLimitService) echo.MiddlewareFunc {
	var (
		mu       sync.Mutex
		limiters = make(map[string]*appLimiter)
	)

	// Background cleanup of stale limiters (apps not seen in 10 min).
	go func() {
		for range time.Tick(5 * time.Minute) {
			mu.Lock()
			for appID, l := range limiters {
				if time.Since(l.lastSeen) > 10*time.Minute {
					delete(limiters, appID)
				}
			}
			mu.Unlock()
		}
	}()

	getLimiter := func(appID string, rpm, burst int) *rate.Limiter {
		mu.Lock()
		defer mu.Unlock()
		existing, ok := limiters[appID]
		if !ok {
			r := rate.Every(time.Minute / time.Duration(rpm))
			existing = &appLimiter{limiter: rate.NewLimiter(r, burst)}
			limiters[appID] = existing
		}
		existing.lastSeen = time.Now()
		return existing.limiter
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			appID := c.Request().Header.Get(AppIDHeader)
			if appID == "" {
				return next(c) // no app ID — skip per-app limiting
			}

			rpm, burst := svc.GetLimit(c.Request().Context(), appID)
			limiter := getLimiter(appID, rpm, burst)

			if !limiter.Allow() {
				retryAfter := int(time.Minute / time.Duration(rpm))
				c.Response().Header().Set("Retry-After", strconv.Itoa(retryAfter))
				c.Response().Header().Set("X-RateLimit-Limit", strconv.Itoa(rpm))
				c.Response().Header().Set("X-RateLimit-App", appID)
				return c.JSON(http.StatusTooManyRequests, map[string]string{
					"error":       "rate limit exceeded for app: " + appID,
					"retry_after": strconv.Itoa(retryAfter) + "s",
				})
			}

			// Expose limit headers on all responses for client visibility.
			c.Response().Header().Set("X-RateLimit-Limit", strconv.Itoa(rpm))
			c.Response().Header().Set("X-RateLimit-App", appID)
			return next(c)
		}
	}
}
