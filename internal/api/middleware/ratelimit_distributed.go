package middleware

import (
	"context"
	"sync"
	"time"

	"github.com/go-redis/redis_rate/v10"
	redisv9 "github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"

	"github.com/engineersmind/emc-auth-server/internal/metrics"
)

// Distributed rate limiting.
//
// Every limiter in this package kept its buckets in a per-process sync.Map. That
// is correct for one instance and quietly wrong for two: each process holds its
// own counters, so a client behind a load balancer gets N times the intended
// allowance simply by having requests land on different instances. At the
// AUTH-07 login limit of 5/min, three instances is 15/min — the brute-force
// protection weakens in proportion to how well the service scales, and nothing
// surfaces that it has happened.
//
// The buckets move to Redis, which this server already runs and already depends
// on for OTP sessions, authorization-code state, and the per-application limits
// in applimit.go. No new infrastructure; the same redis_rate library, the same
// fail-open contract.
//
// # Fail-open is deliberate
//
// When Redis is unreachable the request is ALLOWED, counted on
// rate_limit_fail_open_total, and logged. This is the same decision applimit.go
// made, for the same reason: an authentication server that refuses every login
// because a supporting service blipped has converted a degraded dependency into
// a full outage. Under-enforcing a rate limit for the duration of a Redis
// incident is the lesser failure, and the counter is what stops it being a
// silent one.
//
// The in-memory fallback is retained rather than removed. With no Redis client
// configured — tests, local development, a single-instance deployment that has
// not provisioned one — the limiters behave exactly as before. That keeps this
// change from being a hard dependency on Redis for anyone who does not need it.

// distributedLimiter wraps redis_rate with the fallback and observability the
// auth limiters need. A nil *distributedLimiter is valid and means "in-memory
// only", which is what makes the fallback path free of nil checks at call sites.
type distributedLimiter struct {
	limiter *redis_rate.Limiter
	logger  zerolog.Logger
}

var (
	// sharedLimiter is process-wide because the limiters are package-level
	// middleware constructors with no injection point of their own. Set once at
	// startup by ConfigureDistributedRateLimiting, read on every request.
	sharedLimiter   *distributedLimiter
	sharedLimiterMu sync.RWMutex
)

// ConfigureDistributedRateLimiting switches the auth limiters from per-process
// buckets to Redis-backed ones. Called once at startup, before any request is
// served.
//
// A nil client is not an error: it leaves every limiter on its in-memory store,
// which is the correct behaviour for a single instance and for tests. Callers
// that run more than one instance MUST pass a client, or their limits multiply
// by the instance count.
func ConfigureDistributedRateLimiting(client *redisv9.Client, logger zerolog.Logger) {
	sharedLimiterMu.Lock()
	defer sharedLimiterMu.Unlock()

	if client == nil {
		sharedLimiter = nil
		logger.Warn().Msg("rate limiting: no Redis client — buckets are per-process. " +
			"Running more than one instance multiplies every limit by the instance count.")
		return
	}

	sharedLimiter = &distributedLimiter{
		limiter: redis_rate.NewLimiter(client),
		logger:  logger,
	}
	logger.Info().Msg("rate limiting: Redis-backed, shared across instances")
}

// distributed returns the configured limiter, or nil when none is set.
func distributed() *distributedLimiter {
	sharedLimiterMu.RLock()
	defer sharedLimiterMu.RUnlock()
	return sharedLimiter
}

// allowShared reports whether one request against key is permitted at r per
// minute, and whether the decision came from Redis at all.
//
// The second return value exists so callers can fall back to their in-memory
// store rather than guessing: `false, false` means "Redis said no" is NOT what
// happened — it means Redis could not answer, and the local bucket should decide
// instead. Collapsing that into a single bool is how a Redis outage turns into
// either an open door or a closed one, depending on which way the collapse went.
//
// label names the limiter in metrics and must match the label the caller uses
// for RateLimitHits, so a rejection and a fail-open on the same surface line up
// on a dashboard.
func allowShared(ctx context.Context, label, key string, r int) (allowed, decided bool) {
	d := distributed()
	if d == nil {
		return false, false
	}

	res, err := d.limiter.Allow(ctx, key, redis_rate.Limit{
		Rate:   r,
		Burst:  r,
		Period: time.Minute,
	})
	if err != nil {
		// Fail open. See the package comment above for why this is the right
		// direction for an auth server, and why it must be counted.
		metrics.RateLimitFailOpen.WithLabelValues(label, "redis_error").Inc()
		d.logger.Warn().Err(err).Str("limiter", label).
			Msg("rate limiting: Redis error — falling back to the in-process bucket")
		return false, false
	}

	return res.Allowed > 0, true
}

// allowSharedEvery is allowShared for buckets slower than one token per minute,
// where an integer per-minute rate cannot express the interval — the signing-key
// rotation limiter, for instance, which is one token per hour.
//
// redis_rate takes a rate over a period, so an interval of 1h with burst 2
// becomes Rate 2, Burst 2, Period 2h: the same refill in the same window.
func allowSharedEvery(ctx context.Context, label, key string, interval time.Duration, burst int) (allowed, decided bool) {
	d := distributed()
	if d == nil {
		return false, false
	}

	res, err := d.limiter.Allow(ctx, key, redis_rate.Limit{
		Rate:   burst,
		Burst:  burst,
		Period: interval * time.Duration(burst),
	})
	if err != nil {
		metrics.RateLimitFailOpen.WithLabelValues(label, "redis_error").Inc()
		d.logger.Warn().Err(err).Str("limiter", label).
			Msg("rate limiting: Redis error — falling back to the in-process bucket")
		return false, false
	}

	return res.Allowed > 0, true
}

// allowVia is the decision every converted limiter makes: ask Redis, and use the
// local bucket only when Redis did not answer.
//
// Written once here rather than repeated at each call site, because the failure
// mode of getting it wrong is subtle — consuming a token from BOTH buckets on
// every request halves the effective limit, and consuming from neither disables
// it. The local limiter is touched only on the path where Redis abstained.
func allowVia(ctx context.Context, store *limiterStore, label, key string, r int) bool {
	if allowed, decided := allowShared(ctx, label, key, r); decided {
		return allowed
	}
	return store.getOrCreate(key, r).Allow()
}

// allowViaEvery is allowVia for interval-based buckets.
func allowViaEvery(ctx context.Context, store *limiterStore, label, key string, interval time.Duration, burst int) bool {
	if allowed, decided := allowSharedEvery(ctx, label, key, interval, burst); decided {
		return allowed
	}
	return store.getOrCreateEvery(key, interval, burst).Allow()
}
