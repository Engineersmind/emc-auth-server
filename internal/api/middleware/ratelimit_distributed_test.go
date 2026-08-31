package middleware_test

import (
	"net/http"
	"testing"

	redisv9 "github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"

	"github.com/engineersmind/emc-auth-server/internal/api/middleware"
)

// TestDistributed_NilClientKeepsInProcessBuckets confirms the fallback: with no
// Redis configured the limiters behave exactly as before, so a single-instance
// deployment and the test suite do not gain a hard dependency on Redis.
func TestDistributed_NilClientKeepsInProcessBuckets(t *testing.T) {
	middleware.ConfigureDistributedRateLimiting(nil, zerolog.Nop())
	middleware.ResetStoresForTest()

	mw := middleware.LoginRateLimiter(middleware.DefaultRateLimitConfig())
	for i := 1; i <= 5; i++ {
		if got := makeRequest(t, mw, "198.51.100.7", "a@b.test"); got != http.StatusOK {
			t.Fatalf("attempt %d returned %d, want 200", i, got)
		}
	}
	if got := makeRequest(t, mw, "198.51.100.7", "a@b.test"); got != http.StatusTooManyRequests {
		t.Fatalf("6th attempt returned %d, want 429 — the in-process fallback is not limiting", got)
	}
}

// TestDistributed_UnreachableRedisFailsOpenToLocalBucket is the availability
// guarantee. A Redis outage must not stop authentication: the limiter falls back
// to its in-process bucket rather than refusing every request.
//
// Pointed at a closed port rather than a mock, because the behaviour under test
// is what happens when the client itself errors.
func TestDistributed_UnreachableRedisFailsOpenToLocalBucket(t *testing.T) {
	dead := redisv9.NewClient(&redisv9.Options{
		Addr:       "127.0.0.1:1", // reserved, nothing listens
		MaxRetries: -1,            // fail immediately rather than retrying per call
	})
	defer func() { _ = dead.Close() }()

	middleware.ConfigureDistributedRateLimiting(dead, zerolog.Nop())
	defer middleware.ConfigureDistributedRateLimiting(nil, zerolog.Nop())
	middleware.ResetStoresForTest()

	mw := middleware.LoginRateLimiter(middleware.DefaultRateLimitConfig())

	// Requests still succeed — Redis is unreachable, so the local bucket decides.
	if got := makeRequest(t, mw, "198.51.100.8", "c@d.test"); got != http.StatusOK {
		t.Fatalf("first attempt returned %d with Redis down, want 200 — a Redis "+
			"outage must not become an authentication outage", got)
	}

	// And the local bucket is genuinely still enforcing, not merely waved through:
	// four more consume the allowance, the sixth is refused.
	for i := 2; i <= 5; i++ {
		if got := makeRequest(t, mw, "198.51.100.8", "c@d.test"); got != http.StatusOK {
			t.Fatalf("attempt %d returned %d, want 200", i, got)
		}
	}
	if got := makeRequest(t, mw, "198.51.100.8", "c@d.test"); got != http.StatusTooManyRequests {
		t.Fatalf("6th attempt returned %d, want 429 — fail-open must fall back to "+
			"the local bucket, not disable limiting entirely", got)
	}
}

// TestDistributed_ReconfigureIsSafe confirms the switch can be flipped without
// leaving the limiters in a broken state, which matters because
// ConfigureDistributedRateLimiting is called once at startup but tests call it
// repeatedly.
func TestDistributed_ReconfigureIsSafe(t *testing.T) {
	for i := 0; i < 3; i++ {
		middleware.ConfigureDistributedRateLimiting(nil, zerolog.Nop())
	}
	middleware.ResetStoresForTest()

	mw := middleware.LoginRateLimiter(middleware.DefaultRateLimitConfig())
	if got := makeRequest(t, mw, "198.51.100.9", "e@f.test"); got != http.StatusOK {
		t.Fatalf("limiter broken after repeated reconfiguration: got %d", got)
	}
}
