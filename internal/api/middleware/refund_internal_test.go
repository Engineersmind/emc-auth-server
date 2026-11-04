package middleware

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// refundScenario spends one token, refunds it, then counts how many tokens are
// left by spending until refused. A refund that worked leaves the bucket full.
func refundScenario(t *testing.T, key string, rate int) int {
	t.Helper()
	ctx := context.Background()
	store := &limiterStore{}
	if !allowVia(ctx, store, "test_refund", key, rate) {
		t.Fatal("first spend refused")
	}
	refundVia(ctx, store, "test_refund", key, rate)
	left := 0
	for i := 0; i < rate+2; i++ {
		if !allowVia(ctx, store, "test_refund", key, rate) {
			break
		}
		left++
	}
	return left
}

// Code review (PR #174): refunding the ONLY outstanding token must work in
// Redis mode too. redis_rate's AllowN(-1) silently dropped it, so Redis and
// in-process mode disagreed.
func TestRefund_SameInRedisAndInProcess(t *testing.T) {
	const rate = 5

	ConfigureDistributedRateLimiting(nil, zerolog.Nop())
	if left := refundScenario(t, fmt.Sprintf("refund-local-%d", time.Now().UnixNano()), rate); left != rate {
		t.Fatalf("in-process: %d tokens after spend+refund, want %d", left, rate)
	}

	rdb := testhelper.NewTestRedis(t) // skips when REDIS_URL is unset
	ConfigureDistributedRateLimiting(rdb, zerolog.Nop())
	defer ConfigureDistributedRateLimiting(nil, zerolog.Nop())
	if left := refundScenario(t, fmt.Sprintf("refund-redis-%d", time.Now().UnixNano()), rate); left != rate {
		t.Fatalf("Redis: %d tokens after spend+refund, want %d — the refund was dropped", left, rate)
	}
}

// A refund can never fill a bucket past its burst, in either mode.
func TestRefund_NeverExceedsBurst(t *testing.T) {
	const rate = 3
	ctx := context.Background()
	rdb := testhelper.NewTestRedis(t)
	ConfigureDistributedRateLimiting(rdb, zerolog.Nop())
	defer ConfigureDistributedRateLimiting(nil, zerolog.Nop())

	key := fmt.Sprintf("refund-cap-%d", time.Now().UnixNano())
	store := &limiterStore{}
	for i := 0; i < 5; i++ {
		refundVia(ctx, store, "test_refund", key, rate) // nothing spent yet
	}
	got := 0
	for i := 0; i < rate+3; i++ {
		if allowVia(ctx, store, "test_refund", key, rate) {
			got++
		}
	}
	if got != rate {
		t.Fatalf("after refunds on a full bucket: %d allowed, want exactly the burst %d", got, rate)
	}
}
