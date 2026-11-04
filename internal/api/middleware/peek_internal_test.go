package middleware

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// peekAgreement spends a bucket one token at a time and, at every step, asks
// both peeks whether it is exhausted. firstExhaustedVia batches peeks into one
// Redis round trip (PR #174 review); it must answer exactly what exhaustedVia
// answers, or the resolver's admission check would drift from the buckets it
// guards.
func peekAgreement(t *testing.T, mode string) {
	t.Helper()
	const rate = 5
	ctx := context.Background()
	store := &limiterStore{}
	full := fmt.Sprintf("peek-%s-full-%d", mode, time.Now().UnixNano())
	key := fmt.Sprintf("peek-%s-%d", mode, time.Now().UnixNano())
	for step := 0; step <= rate+1; step++ {
		want := exhaustedVia(ctx, store, "test_peek", key, rate)
		b, got := firstExhaustedVia(ctx, store,
			bucketRef{"test_peek", full, rate}, // never spent: never the answer
			bucketRef{"test_peek", key, rate},
		)
		if got != want || (got && b.key != key) {
			t.Fatalf("%s, after %d spends: firstExhaustedVia = (%q, %v), exhaustedVia = %v", mode, step, b.key, got, want)
		}
		allowVia(ctx, store, "test_peek", key, rate)
	}
	if _, got := firstExhaustedVia(ctx, store, bucketRef{"test_peek", key, rate}); !got {
		t.Fatalf("%s: a bucket spent past its burst must read as exhausted", mode)
	}
}

func TestFirstExhausted_AgreesWithExhaustedVia(t *testing.T) {
	ConfigureDistributedRateLimiting(nil, zerolog.Nop())
	peekAgreement(t, "local")

	rdb := testhelper.NewTestRedis(t) // skips when REDIS_URL is unset
	ConfigureDistributedRateLimiting(rdb, zerolog.Nop())
	defer ConfigureDistributedRateLimiting(nil, zerolog.Nop())
	peekAgreement(t, "redis")
}

// The batched refund must give back exactly what the single refund does.
func TestRefundAll_SameAsRefundEach(t *testing.T) {
	const rate = 5
	ctx := context.Background()
	rdb := testhelper.NewTestRedis(t)
	ConfigureDistributedRateLimiting(rdb, zerolog.Nop())
	defer ConfigureDistributedRateLimiting(nil, zerolog.Nop())

	store := &limiterStore{}
	keys := []string{fmt.Sprintf("refundall-a-%d", time.Now().UnixNano()), fmt.Sprintf("refundall-b-%d", time.Now().UnixNano())}
	var spent []spentToken
	for _, k := range keys {
		if !allowVia(ctx, store, "test_refund", k, rate) {
			t.Fatal("first spend refused")
		}
		spent = append(spent, spentToken{label: "test_refund", key: k, rate: rate})
	}
	refundAllVia(ctx, store, spent)
	for _, k := range keys {
		left := 0
		for i := 0; i < rate+2; i++ {
			if !allowVia(ctx, store, "test_refund", k, rate) {
				break
			}
			left++
		}
		if left != rate {
			t.Fatalf("%s: %d tokens after spend + batched refund, want %d", k, left, rate)
		}
	}
}
