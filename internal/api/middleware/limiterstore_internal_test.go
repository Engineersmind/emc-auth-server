package middleware

import (
	"testing"
	"time"
)

// A capped store must stop growing at its cap and, past it, FAIL CLOSED: every
// new key shares one overflow bucket rather than getting an unlimited limiter
// (PR #174 review — the old fail-open lifted every application's per-user
// limits at once). The in-process fallback only; with Redis configured these
// buckets are not held here.
func TestLimiterStore_CapFailsClosed(t *testing.T) {
	s := &limiterStore{max: 3, label: "test"}
	for i, key := range []string{"a", "b", "c"} {
		if !s.getOrCreate(key, 1).Allow() {
			t.Fatalf("key %d under the cap was refused", i)
		}
	}
	if !s.getOrCreate("d", 1).Allow() {
		t.Fatal("the first key past the cap must get the overflow bucket's token")
	}
	if s.getOrCreate("e", 1).Allow() {
		t.Fatal("a second new key past the cap must share the (now empty) overflow bucket")
	}
	if n := s.n.Load(); n != 3 {
		t.Fatalf("store holds %d keys, want 3", n)
	}

	// Existing keys keep their own buckets at the cap.
	if s.getOrCreate("a", 1) == s.getOrCreate("d", 1) {
		t.Fatal("an existing key must keep its own bucket when the store is full")
	}

	// Eviction frees room.
	s.cleanup(-1)
	if n := s.n.Load(); n != 0 {
		t.Fatalf("after cleanup the store holds %d keys, want 0", n)
	}
	if !s.getOrCreate("d", 1).Allow() {
		t.Fatal("after eviction a new key must get a real bucket")
	}
}

// One partition (one limiter + one application) filling up overflows only
// itself; other applications' new users still get buckets of their own.
func TestLimiterStore_PartitionOverflowsOnlyItself(t *testing.T) {
	s := &limiterStore{max: 100, partition: appUserPartition, partitionMax: 3, label: "test"}
	for i := 0; i < 3; i++ {
		s.getOrCreate("app_login_user:66:"+string(rune('a'+i)), 1)
	}
	if !s.getOrCreate("app_login_user:66:x", 1).Allow() || s.getOrCreate("app_login_user:66:y", 1).Allow() {
		t.Fatal("past its cap, the attacker's partition must share one overflow bucket")
	}
	for i := 0; i < 3; i++ {
		if !s.getOrCreate("app_login_user:12:"+string(rune('a'+i)), 1).Allow() {
			t.Fatalf("another application's user %d was refused: one partition overflowed another", i)
		}
	}
}

// At the cap, buckets idle long enough to be full again are evicted first,
// which loses nothing, before anything overflows.
func TestLimiterStore_SweepsIdleBucketsBeforeOverflowing(t *testing.T) {
	s := &limiterStore{max: 2, idleFull: time.Minute, label: "test"}
	s.getOrCreate("old", 1)
	s.getOrCreate("busy", 1)
	if v, ok := s.store.Load("old"); ok {
		v.(*limiterEntry).lastSeen = time.Now().Add(-2 * time.Minute)
	}
	s.getOrCreate("new", 1)
	if _, ok := s.store.Load("new"); !ok {
		t.Fatal("a new key must get its own bucket in the room an idle, already-full bucket held")
	}
	if _, ok := s.store.Load("old"); ok {
		t.Fatal("the idle bucket must have been swept")
	}
	if _, ok := s.store.Load("busy"); !ok {
		t.Fatal("a recently used bucket must not be swept")
	}
}

func TestLimiterStore_UnboundedByDefault(t *testing.T) {
	s := &limiterStore{}
	for i := 0; i < 1000; i++ {
		if !s.getOrCreate(string(rune('a'+i%26))+string(rune(i)), 5).Allow() {
			t.Fatalf("an unbounded store refused a fresh key %d", i)
		}
	}
}
