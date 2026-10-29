package middleware

import "testing"

// A capped store must stop growing at its cap and let requests through rather
// than grow until the process is killed (the in-process fallback only; with
// Redis configured these buckets are not held here).
func TestLimiterStore_CapFailsOpen(t *testing.T) {
	s := &limiterStore{max: 3, label: "test"}
	for i, key := range []string{"a", "b", "c"} {
		if l := s.getOrCreate(key, 1); l == unlimitedLimiter {
			t.Fatalf("key %d under the cap got the unlimited limiter", i)
		}
	}
	if l := s.getOrCreate("d", 1); l != unlimitedLimiter {
		t.Fatal("a new key past the cap must get the unlimited limiter")
	}
	if n := s.n.Load(); n != 3 {
		t.Fatalf("store holds %d keys, want 3", n)
	}

	// Existing keys keep their own buckets at the cap.
	if l := s.getOrCreate("a", 1); l == unlimitedLimiter {
		t.Fatal("an existing key must keep its bucket when the store is full")
	}

	// Eviction frees room.
	s.cleanup(-1)
	if n := s.n.Load(); n != 0 {
		t.Fatalf("after cleanup the store holds %d keys, want 0", n)
	}
	if l := s.getOrCreate("d", 1); l == unlimitedLimiter {
		t.Fatal("after eviction a new key must get a real bucket")
	}
}

func TestLimiterStore_UnboundedByDefault(t *testing.T) {
	s := &limiterStore{}
	for i := 0; i < 1000; i++ {
		if l := s.getOrCreate(string(rune('a'+i%26))+string(rune(i)), 5); l == unlimitedLimiter {
			t.Fatalf("an unbounded store handed out the unlimited limiter at key %d", i)
		}
	}
}
