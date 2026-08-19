package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// Nonce burn-on-use (security audit 2026-08-07, FED-3).
//
// Against a real Redis rather than a fake, deliberately: the property under test
// is that SET NX makes the test-and-claim a single atomic operation, and a stub
// that returns whatever it is told proves nothing about that. Skips when
// REDIS_URL is unset, like every other Redis-backed test here.

func newNonceStore(t *testing.T) *AuthzSessionStore {
	t.Helper()
	return NewAuthzSessionStore(testhelper.NewTestRedis(t))
}

// uniqueNonce returns a value no previous run has used.
//
// Necessary, not decorative: a burned nonce is remembered for authzNonceTTL (15
// minutes) against a shared Redis, so a fixed literal makes the second run of
// the suite fail on state the first run left behind. That is the kind of
// self-inflicted flake CLAUDE.md deferred #8 and #9 are already about.
func uniqueNonce(t *testing.T, label string) string {
	t.Helper()
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return label + "-" + hex.EncodeToString(b[:])
}

func TestBurnNonce_FirstUseSucceedsSecondIsRefused(t *testing.T) {
	store := newNonceStore(t)
	ctx := context.Background()

	nonce := uniqueNonce(t, "first-use-then-replay")
	if err := store.BurnNonce(ctx, 1, "client-burn-basic", nonce); err != nil {
		t.Fatalf("first burn: want nil, got %v", err)
	}

	err := store.BurnNonce(ctx, 1, "client-burn-basic", nonce)
	if !errors.Is(err, ErrNonceReplayed) {
		t.Fatalf("second burn: want ErrNonceReplayed, got %v", err)
	}

	// A third attempt must stay refused. Guards against an implementation that
	// consumed the marker on the failing read.
	if err := store.BurnNonce(ctx, 1, "client-burn-basic", nonce); !errors.Is(err, ErrNonceReplayed) {
		t.Fatalf("third burn: want ErrNonceReplayed, got %v", err)
	}
}

func TestBurnNonce_EmptyNonceIsNotAReplay(t *testing.T) {
	store := newNonceStore(t)
	ctx := context.Background()

	// A nonce is OPTIONAL in the authorization-code flow, so requests without one
	// must never be refused — and must not collide with each other, which is what
	// would happen if "" were hashed and stored like any other value.
	for i := 0; i < 3; i++ {
		if err := store.BurnNonce(ctx, 1, "client-no-nonce", ""); err != nil {
			t.Fatalf("burn %d of empty nonce: want nil, got %v", i, err)
		}
	}
}

func TestBurnNonce_ScopedPerClientAndTenant(t *testing.T) {
	store := newNonceStore(t)
	ctx := context.Background()

	// The same nonce value from a different client, or a different tenant, is a
	// different request. A global key space would let one client with a weak
	// generator deny another client's sign-ins.
	shared := uniqueNonce(t, "collision-across-clients")

	if err := store.BurnNonce(ctx, 1, "client-scope-a", shared); err != nil {
		t.Fatalf("tenant 1 / client a: want nil, got %v", err)
	}
	if err := store.BurnNonce(ctx, 1, "client-scope-b", shared); err != nil {
		t.Fatalf("tenant 1 / client b: same nonce must be independent, got %v", err)
	}
	if err := store.BurnNonce(ctx, 2, "client-scope-a", shared); err != nil {
		t.Fatalf("tenant 2 / client a: same nonce must be independent, got %v", err)
	}

	// Each of the three is now individually spent.
	for _, tc := range []struct {
		tenant   int64
		clientID string
	}{{1, "client-scope-a"}, {1, "client-scope-b"}, {2, "client-scope-a"}} {
		if err := store.BurnNonce(ctx, tc.tenant, tc.clientID, shared); !errors.Is(err, ErrNonceReplayed) {
			t.Fatalf("tenant %d / %s: want ErrNonceReplayed, got %v", tc.tenant, tc.clientID, err)
		}
	}
}

func TestReleaseNonce_MakesTheValueUsableAgain(t *testing.T) {
	store := newNonceStore(t)
	ctx := context.Background()

	// The path this exists for: the burn succeeded, then code issuance failed, so
	// nothing was actually consumed and the client's retry must work.
	nonce := uniqueNonce(t, "released-after-failure")
	if err := store.BurnNonce(ctx, 1, "client-release", nonce); err != nil {
		t.Fatalf("burn: want nil, got %v", err)
	}
	store.ReleaseNonce(ctx, 1, "client-release", nonce)

	if err := store.BurnNonce(ctx, 1, "client-release", nonce); err != nil {
		t.Fatalf("burn after release: want nil, got %v", err)
	}
}

func TestBurnNonce_ConcurrentBurnsYieldExactlyOneWinner(t *testing.T) {
	store := newNonceStore(t)
	ctx := context.Background()

	// The race the atomic SET NX exists to close. An EXISTS-then-SET
	// implementation passes every test above and fails this one.
	nonce := uniqueNonce(t, "concurrent")
	const attempts = 20

	errs := make(chan error, attempts)
	start := make(chan struct{})
	for i := 0; i < attempts; i++ {
		go func() {
			<-start
			errs <- store.BurnNonce(ctx, 1, "client-concurrent", nonce)
		}()
	}
	close(start)

	var succeeded, replayed int
	for i := 0; i < attempts; i++ {
		switch err := <-errs; {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrNonceReplayed):
			replayed++
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}

	if succeeded != 1 {
		t.Fatalf("want exactly 1 winner out of %d concurrent burns, got %d", attempts, succeeded)
	}
	if replayed != attempts-1 {
		t.Fatalf("want %d replay rejections, got %d", attempts-1, replayed)
	}
}

func TestBurnNonce_KeyDoesNotContainTheRawNonce(t *testing.T) {
	// The nonce arrives verbatim off a query string. An unbounded or crafted
	// value must not flow into the Redis key space — the same reasoning
	// applimit.go hashes client_id for its cache keys.
	raw := strings.Repeat("A", 4096) + ":evil*pattern"
	key := authzNonceKey(1, "client-key-shape", raw)

	if strings.Contains(key, raw) || strings.Contains(key, "evil*pattern") {
		t.Fatalf("key embeds the raw nonce: %q", key)
	}
	if got, want := len(key), len("oauth:authz:nonce:")+64; got != want {
		t.Fatalf("key length = %d, want %d (prefix + hex sha-256)", got, want)
	}

	// Distinct inputs must not collide at the field boundaries. Joining the raw
	// values on ":" would make ("a:b", "c") and ("a", "b:c") the same key — one
	// client's nonce spending another's.
	if authzNonceKey(1, "ab", "c") == authzNonceKey(1, "a", "bc") {
		t.Fatal("client_id/nonce boundary is ambiguous: distinct inputs share a key")
	}
	if authzNonceKey(1, "a:b", "c") == authzNonceKey(1, "a", "b:c") {
		t.Fatal("a separator inside client_id shifts the boundary: distinct inputs share a key")
	}
	if authzNonceKey(1, "c", "x") == authzNonceKey(11, "c", "x") {
		t.Fatal("tenant boundary is ambiguous: distinct tenants share a key")
	}
}

func TestAuthzNonceTTL_MatchesIDTokenLifetime(t *testing.T) {
	// The replay window is the window in which a second ID token would still be
	// accepted, so these two must move together. If IDTokenTTL is ever changed,
	// this is the line that says the nonce memory has to follow.
	if authzNonceTTL != IDTokenTTL {
		t.Fatalf("authzNonceTTL = %v, want IDTokenTTL = %v", authzNonceTTL, IDTokenTTL)
	}
}
