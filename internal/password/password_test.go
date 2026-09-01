package password

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

func testHasher(t *testing.T) *Hasher {
	t.Helper()
	return NewHasher(DefaultParams())
}

func TestHash_RoundTrips(t *testing.T) {
	h := testHasher(t)
	ctx := context.Background()

	const pw = "correct horse battery staple"
	enc, err := h.Hash(ctx, pw)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if err := h.Verify(ctx, pw, enc); err != nil {
		t.Fatalf("Verify of freshly hashed password: %v", err)
	}
}

func TestHash_ProducesPHCFormat(t *testing.T) {
	h := testHasher(t)
	enc, err := h.Hash(context.Background(), "whatever")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}

	if !strings.HasPrefix(enc, "$argon2id$") {
		t.Fatalf("hash does not carry its algorithm: %q", enc)
	}
	if got := Identify(enc); got != AlgorithmArgon2id {
		t.Fatalf("Identify = %q, want argon2id", got)
	}

	p, salt, key, err := DecodeArgon2id(enc)
	if err != nil {
		t.Fatalf("DecodeArgon2id: %v", err)
	}
	want := DefaultParams()
	if p.Memory != want.Memory || p.Iterations != want.Iterations || p.Parallelism != want.Parallelism {
		t.Fatalf("encoded params %+v do not match configured %+v", p, want)
	}
	// Widen the uint32 rather than narrowing len(): same comparison, no
	// conversion that could wrap.
	if len(salt) != int(want.SaltLength) {
		t.Fatalf("salt length %d, want %d", len(salt), want.SaltLength)
	}
	if len(key) != int(want.KeyLength) {
		t.Fatalf("key length %d, want %d", len(key), want.KeyLength)
	}
}

// TestHash_SaltIsUniquePerCall is the property that makes a stolen dump
// expensive: identical passwords must not produce identical hashes, or one
// precomputed table covers every account that shares a common password.
func TestHash_SaltIsUniquePerCall(t *testing.T) {
	h := testHasher(t)
	ctx := context.Background()
	const pw = "same-password-everywhere"

	seen := make(map[string]bool)
	for i := 0; i < 8; i++ {
		enc, err := h.Hash(ctx, pw)
		if err != nil {
			t.Fatalf("Hash: %v", err)
		}
		if seen[enc] {
			t.Fatal("identical hash produced twice — salt is not unique per call")
		}
		seen[enc] = true
	}
}

func TestVerify_RejectsWrongPassword(t *testing.T) {
	h := testHasher(t)
	ctx := context.Background()

	enc, err := h.Hash(ctx, "the-real-password")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	for _, wrong := range []string{"", "the-real-password ", "The-Real-Password", "wrong"} {
		if err := h.Verify(ctx, wrong, enc); err == nil {
			t.Fatalf("Verify accepted %q", wrong)
		}
	}
}

// TestVerify_AcceptsLegacyBcrypt is the migration guarantee: the existing
// credential corpus keeps working after the switch, with no reset.
func TestVerify_AcceptsLegacyBcrypt(t *testing.T) {
	h := testHasher(t)
	ctx := context.Background()
	const pw = "legacy-user-password"

	for _, cost := range []int{10, 11, 12} {
		legacy, err := bcrypt.GenerateFromPassword([]byte(pw), cost)
		if err != nil {
			t.Fatalf("bcrypt at cost %d: %v", cost, err)
		}
		if err := h.Verify(ctx, pw, string(legacy)); err != nil {
			t.Fatalf("cost-%d bcrypt hash rejected after migration to argon2id: %v", cost, err)
		}
		if err := h.Verify(ctx, "wrong", string(legacy)); err == nil {
			t.Fatalf("cost-%d bcrypt hash accepted a wrong password", cost)
		}
	}
}

func TestVerify_RejectsMalformedHashes(t *testing.T) {
	h := testHasher(t)
	ctx := context.Background()

	for _, bad := range []string{
		"",
		"not-a-hash",
		"$argon2id$",
		"$argon2id$v=19$m=47104,t=1,p=1$onlyfourfields",
		"$argon2id$v=19$m=0,t=0,p=0$c2FsdA$aGFzaA",
		"$argon2id$v=99$m=47104,t=1,p=1$c2FsdA$aGFzaA",
		"$argon2d$v=19$m=47104,t=1,p=1$c2FsdA$aGFzaA",
		"$scrypt$whatever",
	} {
		if err := h.Verify(ctx, "anything", bad); err == nil {
			t.Fatalf("Verify accepted malformed hash %q", bad)
		}
	}
}

// TestVerify_MalformedIsIndistinguishableFromWrongPassword pins the error
// channel: a caller must not be able to tell a corrupt stored record from a bad
// password, or the difference becomes an oracle.
func TestVerify_MalformedIsIndistinguishableFromWrongPassword(t *testing.T) {
	h := testHasher(t)
	ctx := context.Background()

	enc, err := h.Hash(ctx, "real")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}

	wrongPW := h.Verify(ctx, "wrong", enc)
	malformed := h.Verify(ctx, "wrong", "$argon2id$garbage")

	if wrongPW == nil || malformed == nil {
		t.Fatal("expected both to fail")
	}
	if wrongPW.Error() != malformed.Error() {
		t.Fatalf("distinguishable errors: wrong-password %q vs malformed %q",
			wrongPW, malformed)
	}
}

func TestNeedsRehash(t *testing.T) {
	h := testHasher(t)
	ctx := context.Background()

	current, err := h.Hash(ctx, "pw")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if h.NeedsRehash(current) {
		t.Fatal("a freshly written hash reports as stale")
	}

	legacy, err := bcrypt.GenerateFromPassword([]byte("pw"), 11)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	if !h.NeedsRehash(string(legacy)) {
		t.Fatal("bcrypt hash not flagged for migration")
	}

	for _, bad := range []string{"", "junk", "$argon2id$broken"} {
		if !h.NeedsRehash(bad) {
			t.Fatalf("malformed hash %q not flagged for rewrite", bad)
		}
	}
}

// TestNeedsRehash_DetectsParameterChangeInBothDirections is why the fleet
// converges. A raise must upgrade existing users; a lower must reach them too,
// or the latency win never arrives for accounts that already exist.
func TestNeedsRehash_DetectsParameterChangeInBothDirections(t *testing.T) {
	ctx := context.Background()
	base := DefaultParams()

	stronger := base
	stronger.Memory = base.Memory * 2
	weaker := base
	weaker.Memory = base.Memory / 2

	for name, other := range map[string]Params{"stronger": stronger, "weaker": weaker} {
		otherHasher := NewHasher(other)
		enc, err := otherHasher.Hash(ctx, "pw")
		if err != nil {
			t.Fatalf("%s: Hash: %v", name, err)
		}
		if !NewHasher(base).NeedsRehash(enc) {
			t.Fatalf("%s parameters not detected as stale against the default", name)
		}
	}
}

// TestVerify_UsesStoredParametersNotCurrent is the compatibility guarantee that
// makes parameter changes safe: a hash written under old settings must still
// verify after the defaults move.
func TestVerify_UsesStoredParametersNotCurrent(t *testing.T) {
	ctx := context.Background()
	const pw = "user-password"

	old := DefaultParams()
	old.Memory = 19456
	old.Iterations = 2

	enc, err := NewHasher(old).Hash(ctx, pw)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}

	// A hasher configured with entirely different parameters must still verify it.
	if err := NewHasher(DefaultParams()).Verify(ctx, pw, enc); err != nil {
		t.Fatalf("hash written under old parameters stopped verifying: %v", err)
	}
}

func TestIdentify(t *testing.T) {
	cases := map[string]Algorithm{
		"$argon2id$v=19$m=1,t=1,p=1$c2FsdA$aGFzaA": AlgorithmArgon2id,
		"$2a$11$abcdefghijklmnopqrstuv":            AlgorithmBcrypt,
		"$2b$11$abcdefghijklmnopqrstuv":            AlgorithmBcrypt,
		"$2y$11$abcdefghijklmnopqrstuv":            AlgorithmBcrypt,
		"$scrypt$x":                                AlgorithmUnknown,
		"":                                         AlgorithmUnknown,
	}
	for in, want := range cases {
		if got := Identify(in); got != want {
			t.Fatalf("Identify(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNewHasher_ZeroFieldsFallBackToDefaults(t *testing.T) {
	h := NewHasher(Params{})
	if got, want := h.Params(), DefaultParams(); got != want {
		t.Fatalf("zero Params produced %+v, want defaults %+v", got, want)
	}
}

// TestParams_MeetOWASPMinimum pins the configuration against the published
// guidance, so tuning for latency cannot silently drop below it.
func TestParams_MeetOWASPMinimum(t *testing.T) {
	p := DefaultParams()

	// OWASP: m=47104 (46MiB) t=1 p=1, or m=19456 (19MiB) t=2 p=1, among others.
	// Both floors below are the weakest OWASP-sanctioned settings.
	const minMemoryKiB = 19456
	const minIterations = 1

	if p.Memory < minMemoryKiB {
		t.Fatalf("Memory %d KiB is below the weakest OWASP-recommended setting (%d KiB)",
			p.Memory, minMemoryKiB)
	}
	if p.Iterations < minIterations {
		t.Fatalf("Iterations %d below minimum %d", p.Iterations, minIterations)
	}
	if p.SaltLength < 16 {
		t.Fatalf("SaltLength %d below the specification's recommended 16 bytes", p.SaltLength)
	}
	if p.KeyLength < 32 {
		t.Fatalf("KeyLength %d below 32 bytes", p.KeyLength)
	}
	if p.Memory == 19456 && p.Iterations < 2 {
		t.Fatal("m=19MiB requires t>=2 per OWASP")
	}
}

func TestVersion_MatchesLibrary(t *testing.T) {
	h := testHasher(t)
	enc, err := h.Hash(context.Background(), "pw")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if !strings.Contains(enc, "$v=19$") || argon2.Version != 19 {
		t.Fatalf("unexpected argon2 version: hash %q, library %d", enc, argon2.Version)
	}
}

// --- concurrency and memory bounding -------------------------------------

// TestMemoryGuard_BoundsConcurrency is the property that keeps a login spike
// from becoming an OOM kill: never more than maxConcurrent derivations at once.
func TestMemoryGuard_BoundsConcurrency(t *testing.T) {
	const limit = 3
	h := NewHasherWithConcurrency(DefaultParams(), limit)
	ctx := context.Background()

	var mu sync.Mutex
	peak := 0

	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			done := make(chan struct{})
			go func() {
				defer close(done)
				_, _ = h.Hash(ctx, "concurrent")
			}()
			// Sample in-flight while work is running.
			for {
				select {
				case <-done:
					return
				default:
					mu.Lock()
					if n := h.InFlight(); n > peak {
						peak = n
					}
					mu.Unlock()
					time.Sleep(time.Millisecond)
				}
			}
		}()
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if peak > limit {
		t.Fatalf("observed %d concurrent derivations, cap is %d — peak memory would exceed the budget", peak, limit)
	}
}

// TestMemoryGuard_RespectsContext confirms a client that hangs up does not hold
// a queue slot, which is what keeps a spike from compounding.
func TestMemoryGuard_RespectsContext(t *testing.T) {
	h := NewHasherWithConcurrency(DefaultParams(), 1)

	// Occupy the single slot.
	release := make(chan struct{})
	started := make(chan struct{})
	go func() {
		ctx := context.Background()
		close(started)
		for {
			select {
			case <-release:
				return
			default:
				_, _ = h.Hash(ctx, "occupier")
			}
		}
	}()
	<-started
	defer close(release)

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	if _, err := h.Hash(cancelled, "queued"); err == nil {
		t.Fatal("Hash succeeded with a cancelled context")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("cancelled Hash waited %v instead of returning promptly", elapsed)
	}
}

func TestPeakMemoryBytes(t *testing.T) {
	h := NewHasherWithConcurrency(DefaultParams(), 8)
	want := uint64(47104) * 1024 * 8
	if got := h.PeakMemoryBytes(); got != want {
		t.Fatalf("PeakMemoryBytes = %d, want %d", got, want)
	}
}

func TestDefaultMaxConcurrent_AtLeastTwo(t *testing.T) {
	if got := DefaultMaxConcurrent(); got < 2 {
		t.Fatalf("DefaultMaxConcurrent = %d, want >= 2", got)
	}
}

// --- benchmarks ----------------------------------------------------------

func BenchmarkHash(b *testing.B) {
	h := NewHasher(DefaultParams())
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := h.Hash(ctx, "benchmark-password"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyArgon2id(b *testing.B) {
	h := NewHasher(DefaultParams())
	ctx := context.Background()
	enc, err := h.Hash(ctx, "benchmark-password")
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := h.Verify(ctx, "benchmark-password", enc); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyBcryptLegacy(b *testing.B) {
	h := NewHasher(DefaultParams())
	ctx := context.Background()
	enc, err := bcrypt.GenerateFromPassword([]byte("benchmark-password"), 11)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := h.Verify(ctx, "benchmark-password", string(enc)); err != nil {
			b.Fatal(err)
		}
	}
}
