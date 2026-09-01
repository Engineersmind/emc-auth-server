// Package password hashes and verifies user passwords.
//
// It exists so the rest of the server never names a hashing algorithm. Callers
// Hash, Verify, and ask NeedsRehash whether a stored credential is stale; which
// algorithm and parameters back those calls is decided here and can change
// without touching a single call site.
//
// # Algorithm
//
// Argon2id, the winner of the 2015 Password Hashing Competition and OWASP's
// first choice for password storage. Bcrypt hashes are still VERIFIED — the
// existing corpus keeps working — but nothing new is written with it.
//
// The reason is memory hardness, and it matters for one specific attacker: the
// one who has stolen the hash dump and is cracking it offline. Bcrypt uses ~4KiB
// regardless of its cost factor, so a GPU with thousands of cores runs thousands
// of guesses in parallel, and raising the cost slows each guess linearly while
// the attacker's parallelism scales far faster. Argon2id at 46MiB forces every
// parallel guess to hold 46MiB, so a 24GB card runs ~500 at once instead of tens
// of thousands. The defence shifts from "how slow is one guess" to "how much
// memory must the attacker buy", which is the expensive axis.
//
// Argon2id specifically — the hybrid — resists GPU cracking like Argon2d and
// side-channel timing like Argon2i.
//
// # Encoding
//
// Hashes are stored in PHC string format:
//
//	$argon2id$v=19$m=47104,t=1,p=1$<b64salt>$<b64hash>
//
// Self-describing, so parameters travel with the hash. A credential written
// under old parameters keeps verifying under those parameters and is upgraded
// opportunistically by NeedsRehash — the fleet converges without a reset, and
// parameters can be raised as hardware improves.
//
// The stored column is TEXT, and bcrypt's own "$2a$..." is equally
// self-describing, which is what lets both live side by side during migration.
package password

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// ErrMismatch is returned when a password does not match its hash. It is
// deliberately the only failure a caller can distinguish: a malformed hash, an
// unknown algorithm, and a wrong password all present identically, so nothing
// about the stored credential leaks through the error channel.
var ErrMismatch = errors.New("password: mismatch")

// Algorithm identifies which scheme produced a hash.
type Algorithm string

const (
	AlgorithmArgon2id Algorithm = "argon2id"
	AlgorithmBcrypt   Algorithm = "bcrypt"
	AlgorithmUnknown  Algorithm = "unknown"
)

// maxFieldLen caps the decoded salt and digest read out of a stored PHC string.
//
// Both are narrowed to the uint32 argon2.IDKey takes, so an unbounded length
// would wrap on a 64-bit platform. 1 MiB is orders of magnitude above any real
// value (OWASP: 16-byte salt, 32-byte digest) and far below the wrap point, so
// it refuses only a corrupt or hostile row. See DecodeArgon2id.
const maxFieldLen = 1 << 20

// Params are the Argon2id cost parameters.
//
// Defaults follow OWASP's recommended configuration for Argon2id: m=46MiB, t=1,
// p=1. OWASP publishes several equivalent-strength settings that trade memory
// against iterations; this is the highest-memory of them, chosen because memory
// is the axis an attacker finds expensive to scale, and because at ~48ms
// measured it is comfortably the fastest option that still meets the guidance.
type Params struct {
	// Memory in KiB. The dominant security parameter.
	Memory uint32
	// Iterations (time cost).
	Iterations uint32
	// Parallelism (lanes). See DefaultParams for why this is 1.
	Parallelism uint8
	// SaltLength in bytes. 16 is the Argon2 specification's recommendation.
	SaltLength uint32
	// KeyLength in bytes.
	KeyLength uint32
}

// DefaultParams is the parameter set used for all new hashes.
//
// Parallelism is 1, not runtime.NumCPU(). Lanes divide ONE hash across cores,
// which shortens a single login but does nothing for throughput — and this
// server's load is many concurrent logins, not one at a time. Under concurrency
// the goroutines already occupy every core, so lanes only add contention. Worse,
// parallelism is baked into the hash: a fleet whose members disagree on NumCPU
// would write mutually incomparable parameters. A fixed 1 is deterministic,
// reproducible across machines, and leaves the cores free to serve other logins.
func DefaultParams() Params {
	return Params{
		Memory:      47104, // 46 MiB
		Iterations:  1,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   32,
	}
}

// Hasher hashes and verifies passwords under a fixed parameter set.
//
// Safe for concurrent use: it holds immutable configuration plus a semaphore.
type Hasher struct {
	params        Params
	maxConcurrent int
	guard         *memoryGuard
	// observer is optional; nil disables telemetry. See observer.go.
	observer Observer
}

// NewHasher returns a Hasher using the given parameters and DefaultMaxConcurrent.
// Zero-valued fields fall back to DefaultParams, so a partially-specified
// override cannot silently produce a weak configuration.
func NewHasher(p Params) *Hasher {
	return NewHasherWithConcurrency(p, DefaultMaxConcurrent())
}

// NewHasherWithConcurrency returns a Hasher that permits at most maxConcurrent
// simultaneous derivations. See memoryGuard for why that bound is mandatory
// rather than advisory.
func NewHasherWithConcurrency(p Params, maxConcurrent int) *Hasher {
	d := DefaultParams()
	if p.Memory == 0 {
		p.Memory = d.Memory
	}
	if p.Iterations == 0 {
		p.Iterations = d.Iterations
	}
	if p.Parallelism == 0 {
		p.Parallelism = d.Parallelism
	}
	if p.SaltLength == 0 {
		p.SaltLength = d.SaltLength
	}
	if p.KeyLength == 0 {
		p.KeyLength = d.KeyLength
	}
	if maxConcurrent < 1 {
		maxConcurrent = DefaultMaxConcurrent()
	}
	return &Hasher{
		params:        p,
		maxConcurrent: maxConcurrent,
		guard:         newMemoryGuard(maxConcurrent),
	}
}

// InFlight reports how many derivations are currently running. For metrics.
func (h *Hasher) InFlight() int { return h.guard.inFlight() }

// MaxConcurrent reports the derivation cap.
func (h *Hasher) MaxConcurrent() int { return h.maxConcurrent }

// Params returns the configured parameters.
func (h *Hasher) Params() Params { return h.params }

// Hash returns a PHC-encoded Argon2id hash of password.
//
// The salt is fresh per call and drawn from crypto/rand: a failure to read
// randomness is returned rather than degraded, because a predictable salt would
// let one precomputed table cover every account.
func (h *Hasher) Hash(ctx context.Context, password string) (string, error) {
	salt := make([]byte, h.params.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("password: read salt: %w", err)
	}

	if err := h.guard.acquire(ctx); err != nil {
		return "", fmt.Errorf("password: hash cancelled while queued: %w", err)
	}
	defer h.guard.release()
	h.observeInFlight()
	defer h.observeInFlight()

	start := time.Now()
	key := argon2.IDKey(
		[]byte(password), salt,
		h.params.Iterations, h.params.Memory, h.params.Parallelism, h.params.KeyLength,
	)
	h.observeHash(AlgorithmArgon2id, "hash", time.Since(start))

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		h.params.Memory, h.params.Iterations, h.params.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

// Verify reports whether password matches encodedHash.
//
// Dispatches on the hash's own prefix, so an Argon2id credential and a legacy
// bcrypt one are both accepted for as long as the latter exists. Returns
// ErrMismatch for every failure — wrong password, malformed hash, unknown
// algorithm — so a caller cannot distinguish "bad password" from "corrupt
// record", and neither can anyone watching the response.
func (h *Hasher) Verify(ctx context.Context, password, encodedHash string) error {
	switch Identify(encodedHash) {
	case AlgorithmArgon2id:
		return h.verifyArgon2id(ctx, password, encodedHash)
	case AlgorithmBcrypt:
		// Not gated: bcrypt holds ~4KiB, so concurrency costs nothing in memory
		// and queueing legacy verifications behind the Argon2id semaphore would
		// slow the migration for no benefit.
		start := time.Now()
		err := bcrypt.CompareHashAndPassword([]byte(encodedHash), []byte(password))
		h.observeHash(AlgorithmBcrypt, "verify", time.Since(start))
		if err != nil {
			return ErrMismatch
		}
		return nil
	default:
		return ErrMismatch
	}
}

func (h *Hasher) verifyArgon2id(ctx context.Context, password, encodedHash string) error {
	p, salt, want, err := DecodeArgon2id(encodedHash)
	if err != nil {
		return ErrMismatch
	}

	if err := h.guard.acquire(ctx); err != nil {
		// Queued and abandoned. Distinct from ErrMismatch on purpose: the caller
		// must not record a failed login attempt against an account whose password
		// was never actually checked.
		return fmt.Errorf("password: verify cancelled while queued: %w", err)
	}
	defer h.guard.release()
	h.observeInFlight()
	defer h.observeInFlight()

	// Derived with the STORED parameters, not the current ones — that is what
	// lets parameters be raised without invalidating existing credentials.
	start := time.Now()
	// p.KeyLength IS len(want) — DecodeArgon2id sets it from that slice, having
	// bounded it first. Using the field rather than re-narrowing len() keeps the
	// conversion in the one place that validates it.
	got := argon2.IDKey([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)
	h.observeHash(AlgorithmArgon2id, "verify", time.Since(start))

	// Constant-time: a byte-wise early exit would leak how much of the digest
	// matched, which is a usable oracle against a stolen-salt attacker.
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return ErrMismatch
	}
	return nil
}

// NeedsRehash reports whether a stored hash should be replaced on the next
// successful verification.
//
// True when the hash is bcrypt (migrate it forward), when it is malformed
// (rewrite it cleanly), or when its Argon2id parameters differ from the current
// ones in ANY direction. Downgrades count: after lowering a parameter, existing
// users would otherwise keep paying the old cost forever, so the fleet would
// never converge and a latency fix would never reach the accounts that already
// exist.
func (h *Hasher) NeedsRehash(encodedHash string) bool {
	switch Identify(encodedHash) {
	case AlgorithmArgon2id:
		p, _, _, err := DecodeArgon2id(encodedHash)
		if err != nil {
			return true
		}
		// p.KeyLength is the decoded digest's length, bounded and narrowed once
		// inside DecodeArgon2id.
		return p.Memory != h.params.Memory ||
			p.Iterations != h.params.Iterations ||
			p.Parallelism != h.params.Parallelism ||
			p.KeyLength != h.params.KeyLength
	default:
		// Bcrypt and anything unrecognised: rewrite on next verify.
		return true
	}
}

// Identify reports which algorithm produced a hash, from its prefix alone.
func Identify(encodedHash string) Algorithm {
	switch {
	case strings.HasPrefix(encodedHash, "$argon2id$"):
		return AlgorithmArgon2id
	case strings.HasPrefix(encodedHash, "$2a$"),
		strings.HasPrefix(encodedHash, "$2b$"),
		strings.HasPrefix(encodedHash, "$2y$"):
		return AlgorithmBcrypt
	default:
		return AlgorithmUnknown
	}
}

// DecodeArgon2id parses a PHC-encoded Argon2id hash into its parameters, salt,
// and digest. Exported for tests and for operational tooling that needs to audit
// stored parameters without verifying a password.
func DecodeArgon2id(encodedHash string) (Params, []byte, []byte, error) {
	// $argon2id$v=19$m=47104,t=1,p=1$<salt>$<hash>
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return Params{}, nil, nil, errors.New("password: not an argon2id hash")
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return Params{}, nil, nil, errors.New("password: unreadable version")
	}
	if version != argon2.Version {
		// A hash from a different Argon2 revision cannot be verified by this
		// build; treat it as unusable rather than deriving a key that will never
		// match for reasons the operator cannot see.
		return Params{}, nil, nil, fmt.Errorf("password: unsupported argon2 version %d", version)
	}

	var mem, iter, par uint64
	for _, kv := range strings.Split(parts[3], ",") {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return Params{}, nil, nil, errors.New("password: malformed parameters")
		}
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return Params{}, nil, nil, errors.New("password: malformed parameter value")
		}
		switch k {
		case "m":
			mem = n
		case "t":
			iter = n
		case "p":
			par = n
		}
	}
	if mem == 0 || iter == 0 || par == 0 || par > 255 {
		return Params{}, nil, nil, errors.New("password: missing or invalid parameters")
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return Params{}, nil, nil, errors.New("password: malformed salt")
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return Params{}, nil, nil, errors.New("password: malformed digest")
	}

	// Bound both before they are ever narrowed to uint32.
	//
	// Every caller converts len(salt)/len(key) to the uint32 argon2.IDKey takes,
	// and on a 64-bit platform that conversion is unchecked. A stored hash is
	// data — ordinarily our own, but a row an attacker can write is a row that
	// reaches here — so a multi-gigabyte field should be refused outright rather
	// than wrapped into a small length and used to derive a key.
	//
	// maxFieldLen is far above any legitimate value (OWASP salts are 16 bytes,
	// digests 32) and far below the wrap point, so it rejects only nonsense.
	saltLen, keyLen := len(salt), len(key)
	if saltLen > maxFieldLen || keyLen > maxFieldLen {
		return Params{}, nil, nil, errors.New("password: salt or digest out of range")
	}

	p := Params{
		Memory:      uint32(mem),
		Iterations:  uint32(iter),
		Parallelism: uint8(par),
		// #nosec G115 -- bounded by maxFieldLen (1 MiB) immediately above, and a
		// length is never negative, so neither conversion can wrap.
		SaltLength: uint32(saltLen),
		// #nosec G115 -- same bound.
		KeyLength: uint32(keyLen),
	}
	return p, salt, key, nil
}
