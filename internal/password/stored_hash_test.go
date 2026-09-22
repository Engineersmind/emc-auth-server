package password

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// Bulk user import (issue #24) accepts pre-hashed credentials exported from
// another identity provider, so a stored hash can arrive from outside this
// server for the first time. Both tests below cover a way that used to go wrong
// and could not be noticed until a user complained or the host fell over.

// TestDecodeArgon2id_RefusesRuinousCostParameters is the memory-exhaustion gate.
//
// The parameters in a PHC string are handed straight to argon2.IDKey, which
// allocates `m` KiB and runs `t` passes over it. DecodeArgon2id checked only
// that they were non-zero, so an uploaded hash could declare any cost it liked
// and this process would honour it — the first login attempt against that
// account became an out-of-memory kill, triggered by a file an administrator
// was invited to upload.
//
// The ceiling is refused at DECODE time rather than at verification, so a row
// written before the bound existed is also refused on read instead of honoured.
func TestDecodeArgon2id_RefusesRuinousCostParameters(t *testing.T) {
	// A structurally perfect hash: real salt, real digest, only the cost fields
	// are hostile. Anything that failed on shape instead would not prove the
	// bound is doing the work.
	wellFormed := func(mem uint32, iter uint32) string {
		enc, err := NewHasher(DefaultParams()).Hash(context.Background(), "correct-horse")
		if err != nil {
			t.Fatalf("hash: %v", err)
		}
		parts := strings.Split(enc, "$")
		// $argon2id$v=19$m=...,t=...,p=...$salt$digest
		parts[3] = fmt.Sprintf("m=%d,t=%d,p=1", mem, iter)
		return strings.Join(parts, "$")
	}

	for name, h := range map[string]string{
		"4 GiB of memory":  wellFormed(4*1024*1024, 1),
		"1 GiB over":       wellFormed(maxArgon2Memory+1, 1),
		"32 iterations up": wellFormed(DefaultParams().Memory, maxArgon2Iterations+1),
	} {
		if _, _, _, err := DecodeArgon2id(h); err == nil {
			t.Errorf("%s was accepted — verifying it would let one uploaded row exhaust the host", name)
		}
	}

	// The product's own parameters must still decode, or this bound has broken
	// every existing account rather than only the hostile ones.
	own, err := NewHasher(DefaultParams()).Hash(context.Background(), "correct-horse")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if _, _, _, err := DecodeArgon2id(own); err != nil {
		t.Fatalf("the server's own hash no longer decodes: %v", err)
	}

	// And a source system tuned harder than this one is still importable: the
	// bound exists to stop the absurd, not to impose our tuning on a migration.
	if _, _, _, err := DecodeArgon2id(wellFormed(256*1024, 4)); err != nil {
		t.Errorf("a legitimately expensive hash (256 MiB, t=4) was refused: %v", err)
	}
}

/*
 * TestValidateStoredHash_RefusesUnverifiableBcrypt is the "imported account can
 * never log in" gate.
 *
 * Identify reads the prefix and nothing else — correctly, and its doc says so —
 * so `$2a$10$abc` identified as bcrypt and passed every check the importer made.
 * The row was accepted, the account was created, and bcrypt.Cost then refused
 * the stored value at every login for the life of that account. Nothing in the
 * product could explain why a password that imported successfully did not work.
 *
 * ValidateStoredHash exists to be the acceptance test Identify is not.
 */
func TestValidateStoredHash_RefusesUnverifiableBcrypt(t *testing.T) {
	for name, h := range map[string]string{
		"truncated after the cost": "$2a$10$abc",
		"no salt or digest":        "$2b$12$",
		"cost field missing":       "$2y$$" + strings.Repeat("a", 53),
		"not a hash at all":        "$2a$",
	} {
		if err := ValidateStoredHash(h); err == nil {
			t.Errorf("%s (%q) was accepted — it would create an account that can never authenticate", name, h)
		}
		// The point of the fix: the prefix check alone still says "bcrypt".
		if got := Identify(h); got != AlgorithmBcrypt {
			t.Errorf("%s: Identify = %q, want bcrypt — the fixture no longer exercises the gap", name, got)
		}
	}

	// A real bcrypt hash, from the library itself, must pass.
	real, err := bcrypt.GenerateFromPassword([]byte("correct-horse"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	if err := ValidateStoredHash(string(real)); err != nil {
		t.Errorf("a genuine bcrypt hash was refused: %v", err)
	}
}

// TestValidateStoredHash_AcceptsWhatVerifyAccepts pins the contract that makes
// this function worth calling: anything it admits, Verify can read back. A
// validator that disagreed with the verifier would simply move the failure.
func TestValidateStoredHash_AcceptsWhatVerifyAccepts(t *testing.T) {
	h := NewHasher(DefaultParams())

	argon, err := h.Hash(context.Background(), "correct-horse")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	bc, err := bcrypt.GenerateFromPassword([]byte("correct-horse"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}

	for name, stored := range map[string]string{"argon2id": argon, "bcrypt": string(bc)} {
		if err := ValidateStoredHash(stored); err != nil {
			t.Errorf("%s: validation refused a hash Verify accepts: %v", name, err)
		}
	}

	if err := ValidateStoredHash("plaintext-not-a-hash"); err == nil {
		t.Error("an unrecognised format was accepted")
	}
}
