package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
)

// PKCE (RFC 7636) for the INBOUND direction — EMC as the authorization server,
// verifying a code_verifier presented at the token endpoint against the
// code_challenge recorded at the authorize endpoint.
//
// This is the mirror image of the PKCE in google.go / github.go, where EMC is
// the OAuth *client* and generates a verifier for someone else to check. None
// of that code is reusable here: generating and verifying are different halves.

const (
	// PKCEMethodS256 is the only challenge method this server accepts.
	//
	// The CHECK constraint on oauth_authorization_codes.code_challenge_method
	// (migration 00032) also permits 'plain', where the challenge IS the
	// verifier. That offers no protection at all against an attacker who can
	// read the authorization request — which is precisely the attacker PKCE
	// exists to stop. RFC 7636 §7.2 permits 'plain' only for clients that
	// cannot compute SHA-256; nothing in 2026 qualifies.
	//
	// The constraint is left as-is rather than tightened: the column is shared
	// with login_code rows, and rejecting here keeps the decision in one
	// readable place instead of splitting it across a migration and a handler.
	PKCEMethodS256 = "S256"

	// minVerifierLen / maxVerifierLen are RFC 7636 §4.1. The lower bound is the
	// security-relevant one — it is what makes the verifier unguessable.
	minVerifierLen = 43
	maxVerifierLen = 128
)

// ErrInvalidCodeVerifier is returned when a code_verifier is malformed or does
// not match the stored challenge.
//
// One sentinel for both cases on purpose: at the token endpoint they collapse
// into the same RFC 6749 §5.2 response (invalid_grant), and distinguishing them
// to the caller would tell an attacker whether a guessed verifier was
// well-formed — a free oracle on the shape of the secret.
var ErrInvalidCodeVerifier = errors.New("pkce: invalid code_verifier")

// ErrUnsupportedChallengeMethod is returned for any method other than S256,
// including the empty string and 'plain'.
var ErrUnsupportedChallengeMethod = errors.New("pkce: code_challenge_method must be S256")

// ErrMissingCodeChallenge is returned when a client that requires PKCE sends an
// authorization request without a challenge.
var ErrMissingCodeChallenge = errors.New("pkce: code_challenge is required")

// isUnreservedPKCE reports whether b is in RFC 7636's ABNF for code_verifier:
// ALPHA / DIGIT / "-" / "." / "_" / "~".
//
// Enforced rather than assumed because the verifier is compared byte-for-byte
// against a base64url-derived challenge; accepting characters outside the set
// would let a client send a verifier that can never match anything, and read
// the resulting failure as a server bug.
func isUnreservedPKCE(b byte) bool {
	switch {
	case b >= 'A' && b <= 'Z',
		b >= 'a' && b <= 'z',
		b >= '0' && b <= '9',
		b == '-', b == '.', b == '_', b == '~':
		return true
	}
	return false
}

// ValidateCodeVerifier checks a verifier's shape without reference to any
// challenge. Callers still MUST call VerifyPKCE — passing this proves only that
// the value is well-formed, never that it is correct.
func ValidateCodeVerifier(verifier string) error {
	if len(verifier) < minVerifierLen || len(verifier) > maxVerifierLen {
		return ErrInvalidCodeVerifier
	}
	for i := 0; i < len(verifier); i++ {
		if !isUnreservedPKCE(verifier[i]) {
			return ErrInvalidCodeVerifier
		}
	}
	return nil
}

// ValidateCodeChallenge checks the challenge recorded at the authorize
// endpoint. A well-formed S256 challenge is the base64url (no padding) encoding
// of a 32-byte digest, i.e. exactly 43 characters.
func ValidateCodeChallenge(challenge, method string) error {
	if method != PKCEMethodS256 {
		return ErrUnsupportedChallengeMethod
	}
	if challenge == "" {
		return ErrMissingCodeChallenge
	}
	// A correct S256 challenge is always exactly 43 base64url characters.
	// Checking the length here turns "client computed the challenge wrong"
	// into an error at authorize time, where it can be reported usefully,
	// instead of an unexplainable invalid_grant one round trip later.
	if len(challenge) != 43 {
		return ErrInvalidCodeVerifier
	}
	if _, err := base64.RawURLEncoding.DecodeString(challenge); err != nil {
		return ErrInvalidCodeVerifier
	}
	return nil
}

// DeriveS256Challenge returns base64url(SHA256(verifier)) with no padding —
// RFC 7636 §4.2.
//
// Note this is NOT HashToken: that returns hex, which is what our refresh
// tokens and client secrets use at rest. PKCE challenges are wire values
// defined by the RFC as unpadded base64url, and a hex digest would never match
// a conformant client's challenge.
func DeriveS256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// VerifyPKCE checks a presented verifier against a stored challenge.
//
// The comparison is constant-time. The challenge is not secret — it travelled
// in a query string — but the verifier is, and a variable-time compare against
// a value the attacker can vary leaks how many leading characters were right.
func VerifyPKCE(challenge, method, verifier string) error {
	if method != PKCEMethodS256 {
		return ErrUnsupportedChallengeMethod
	}
	if err := ValidateCodeVerifier(verifier); err != nil {
		return err
	}
	derived := DeriveS256Challenge(verifier)
	if subtle.ConstantTimeCompare([]byte(derived), []byte(challenge)) != 1 {
		return ErrInvalidCodeVerifier
	}
	return nil
}
