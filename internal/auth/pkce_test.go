package auth_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// rfc7636Verifier and rfc7636Challenge are the worked example from
// RFC 7636 Appendix B. Using the RFC's own vector rather than a
// round-trip of our own function is the point: a self-consistent
// implementation of the WRONG transform (hex instead of base64url, padded
// instead of raw, full digest instead of the specified encoding) passes every
// round-trip test and fails against every real client.
const (
	rfc7636Verifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	rfc7636Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

func TestDeriveS256Challenge_RFC7636Vector(t *testing.T) {
	got := auth.DeriveS256Challenge(rfc7636Verifier)
	if got != rfc7636Challenge {
		t.Fatalf("DeriveS256Challenge() = %q, want RFC 7636 Appendix B value %q", got, rfc7636Challenge)
	}
}

func TestDeriveS256Challenge_IsNotHashToken(t *testing.T) {
	// HashToken returns hex; PKCE requires unpadded base64url. They must never
	// be confused — a challenge built with HashToken would never match a
	// conformant client, and the failure would surface as an unexplainable
	// invalid_grant at the token endpoint rather than as a bug here.
	if auth.DeriveS256Challenge(rfc7636Verifier) == auth.HashToken(rfc7636Verifier) {
		t.Fatal("DeriveS256Challenge must not equal HashToken — PKCE is base64url, HashToken is hex")
	}
	if strings.ContainsAny(auth.DeriveS256Challenge(rfc7636Verifier), "+/=") {
		t.Error("challenge must be RAW base64url — no +, / or = padding")
	}
}

func TestVerifyPKCE(t *testing.T) {
	tests := []struct {
		name      string
		challenge string
		method    string
		verifier  string
		wantErr   error
	}{
		{"correct verifier", rfc7636Challenge, "S256", rfc7636Verifier, nil},
		{"wrong verifier", rfc7636Challenge, "S256", "wrong" + rfc7636Verifier[5:], auth.ErrInvalidCodeVerifier},
		{"plain method refused", rfc7636Verifier, "plain", rfc7636Verifier, auth.ErrUnsupportedChallengeMethod},
		{"empty method refused", rfc7636Challenge, "", rfc7636Verifier, auth.ErrUnsupportedChallengeMethod},
		{"lowercase s256 refused", rfc7636Challenge, "s256", rfc7636Verifier, auth.ErrUnsupportedChallengeMethod},
		{"empty verifier", rfc7636Challenge, "S256", "", auth.ErrInvalidCodeVerifier},
		{"verifier too short", rfc7636Challenge, "S256", strings.Repeat("a", 42), auth.ErrInvalidCodeVerifier},
		{"verifier too long", rfc7636Challenge, "S256", strings.Repeat("a", 129), auth.ErrInvalidCodeVerifier},
		{"illegal character", rfc7636Challenge, "S256", strings.Repeat("a", 42) + "!", auth.ErrInvalidCodeVerifier},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := auth.VerifyPKCE(tt.challenge, tt.method, tt.verifier)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("VerifyPKCE() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestVerifyPKCE_BoundaryLengths(t *testing.T) {
	// 43 and 128 are the inclusive bounds of RFC 7636 §4.1. Off-by-one here
	// would reject the shortest legal verifier, which is exactly what a client
	// generating the minimum 32 bytes of entropy produces.
	for _, n := range []int{43, 128} {
		v := strings.Repeat("a", n)
		if err := auth.VerifyPKCE(auth.DeriveS256Challenge(v), "S256", v); err != nil {
			t.Errorf("verifier of length %d rejected: %v", n, err)
		}
	}
}

func TestValidateCodeChallenge(t *testing.T) {
	tests := []struct {
		name      string
		challenge string
		method    string
		wantErr   bool
	}{
		{"valid S256", rfc7636Challenge, "S256", false},
		{"plain refused", rfc7636Verifier, "plain", true},
		{"empty challenge", "", "S256", true},
		{"wrong length", "tooshort", "S256", true},
		{"non-base64url characters", strings.Repeat("!", 43), "S256", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := auth.ValidateCodeChallenge(tt.challenge, tt.method)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateCodeChallenge(%q, %q) error = %v, wantErr %v",
					tt.challenge, tt.method, err, tt.wantErr)
			}
		})
	}
}
