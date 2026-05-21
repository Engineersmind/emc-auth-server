package auth_test

import (
	"testing"

	"github.com/engineersmind/emc-auth-server/internal/auth"
)

func TestGenerateRefreshToken_Length(t *testing.T) {
	raw, err := auth.GenerateRefreshToken()
	if err != nil {
		t.Fatalf("GenerateRefreshToken() error = %v", err)
	}
	// 32 bytes encoded as hex = 64 characters
	if got := len(raw); got != 64 {
		t.Errorf("GenerateRefreshToken() len = %d, want 64", got)
	}
}

func TestGenerateRefreshToken_Unique(t *testing.T) {
	t1, err := auth.GenerateRefreshToken()
	if err != nil {
		t.Fatalf("first GenerateRefreshToken() error = %v", err)
	}
	t2, err := auth.GenerateRefreshToken()
	if err != nil {
		t.Fatalf("second GenerateRefreshToken() error = %v", err)
	}
	if t1 == t2 {
		t.Error("GenerateRefreshToken() returned identical tokens on consecutive calls")
	}
}

func TestHashToken_Deterministic(t *testing.T) {
	h1 := auth.HashToken("abc")
	h2 := auth.HashToken("abc")
	if h1 != h2 {
		t.Errorf("HashToken() is not deterministic: %q != %q", h1, h2)
	}
}

func TestHashToken_Length(t *testing.T) {
	h := auth.HashToken("x")
	// SHA-256 = 32 bytes = 64 hex characters
	if got := len(h); got != 64 {
		t.Errorf("HashToken() len = %d, want 64", got)
	}
}

func TestHashToken_DifferentInputs(t *testing.T) {
	h1 := auth.HashToken("tokenA")
	h2 := auth.HashToken("tokenB")
	if h1 == h2 {
		t.Error("HashToken() returned same hash for different inputs")
	}
}
