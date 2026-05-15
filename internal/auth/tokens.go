package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// GenerateRefreshToken produces a cryptographically random 32-byte value
// encoded as a 64-character hex string. This raw value is returned to the
// client ONCE and never persisted (only its SHA-256 hash is stored).
func GenerateRefreshToken() (raw string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", fmt.Errorf("generate refresh token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// HashToken returns the hex-encoded SHA-256 hash of the given raw token string.
// Used for both refresh tokens (NFR-05) and password reset tokens (RESET-04).
func HashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
