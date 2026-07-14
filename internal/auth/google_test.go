package auth

import (
	"errors"
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

func TestResolveRedirect(t *testing.T) {
	allow := []string{
		"https://app.acme.com/auth/callback",
		"https://staging.acme.com/auth/callback",
	}

	tests := []struct {
		name      string
		requested string
		allow     []string
		want      string
		wantErr   error
	}{
		{"exact match", "https://app.acme.com/auth/callback", allow, "https://app.acme.com/auth/callback", nil},
		{"second entry match", "https://staging.acme.com/auth/callback", allow, "https://staging.acme.com/auth/callback", nil},
		{"empty with single-entry list defaults", "", allow[:1], allow[0], nil},
		{"empty with multi-entry list rejected", "", allow, "", ErrInvalidRedirectURI},
		{"empty with empty list rejected", "", []string{}, "", ErrInvalidRedirectURI},
		{"prefix is NOT a match", "https://app.acme.com/auth/callback/extra", allow, "", ErrInvalidRedirectURI},
		{"subdomain trick rejected", "https://app.acme.com.evil.com/auth/callback", allow, "", ErrInvalidRedirectURI},
		{"scheme downgrade rejected", "http://app.acme.com/auth/callback", allow, "", ErrInvalidRedirectURI},
		{"trailing slash is a different URL", "https://app.acme.com/auth/callback/", allow, "", ErrInvalidRedirectURI},
		{"case variant rejected", "https://APP.acme.com/auth/callback", allow, "", ErrInvalidRedirectURI},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveRedirect(tt.requested, tt.allow)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("resolveRedirect() error = %v, want %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("resolveRedirect() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestValidateRedirectAllow(t *testing.T) {
	tests := []struct {
		name    string
		entries []string
		wantErr bool
	}{
		{"valid https", []string{"https://app.acme.com/cb"}, false},
		{"valid http (dev)", []string{"http://localhost:3000/cb"}, false},
		{"empty list ok", []string{}, false},
		{"relative URL rejected", []string{"/cb"}, true},
		{"missing scheme rejected", []string{"app.acme.com/cb"}, true},
		{"javascript scheme rejected", []string{"javascript:alert(1)"}, true},
		{"fragment rejected", []string{"https://app.acme.com/cb#frag"}, true},
		{"too many entries rejected", make([]string, maxRedirectAllowEntries+1), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Fill the oversized slice with valid URLs so only the count fails.
			if len(tt.entries) > maxRedirectAllowEntries {
				for i := range tt.entries {
					tt.entries[i] = "https://app.acme.com/cb"
				}
			}
			err := validateRedirectAllow(tt.entries)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateRedirectAllow(%v) error = %v, wantErr %v", tt.entries, err, tt.wantErr)
			}
		})
	}
}

func TestAppendLoginCode(t *testing.T) {
	tests := []struct {
		name     string
		redirect string
		code     string
		want     string
	}{
		{"plain URL", "https://app.acme.com/cb", "abc123", "https://app.acme.com/cb?login_code=abc123"},
		{"existing query preserved", "https://app.acme.com/cb?next=%2Fhome", "abc123", "https://app.acme.com/cb?login_code=abc123&next=%2Fhome"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := appendLoginCode(tt.redirect, tt.code)
			if err != nil {
				t.Fatalf("appendLoginCode() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("appendLoginCode() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAppendLoginError(t *testing.T) {
	got := AppendLoginError("https://app.acme.com/cb", "access_denied")
	if got != "https://app.acme.com/cb?error=access_denied" {
		t.Fatalf("AppendLoginError() = %q", got)
	}
}

func TestSecretBoxRoundTrip(t *testing.T) {
	key := strings.Repeat("ab", 32) // 64 hex chars
	box, err := NewSecretBox(key, "development", "TEST_KEY", zerolog.Nop())
	if err != nil {
		t.Fatalf("NewSecretBox() error = %v", err)
	}

	plaintext := "GOCSPX-test-client-secret"
	enc, err := box.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}
	if enc == plaintext || strings.Contains(enc, plaintext) {
		t.Fatal("Encrypt() output contains plaintext")
	}

	dec, err := box.Decrypt(enc)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	if dec != plaintext {
		t.Fatalf("Decrypt() = %q, want %q", dec, plaintext)
	}

	// Fresh nonce per encryption — same plaintext must not repeat ciphertext.
	enc2, err := box.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt() second call error = %v", err)
	}
	if enc == enc2 {
		t.Fatal("Encrypt() produced identical ciphertext twice — nonce reuse")
	}

	// Tampered ciphertext must fail authentication.
	tampered := "A" + enc[1:]
	if _, err := box.Decrypt(tampered); err == nil {
		t.Fatal("Decrypt() accepted tampered ciphertext")
	}
}

func TestSecretBoxKeyRotation(t *testing.T) {
	oldKey := strings.Repeat("aa", 32)
	newKey := strings.Repeat("bb", 32)

	oldBox, err := NewSecretBox(oldKey, "production", "TEST_KEY", zerolog.Nop())
	if err != nil {
		t.Fatalf("NewSecretBox(old): %v", err)
	}
	encUnderOld, err := oldBox.Encrypt("tenant-google-secret")
	if err != nil {
		t.Fatalf("Encrypt under old key: %v", err)
	}

	// Rotated box: new primary key + old key as previous.
	newBox, err := NewSecretBox(newKey, "production", "TEST_KEY", zerolog.Nop())
	if err != nil {
		t.Fatalf("NewSecretBox(new): %v", err)
	}
	if err := newBox.WithPreviousKey(oldKey, "TEST_KEY_PREVIOUS"); err != nil {
		t.Fatalf("WithPreviousKey: %v", err)
	}

	// Old-key ciphertext still decrypts during rotation.
	dec, err := newBox.Decrypt(encUnderOld)
	if err != nil || dec != "tenant-google-secret" {
		t.Fatalf("Decrypt old-key value after rotation: %q, %v", dec, err)
	}

	// New writes use the new key — decryptable WITHOUT the previous key.
	encUnderNew, err := newBox.Encrypt("tenant-google-secret")
	if err != nil {
		t.Fatalf("Encrypt under new key: %v", err)
	}
	soloNewBox, _ := NewSecretBox(newKey, "production", "TEST_KEY", zerolog.Nop())
	if dec, err := soloNewBox.Decrypt(encUnderNew); err != nil || dec != "tenant-google-secret" {
		t.Fatalf("Decrypt new-key value without previous key: %q, %v", dec, err)
	}

	// Without the previous key, old ciphertext must fail (rotation not done).
	if _, err := soloNewBox.Decrypt(encUnderOld); err == nil {
		t.Fatal("Decrypt old-key value succeeded without previous key")
	}

	// Legacy un-prefixed values (pre-versioning rows) still decrypt.
	legacy := strings.TrimPrefix(encUnderNew, "v1:")
	if dec, err := soloNewBox.Decrypt(legacy); err != nil || dec != "tenant-google-secret" {
		t.Fatalf("Decrypt legacy un-prefixed value: %q, %v", dec, err)
	}
}

func TestNewSecretBoxKeyPolicy(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		env     string
		wantErr bool
	}{
		{"missing key in production fails hard", "", "production", true},
		{"missing key in staging fails hard", "", "staging", true},
		{"missing key in development falls back", "", "development", false},
		{"invalid hex rejected", "not-hex", "development", true},
		{"wrong length rejected", "abcd", "production", true},
		{"valid key accepted in production", strings.Repeat("0f", 32), "production", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewSecretBox(tt.key, tt.env, "TEST_KEY", zerolog.Nop())
			if (err != nil) != tt.wantErr {
				t.Fatalf("NewSecretBox(env=%s) error = %v, wantErr %v", tt.env, err, tt.wantErr)
			}
		})
	}
}
