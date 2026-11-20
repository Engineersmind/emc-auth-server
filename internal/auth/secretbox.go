package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/rs/zerolog"
)

// secretBoxVersionPrefix tags ciphertexts produced by the current scheme so
// future format changes (or key rotations) can be recognised on read.
const secretBoxVersionPrefix = "v1:"

// SecretBox is a reusable AES-256-GCM encryptor for secrets at rest.
// Same scheme as the TOTP secret encryption (random 12-byte nonce prepended
// to the ciphertext, base64 encoded) but shared, so new secret kinds
// (e.g. identity provider client secrets) don't re-implement it.
//
// Key rotation: set the new key as the primary and the old key via
// WithPreviousKey. Decrypt falls back to the previous key transparently;
// values re-encrypt under the new key on their next write (e.g. the admin
// upsert). Once no old-key ciphertexts remain, drop the previous key.
type SecretBox struct {
	key     []byte
	prevKey []byte // optional previous key accepted for decryption during rotation
	// zeroKey records that the box was built on the development all-zero
	// fallback. Callers that persist ciphertext must not write under it — the
	// moment a real key is configured, zero-key ciphertext is unreadable
	// (GHSA-4x5m-3gph-938r review).
	zeroKey bool
}

// ErrEncryptionKeyRequired is returned when a required encryption key is
// missing in an environment where an insecure fallback is not acceptable.
var ErrEncryptionKeyRequired = errors.New("encryption key is required in production — set the env var to a 64-character hex string (openssl rand -hex 32)")

// ErrZeroEncryptionKey is returned when an encryption key is the all-zero
// development key in an environment that must not use it. The key protects the
// JWT signing key and OAuth client secrets — a publicly known key under it
// means anyone who reads the database can mint tokens and unwrap secrets.
var ErrZeroEncryptionKey = errors.New("encryption key is the all-zero development key, which is publicly known — generate a real one (openssl rand -hex 32)")

// NewSecretBox builds a SecretBox from a 64-character hex key (32 bytes).
//
// env controls the missing-key and zero-key behaviour, with the same contract
// as NewTOTPService and Config.Validate: only the two named non-deployed
// environments, "development" and "test", may fall back to or use the insecure
// zero key — with a loud warning so local setups keep working. Any other value
// — "production", "staging", a misspelling such as "prodution", or an empty
// ENV — fails closed, so a typo in ENV cannot quietly encrypt secrets under a
// publicly known key. keyName is only used in log/error messages (e.g.
// "OAUTH_CLIENT_SECRET_ENCRYPTION_KEY").
func NewSecretBox(keyHex, env, keyName string, logger zerolog.Logger) (*SecretBox, error) {
	deployed := env != "development" && env != "test"
	if keyHex == "" {
		if deployed {
			return nil, fmt.Errorf("%s (ENV=%q): %w", keyName, env, ErrEncryptionKeyRequired)
		}
		logger.Warn().Str("key", keyName).Msg("encryption key not set — using insecure zero key (dev only)")
		keyHex = strings.Repeat("0", 64)
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("%s must be a 64-character hex string (32 bytes)", keyName)
	}
	if deployed && isZeroKey(key) {
		return nil, fmt.Errorf("%s (ENV=%q): %w", keyName, env, ErrZeroEncryptionKey)
	}
	return &SecretBox{key: key, zeroKey: isZeroKey(key)}, nil
}

// UsesInsecureZeroKey reports whether the box encrypts under the development
// all-zero key. Writers of persistent ciphertext should skip writing when this
// is true — the value would become undecryptable as soon as a real key is set.
func (b *SecretBox) UsesInsecureZeroKey() bool {
	return b != nil && b.zeroKey
}

// HasPreviousKey reports whether a rotation is in progress — a previous key was
// configured via WithPreviousKey and Decrypt accepts ciphertext under either
// key. Readers use this to decide whether a re-encryption sweep is needed:
// ciphertext written under the old key must be re-sealed under the new one
// before the previous key is retired (GHSA-4x5m-3gph-938r review).
func (b *SecretBox) HasPreviousKey() bool {
	return b != nil && b.prevKey != nil
}

// WithPreviousKey accepts the previous 64-character hex key for decryption
// fallback during key rotation. An empty key is a no-op.
func (b *SecretBox) WithPreviousKey(keyHex, keyName string) error {
	if keyHex == "" {
		return nil
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil || len(key) != 32 {
		return fmt.Errorf("%s must be a 64-character hex string (32 bytes)", keyName)
	}
	b.prevKey = key
	return nil
}

// Encrypt seals plaintext with AES-256-GCM under a fresh random nonce,
// always with the PRIMARY key (rotation re-encrypts on write).
func (b *SecretBox) Encrypt(plaintext string) (string, error) {
	block, err := aes.NewCipher(b.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return secretBoxVersionPrefix + base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt opens a value produced by Encrypt. Un-prefixed legacy values (from
// before the version tag) are accepted. During rotation, decryption falls
// back to the previous key when the primary key fails to authenticate.
func (b *SecretBox) Decrypt(encrypted string) (string, error) {
	encrypted = strings.TrimPrefix(encrypted, secretBoxVersionPrefix)
	data, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", fmt.Errorf("base64 decode: %w", err)
	}
	plaintext, err := decryptGCM(b.key, data)
	if err != nil && b.prevKey != nil {
		if plaintextPrev, prevErr := decryptGCM(b.prevKey, data); prevErr == nil {
			return plaintextPrev, nil
		}
	}
	if err != nil {
		return "", err
	}
	return plaintext, nil
}

// decryptGCM opens nonce-prefixed AES-256-GCM data with one specific key.
func decryptGCM(key, data []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}
	plaintext, err := gcm.Open(nil, data[:nonceSize], data[nonceSize:], nil)
	if err != nil {
		return "", fmt.Errorf("gcm open: %w", err)
	}
	return string(plaintext), nil
}
