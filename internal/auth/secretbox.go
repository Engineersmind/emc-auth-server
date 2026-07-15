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
}

// ErrEncryptionKeyRequired is returned when a required encryption key is
// missing in an environment where an insecure fallback is not acceptable.
var ErrEncryptionKeyRequired = errors.New("encryption key is required in production — set the env var to a 64-character hex string (openssl rand -hex 32)")

// NewSecretBox builds a SecretBox from a 64-character hex key (32 bytes).
//
// env controls the missing-key behaviour: in "production" (and "staging") a
// missing key is a hard error; in development it falls back to an insecure
// zero key with a loud warning so local setups keep working. keyName is only
// used in log/error messages (e.g. "OAUTH_CLIENT_SECRET_ENCRYPTION_KEY").
func NewSecretBox(keyHex, env, keyName string, logger zerolog.Logger) (*SecretBox, error) {
	if keyHex == "" {
		if env == "production" || env == "staging" {
			return nil, fmt.Errorf("%s: %w", keyName, ErrEncryptionKeyRequired)
		}
		logger.Warn().Str("key", keyName).Msg("encryption key not set — using insecure zero key (dev only)")
		keyHex = strings.Repeat("0", 64)
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("%s must be a 64-character hex string (32 bytes)", keyName)
	}
	return &SecretBox{key: key}, nil
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
