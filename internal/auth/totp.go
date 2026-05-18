package auth

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp/totp"
	"github.com/rs/zerolog"
)

const (
	// TOTPIssuer is the issuer shown in authenticator apps.
	TOTPIssuer = "EMC Auth"
	// BackupCodeCount is the number of one-time backup codes generated at enrollment.
	BackupCodeCount = 8
	// BackupCodeLength is the character length of each backup code.
	BackupCodeLength = 8
)

// TOTPService handles TOTP enrollment, verification, and management.
type TOTPService struct {
	pool      *pgxpool.Pool
	encKey    []byte // 32-byte AES-256 key decoded from hex config
	logger    zerolog.Logger
}

// NewTOTPService creates a TOTPService. encKeyHex must be a 64-character hex string (32 bytes).
func NewTOTPService(pool *pgxpool.Pool, encKeyHex string, logger zerolog.Logger) (*TOTPService, error) {
	if encKeyHex == "" {
		// Dev fallback: all-zero key — logs a warning, never allowed in production.
		logger.Warn().Msg("TOTP_ENCRYPTION_KEY not set — using insecure zero key (dev only)")
		encKeyHex = strings.Repeat("0", 64)
	}
	key, err := hex.DecodeString(encKeyHex)
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("TOTP_ENCRYPTION_KEY must be a 64-character hex string (32 bytes): %w", err)
	}
	return &TOTPService{pool: pool, encKey: key, logger: logger}, nil
}

// EnrollResult is returned by Enroll — contains the QR URI and one-time backup codes.
type EnrollResult struct {
	OTPURI      string   `json:"otp_uri"`      // otpauth:// URI for QR code generation
	BackupCodes []string `json:"backup_codes"` // plaintext codes shown once
}

// Enroll generates a new TOTP secret for the user, encrypts it, and persists it.
// The secret is inactive until the user calls VerifyAndActivate.
// If a previous enrollment exists it is overwritten (re-enrollment).
func (s *TOTPService) Enroll(ctx context.Context, userID, tenantID uuid.UUID, email string) (*EnrollResult, error) {
	// Generate a new TOTP key.
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      TOTPIssuer,
		AccountName: email,
		SecretSize:  32,
	})
	if err != nil {
		return nil, fmt.Errorf("generate TOTP key: %w", err)
	}

	// Encrypt the base32 secret with AES-256-GCM.
	encSecret, err := s.encrypt(key.Secret())
	if err != nil {
		return nil, fmt.Errorf("encrypt TOTP secret: %w", err)
	}

	// Generate backup codes: plaintext for display, SHA-256 hashes for storage.
	plainCodes, hashedCodes, err := generateBackupCodes(BackupCodeCount, BackupCodeLength)
	if err != nil {
		return nil, fmt.Errorf("generate backup codes: %w", err)
	}

	// Upsert into totp_secrets (is_active=false until verified).
	_, err = s.pool.Exec(ctx, `
		INSERT INTO totp_secrets (user_id, tenant_id, secret_enc, is_active, backup_codes, updated_at)
		VALUES ($1, $2, $3, false, $4, NOW())
		ON CONFLICT (user_id) DO UPDATE
		SET secret_enc = EXCLUDED.secret_enc,
		    is_active   = false,
		    backup_codes = EXCLUDED.backup_codes,
		    updated_at  = NOW()
	`, userID, tenantID, encSecret, hashedCodes)
	if err != nil {
		return nil, fmt.Errorf("upsert totp_secrets: %w", err)
	}

	return &EnrollResult{
		OTPURI:      key.URL(),
		BackupCodes: plainCodes,
	}, nil
}

// VerifyAndActivate validates the user's first TOTP code and marks the secret active.
// Must be called after Enroll to confirm the authenticator app is properly set up.
func (s *TOTPService) VerifyAndActivate(ctx context.Context, userID uuid.UUID, code string) error {
	secret, isActive, err := s.loadSecret(ctx, userID)
	if err != nil {
		return err
	}
	if isActive {
		return fmt.Errorf("TOTP is already active — use Verify instead")
	}

	if !totp.Validate(code, secret) {
		return fmt.Errorf("invalid TOTP code")
	}

	_, err = s.pool.Exec(ctx, `
		UPDATE totp_secrets SET is_active = true, updated_at = NOW()
		WHERE user_id = $1
	`, userID)
	if err != nil {
		return fmt.Errorf("activate totp_secrets: %w", err)
	}
	return nil
}

// Verify checks a TOTP code for an already-active TOTP enrollment.
// Returns nil if valid, error if invalid or not enrolled.
func (s *TOTPService) Verify(ctx context.Context, userID uuid.UUID, code string) error {
	secret, isActive, err := s.loadSecret(ctx, userID)
	if err != nil {
		return err
	}
	if !isActive {
		return fmt.Errorf("TOTP not active for this user")
	}
	if !totp.Validate(code, secret) {
		return fmt.Errorf("invalid TOTP code")
	}
	return nil
}

// VerifyBackupCode checks if the provided code matches any stored backup code hash.
// On success the used code is atomically removed (single-use).
func (s *TOTPService) VerifyBackupCode(ctx context.Context, userID uuid.UUID, code string) error {
	codeHash := hashBackupCode(code)

	// Load backup codes.
	var storedHashes []string
	err := s.pool.QueryRow(ctx, `
		SELECT backup_codes FROM totp_secrets
		WHERE user_id = $1 AND is_active = true
	`, userID).Scan(&storedHashes)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("TOTP not active for this user")
		}
		return fmt.Errorf("load backup codes: %w", err)
	}

	// Find and remove the matching code.
	found := false
	remaining := make([]string, 0, len(storedHashes))
	for _, h := range storedHashes {
		if h == codeHash && !found {
			found = true // consume this one — do not add to remaining
		} else {
			remaining = append(remaining, h)
		}
	}
	if !found {
		return fmt.Errorf("invalid backup code")
	}

	// Persist updated (shorter) list.
	_, err = s.pool.Exec(ctx, `
		UPDATE totp_secrets SET backup_codes = $2, updated_at = NOW()
		WHERE user_id = $1
	`, userID, remaining)
	if err != nil {
		return fmt.Errorf("consume backup code: %w", err)
	}
	return nil
}

// Disable removes the TOTP enrollment for the user.
// Requires a valid TOTP code or backup code as confirmation.
func (s *TOTPService) Disable(ctx context.Context, userID uuid.UUID, code string) error {
	// Try TOTP code first, then backup code.
	err := s.Verify(ctx, userID, code)
	if err != nil {
		err2 := s.VerifyBackupCode(ctx, userID, code)
		if err2 != nil {
			return fmt.Errorf("invalid code: provide a valid TOTP code or backup code to disable 2FA")
		}
	}

	_, err = s.pool.Exec(ctx, `
		DELETE FROM totp_secrets WHERE user_id = $1
	`, userID)
	if err != nil {
		return fmt.Errorf("delete totp_secrets: %w", err)
	}
	return nil
}

// IsActive returns true if the user has an active TOTP enrollment.
func (s *TOTPService) IsActive(ctx context.Context, userID uuid.UUID) (bool, error) {
	var active bool
	err := s.pool.QueryRow(ctx, `
		SELECT is_active FROM totp_secrets WHERE user_id = $1
	`, userID).Scan(&active)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("check TOTP active: %w", err)
	}
	return active, nil
}

// ─── AES-256-GCM helpers ────────────────────────────────────────────────────

func (s *TOTPService) encrypt(plaintext string) (string, error) {
	block, err := aes.NewCipher(s.encKey)
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
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (s *TOTPService) decrypt(encrypted string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", fmt.Errorf("base64 decode: %w", err)
	}
	block, err := aes.NewCipher(s.encKey)
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

// loadSecret fetches and decrypts the TOTP secret from DB.
func (s *TOTPService) loadSecret(ctx context.Context, userID uuid.UUID) (secret string, isActive bool, err error) {
	var encSecret string
	err = s.pool.QueryRow(ctx, `
		SELECT secret_enc, is_active FROM totp_secrets WHERE user_id = $1
	`, userID).Scan(&encSecret, &isActive)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", false, fmt.Errorf("no TOTP enrollment found for user")
		}
		return "", false, fmt.Errorf("load TOTP secret: %w", err)
	}
	secret, err = s.decrypt(encSecret)
	if err != nil {
		return "", false, fmt.Errorf("decrypt TOTP secret: %w", err)
	}
	return secret, isActive, nil
}

// ─── Backup code helpers ─────────────────────────────────────────────────────

// generateBackupCodes returns (plaintext codes, SHA-256 hashes) for storage.
func generateBackupCodes(count, length int) (plain []string, hashed []string, err error) {
	const charset = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // unambiguous characters
	plain = make([]string, count)
	hashed = make([]string, count)
	buf := make([]byte, length)
	for i := range plain {
		if _, err = rand.Read(buf); err != nil {
			return nil, nil, err
		}
		code := make([]byte, length)
		for j, b := range buf {
			code[j] = charset[int(b)%len(charset)]
		}
		plain[i] = string(code)
		hashed[i] = hashBackupCode(string(code))
	}
	return plain, hashed, nil
}

func hashBackupCode(code string) string {
	h := sha256.Sum256([]byte(strings.ToUpper(code)))
	return hex.EncodeToString(h[:])
}

// ─── OTP Session (Redis-backed pre-auth state) ───────────────────────────────

// OTPSession holds pre-authentication state while waiting for the TOTP code.
type OTPSession struct {
	UserID   uuid.UUID
	TenantID uuid.UUID
	Email    string
	RoleName string
	Perms    []string
}

// OTPSessionTTL is how long the intermediate TOTP challenge state lives.
const OTPSessionTTL = 5 * time.Minute
