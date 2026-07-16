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

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp/totp"
	"github.com/rs/zerolog"
)

const (
	TOTPIssuer       = "EMC Auth"
	BackupCodeCount  = 8
	BackupCodeLength = 8
)

// TOTPService handles TOTP enrollment, verification, and management.
type TOTPService struct {
	pool   *pgxpool.Pool
	encKey []byte
	logger zerolog.Logger
}

// NewTOTPService creates a TOTPService. encKeyHex must be a 64-character hex string (32 bytes).
func NewTOTPService(pool *pgxpool.Pool, encKeyHex string, logger zerolog.Logger) (*TOTPService, error) {
	if encKeyHex == "" {
		logger.Warn().Msg("TOTP_ENCRYPTION_KEY not set — using insecure zero key (dev only)")
		encKeyHex = strings.Repeat("0", 64)
	}
	key, err := hex.DecodeString(encKeyHex)
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("TOTP_ENCRYPTION_KEY must be a 64-character hex string (32 bytes): %w", err)
	}
	return &TOTPService{pool: pool, encKey: key, logger: logger}, nil
}

// EnrollResult is returned by Enroll.
type EnrollResult struct {
	OTPURI      string   `json:"otp_uri"`
	BackupCodes []string `json:"backup_codes"`
}

// Enroll generates a new TOTP secret for the user. issuer labels the entry in
// the user's authenticator app — pass the owning application's name for
// app-scoped users (or "" for the server-wide TOTPIssuer fallback).
//
// Enroll is the raw primitive: it applies no application policy and no
// re-enrollment proof. User-initiated enrollment must go through EnrollUser
// (mfa.go), which enforces both.
func (s *TOTPService) Enroll(ctx context.Context, userID, tenantID int64, email, issuer string) (*EnrollResult, error) {
	if issuer == "" {
		issuer = TOTPIssuer
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: email,
		SecretSize:  32,
	})
	if err != nil {
		return nil, fmt.Errorf("generate TOTP key: %w", err)
	}

	encSecret, err := s.encrypt(key.Secret())
	if err != nil {
		return nil, fmt.Errorf("encrypt TOTP secret: %w", err)
	}

	plainCodes, hashedCodes, err := generateBackupCodes(BackupCodeCount, BackupCodeLength)
	if err != nil {
		return nil, fmt.Errorf("generate backup codes: %w", err)
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO totp_secrets (user_id, tenant_id, secret_enc, is_active, backup_codes, updated_at)
		VALUES ($1, $2, $3, false, $4, NOW())
		ON CONFLICT (user_id) DO UPDATE
		SET secret_enc   = EXCLUDED.secret_enc,
		    is_active    = false,
		    backup_codes = EXCLUDED.backup_codes,
		    updated_at   = NOW()
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
func (s *TOTPService) VerifyAndActivate(ctx context.Context, userID int64, code string) error {
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
func (s *TOTPService) Verify(ctx context.Context, userID int64, code string) error {
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
func (s *TOTPService) VerifyBackupCode(ctx context.Context, userID int64, code string) error {
	codeHash := hashBackupCode(code)

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

	found := false
	remaining := make([]string, 0, len(storedHashes))
	for _, h := range storedHashes {
		if h == codeHash && !found {
			found = true
		} else {
			remaining = append(remaining, h)
		}
	}
	if !found {
		return fmt.Errorf("invalid backup code")
	}

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
func (s *TOTPService) Disable(ctx context.Context, userID int64, code string) error {
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

// TOTPStatus is returned by Status — the user-facing view of their own MFA
// state, including how many single-use backup codes remain so clients can
// prompt regeneration before the user runs out. EmailActive reflects the
// email-OTP method and is populated by the handler (email MFA lives in its
// own service).
type TOTPStatus struct {
	Enrolled             bool `json:"enrolled"`
	Active               bool `json:"active"`
	BackupCodesRemaining int  `json:"backup_codes_remaining"`
	EmailActive          bool `json:"email_active"`
}

// Status reports the user's TOTP enrollment state and remaining backup codes.
func (s *TOTPService) Status(ctx context.Context, userID int64) (*TOTPStatus, error) {
	st := &TOTPStatus{}
	var codes []string
	err := s.pool.QueryRow(ctx, `
		SELECT is_active, backup_codes FROM totp_secrets WHERE user_id = $1
	`, userID).Scan(&st.Active, &codes)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return st, nil
		}
		return nil, fmt.Errorf("load TOTP status: %w", err)
	}
	st.Enrolled = true
	st.BackupCodesRemaining = len(codes)
	return st, nil
}

// RegenerateBackupCodes replaces the user's backup codes with a fresh set of
// BackupCodeCount codes WITHOUT rotating the TOTP secret — the authenticator
// app keeps working. Requires an active enrollment and proof of control
// (a valid current TOTP or remaining backup code); every previous backup code
// is invalidated. The plaintext codes are returned exactly once.
func (s *TOTPService) RegenerateBackupCodes(ctx context.Context, userID int64, currentCode string) ([]string, error) {
	if currentCode == "" {
		return nil, ErrTOTPProofRequired
	}
	if err := s.Verify(ctx, userID, currentCode); err != nil {
		if err2 := s.VerifyBackupCode(ctx, userID, currentCode); err2 != nil {
			return nil, ErrTOTPProofRequired
		}
	}

	plainCodes, hashedCodes, err := generateBackupCodes(BackupCodeCount, BackupCodeLength)
	if err != nil {
		return nil, fmt.Errorf("generate backup codes: %w", err)
	}

	tag, err := s.pool.Exec(ctx, `
		UPDATE totp_secrets SET backup_codes = $2, updated_at = NOW()
		WHERE user_id = $1 AND is_active = true
	`, userID, hashedCodes)
	if err != nil {
		return nil, fmt.Errorf("store backup codes: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return nil, fmt.Errorf("TOTP not active for this user")
	}
	return plainCodes, nil
}

// IsActive returns true if the user has an active TOTP enrollment.
func (s *TOTPService) IsActive(ctx context.Context, userID int64) (bool, error) {
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
// Package-level so other services (e.g. EmailSenderService for SMTP
// passwords) can share the same envelope format and server encryption key.

func encryptAESGCM(key []byte, plaintext string) (string, error) {
	block, err := aes.NewCipher(key)
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

func decryptAESGCM(key []byte, encrypted string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", fmt.Errorf("base64 decode: %w", err)
	}
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

func (s *TOTPService) encrypt(plaintext string) (string, error) {
	return encryptAESGCM(s.encKey, plaintext)
}

func (s *TOTPService) decrypt(encrypted string) (string, error) {
	return decryptAESGCM(s.encKey, encrypted)
}

// EncryptionKey exposes the server encryption key for sibling services that
// share the same AES-256-GCM envelope (SMTP password storage).
func (s *TOTPService) EncryptionKey() []byte { return s.encKey }

// loadSecret fetches and decrypts the TOTP secret from DB.
func (s *TOTPService) loadSecret(ctx context.Context, userID int64) (secret string, isActive bool, err error) {
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

func generateBackupCodes(count, length int) (plain []string, hashed []string, err error) {
	const charset = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
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

// OTPSession holds pre-authentication state while waiting for the TOTP code
// (or, for 'required'-mode applications, while the user completes enrollment).
type OTPSession struct {
	UserID   int64
	TenantID int64
	Email    string
	RoleName string
	Perms    []string
	// AppID is the string-encoded oauth_clients.id when the login came through
	// a registered application; "" for tenant-level logins. Carried through the
	// challenge so the finally-issued JWT keeps its app_id claim.
	AppID string
	// Methods lists the MFA methods relevant to this session: for an OTP
	// challenge, the user's ACTIVE methods; for a forced-enrollment session,
	// the application's ALLOWED methods.
	Methods []string
}

// OTPSessionTTL is how long the intermediate TOTP challenge state lives.
const OTPSessionTTL = 5 * time.Minute

// MFAEnrollmentSessionTTL is how long a pending forced-enrollment session
// lives — longer than OTPSessionTTL because the user must install/open an
// authenticator app, scan the QR code, and type the first code.
const MFAEnrollmentSessionTTL = 10 * time.Minute

// MaxOTPAttempts is the per-session budget of incorrect codes before the
// challenge (or pending enrollment) is invalidated and the user must restart
// from the password step. Hard cap against 6-digit brute force inside the
// session TTL window.
const MaxOTPAttempts = 5
