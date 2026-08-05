package auth_test

import (
	"context"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp/totp"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/store"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// totpEncKey is the dev fallback key — 64 zero hex chars.
const totpEncKey = "0000000000000000000000000000000000000000000000000000000000000000"

// totpEnvKey returns the TOTP_ENCRYPTION_KEY env var, falling back to the dev zero key.
func totpEnvKey() string {
	if k := os.Getenv("TOTP_ENCRYPTION_KEY"); k != "" {
		return k
	}
	return totpEncKey
}

// newTOTPService creates a real TOTPService with DB + dev encryption key.
// Returns the service, a background context, the pool, and the seed tenant ID.
func newTOTPService(t *testing.T) (*auth.TOTPService, context.Context, *pgxpool.Pool, int64) {
	t.Helper()
	pool := testhelper.NewTestDB(t)
	testhelper.CleanupTables(t, pool)
	logger := testhelper.TestLogger()

	ctx := context.Background()
	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}

	var tenantID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM tenants WHERE slug = 'emc' AND deleted_at IS NULL`).Scan(&tenantID); err != nil {
		t.Fatalf("fetch seed tenant id: %v", err)
	}

	svc, err := auth.NewTOTPService(pool, totpEnvKey(), logger)
	if err != nil {
		t.Fatalf("NewTOTPService: %v", err)
	}
	return svc, ctx, pool, tenantID
}

// insertTOTPTestUser registers a real user via AuthService and returns their int64 ID.
// TOTP secrets have a FK on users.id, so a real row is required.
func insertTOTPTestUser(t *testing.T, ctx context.Context, pool *pgxpool.Pool, email string) int64 {
	t.Helper()
	logger := testhelper.TestLogger()
	jwtSvc := newTestJWTService(t, pool, "https://auth.emc.local")
	authSvc := auth.NewAuthService(pool, jwtSvc, logger)
	_, err := authSvc.Register(ctx, auth.RegisterInput{
		TenantSlug: "emc",
		Email:      email,
		Password:   "TestPass123!",
		FirstName:  "TOTP",
		LastName:   "Test",
	})
	if err != nil {
		t.Fatalf("insertTOTPTestUser Register(%q): %v", email, err)
	}
	var userID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM users WHERE email = $1 AND deleted_at IS NULL`, email).Scan(&userID); err != nil {
		t.Fatalf("insertTOTPTestUser fetch id for %q: %v", email, err)
	}
	return userID
}

// secretFromOTPURI extracts the TOTP secret from an otpauth:// URI.
func secretFromOTPURI(t *testing.T, uri string) string {
	t.Helper()
	u, err := url.Parse(uri)
	if err != nil {
		t.Fatalf("parse OTP URI: %v", err)
	}
	secret := u.Query().Get("secret")
	if secret == "" {
		t.Fatalf("no secret in OTP URI: %s", uri)
	}
	return secret
}

func TestTOTPService_Enroll_ReturnsURIAndCodes(t *testing.T) {
	svc, ctx, pool, tenantID := newTOTPService(t)

	userID := insertTOTPTestUser(t, ctx, pool, "enroll-uri@emc.local")

	result, err := svc.Enroll(ctx, userID, tenantID, "enroll-uri@emc.local", "")
	if err != nil {
		t.Fatalf("Enroll() error = %v", err)
	}
	if !strings.HasPrefix(result.OTPURI, "otpauth://") {
		t.Errorf("Enroll() OTPURI = %q, want prefix \"otpauth://\"", result.OTPURI)
	}
	if len(result.BackupCodes) != auth.BackupCodeCount {
		t.Errorf("Enroll() BackupCodes len = %d, want %d", len(result.BackupCodes), auth.BackupCodeCount)
	}
	for i, code := range result.BackupCodes {
		if len(code) != auth.BackupCodeLength {
			t.Errorf("BackupCode[%d] len = %d, want %d", i, len(code), auth.BackupCodeLength)
		}
	}
}

func TestTOTPService_VerifyAndActivate(t *testing.T) {
	pool := testhelper.NewTestDB(t)
	testhelper.CleanupTables(t, pool)
	logger := testhelper.TestLogger()
	ctx := context.Background()

	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}

	var tenantID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM tenants WHERE slug = 'emc' AND deleted_at IS NULL`).Scan(&tenantID); err != nil {
		t.Fatalf("fetch seed tenant id: %v", err)
	}

	svc, err := auth.NewTOTPService(pool, totpEnvKey(), logger)
	if err != nil {
		t.Fatalf("NewTOTPService: %v", err)
	}

	userID := insertTOTPTestUser(t, ctx, pool, "activate@emc.local")

	result, err := svc.Enroll(ctx, userID, tenantID, "activate@emc.local", "")
	if err != nil {
		t.Fatalf("Enroll() error = %v", err)
	}

	// Extract TOTP secret from the URI and generate a valid code.
	secret := secretFromOTPURI(t, result.OTPURI)
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}

	if err := svc.VerifyAndActivate(ctx, userID, code); err != nil {
		t.Fatalf("VerifyAndActivate() error = %v", err)
	}

	active, err := svc.IsActive(ctx, userID)
	if err != nil {
		t.Fatalf("IsActive() error = %v", err)
	}
	if !active {
		t.Error("IsActive() = false, want true after VerifyAndActivate")
	}
}

func TestTOTPService_Verify_InvalidCode(t *testing.T) {
	pool := testhelper.NewTestDB(t)
	testhelper.CleanupTables(t, pool)
	logger := testhelper.TestLogger()
	ctx := context.Background()

	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}

	var tenantID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM tenants WHERE slug = 'emc' AND deleted_at IS NULL`).Scan(&tenantID); err != nil {
		t.Fatalf("fetch seed tenant id: %v", err)
	}

	svc, err := auth.NewTOTPService(pool, totpEnvKey(), logger)
	if err != nil {
		t.Fatalf("NewTOTPService: %v", err)
	}

	userID := insertTOTPTestUser(t, ctx, pool, "verify-invalid@emc.local")

	result, err := svc.Enroll(ctx, userID, tenantID, "verify-invalid@emc.local", "")
	if err != nil {
		t.Fatalf("Enroll() error = %v", err)
	}

	// Activate with valid code first.
	secret := secretFromOTPURI(t, result.OTPURI)
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	if err := svc.VerifyAndActivate(ctx, userID, code); err != nil {
		t.Fatalf("VerifyAndActivate() error = %v", err)
	}

	// Now call Verify with a bad code.
	err = svc.Verify(ctx, userID, "000000")
	if err == nil {
		t.Fatal("Verify() expected error for invalid code, got nil")
	}
}

func TestTOTPService_VerifyBackupCode_ConsumesCode(t *testing.T) {
	pool := testhelper.NewTestDB(t)
	testhelper.CleanupTables(t, pool)
	logger := testhelper.TestLogger()
	ctx := context.Background()

	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}

	var tenantID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM tenants WHERE slug = 'emc' AND deleted_at IS NULL`).Scan(&tenantID); err != nil {
		t.Fatalf("fetch seed tenant id: %v", err)
	}

	svc, err := auth.NewTOTPService(pool, totpEnvKey(), logger)
	if err != nil {
		t.Fatalf("NewTOTPService: %v", err)
	}

	userID := insertTOTPTestUser(t, ctx, pool, "backupcode@emc.local")

	result, err := svc.Enroll(ctx, userID, tenantID, "backupcode@emc.local", "")
	if err != nil {
		t.Fatalf("Enroll() error = %v", err)
	}

	// Manually set is_active = true so VerifyBackupCode can work.
	_, err = pool.Exec(ctx, `UPDATE totp_secrets SET is_active = true WHERE user_id = $1`, userID)
	if err != nil {
		t.Fatalf("set is_active: %v", err)
	}

	firstCode := result.BackupCodes[0]

	// First use — should succeed.
	if err := svc.VerifyBackupCode(ctx, userID, firstCode); err != nil {
		t.Fatalf("first VerifyBackupCode() error = %v", err)
	}

	// Second use of the same code — should fail (consumed).
	if err := svc.VerifyBackupCode(ctx, userID, firstCode); err == nil {
		t.Fatal("second VerifyBackupCode() expected error for consumed code, got nil")
	}
}

func TestTOTPService_Disable(t *testing.T) {
	pool := testhelper.NewTestDB(t)
	testhelper.CleanupTables(t, pool)
	logger := testhelper.TestLogger()
	ctx := context.Background()

	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}

	var tenantID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM tenants WHERE slug = 'emc' AND deleted_at IS NULL`).Scan(&tenantID); err != nil {
		t.Fatalf("fetch seed tenant id: %v", err)
	}

	svc, err := auth.NewTOTPService(pool, totpEnvKey(), logger)
	if err != nil {
		t.Fatalf("NewTOTPService: %v", err)
	}

	userID := insertTOTPTestUser(t, ctx, pool, "disable@emc.local")

	result, err := svc.Enroll(ctx, userID, tenantID, "disable@emc.local", "")
	if err != nil {
		t.Fatalf("Enroll() error = %v", err)
	}

	// Activate via VerifyAndActivate.
	secret := secretFromOTPURI(t, result.OTPURI)
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	if err := svc.VerifyAndActivate(ctx, userID, code); err != nil {
		t.Fatalf("VerifyAndActivate() error = %v", err)
	}

	// Generate another code to use for Disable.
	code2, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode for disable: %v", err)
	}

	if err := svc.Disable(ctx, userID, code2); err != nil {
		t.Fatalf("Disable() error = %v", err)
	}

	active, err := svc.IsActive(ctx, userID)
	if err != nil {
		t.Fatalf("IsActive() after Disable error = %v", err)
	}
	if active {
		t.Error("IsActive() = true after Disable, want false")
	}
}
