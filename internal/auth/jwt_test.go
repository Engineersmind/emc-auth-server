package auth_test

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/store"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)


func TestJWTService_SignAndVerify(t *testing.T) {
	pool := testhelper.NewTestDB(t)
	testhelper.CleanupTables(t, pool)

	ctx := context.Background()
	logger := testhelper.TestLogger()

	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}

	var tenantID, userID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM tenants WHERE slug = 'emc' AND deleted_at IS NULL`).Scan(&tenantID); err != nil {
		t.Fatalf("fetch seed tenant id: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT id FROM users WHERE email = 'admin@emc.local' AND deleted_at IS NULL`).Scan(&userID); err != nil {
		t.Fatalf("fetch seed user id: %v", err)
	}

	jwtSvc := auth.NewJWTService(pool, "https://auth.emc.local")

	userIDStr := strconv.FormatInt(userID, 10)
	tenantIDStr := strconv.FormatInt(tenantID, 10)

	claims := &auth.Claims{
		UserID:      userIDStr,
		TenantID:    tenantIDStr,
		Email:       "admin@emc.local",
		Role:        "super_admin",
		Permissions: []string{"admin:access"},
	}

	token, err := jwtSvc.Sign(ctx, tenantID, "emc-auth-server", claims)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if token == "" {
		t.Fatal("Sign() returned empty token")
	}

	verified, err := jwtSvc.Verify(ctx, token)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if verified.UserID != userIDStr {
		t.Errorf("Verify() UserID = %q, want %q", verified.UserID, userIDStr)
	}
	if verified.Email != "admin@emc.local" {
		t.Errorf("Verify() Email = %q, want %q", verified.Email, "admin@emc.local")
	}
}

func TestJWTService_Verify_ExpiredToken(t *testing.T) {
	pool := testhelper.NewTestDB(t)
	testhelper.CleanupTables(t, pool)

	ctx := context.Background()
	logger := testhelper.TestLogger()

	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}

	var tenantID, userID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM tenants WHERE slug = 'emc' AND deleted_at IS NULL`).Scan(&tenantID); err != nil {
		t.Fatalf("fetch seed tenant id: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT id FROM users WHERE email = 'admin@emc.local' AND deleted_at IS NULL`).Scan(&userID); err != nil {
		t.Fatalf("fetch seed user id: %v", err)
	}

	var jwtSecret string
	err := pool.QueryRow(ctx,
		`SELECT jwt_secret FROM tenants WHERE id = $1 AND is_active = true`,
		tenantID,
	).Scan(&jwtSecret)
	if err != nil {
		t.Fatalf("fetch jwt_secret: %v", err)
	}

	userIDStr := strconv.FormatInt(userID, 10)
	tenantIDStr := strconv.FormatInt(tenantID, 10)

	past := time.Now().Add(-2 * time.Hour)
	expiredClaims := &auth.Claims{
		UserID:   userIDStr,
		TenantID: tenantIDStr,
		Email:    "admin@emc.local",
		Role:     "super_admin",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://auth.emc.local",
			Subject:   userIDStr,
			IssuedAt:  jwt.NewNumericDate(past),
			ExpiresAt: jwt.NewNumericDate(past.Add(time.Minute)),
		},
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, expiredClaims)
	signed, err := tok.SignedString([]byte(jwtSecret))
	if err != nil {
		t.Fatalf("sign expired token: %v", err)
	}

	jwtSvc := auth.NewJWTService(pool, "https://auth.emc.local")
	_, err = jwtSvc.Verify(ctx, signed)
	if err == nil {
		t.Fatal("Verify() expected error for expired token, got nil")
	}
	if !strings.Contains(err.Error(), "expired") && !strings.Contains(err.Error(), "token") {
		t.Errorf("Verify() error = %q, expected to mention 'expired' or 'token'", err.Error())
	}
}

func TestJWTService_Verify_WrongTenant(t *testing.T) {
	pool := testhelper.NewTestDB(t)
	testhelper.CleanupTables(t, pool)

	ctx := context.Background()
	logger := testhelper.TestLogger()

	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}

	var tenantID, userID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM tenants WHERE slug = 'emc' AND deleted_at IS NULL`).Scan(&tenantID); err != nil {
		t.Fatalf("fetch seed tenant id: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT id FROM users WHERE email = 'admin@emc.local' AND deleted_at IS NULL`).Scan(&userID); err != nil {
		t.Fatalf("fetch seed user id: %v", err)
	}

	jwtSvc := auth.NewJWTService(pool, "https://auth.emc.local")

	// Build a token with a non-existent tenant ID in claims.
	// Use seed tenant's secret for signing but embed wrong TenantID in claims.
	var jwtSecret string
	err := pool.QueryRow(ctx,
		`SELECT jwt_secret FROM tenants WHERE id = $1`,
		tenantID,
	).Scan(&jwtSecret)
	if err != nil {
		t.Fatalf("fetch jwt_secret: %v", err)
	}

	userIDStr := strconv.FormatInt(userID, 10)

	claims := &auth.Claims{
		UserID:      userIDStr,
		TenantID:    "999999", // non-existent tenant ID
		Email:       "admin@emc.local",
		Role:        "super_admin",
		Permissions: []string{},
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://auth.emc.local",
			Subject:   userIDStr,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString([]byte(jwtSecret))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	_, err = jwtSvc.Verify(ctx, signed)
	if err == nil {
		t.Fatal("Verify() expected error for unknown tenant, got nil")
	}
}
