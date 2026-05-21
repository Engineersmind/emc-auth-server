package auth_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/store"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

func TestJWTService_SignAndVerify(t *testing.T) {
	pool := testhelper.NewTestDB(t)
	testhelper.CleanupTables(t, pool)

	ctx := context.Background()
	logger := testhelper.TestLogger()

	// Ensure seed data exists.
	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}

	jwtSvc := auth.NewJWTService(pool, "https://auth.emc.local")

	claims := &auth.Claims{
		UserID:      store.SeedUserID.String(),
		TenantID:    store.SeedTenantID.String(),
		Email:       "admin@emc.local",
		Role:        "super_admin",
		Permissions: []string{"admin:access"},
	}

	token, err := jwtSvc.Sign(ctx, store.SeedTenantID, "emc-auth-server", claims)
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
	if verified.UserID != store.SeedUserID.String() {
		t.Errorf("Verify() UserID = %q, want %q", verified.UserID, store.SeedUserID.String())
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

	// Fetch the tenant's jwt_secret directly to build a manually-crafted expired token.
	var jwtSecret string
	err := pool.QueryRow(ctx,
		`SELECT jwt_secret FROM tenants WHERE id = $1 AND is_active = true`,
		store.SeedTenantID,
	).Scan(&jwtSecret)
	if err != nil {
		t.Fatalf("fetch jwt_secret: %v", err)
	}

	past := time.Now().Add(-2 * time.Hour)
	expiredClaims := &auth.Claims{
		UserID:   store.SeedUserID.String(),
		TenantID: store.SeedTenantID.String(),
		Email:    "admin@emc.local",
		Role:     "super_admin",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://auth.emc.local",
			Subject:   store.SeedUserID.String(),
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

	// First sign a token using seed tenant.
	jwtSvc := auth.NewJWTService(pool, "https://auth.emc.local")
	claims := &auth.Claims{
		UserID:      store.SeedUserID.String(),
		TenantID:    uuid.New().String(), // random UUID not in DB
		Email:       "admin@emc.local",
		Role:        "super_admin",
		Permissions: []string{},
	}

	// Build a token with a non-existent tenant ID manually.
	// We need SOME secret to sign with. Use seed tenant's secret but embed wrong TenantID in claims.
	var jwtSecret string
	err := pool.QueryRow(ctx,
		`SELECT jwt_secret FROM tenants WHERE id = $1`,
		store.SeedTenantID,
	).Scan(&jwtSecret)
	if err != nil {
		t.Fatalf("fetch jwt_secret: %v", err)
	}

	claims.RegisteredClaims = jwt.RegisteredClaims{
		Issuer:    "https://auth.emc.local",
		Subject:   store.SeedUserID.String(),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
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
