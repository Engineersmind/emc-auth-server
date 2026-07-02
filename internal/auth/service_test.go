package auth_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/store"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// newServiceForTest creates a real AuthService backed by the provided pool and Redis client.
// It runs seed before returning so the "emc" tenant always exists.
func newServiceForTest(t *testing.T) (*auth.AuthService, func()) {
	t.Helper()
	pool := testhelper.NewTestDB(t)
	rdb := testhelper.NewTestRedis(t)
	logger := testhelper.TestLogger()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}

	jwtSvc := auth.NewJWTService(pool, "https://auth.emc.local")
	svc := auth.NewAuthService(pool, jwtSvc, logger)
	svc = svc.WithTOTP(nil, rdb) // no TOTP for most service tests

	cleanup := func() {
		testhelper.CleanupTables(t, pool)
	}
	return svc, cleanup
}

// uniqueEmail generates a collision-free email for parallel-safe tests.
func uniqueEmail(prefix string) string {
	return fmt.Sprintf("%s-%d@test.example.com", prefix, time.Now().UnixNano())
}

func TestRegister_Success(t *testing.T) {
	svc, cleanup := newServiceForTest(t)
	defer cleanup()

	ctx := context.Background()
	email := uniqueEmail("register-success")

	result, err := svc.Register(ctx, auth.RegisterInput{
		TenantSlug: "emc",
		Email:      email,
		Password:   "Password123!",
		FirstName:  "New",
		LastName:   "User",
	})
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if result == nil {
		t.Fatal("Register() result is nil")
	}
	if result.AccessToken == "" {
		t.Error("Register() AccessToken is empty")
	}
	if result.RefreshToken == "" {
		t.Error("Register() RefreshToken is empty")
	}
	if result.TokenType != "Bearer" {
		t.Errorf("Register() TokenType = %q, want %q", result.TokenType, "Bearer")
	}
	if result.ExpiresIn != 900 { // AccessTokenTTL = 15 min = 900s
		t.Errorf("Register() ExpiresIn = %d, want 900", result.ExpiresIn)
	}
}

func TestRegister_DuplicateEmail(t *testing.T) {
	svc, cleanup := newServiceForTest(t)
	defer cleanup()

	ctx := context.Background()
	email := uniqueEmail("dup-email")

	_, err := svc.Register(ctx, auth.RegisterInput{
		TenantSlug: "emc",
		Email:      email,
		Password:   "Password123!",
		FirstName:  "First",
		LastName:   "User",
	})
	if err != nil {
		t.Fatalf("first Register() unexpected error = %v", err)
	}

	_, err = svc.Register(ctx, auth.RegisterInput{
		TenantSlug: "emc",
		Email:      email,
		Password:   "AnotherPass456!",
		FirstName:  "Second",
		LastName:   "User",
	})
	if err == nil {
		t.Fatal("second Register() expected error for duplicate email, got nil")
	}
}

func TestLogin_Success(t *testing.T) {
	svc, cleanup := newServiceForTest(t)
	defer cleanup()

	ctx := context.Background()
	email := uniqueEmail("login-success")
	password := "Password123!"

	_, err := svc.Register(ctx, auth.RegisterInput{
		TenantSlug: "emc",
		Email:      email,
		Password:   password,
		FirstName:  "Login",
		LastName:   "Test",
	})
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	result, err := svc.Login(ctx, auth.LoginInput{
		Email:    email,
		Password: password,
	})
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	if result == nil {
		t.Fatal("Login() result is nil")
	}
	if result.Token == nil {
		t.Fatal("Login() Token is nil (TOTP challenge unexpected)")
	}
	if result.OTPChallenge != nil {
		t.Error("Login() OTPChallenge should be nil for user without TOTP")
	}
}

func TestLogin_WrongPassword(t *testing.T) {
	svc, cleanup := newServiceForTest(t)
	defer cleanup()

	ctx := context.Background()
	email := uniqueEmail("login-wrong-pw")

	_, err := svc.Register(ctx, auth.RegisterInput{
		TenantSlug: "emc",
		Email:      email,
		Password:   "CorrectPassword123!",
		FirstName:  "Login",
		LastName:   "WrongPW",
	})
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	_, err = svc.Login(ctx, auth.LoginInput{
		Email:    email,
		Password: "WrongPassword!",
	})
	if err == nil {
		t.Fatal("Login() expected error for wrong password, got nil")
	}
	if err.Error() != "invalid credentials" {
		t.Errorf("Login() error = %q, want \"invalid credentials\"", err.Error())
	}
}

func TestLogin_UnknownEmail(t *testing.T) {
	svc, cleanup := newServiceForTest(t)
	defer cleanup()

	ctx := context.Background()

	_, err := svc.Login(ctx, auth.LoginInput{
		Email:    "no-such-user@example.com",
		Password: "Password123!",
	})
	if err == nil {
		t.Fatal("Login() expected error for unknown email, got nil")
	}
}

func TestRefresh_RotatesToken(t *testing.T) {
	svc, cleanup := newServiceForTest(t)
	defer cleanup()

	ctx := context.Background()
	email := uniqueEmail("refresh-rotate")
	password := "Password123!"

	regResult, err := svc.Register(ctx, auth.RegisterInput{
		TenantSlug: "emc",
		Email:      email,
		Password:   password,
		FirstName:  "Refresh",
		LastName:   "Rotate",
	})
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	originalRefresh := regResult.RefreshToken

	newResult, err := svc.Refresh(ctx, originalRefresh)
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if newResult == nil {
		t.Fatal("Refresh() result is nil")
	}
	if newResult.AccessToken == "" {
		t.Error("Refresh() AccessToken is empty")
	}
	if newResult.RefreshToken == "" {
		t.Error("Refresh() RefreshToken is empty")
	}
	if newResult.RefreshToken == originalRefresh {
		t.Error("Refresh() did not rotate refresh token — new token equals original")
	}
}

func TestRefresh_ReplayAttack(t *testing.T) {
	svc, cleanup := newServiceForTest(t)
	defer cleanup()

	ctx := context.Background()
	email := uniqueEmail("refresh-replay")
	password := "Password123!"

	regResult, err := svc.Register(ctx, auth.RegisterInput{
		TenantSlug: "emc",
		Email:      email,
		Password:   password,
		FirstName:  "Replay",
		LastName:   "Attack",
	})
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	oldRefreshToken := regResult.RefreshToken

	// First Refresh succeeds — consumes old token, issues new one.
	_, err = svc.Refresh(ctx, oldRefreshToken)
	if err != nil {
		t.Fatalf("first Refresh() error = %v", err)
	}

	// Second Refresh with the SAME old token must fail.
	_, err = svc.Refresh(ctx, oldRefreshToken)
	if err == nil {
		t.Fatal("second Refresh() with same token expected error, got nil")
	}
	if !errors.Is(err, auth.ErrInvalidRefreshToken) {
		t.Errorf("second Refresh() error = %v, want auth.ErrInvalidRefreshToken", err)
	}
}

func TestLogout_RevokesToken(t *testing.T) {
	svc, cleanup := newServiceForTest(t)
	defer cleanup()

	ctx := context.Background()
	email := uniqueEmail("logout-revokes")
	password := "Password123!"

	regResult, err := svc.Register(ctx, auth.RegisterInput{
		TenantSlug: "emc",
		Email:      email,
		Password:   password,
		FirstName:  "Logout",
		LastName:   "Revokes",
	})
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	refreshToken := regResult.RefreshToken

	// Logout should succeed.
	if err := svc.Logout(ctx, refreshToken); err != nil {
		t.Fatalf("Logout() error = %v", err)
	}

	// Refresh after logout must fail.
	_, err = svc.Refresh(ctx, refreshToken)
	if err == nil {
		t.Fatal("Refresh() after Logout() expected error, got nil")
	}
	if !errors.Is(err, auth.ErrInvalidRefreshToken) {
		t.Errorf("Refresh() after Logout() error = %v, want auth.ErrInvalidRefreshToken", err)
	}
}

func TestMe_ReturnsClaims(t *testing.T) {
	svc, cleanup := newServiceForTest(t)
	defer cleanup()

	claims := &auth.Claims{
		UserID:      "uid-123",
		TenantID:    "tid-456",
		Email:       "user@example.com",
		Role:        "admin",
		Permissions: []string{"read:data", "write:data"},
	}

	result := svc.Me(claims)
	if result == nil {
		t.Fatal("Me() result is nil")
	}
	if result.UserID != claims.UserID {
		t.Errorf("Me() UserID = %q, want %q", result.UserID, claims.UserID)
	}
	if result.TenantID != claims.TenantID {
		t.Errorf("Me() TenantID = %q, want %q", result.TenantID, claims.TenantID)
	}
	if result.Email != claims.Email {
		t.Errorf("Me() Email = %q, want %q", result.Email, claims.Email)
	}
	if result.Role != claims.Role {
		t.Errorf("Me() Role = %q, want %q", result.Role, claims.Role)
	}
	if len(result.Permissions) != len(claims.Permissions) {
		t.Errorf("Me() Permissions len = %d, want %d", len(result.Permissions), len(claims.Permissions))
	}
}
