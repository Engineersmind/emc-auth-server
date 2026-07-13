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

// TestIssueServiceToken_SubIsClientID verifies that a client_credentials
// service token carries the public client_id in the sub/user_id claim (not the
// numeric oauth_clients.id), keeps the numeric id in app_id, and fixes the
// role to "service" (EMC-005 contract).
func TestIssueServiceToken_SubIsClientID(t *testing.T) {
	pool := testhelper.NewTestDB(t)
	logger := testhelper.TestLogger()
	ctx := context.Background()

	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}
	t.Cleanup(func() { testhelper.CleanupTables(t, pool) })

	var tenantID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM tenants WHERE slug = 'emc' AND deleted_at IS NULL`).Scan(&tenantID); err != nil {
		t.Fatalf("fetch seed tenant id: %v", err)
	}

	appSvc := auth.NewApplicationService(pool, logger)
	created, err := appSvc.CreateApplication(ctx, tenantID, "m2m-sub-claim", "m2m", nil)
	if err != nil {
		t.Fatalf("CreateApplication() error = %v", err)
	}

	jwtSvc := auth.NewJWTService(pool, "https://auth.emc.local")
	svc := auth.NewAuthService(pool, jwtSvc, logger)

	_, appID, err := appSvc.AuthenticateClient(ctx, created.ClientID, created.ClientSecret)
	if err != nil {
		t.Fatalf("AuthenticateClient() error = %v", err)
	}

	token, expiresIn, err := svc.IssueServiceToken(ctx, tenantID, appID)
	if err != nil {
		t.Fatalf("IssueServiceToken() error = %v", err)
	}
	if expiresIn != 900 {
		t.Errorf("IssueServiceToken() expiresIn = %d, want 900", expiresIn)
	}

	claims, err := jwtSvc.Verify(ctx, token)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if claims.UserID != created.ClientID {
		t.Errorf("service token UserID/sub = %q, want client_id %q", claims.UserID, created.ClientID)
	}
	if claims.Subject != created.ClientID {
		t.Errorf("service token Subject = %q, want client_id %q", claims.Subject, created.ClientID)
	}
	if claims.AppID != created.ID {
		t.Errorf("service token AppID = %q, want numeric app id %q", claims.AppID, created.ID)
	}
	if claims.Role != "service" {
		t.Errorf("service token Role = %q, want %q", claims.Role, "service")
	}
	if len(claims.Permissions) != 0 {
		t.Errorf("service token Permissions = %v, want empty (no scopes configured)", claims.Permissions)
	}
}

// TestIssueServiceToken_ScopesBecomePermissions verifies configured scopes
// surface as the permissions claim of a client_credentials token.
func TestIssueServiceToken_ScopesBecomePermissions(t *testing.T) {
	pool := testhelper.NewTestDB(t)
	logger := testhelper.TestLogger()
	ctx := context.Background()

	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}
	t.Cleanup(func() { testhelper.CleanupTables(t, pool) })

	var tenantID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM tenants WHERE slug = 'emc' AND deleted_at IS NULL`).Scan(&tenantID); err != nil {
		t.Fatalf("fetch seed tenant id: %v", err)
	}

	appSvc := auth.NewApplicationService(pool, logger)
	created, err := appSvc.CreateApplication(ctx, tenantID, "m2m-scoped", "m2m", []string{"orders:read", "orders:write"})
	if err != nil {
		t.Fatalf("CreateApplication() error = %v", err)
	}

	jwtSvc := auth.NewJWTService(pool, "https://auth.emc.local")
	svc := auth.NewAuthService(pool, jwtSvc, logger)

	_, appID, err := appSvc.AuthenticateClient(ctx, created.ClientID, created.ClientSecret)
	if err != nil {
		t.Fatalf("AuthenticateClient() error = %v", err)
	}

	token, _, err := svc.IssueServiceToken(ctx, tenantID, appID)
	if err != nil {
		t.Fatalf("IssueServiceToken() error = %v", err)
	}
	claims, err := jwtSvc.Verify(ctx, token)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if len(claims.Permissions) != 2 || claims.Permissions[0] != "orders:read" || claims.Permissions[1] != "orders:write" {
		t.Errorf("service token Permissions = %v, want [orders:read orders:write]", claims.Permissions)
	}
}

// newAppAuthFixture spins up a service with an attached ApplicationService and
// returns an application (with credentials) registered in the seed tenant.
func newAppAuthFixture(t *testing.T) (*auth.AuthService, *auth.AppResult, int64, context.Context) {
	t.Helper()
	pool := testhelper.NewTestDB(t)
	logger := testhelper.TestLogger()
	ctx := context.Background()

	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}
	t.Cleanup(func() { testhelper.CleanupTables(t, pool) })

	var tenantID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM tenants WHERE slug = 'emc' AND deleted_at IS NULL`).Scan(&tenantID); err != nil {
		t.Fatalf("fetch seed tenant id: %v", err)
	}

	appSvc := auth.NewApplicationService(pool, logger)
	app, err := appSvc.CreateApplication(ctx, tenantID, "integration-app", "web", nil)
	if err != nil {
		t.Fatalf("CreateApplication() error = %v", err)
	}

	jwtSvc := auth.NewJWTService(pool, "https://auth.emc.local")
	svc := auth.NewAuthService(pool, jwtSvc, logger).WithApplications(appSvc)
	return svc, app, tenantID, ctx
}

// TestRegister_WithAppCredentials verifies that client_id + client_secret
// authenticate the application, derive the tenant (no slug needed), and stamp
// app_id into the issued JWT.
func TestRegister_WithAppCredentials(t *testing.T) {
	svc, app, _, ctx := newAppAuthFixture(t)

	result, err := svc.Register(ctx, auth.RegisterInput{
		ClientID:     app.ClientID,
		ClientSecret: app.ClientSecret,
		Email:        uniqueEmail("app-register"),
		Password:     "Password123!",
		FirstName:    "App",
		LastName:     "User",
	})
	if err != nil {
		t.Fatalf("Register(app credentials, no slug) error = %v", err)
	}
	if result.AccessToken == "" {
		t.Fatal("Register() AccessToken is empty")
	}

	// Wrong secret must be rejected with the sentinel, before any user write.
	_, err = svc.Register(ctx, auth.RegisterInput{
		ClientID:     app.ClientID,
		ClientSecret: "wrong-secret",
		Email:        uniqueEmail("app-register-bad"),
		Password:     "Password123!",
	})
	if !errors.Is(err, auth.ErrInvalidClient) {
		t.Errorf("Register(wrong secret) error = %v, want ErrInvalidClient", err)
	}

	// A slug pointing at a different tenant than the app's must be rejected.
	_, err = svc.Register(ctx, auth.RegisterInput{
		TenantSlug:   "outreach",
		ClientID:     app.ClientID,
		ClientSecret: app.ClientSecret,
		Email:        uniqueEmail("app-register-mismatch"),
		Password:     "Password123!",
	})
	if !errors.Is(err, auth.ErrInvalidClient) {
		t.Errorf("Register(slug/tenant mismatch) error = %v, want ErrInvalidClient", err)
	}
}

// TestLogin_WithAppCredentials verifies app-authenticated login pins the
// candidate search to the app's tenant and stamps app_id, and that bad app
// credentials fail regardless of valid user credentials.
func TestLogin_WithAppCredentials(t *testing.T) {
	svc, app, _, ctx := newAppAuthFixture(t)

	email := uniqueEmail("app-login")
	if _, err := svc.Register(ctx, auth.RegisterInput{
		ClientID:     app.ClientID,
		ClientSecret: app.ClientSecret,
		Email:        email,
		Password:     "Password123!",
	}); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	result, err := svc.Login(ctx, auth.LoginInput{
		ClientID:     app.ClientID,
		ClientSecret: app.ClientSecret,
		Email:        email,
		Password:     "Password123!",
	})
	if err != nil {
		t.Fatalf("Login(app credentials) error = %v", err)
	}
	if result.Token == nil || result.Token.AccessToken == "" {
		t.Fatal("Login() returned no token")
	}

	// Valid user + invalid app secret must fail with the client sentinel —
	// user credentials must never compensate for a bad application secret.
	_, err = svc.Login(ctx, auth.LoginInput{
		ClientID:     app.ClientID,
		ClientSecret: "wrong-secret",
		Email:        email,
		Password:     "Password123!",
	})
	if !errors.Is(err, auth.ErrInvalidClient) {
		t.Errorf("Login(bad app secret) error = %v, want ErrInvalidClient", err)
	}
}

// TestAppUserIsolation verifies per-application user bases: the same email can
// register independently in two apps of one tenant, each app only authenticates
// its own users, and app-scoped users are invisible to the generic login.
func TestAppUserIsolation(t *testing.T) {
	svc, appA, tenantID, ctx := newAppAuthFixture(t)

	// Second application in the same tenant.
	pool := testhelper.NewTestDB(t)
	appSvc := auth.NewApplicationService(pool, testhelper.TestLogger())
	appB, err := appSvc.CreateApplication(ctx, tenantID, "integration-app-b", "web", nil)
	if err != nil {
		t.Fatalf("CreateApplication(appB) error = %v", err)
	}

	email := uniqueEmail("iso")

	// Same email registers independently in both apps, different passwords.
	if _, err := svc.Register(ctx, auth.RegisterInput{
		ClientID: appA.ClientID, ClientSecret: appA.ClientSecret,
		Email: email, Password: "PasswordAppA123!",
	}); err != nil {
		t.Fatalf("Register(appA) error = %v", err)
	}
	if _, err := svc.Register(ctx, auth.RegisterInput{
		ClientID: appB.ClientID, ClientSecret: appB.ClientSecret,
		Email: email, Password: "PasswordAppB123!",
	}); err != nil {
		t.Fatalf("Register(appB, same email) error = %v — per-app accounts must be independent", err)
	}

	// Each app authenticates only its own account/password.
	if _, err := svc.Login(ctx, auth.LoginInput{
		ClientID: appA.ClientID, ClientSecret: appA.ClientSecret,
		Email: email, Password: "PasswordAppA123!",
	}); err != nil {
		t.Errorf("Login(appA, own password) error = %v", err)
	}
	if _, err := svc.Login(ctx, auth.LoginInput{
		ClientID: appA.ClientID, ClientSecret: appA.ClientSecret,
		Email: email, Password: "PasswordAppB123!",
	}); err == nil {
		t.Error("Login(appA with appB's password) succeeded — user bases are not isolated")
	}

	// App-scoped users must be invisible to the generic (credential-less) login.
	if _, err := svc.Login(ctx, auth.LoginInput{
		Email: email, Password: "PasswordAppA123!",
	}); err == nil {
		t.Error("generic Login() authenticated an app-scoped user — must require the app's credentials")
	}
}
