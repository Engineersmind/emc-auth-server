package auth_test

import (
	"context"
	"errors"
	"fmt"
	"strconv"
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

	jwtSvc := newTestJWTService(t, pool, "https://auth.emc.local")
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

// registerAndLogin creates an account and signs it in, returning the token pair.
//
// Exists because registration deliberately no longer issues tokens: creating an
// account and starting a session are separate acts. Most tests here only ever wanted
// "give me a signed-in user", and this keeps that one line at the call site rather
// than two calls and an error check repeated a dozen times.
func registerAndLogin(t *testing.T, svc *auth.AuthService, email, password string) *auth.AuthResult {
	t.Helper()
	ctx := context.Background()
	if _, err := svc.Register(ctx, auth.RegisterInput{
		Email:     email,
		Password:  password,
		FirstName: "Test",
		LastName:  "User",
	}); err != nil {
		t.Fatalf("Register(%s): %v", email, err)
	}
	res, err := svc.Login(ctx, auth.LoginInput{Email: email, Password: password})
	if err != nil {
		t.Fatalf("Login(%s): %v", email, err)
	}
	if res.Token == nil {
		t.Fatalf("Login(%s) returned no token pair", email)
	}
	return res.Token
}

func TestRegister_Success(t *testing.T) {
	svc, cleanup := newServiceForTest(t)
	defer cleanup()

	ctx := context.Background()
	email := uniqueEmail("register-success")

	result, err := svc.Register(ctx, auth.RegisterInput{
		Email:     email,
		Password:  "Password123!",
		FirstName: "New",
		LastName:  "User",
	})
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if result == nil {
		t.Fatal("Register() result is nil")
	}
	if result.UserID == 0 {
		t.Error("Register() UserID is zero")
	}
	if result.Email != email {
		t.Errorf("Register() Email = %q, want %q", result.Email, email)
	}
	if result.TenantID == 0 {
		t.Error("Register() TenantID is zero")
	}
	if result.ApplicationID != nil {
		t.Errorf("Register() ApplicationID = %v, want nil for a tenant-level account", *result.ApplicationID)
	}
}

// Registration creates an account and nothing else.
//
// It used to return a token pair, which meant a session: every new account started
// with one nobody asked for, and a client that registered then logged in — the
// normal shape — ended up with two sessions seconds apart and a device list opening
// on an entry the user could not account for.
func TestRegister_DoesNotCreateASession(t *testing.T) {
	svc, cleanup := newServiceForTest(t)
	defer cleanup()

	ctx := context.Background()
	email := uniqueEmail("register-no-session")

	reg, err := svc.Register(ctx, auth.RegisterInput{
		Email:     email,
		Password:  "Password123!",
		FirstName: "No",
		LastName:  "Session",
	})
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	// Its own pool against the same DATABASE_URL: newServiceForTest does not expose
	// one, and a second handle to the same database is cheaper than reshaping the
	// fixture every other test in this file relies on.
	pool := testhelper.NewTestDB(t)

	var sessions, tokens int
	if err := pool.QueryRow(ctx,
		`SELECT (SELECT COUNT(*) FROM user_sessions WHERE user_id = $1),
		        (SELECT COUNT(*) FROM refresh_tokens WHERE user_id = $1)`,
		reg.UserID).Scan(&sessions, &tokens); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if sessions != 0 {
		t.Errorf("sessions after register = %d, want 0", sessions)
	}
	if tokens != 0 {
		t.Errorf("refresh tokens after register = %d, want 0", tokens)
	}

	// And signing in afterwards produces exactly one.
	if _, err := svc.Login(ctx, auth.LoginInput{Email: email, Password: "Password123!"}); err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM user_sessions WHERE user_id = $1`, reg.UserID).Scan(&sessions); err != nil {
		t.Fatalf("recount sessions: %v", err)
	}
	if sessions != 1 {
		t.Errorf("sessions after register+login = %d, want 1", sessions)
	}
}

func TestRegister_DuplicateEmail(t *testing.T) {
	svc, cleanup := newServiceForTest(t)
	defer cleanup()

	ctx := context.Background()
	email := uniqueEmail("dup-email")

	_, err := svc.Register(ctx, auth.RegisterInput{
		Email:     email,
		Password:  "Password123!",
		FirstName: "First",
		LastName:  "User",
	})
	if err != nil {
		t.Fatalf("first Register() unexpected error = %v", err)
	}

	_, err = svc.Register(ctx, auth.RegisterInput{
		Email:     email,
		Password:  "AnotherPass456!",
		FirstName: "Second",
		LastName:  "User",
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
		Email:     email,
		Password:  password,
		FirstName: "Login",
		LastName:  "Test",
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
		Email:     email,
		Password:  "CorrectPassword123!",
		FirstName: "Login",
		LastName:  "WrongPW",
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

	regResult := registerAndLogin(t, svc, email, password)
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

	regResult := registerAndLogin(t, svc, email, password)
	oldRefreshToken := regResult.RefreshToken

	// First Refresh succeeds — consumes old token, issues new one.
	_, err := svc.Refresh(ctx, oldRefreshToken)
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

	regResult := registerAndLogin(t, svc, email, password)
	refreshToken := regResult.RefreshToken

	// Logout should succeed.
	if err := svc.Logout(ctx, refreshToken); err != nil {
		t.Fatalf("Logout() error = %v", err)
	}

	// Refresh after logout must fail.
	_, err := svc.Refresh(ctx, refreshToken)
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

	jwtSvc := newTestJWTService(t, pool, "https://auth.emc.local")
	svc := auth.NewAuthService(pool, jwtSvc, logger)

	_, appID, err := appSvc.AuthenticateClient(ctx, created.ClientID, created.ClientSecret)
	if err != nil {
		t.Fatalf("AuthenticateClient() error = %v", err)
	}

	token, expiresIn, err := svc.IssueServiceToken(ctx, tenantID, appID, "")
	if err != nil {
		t.Fatalf("IssueServiceToken() error = %v", err)
	}
	if expiresIn != 900 {
		t.Errorf("IssueServiceToken() expiresIn = %d, want 900", expiresIn)
	}

	// VerifyM2M, not Verify: a service token carries AudienceM2M and is refused
	// on the user/session path by design (issue #84).
	claims, err := jwtSvc.VerifyM2M(ctx, token)
	if err != nil {
		t.Fatalf("VerifyM2M() error = %v", err)
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

	jwtSvc := newTestJWTService(t, pool, "https://auth.emc.local")
	svc := auth.NewAuthService(pool, jwtSvc, logger)

	_, appID, err := appSvc.AuthenticateClient(ctx, created.ClientID, created.ClientSecret)
	if err != nil {
		t.Fatalf("AuthenticateClient() error = %v", err)
	}

	token, _, err := svc.IssueServiceToken(ctx, tenantID, appID, "")
	if err != nil {
		t.Fatalf("IssueServiceToken() error = %v", err)
	}
	claims, err := jwtSvc.VerifyM2M(ctx, token)
	if err != nil {
		t.Fatalf("VerifyM2M() error = %v", err)
	}
	if len(claims.Permissions) != 2 || claims.Permissions[0] != "orders:read" || claims.Permissions[1] != "orders:write" {
		t.Errorf("service token Permissions = %v, want [orders:read orders:write]", claims.Permissions)
	}
}

// TestIssueServiceToken_AudienceIsM2M pins the audience of a client_credentials
// token: it must be distinguishable from a user session token, so a leaked
// service token cannot be replayed on user self-service routes (issue #84).
// TestIssueServiceToken_AudienceIsTheClientsOwnAPI was
// TestIssueServiceToken_AudienceIsM2M and asserted aud == "emc-auth-m2m".
//
// Issue #131 changes that value on purpose: "aud" now names the API a token may
// be spent at, and a client that asks for nothing gets its own. The thing the
// original test was really protecting — that a machine token cannot act as a
// user — is unchanged and is still asserted at the bottom; since #130 it is
// carried by "gty", which is why moving "aud" does not weaken it.
//
// Renamed rather than edited in place so a reviewer sees the contract changed
// rather than finding a test whose name no longer describes it.
func TestIssueServiceToken_AudienceIsTheClientsOwnAPI(t *testing.T) {
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
	created, err := appSvc.CreateApplication(ctx, tenantID, "m2m-audience", "m2m", nil)
	if err != nil {
		t.Fatalf("CreateApplication() error = %v", err)
	}

	jwtSvc := newTestJWTService(t, pool, "https://auth.emc.local")
	svc := auth.NewAuthService(pool, jwtSvc, logger)

	_, appID, err := appSvc.AuthenticateClient(ctx, created.ClientID, created.ClientSecret)
	if err != nil {
		t.Fatalf("AuthenticateClient() error = %v", err)
	}

	token, _, err := svc.IssueServiceToken(ctx, tenantID, appID, "")
	if err != nil {
		t.Fatalf("IssueServiceToken() error = %v", err)
	}

	claims, err := jwtSvc.VerifyM2M(ctx, token)
	if err != nil {
		t.Fatalf("VerifyM2M() error = %v", err)
	}
	// The client asked for no audience, so it gets its own (issue #131 §7
	// case 2) — the resolution that keeps existing client_credentials
	// integrations working with no changes at all.
	if len(claims.Audience) != 1 || claims.Audience[0] != created.Audience {
		t.Errorf("service token aud = %v, want [%s] (the client's own audience)",
			[]string(claims.Audience), created.Audience)
	}
	if claims.Gty != auth.GrantClientCredentials {
		t.Errorf("service token gty = %q, want %q — machine-ness moved to gty in #130 and is what the boundary now rests on",
			claims.Gty, auth.GrantClientCredentials)
	}

	// The property issue #84 established, unchanged: the same token must not
	// authenticate as a user session. It is enforced through "gty" now rather
	// than through "aud", which is precisely why #131 could repurpose "aud".
	if _, err := jwtSvc.Verify(ctx, token); !errors.Is(err, auth.ErrUnexpectedAudience) {
		t.Errorf("Verify(service token) error = %v, want ErrUnexpectedAudience", err)
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

	jwtSvc := newTestJWTService(t, pool, "https://auth.emc.local")
	svc := auth.NewAuthService(pool, jwtSvc, logger).WithApplications(appSvc)
	return svc, app, tenantID, ctx
}

// TestRegister_WithAppCredentials verifies that client_id + client_secret
// authenticate the application, derive the tenant (no slug needed), and own the
// created account.
func TestRegister_WithAppCredentials(t *testing.T) {
	svc, app, tenantID, ctx := newAppAuthFixture(t)

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
	if result.UserID == 0 {
		t.Fatal("Register() UserID is zero")
	}
	// The tenant was derived from the authenticated application, not from a slug.
	if result.TenantID != tenantID {
		t.Errorf("Register() TenantID = %d, want %d derived from the application", result.TenantID, tenantID)
	}
	// The account belongs to that application's isolated user base — previously
	// asserted via the app_id claim in the token registration used to return.
	if result.ApplicationID == nil {
		t.Error("Register() ApplicationID is nil, want the authenticated application")
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

	// There was a third case here: a slug naming a different tenant than the
	// app's credentials had to be rejected as a confused deputy. RegisterInput no
	// longer carries a tenant selector, so the mismatch cannot be expressed and
	// the guard it tested is gone. The tenant comes from the authenticated
	// application, full stop.
}

// TestRegister_AssignsApplicationDefaultRole verifies that an app-scoped
// registration is assigned the application's default role (and its
// permissions), and that a role default in one application is not leaked
// into another application's registrations.
func TestRegister_AssignsApplicationDefaultRole(t *testing.T) {
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
	app, err := appSvc.CreateApplication(ctx, tenantID, "default-role-app", "web", nil)
	if err != nil {
		t.Fatalf("CreateApplication() error = %v", err)
	}
	appID, err := strconv.ParseInt(app.ID, 10, 64)
	if err != nil {
		t.Fatalf("parse app id: %v", err)
	}

	var permID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO permissions (tenant_id, name, description) VALUES ($1, 'widgets:read', '')
		RETURNING id
	`, tenantID).Scan(&permID); err != nil {
		t.Fatalf("insert permission: %v", err)
	}

	var roleID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO roles (tenant_id, application_id, name, is_system, is_default, created_at)
		VALUES ($1, $2, 'viewer', false, true, NOW())
		RETURNING id
	`, tenantID, appID).Scan(&roleID); err != nil {
		t.Fatalf("insert default role: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO role_permissions (role_id, permission_id, tenant_id) VALUES ($1, $2, $3)
	`, roleID, permID, tenantID); err != nil {
		t.Fatalf("assign permission to role: %v", err)
	}

	jwtSvc := newTestJWTService(t, pool, "https://auth.emc.local")
	svc := auth.NewAuthService(pool, jwtSvc, logger).WithApplications(appSvc)

	result, err := svc.Register(ctx, auth.RegisterInput{
		ClientID:     app.ClientID,
		ClientSecret: app.ClientSecret,
		Email:        uniqueEmail("default-role"),
		Password:     "Password123!",
	})
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	// Read off the result rather than out of a token: registration no longer issues
	// one. The role is what matters here, and it is now returned directly.
	if result.Role != "viewer" {
		t.Errorf("Register() assigned role = %q, want %q", result.Role, "viewer")
	}
	// The permissions the role carries are still worth asserting, so they are read
	// from the session the user gets when they sign in.
	login, err := svc.Login(ctx, auth.LoginInput{
		ClientID:     app.ClientID,
		ClientSecret: app.ClientSecret,
		Email:        result.Email,
		Password:     "Password123!",
	})
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	claims, err := jwtSvc.Verify(ctx, login.Token.AccessToken)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if claims.Role != "viewer" {
		t.Errorf("token role = %q, want %q", claims.Role, "viewer")
	}
	if len(claims.Permissions) != 1 || claims.Permissions[0] != "widgets:read" {
		t.Errorf("token permissions = %v, want [widgets:read]", claims.Permissions)
	}

	// A second application with no default role configured must register the
	// user with no role, not fall back to any other application's default.
	appB, err := appSvc.CreateApplication(ctx, tenantID, "no-default-role-app", "web", nil)
	if err != nil {
		t.Fatalf("CreateApplication(appB) error = %v", err)
	}
	resultB, err := svc.Register(ctx, auth.RegisterInput{
		ClientID:     appB.ClientID,
		ClientSecret: appB.ClientSecret,
		Email:        uniqueEmail("no-default-role"),
		Password:     "Password123!",
	})
	if err != nil {
		t.Fatalf("Register(appB) error = %v", err)
	}
	if resultB.Role != "" {
		t.Errorf("Register(appB, no default role) assigned role = %q, want empty", resultB.Role)
	}
}

// TestRegister_LegacyDoesNotInheritSystemRole verifies that tenant-level
// registration (no application credentials) never falls back to a
// tenant-management role such as owner/super_admin — those must only ever be
// assigned by explicit admin action, never by self-registration.
func TestRegister_LegacyDoesNotInheritSystemRole(t *testing.T) {
	pool := testhelper.NewTestDB(t)
	logger := testhelper.TestLogger()
	ctx := context.Background()

	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}
	t.Cleanup(func() { testhelper.CleanupTables(t, pool) })

	jwtSvc := newTestJWTService(t, pool, "https://auth.emc.local")
	svc := auth.NewAuthService(pool, jwtSvc, logger)

	result, err := svc.Register(ctx, auth.RegisterInput{
		Email:    uniqueEmail("legacy-no-role"),
		Password: "Password123!",
	})
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	if result.Role == "owner" || result.Role == "super_admin" {
		t.Errorf("Register() legacy registration got system role %q, want no system role", result.Role)
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

// newAppRefreshFixture builds a service with an attached ApplicationService and
// the JWTService needed to Verify issued tokens, plus a registered application.
func newAppRefreshFixture(t *testing.T) (*auth.AuthService, *auth.JWTService, *auth.AppResult, context.Context) {
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
	app, err := appSvc.CreateApplication(ctx, tenantID, "refresh-app", "web", nil)
	if err != nil {
		t.Fatalf("CreateApplication() error = %v", err)
	}

	jwtSvc := newTestJWTService(t, pool, "https://auth.emc.local")
	svc := auth.NewAuthService(pool, jwtSvc, logger).WithApplications(appSvc)
	return svc, jwtSvc, app, ctx
}

// TestRefreshWithLock_PreservesAppID is the regression test for issue #82: an
// application-scoped user's app_id claim must survive token rotation. Before the
// fix the refreshed access token was reissued with an empty AppID, silently
// dropping app context (and with it app-scoped RBAC/MFA/rate-limit gating) after
// a single refresh.
func TestRefreshWithLock_PreservesAppID(t *testing.T) {
	svc, jwtSvc, app, ctx := newAppRefreshFixture(t)

	// Register then sign in: registration creates the account without starting a
	// session, so the token pair comes from the login.
	email := uniqueEmail("refresh-appid")
	if _, err := svc.Register(ctx, auth.RegisterInput{
		ClientID:     app.ClientID,
		ClientSecret: app.ClientSecret,
		Email:        email,
		Password:     "Password123!",
	}); err != nil {
		t.Fatalf("Register(app credentials) error = %v", err)
	}
	loginRes, err := svc.Login(ctx, auth.LoginInput{
		ClientID:     app.ClientID,
		ClientSecret: app.ClientSecret,
		Email:        email,
		Password:     "Password123!",
	})
	if err != nil {
		t.Fatalf("Login(app credentials) error = %v", err)
	}
	reg := loginRes.Token

	// Sanity: the original access token carries the application id.
	origClaims, err := jwtSvc.Verify(ctx, reg.AccessToken)
	if err != nil {
		t.Fatalf("Verify(original) error = %v", err)
	}
	if origClaims.AppID != app.ID {
		t.Fatalf("original token AppID = %q, want %q", origClaims.AppID, app.ID)
	}

	// Rotate (nil Redis → lock-free, but rotation and app-id threading are
	// identical to the locked path).
	result, grace, err := svc.RefreshWithLock(ctx, reg.RefreshToken, nil)
	if err != nil {
		t.Fatalf("RefreshWithLock() error = %v", err)
	}
	if grace != nil {
		t.Fatal("RefreshWithLock() returned an unexpected grace result on first rotation")
	}

	newClaims, err := jwtSvc.Verify(ctx, result.AccessToken)
	if err != nil {
		t.Fatalf("Verify(rotated) error = %v", err)
	}
	if newClaims.AppID != app.ID {
		t.Errorf("rotated token AppID = %q, want %q — application context did not survive refresh", newClaims.AppID, app.ID)
	}
}

// TestRefreshWithLock_ReplayRevokesFamily verifies that replaying an
// already-rotated refresh token through the locked path is detected as a replay
// (not a generic invalid-token error) and revokes the entire session family —
// the guarantee issue #82 requires the explicit /auth/refresh endpoint to have.
func TestRefreshWithLock_ReplayRevokesFamily(t *testing.T) {
	svc, _, app, ctx := newAppRefreshFixture(t)
	rdb := testhelper.NewTestRedis(t)

	// Register then sign in: registration creates the account without starting a
	// session, so the token pair comes from the login.
	email := uniqueEmail("refresh-replay-lock")
	if _, err := svc.Register(ctx, auth.RegisterInput{
		ClientID:     app.ClientID,
		ClientSecret: app.ClientSecret,
		Email:        email,
		Password:     "Password123!",
	}); err != nil {
		t.Fatalf("Register(app credentials) error = %v", err)
	}
	loginRes, err := svc.Login(ctx, auth.LoginInput{
		ClientID:     app.ClientID,
		ClientSecret: app.ClientSecret,
		Email:        email,
		Password:     "Password123!",
	})
	if err != nil {
		t.Fatalf("Login(app credentials) error = %v", err)
	}
	reg := loginRes.Token

	// First rotation consumes the original token and issues a fresh pair.
	rotated, grace, err := svc.RefreshWithLock(ctx, reg.RefreshToken, rdb)
	if err != nil {
		t.Fatalf("first RefreshWithLock() error = %v", err)
	}
	if grace != nil {
		t.Fatal("unexpected grace result on first rotation")
	}

	// Replaying the original (now revoked) token must be flagged as a replay.
	if _, _, err = svc.RefreshWithLock(ctx, reg.RefreshToken, rdb); !errors.Is(err, auth.ErrTokenReplay) {
		t.Fatalf("replay RefreshWithLock() error = %v, want auth.ErrTokenReplay", err)
	}

	// The still-valid rotated sibling must now be dead too — the whole family
	// was revoked by the replay response.
	if _, _, err = svc.RefreshWithLock(ctx, rotated.RefreshToken, rdb); err == nil {
		t.Fatal("sibling token still valid after replay — session family was not revoked")
	}
}
