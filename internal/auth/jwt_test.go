package auth_test

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/store"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// newTestJWTService builds a JWTService for tests, failing the test rather than
// returning an error — NewJWTService only errors on an empty issuer, which is a
// construction bug, not a case any test other than
// TestNewJWTService_RejectsEmptyIssuer exercises.
func newTestJWTService(t *testing.T, pool *pgxpool.Pool, issuer string) *auth.JWTService {
	t.Helper()
	svc, err := auth.NewJWTService(pool, issuer)
	if err != nil {
		t.Fatalf("NewJWTService(%q): %v", issuer, err)
	}
	return svc
}

// TestNewJWTService_RejectsEmptyIssuer pins that issuer validation happens at
// construction. Verification enforces iss unconditionally, so a service built
// without an issuer must not exist at all — otherwise a misconfigured deploy
// would silently ship a server whose tokens cannot be told apart from those of
// any other server sharing the tenant secret.
func TestNewJWTService_RejectsEmptyIssuer(t *testing.T) {
	pool := testhelper.NewTestDB(t)

	svc, err := auth.NewJWTService(pool, "")
	if !errors.Is(err, auth.ErrEmptyIssuer) {
		t.Errorf("NewJWTService(\"\") error = %v, want ErrEmptyIssuer", err)
	}
	if svc != nil {
		t.Error("NewJWTService(\"\") returned a service; want nil")
	}
}

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

	jwtSvc := newTestJWTService(t, pool, "https://auth.emc.local")

	userIDStr := strconv.FormatInt(userID, 10)
	tenantIDStr := strconv.FormatInt(tenantID, 10)

	claims := &auth.Claims{
		UserID:      userIDStr,
		TenantID:    tenantIDStr,
		Email:       "admin@emc.local",
		Role:        "super_admin",
		Permissions: []string{"admin:access"},
	}

	token, err := jwtSvc.Sign(ctx, tenantID, auth.AudienceAPI, claims)
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

	jwtSvc := newTestJWTService(t, pool, "https://auth.emc.local")
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

	jwtSvc := newTestJWTService(t, pool, "https://auth.emc.local")

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

// ---------------------------------------------------------------------------
// Audience enforcement (issue #84)
//
// The aud claim is this server's token-type discriminator. These tests pin the
// contract that each verify path accepts only the token types it is meant to,
// so a token minted for one flow cannot be replayed on another.
// ---------------------------------------------------------------------------

// audienceFixture seeds the DB and returns everything the audience tests need:
// a JWTService, the seed tenant's id and jwt_secret (for hand-rolling tokens
// that the Sign* methods cannot produce), and the seed user's id as a string.
func audienceFixture(t *testing.T) (ctx context.Context, jwtSvc *auth.JWTService, tenantID int64, userIDStr, jwtSecret string) {
	t.Helper()

	pool := testhelper.NewTestDB(t)
	testhelper.CleanupTables(t, pool)

	ctx = context.Background()
	if err := store.RunSeed(ctx, pool, testhelper.TestLogger()); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}

	var userID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM tenants WHERE slug = 'emc' AND deleted_at IS NULL`).Scan(&tenantID); err != nil {
		t.Fatalf("fetch seed tenant id: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT id FROM users WHERE email = 'admin@emc.local' AND deleted_at IS NULL`).Scan(&userID); err != nil {
		t.Fatalf("fetch seed user id: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`SELECT jwt_secret FROM tenants WHERE id = $1 AND is_active = true`, tenantID,
	).Scan(&jwtSecret); err != nil {
		t.Fatalf("fetch jwt_secret: %v", err)
	}

	return ctx, newTestJWTService(t, pool, testIssuer), tenantID, strconv.FormatInt(userID, 10), jwtSecret
}

// testIssuer is the issuer every audience-test token is minted with; Verify
// enforces iss, so hand-rolled tokens must use the same value.
const testIssuer = "https://auth.emc.local"

// userClaims builds a minimal user-shaped claim set for the seed tenant/user.
func userClaims(userIDStr string, tenantID int64) *auth.Claims {
	return &auth.Claims{
		UserID:      userIDStr,
		TenantID:    strconv.FormatInt(tenantID, 10),
		Email:       "admin@emc.local",
		Role:        "super_admin",
		Permissions: []string{"admin:access"},
	}
}

// TestJWTService_Verify_RejectsNonUserAudiences is the core regression guard for
// issue #84: Verify() is the user/session path, so every other token type this
// server mints must be refused there — including real management and agent
// tokens built by their actual Sign* methods, not stand-ins.
func TestJWTService_Verify_RejectsNonUserAudiences(t *testing.T) {
	ctx, jwtSvc, tenantID, userIDStr, _ := audienceFixture(t)

	mgmtToken, err := jwtSvc.SignManagement(ctx, &auth.APIKeyIdentity{
		KeyID:       42,
		TenantID:    tenantID,
		Name:        "ci-deploy-key",
		Permissions: []string{"apps:read"},
	})
	if err != nil {
		t.Fatalf("SignManagement() error = %v", err)
	}

	agentToken, err := jwtSvc.SignAgent(ctx, &auth.AgentIdentity{
		AgentID:      uuid.New(),
		TenantID:     tenantID,
		Name:         "report-bot",
		AgentType:    "assistant",
		Capabilities: []string{"read"},
	})
	if err != nil {
		t.Fatalf("SignAgent() error = %v", err)
	}

	m2mToken, err := jwtSvc.Sign(ctx, tenantID, auth.AudienceM2M, userClaims(userIDStr, tenantID))
	if err != nil {
		t.Fatalf("Sign(AudienceM2M) error = %v", err)
	}

	// A token from before this change: correctly signed, unrecognised audience.
	legacyToken, err := jwtSvc.Sign(ctx, tenantID, "emc-auth-server", userClaims(userIDStr, tenantID))
	if err != nil {
		t.Fatalf("Sign(legacy audience) error = %v", err)
	}

	tests := []struct {
		name  string
		token string
	}{
		{"management token", mgmtToken},
		{"agent token", agentToken},
		{"m2m service token", m2mToken},
		{"legacy emc-auth-server token", legacyToken},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := jwtSvc.Verify(ctx, tc.token); !errors.Is(err, auth.ErrUnexpectedAudience) {
				t.Errorf("Verify() error = %v, want ErrUnexpectedAudience", err)
			}
		})
	}
}

// TestJWTService_Verify_AcceptsUserAudience is the positive counterpart: the
// audience check must not break the flow it is meant to allow.
func TestJWTService_Verify_AcceptsUserAudience(t *testing.T) {
	ctx, jwtSvc, tenantID, userIDStr, _ := audienceFixture(t)

	token, err := jwtSvc.Sign(ctx, tenantID, auth.AudienceAPI, userClaims(userIDStr, tenantID))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	verified, err := jwtSvc.Verify(ctx, token)
	if err != nil {
		t.Fatalf("Verify() error = %v, want nil", err)
	}
	if verified.UserID != userIDStr {
		t.Errorf("Verify() UserID = %q, want %q", verified.UserID, userIDStr)
	}
}

// TestJWTService_VerifyM2M enforces the M2M path in both directions: a service
// token passes, a user token does not. Without the second half, an M2M-only
// endpoint would still accept a human's token.
func TestJWTService_VerifyM2M(t *testing.T) {
	ctx, jwtSvc, tenantID, userIDStr, _ := audienceFixture(t)

	serviceClaims := userClaims(userIDStr, tenantID)
	serviceClaims.Role = "service"
	serviceClaims.Permissions = []string{"users:read"}

	m2mToken, err := jwtSvc.Sign(ctx, tenantID, auth.AudienceM2M, serviceClaims)
	if err != nil {
		t.Fatalf("Sign(AudienceM2M) error = %v", err)
	}
	verified, err := jwtSvc.VerifyM2M(ctx, m2mToken)
	if err != nil {
		t.Fatalf("VerifyM2M() error = %v, want nil", err)
	}
	if verified.Role != "service" {
		t.Errorf("VerifyM2M() Role = %q, want %q", verified.Role, "service")
	}
	if len(verified.Permissions) != 1 || verified.Permissions[0] != "users:read" {
		t.Errorf("VerifyM2M() Permissions = %v, want [users:read]", verified.Permissions)
	}

	userToken, err := jwtSvc.Sign(ctx, tenantID, auth.AudienceAPI, userClaims(userIDStr, tenantID))
	if err != nil {
		t.Fatalf("Sign(AudienceAPI) error = %v", err)
	}
	if _, err := jwtSvc.VerifyM2M(ctx, userToken); !errors.Is(err, auth.ErrUnexpectedAudience) {
		t.Errorf("VerifyM2M(user token) error = %v, want ErrUnexpectedAudience", err)
	}
}

// TestJWTService_VerifyForAudience_MultipleAllowed covers the admin-route
// wiring: operators, API-key integrations, and machine clients are all valid
// callers there, while an agent token still is not.
func TestJWTService_VerifyForAudience_MultipleAllowed(t *testing.T) {
	ctx, jwtSvc, tenantID, userIDStr, _ := audienceFixture(t)

	adminAudiences := []string{auth.AudienceAPI, auth.AudienceManagement, auth.AudienceM2M}

	for _, aud := range adminAudiences {
		token, err := jwtSvc.Sign(ctx, tenantID, aud, userClaims(userIDStr, tenantID))
		if err != nil {
			t.Fatalf("Sign(%s) error = %v", aud, err)
		}
		if _, err := jwtSvc.VerifyForAudience(ctx, token, adminAudiences...); err != nil {
			t.Errorf("VerifyForAudience(%s) error = %v, want nil", aud, err)
		}
	}

	agentToken, err := jwtSvc.SignAgent(ctx, &auth.AgentIdentity{
		AgentID:  uuid.New(),
		TenantID: tenantID,
		Name:     "report-bot",
	})
	if err != nil {
		t.Fatalf("SignAgent() error = %v", err)
	}
	if _, err := jwtSvc.VerifyForAudience(ctx, agentToken, adminAudiences...); !errors.Is(err, auth.ErrUnexpectedAudience) {
		t.Errorf("VerifyForAudience(agent token) error = %v, want ErrUnexpectedAudience", err)
	}
}

// TestJWTService_VerifyForAudience_EmptyAllowListFailsClosed pins the
// fail-closed behaviour: a caller that forgets to declare audiences must get an
// error, never a token accepted because the check was effectively disabled.
func TestJWTService_VerifyForAudience_EmptyAllowListFailsClosed(t *testing.T) {
	ctx, jwtSvc, tenantID, userIDStr, _ := audienceFixture(t)

	token, err := jwtSvc.Sign(ctx, tenantID, auth.AudienceAPI, userClaims(userIDStr, tenantID))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if _, err := jwtSvc.VerifyForAudience(ctx, token); !errors.Is(err, auth.ErrNoAudienceAllowed) {
		t.Errorf("VerifyForAudience(no audiences) error = %v, want ErrNoAudienceAllowed", err)
	}
}

// TestJWTService_Verify_RejectsMultiAudienceToken guards the single-audience
// invariant: a token must not satisfy a route by listing an accepted audience
// alongside others. No Sign* method produces this shape, so it is built by hand.
func TestJWTService_Verify_RejectsMultiAudienceToken(t *testing.T) {
	ctx, jwtSvc, tenantID, userIDStr, jwtSecret := audienceFixture(t)

	claims := userClaims(userIDStr, tenantID)
	claims.RegisteredClaims = jwt.RegisteredClaims{
		Issuer:    testIssuer,
		Audience:  jwt.ClaimStrings{auth.AudienceAgent, auth.AudienceAPI},
		Subject:   userIDStr,
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}

	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(jwtSecret))
	if err != nil {
		t.Fatalf("sign multi-audience token: %v", err)
	}

	if _, err := jwtSvc.Verify(ctx, signed); !errors.Is(err, auth.ErrUnexpectedAudience) {
		t.Errorf("Verify(multi-audience) error = %v, want ErrUnexpectedAudience", err)
	}
}

// TestJWTService_Verify_RejectsWrongIssuer covers the iss enforcement added
// alongside the audience check — every token this server mints carries iss, so
// one that does not match the configured issuer is not ours.
func TestJWTService_Verify_RejectsWrongIssuer(t *testing.T) {
	ctx, jwtSvc, tenantID, userIDStr, jwtSecret := audienceFixture(t)

	claims := userClaims(userIDStr, tenantID)
	claims.RegisteredClaims = jwt.RegisteredClaims{
		Issuer:    "https://evil.example.com",
		Audience:  jwt.ClaimStrings{auth.AudienceAPI},
		Subject:   userIDStr,
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}

	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(jwtSecret))
	if err != nil {
		t.Fatalf("sign wrong-issuer token: %v", err)
	}

	if _, err := jwtSvc.Verify(ctx, signed); !errors.Is(err, jwt.ErrTokenInvalidIssuer) {
		t.Errorf("Verify(wrong issuer) error = %v, want ErrTokenInvalidIssuer", err)
	}
}
