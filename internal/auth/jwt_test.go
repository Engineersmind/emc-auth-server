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

	token, err := jwtSvc.Sign(ctx, tenantID, auth.AudienceAPI, auth.GrantPassword, claims)
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

// mintLegacyShape hand-signs a token in the PRE-#130 shape: a token-type value
// in "aud" and no "gty" claim at all.
//
// Hand-rolled rather than produced by Sign(), for the same reason
// mintWithIssuer is: Sign now stamps a grant on every token it mints, so it can
// no longer produce the shape these tests exist to cover. Without a hand-rolled
// legacy token the dual-read fallback would have no test at all — and the
// fallback is the entire reason issue #130 is not a breaking change.
func mintLegacyShape(t *testing.T, jwtSecret, userIDStr string, tenantID int64, audience string) string {
	t.Helper()

	claims := userClaims(userIDStr, tenantID)
	claims.RegisteredClaims = jwt.RegisteredClaims{
		Issuer:    testIssuer,
		Audience:  jwt.ClaimStrings{audience},
		Subject:   userIDStr,
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}
	if claims.Gty != "" {
		t.Fatalf("mintLegacyShape produced a token carrying gty=%q; the fallback would not be exercised", claims.Gty)
	}

	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(jwtSecret))
	if err != nil {
		t.Fatalf("sign legacy-shape token (aud=%q): %v", audience, err)
	}
	return signed
}

// TestJWTService_Verify_RejectsNonUserAudiences is the core regression guard for
// issue #84: Verify() is the user/session path, so every other token type this
// server mints must be refused there — including real management and agent
// tokens built by their actual Sign* methods, not stand-ins.
//
// Since #130 the refusal is decided by "gty" rather than "aud", and the last row
// covers the legacy shape: an unrecognised audience with no gty maps to no
// grants and is still refused.
func TestJWTService_Verify_RejectsNonUserAudiences(t *testing.T) {
	ctx, jwtSvc, tenantID, userIDStr, jwtSecret := audienceFixture(t)

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

	m2mToken, err := jwtSvc.Sign(ctx, tenantID, auth.AudienceM2M, auth.GrantClientCredentials, userClaims(userIDStr, tenantID))
	if err != nil {
		t.Fatalf("Sign(AudienceM2M) error = %v", err)
	}

	// A token from before issue #84: correctly signed, unrecognised audience, and
	// (being pre-#130) no gty either, so nothing about it names a known grant.
	legacyToken := mintLegacyShape(t, jwtSecret, userIDStr, tenantID, "emc-auth-server")

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

	token, err := jwtSvc.Sign(ctx, tenantID, auth.AudienceAPI, auth.GrantPassword, userClaims(userIDStr, tenantID))
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

	m2mToken, err := jwtSvc.Sign(ctx, tenantID, auth.AudienceM2M, auth.GrantClientCredentials, serviceClaims)
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

	userToken, err := jwtSvc.Sign(ctx, tenantID, auth.AudienceAPI, auth.GrantPassword, userClaims(userIDStr, tenantID))
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
//
// Declared as the three grant sets, exactly as routes.go declares them, so the
// test follows a set that gains a member instead of pinning a hand-written list
// the route no longer matches.
func TestJWTService_VerifyForAudience_MultipleAllowed(t *testing.T) {
	ctx, jwtSvc, tenantID, userIDStr, _ := audienceFixture(t)

	adminGrants := append(append(append([]string{},
		auth.HumanGrants...), auth.AdminGrants...), auth.MachineGrants...)

	for _, grant := range adminGrants {
		// The audience is irrelevant to the decision now; the grant is what is
		// being exercised. Passing AudienceAPI throughout makes that visible.
		token, err := jwtSvc.Sign(ctx, tenantID, auth.AudienceAPI, grant, userClaims(userIDStr, tenantID))
		if err != nil {
			t.Fatalf("Sign(%s) error = %v", grant, err)
		}
		if _, err := jwtSvc.VerifyForAudience(ctx, token, adminGrants...); err != nil {
			t.Errorf("VerifyForAudience(%s) error = %v, want nil", grant, err)
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
	if _, err := jwtSvc.VerifyForAudience(ctx, agentToken, adminGrants...); !errors.Is(err, auth.ErrUnexpectedAudience) {
		t.Errorf("VerifyForAudience(agent token) error = %v, want ErrUnexpectedAudience", err)
	}
}

// TestJWTService_VerifyForAudience_EmptyAllowListFailsClosed pins the
// fail-closed behaviour: a caller that forgets to declare audiences must get an
// error, never a token accepted because the check was effectively disabled.
func TestJWTService_VerifyForAudience_EmptyAllowListFailsClosed(t *testing.T) {
	ctx, jwtSvc, tenantID, userIDStr, _ := audienceFixture(t)

	token, err := jwtSvc.Sign(ctx, tenantID, auth.AudienceAPI, auth.GrantPassword, userClaims(userIDStr, tenantID))
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

	// ErrUnexpectedIssuer, not jwt.ErrTokenInvalidIssuer: since issue #7 the
	// expected issuer depends on the token's own tenant, which golang-jwt's
	// WithIssuer option cannot express (it compares against one string fixed
	// before parsing). The check moved out of the parser and into issuerAllowed,
	// which runs after the signature is proven. The rejection is unchanged — only
	// which sentinel reports it.
	if _, err := jwtSvc.Verify(ctx, signed); !errors.Is(err, auth.ErrUnexpectedIssuer) {
		t.Errorf("Verify(wrong issuer) error = %v, want ErrUnexpectedIssuer", err)
	}
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Issue #95: "kid" (key ID) header and the legacy symmetric verify path.
//
// Signing itself is RS256 and is covered in signingkey_test.go. What is tested
// here is the LEGACY path — a JWTService with no signing keys wired, which is what
// every token minted before this change came from. Those tokens carry no kid, and
// they must keep verifying until the Phase 4 cutover, or deploying RS256 would log
// out every active session.
// ---------------------------------------------------------------------------

// kidOf returns the "kid" header of a signed token, failing the test if absent.
func kidOf(t *testing.T, token string) string {
	t.Helper()

	raw, ok := mustParseHeader(t, token)["kid"]
	if !ok {
		t.Fatal("token has no kid header, want one")
	}
	kid, ok := raw.(string)
	if !ok {
		t.Fatalf("kid header = %T, want string", raw)
	}
	return kid
}

// TestJWTService_LegacySigningEmitsNoKID pins down a deliberate decision.
//
// An earlier revision emitted a kid derived from the HS256 secret on symmetric
// tokens. That was dropped: a kid names a key a verifier is expected to resolve,
// and a symmetric secret appears in no JWKS, so such a value would send a verifier
// on a lookup that can never succeed. Absence is the honest signal, and the verify
// path already reads "no kid" as "legacy, use the tenant secret".
func TestJWTService_LegacySigningEmitsNoKID(t *testing.T) {
	ctx, jwtSvc, tenantID, userIDStr, _ := audienceFixture(t)

	token, err := jwtSvc.Sign(ctx, tenantID, auth.AudienceAPI, auth.GrantPassword, userClaims(userIDStr, tenantID))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if kid, present := mustParseHeader(t, token)["kid"]; present {
		t.Errorf("legacy HS256 token carries kid %v — it resolves to no published key", kid)
	}
	if alg := mustParseHeader(t, token)["alg"]; alg != "HS256" {
		t.Errorf("alg = %v, want HS256 for a service with no signing keys", alg)
	}
}

// TestJWTService_Verify_KIDIsBackwardCompatible is the no-regression guarantee for
// the migration: tokens minted before asymmetric signing carry no kid and must keep
// verifying, and a kid must never be able to steer verification on its own — it is
// an unauthenticated header.
func TestJWTService_Verify_KIDIsBackwardCompatible(t *testing.T) {
	ctx, jwtSvc, tenantID, userIDStr, jwtSecret := audienceFixture(t)

	now := time.Now().UTC()
	registered := jwt.RegisteredClaims{
		ID:        uuid.New().String(),
		Issuer:    testIssuer,
		Audience:  jwt.ClaimStrings{auth.AudienceAPI},
		Subject:   userIDStr,
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(auth.AccessTokenTTL)),
	}

	t.Run("token without kid still verifies", func(t *testing.T) {
		claims := userClaims(userIDStr, tenantID)
		claims.RegisteredClaims = registered
		signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(jwtSecret))
		if err != nil {
			t.Fatalf("SignedString() error = %v", err)
		}
		if _, ok := mustParseHeader(t, signed)["kid"]; ok {
			t.Fatal("fixture unexpectedly carries a kid — it must model a pre-#95 token")
		}
		if _, err := jwtSvc.Verify(ctx, signed); err != nil {
			t.Errorf("Verify(token without kid) error = %v, want nil", err)
		}
	})

	// An attacker-chosen kid must not change anything: the signature decides. A
	// verifier that trusted the kid would let an unauthenticated header steer key
	// selection.
	t.Run("bogus kid does not change the outcome", func(t *testing.T) {
		claims := userClaims(userIDStr, tenantID)
		claims.RegisteredClaims = registered
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		token.Header["kid"] = "attacker-supplied"
		signed, err := token.SignedString([]byte(jwtSecret))
		if err != nil {
			t.Fatalf("SignedString() error = %v", err)
		}
		if _, err := jwtSvc.Verify(ctx, signed); err != nil {
			t.Errorf("Verify(correctly signed, bogus kid) error = %v, want nil", err)
		}
	})

	t.Run("plausible kid with a bad signature still fails", func(t *testing.T) {
		claims := userClaims(userIDStr, tenantID)
		claims.RegisteredClaims = registered
		forged := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		forged.Header["kid"] = "looks-legitimate"
		signed, err := forged.SignedString([]byte("not-the-tenant-secret"))
		if err != nil {
			t.Fatalf("SignedString() error = %v", err)
		}
		if _, err := jwtSvc.Verify(ctx, signed); err == nil {
			t.Error("Verify(plausible kid, wrong signing key) error = nil, want signature failure")
		}
	})
}

// mustParseHeader returns a signed token's JOSE header.
func mustParseHeader(t *testing.T, token string) map[string]interface{} {
	t.Helper()

	parsed, _, err := jwt.NewParser().ParseUnverified(token, &auth.Claims{})
	if err != nil {
		t.Fatalf("ParseUnverified() error = %v", err)
	}
	return parsed.Header
}
