package auth_test

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/store"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// Issue #7 — per-tenant OIDC issuers.
//
// What these tests defend is the property that makes OIDC discovery possible at
// all: a token's iss must name the tenant whose JWKS can verify it. The failure
// this replaces is silent and remote — a relying party fetches discovery, gets a
// jwks_uri, and finds no key there matching the token — so it must be pinned here
// rather than discovered by an integrator.

// testIssuerBaseURL is the origin per-tenant issuers are built from in tests.
// Deliberately different from testIssuer (the legacy global value) so a test
// asserting one cannot pass by accidentally matching the other.
const testIssuerBaseURL = "https://auth.test.local"

// issuerEnv bundles what the issue #7 tests need, so each test names only the
// parts it uses instead of threading six positional results.
type issuerEnv struct {
	ctx       context.Context
	pool      *pgxpool.Pool
	svc       *auth.JWTService
	resolver  *auth.TenantIssuerResolver
	tenantID  int64
	slug      string
	userIDStr string
	jwtSecret string
}

// tenantIssuer is the issuer the fixture's tenant should be minting.
func (e issuerEnv) tenantIssuer() string {
	return testIssuerBaseURL + "/tenants/" + e.slug
}

// issuerFixture seeds a tenant and returns a JWTService with per-tenant issuers
// wired.
func issuerFixture(t *testing.T) issuerEnv {
	t.Helper()

	pool := testhelper.NewTestDB(t)
	testhelper.CleanupTables(t, pool)

	ctx := context.Background()
	if err := store.RunSeed(ctx, pool, testhelper.TestLogger()); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}

	env := issuerEnv{ctx: ctx, pool: pool}
	var userID int64
	if err := pool.QueryRow(ctx,
		`SELECT id, slug, jwt_secret FROM tenants WHERE slug = 'emc' AND deleted_at IS NULL`,
	).Scan(&env.tenantID, &env.slug, &env.jwtSecret); err != nil {
		t.Fatalf("fetch seed tenant: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`SELECT id FROM users WHERE email = 'admin@emc.local' AND deleted_at IS NULL`,
	).Scan(&userID); err != nil {
		t.Fatalf("fetch seed user id: %v", err)
	}
	env.userIDStr = strconv.FormatInt(userID, 10)

	resolver, err := auth.NewTenantIssuerResolver(pool, testIssuerBaseURL)
	if err != nil {
		t.Fatalf("NewTenantIssuerResolver: %v", err)
	}
	env.resolver = resolver
	env.svc = newTestJWTService(t, pool, testIssuer).WithTenantIssuers(resolver)
	return env
}

// issuerOf reads the "iss" claim off a signed token without verifying it — these
// tests assert on what was minted, which is a separate question from whether it
// verifies.
func issuerOf(t *testing.T, token string) string {
	t.Helper()

	var claims jwt.RegisteredClaims
	if _, _, err := jwt.NewParser().ParseUnverified(token, &claims); err != nil {
		t.Fatalf("parse token: %v", err)
	}
	return claims.Issuer
}

// mintWithIssuer hand-signs a valid HS256 user token carrying an arbitrary
// issuer. Hand-rolled rather than produced by Sign(), because the whole point is
// to build issuers that no current mint path would ever emit.
func mintWithIssuer(t *testing.T, env issuerEnv, issuer string) string {
	t.Helper()

	claims := userClaims(env.userIDStr, env.tenantID)
	claims.RegisteredClaims = jwt.RegisteredClaims{
		Issuer:    issuer,
		Audience:  jwt.ClaimStrings{auth.AudienceAPI},
		Subject:   env.userIDStr,
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}

	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(env.jwtSecret))
	if err != nil {
		t.Fatalf("sign token with issuer %q: %v", issuer, err)
	}
	return signed
}

// TestTenantIssuerResolver_RejectsEmptyBaseURL pins construction-time validation,
// for the same reason NewJWTService rejects an empty issuer: a resolver with no
// base URL would mint tokens whose iss is a bare "/tenants/emc", which is not a
// valid issuer identifier and would break every relying party rather than failing
// visibly at startup.
func TestTenantIssuerResolver_RejectsEmptyBaseURL(t *testing.T) {
	pool := testhelper.NewTestDB(t)

	for _, base := range []string{"", "   ", "/"} {
		r, err := auth.NewTenantIssuerResolver(pool, base)
		if !errors.Is(err, auth.ErrEmptyIssuerBaseURL) {
			t.Errorf("NewTenantIssuerResolver(%q) error = %v, want ErrEmptyIssuerBaseURL", base, err)
		}
		if r != nil {
			t.Errorf("NewTenantIssuerResolver(%q) returned a resolver; want nil", base)
		}
	}
}

// TestTenantIssuerResolver_TrimsTrailingSlash guards an exact-string-match trap.
// OIDC compares issuers byte for byte, so https://auth.test.local/tenants/emc and
// https://auth.test.local//tenants/emc are different issuers — and the second is
// what a base URL copied from a browser address bar would produce.
func TestTenantIssuerResolver_TrimsTrailingSlash(t *testing.T) {
	pool := testhelper.NewTestDB(t)

	r, err := auth.NewTenantIssuerResolver(pool, testIssuerBaseURL+"/")
	if err != nil {
		t.Fatalf("NewTenantIssuerResolver: %v", err)
	}
	if got, want := r.IssuerForSlug("emc"), testIssuerBaseURL+"/tenants/emc"; got != want {
		t.Errorf("IssuerForSlug = %q, want %q", got, want)
	}
}

// TestTenantIssuerResolver_IssuerMatchesJWKSPath is the load-bearing assertion of
// issue #7: the issuer and the JWKS URL published in #95 must sit in the same URL
// space, because discovery at {iss}/.well-known/openid-configuration is what tells
// a relying party where the keys are. If these two ever diverge, every external
// verifier breaks and nothing on this side reports it.
func TestTenantIssuerResolver_IssuerMatchesJWKSPath(t *testing.T) {
	env := issuerFixture(t)

	issuer, err := env.resolver.Issuer(env.ctx, env.tenantID)
	if err != nil {
		t.Fatalf("Issuer: %v", err)
	}
	if issuer != env.tenantIssuer() {
		t.Fatalf("Issuer = %q, want %q", issuer, env.tenantIssuer())
	}
	// Must equal the route registered in routes.go for issue #95.
	want := testIssuerBaseURL + "/tenants/" + env.slug + "/.well-known/jwks.json"
	if got := issuer + "/.well-known/jwks.json"; got != want {
		t.Errorf("derived JWKS URL = %q, want %q", got, want)
	}
}

// TestTenantIssuerResolver_UnknownTenant pins that an unresolvable tenant is an
// error rather than a fabricated issuer. Silently returning the base URL would
// mint tokens that pass our own verification and fail nobody's until an external
// verifier saw them.
func TestTenantIssuerResolver_UnknownTenant(t *testing.T) {
	env := issuerFixture(t)

	if _, err := env.resolver.Issuer(env.ctx, 999999999); !errors.Is(err, auth.ErrUnknownTenantIssuer) {
		t.Errorf("Issuer(unknown tenant) error = %v, want ErrUnknownTenantIssuer", err)
	}
}

// TestJWTService_SignsPerTenantIssuer checks the mint path end to end: with a
// resolver wired, tokens must carry the tenant issuer and not the global one.
func TestJWTService_SignsPerTenantIssuer(t *testing.T) {
	env := issuerFixture(t)

	signed, err := env.svc.Sign(env.ctx, env.tenantID, auth.AudienceAPI, userClaims(env.userIDStr, env.tenantID))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	claims, err := env.svc.Verify(env.ctx, signed)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Issuer != env.tenantIssuer() {
		t.Errorf("iss = %q, want %q", claims.Issuer, env.tenantIssuer())
	}
	if claims.Issuer == testIssuer {
		t.Error("iss is still the legacy global issuer; per-tenant issuers are not in effect")
	}
}

// TestJWTService_ManagementAndAgentTokensCarryTenantIssuer covers the other two
// mint paths. They are separate methods with their own RegisteredClaims literals,
// which is exactly the shape of bug where one forgotten path keeps emitting the
// old value — the same class #95 guarded against by funnelling signing through
// signClaims.
func TestJWTService_ManagementAndAgentTokensCarryTenantIssuer(t *testing.T) {
	env := issuerFixture(t)
	want := env.tenantIssuer()

	mgmt, err := env.svc.SignManagement(env.ctx, &auth.APIKeyIdentity{
		KeyID:       1,
		TenantID:    env.tenantID,
		Name:        "test-key",
		Permissions: []string{"admin:access"},
	})
	if err != nil {
		t.Fatalf("SignManagement: %v", err)
	}
	if got := issuerOf(t, mgmt); got != want {
		t.Errorf("management token iss = %q, want %q", got, want)
	}

	agent, err := env.svc.SignAgent(env.ctx, &auth.AgentIdentity{
		AgentID:      uuid.New(),
		TenantID:     env.tenantID,
		Name:         "test-agent",
		AgentType:    "test",
		Capabilities: []string{"read"},
	})
	if err != nil {
		t.Fatalf("SignAgent: %v", err)
	}
	if got := issuerOf(t, agent); got != want {
		t.Errorf("agent token iss = %q, want %q", got, want)
	}
}

// TestJWTService_AcceptsLegacyIssuerDuringMigration is the no-broken-sessions
// guard. Every token minted before this change carries the global issuer, and
// they must keep verifying until they expire — otherwise deploying issue #7 logs
// out every active session, which is precisely the outcome the staged rollout in
// #95 was designed to avoid repeating.
func TestJWTService_AcceptsLegacyIssuerDuringMigration(t *testing.T) {
	env := issuerFixture(t)

	legacy := mintWithIssuer(t, env, testIssuer)

	if _, err := env.svc.Verify(env.ctx, legacy); err != nil {
		t.Errorf("Verify(legacy issuer token) = %v, want nil — pre-#7 tokens must survive the migration window", err)
	}
}

// TestJWTService_RejectsLegacyIssuerAfterCutover pins the other side of the
// switch: once WithLegacyIssuer(false) is set, the old value buys nothing.
func TestJWTService_RejectsLegacyIssuerAfterCutover(t *testing.T) {
	env := issuerFixture(t)
	env.svc.WithLegacyIssuer(false)

	legacy := mintWithIssuer(t, env, testIssuer)

	if _, err := env.svc.Verify(env.ctx, legacy); !errors.Is(err, auth.ErrUnexpectedIssuer) {
		t.Errorf("Verify(legacy issuer, cutover done) error = %v, want ErrUnexpectedIssuer", err)
	}
}

// TestJWTService_RejectsForeignTenantIssuer is the tenant-isolation assertion at
// the issuer layer. A token correctly signed for tenant A but carrying tenant B's
// issuer must not verify: the issuer is what a relying party keys its trust
// decision on, so accepting a mismatched one would let a token be presented to an
// audience that believes it came from a different issuer.
func TestJWTService_RejectsForeignTenantIssuer(t *testing.T) {
	env := issuerFixture(t)

	foreign := env.resolver.IssuerForSlug("some-other-tenant")
	token := mintWithIssuer(t, env, foreign)

	if _, err := env.svc.Verify(env.ctx, token); !errors.Is(err, auth.ErrUnexpectedIssuer) {
		t.Errorf("Verify(foreign tenant issuer) error = %v, want ErrUnexpectedIssuer", err)
	}
}

// TestJWTService_RejectsMissingTenantIDForIssuerCheck closes the obvious bypass:
// the expected issuer is derived from the tenant_id claim, so a token omitting it
// must fail rather than fall through to the weaker legacy comparison.
func TestJWTService_RejectsMissingTenantIDForIssuerCheck(t *testing.T) {
	env := issuerFixture(t)

	claims := userClaims(env.userIDStr, env.tenantID)
	claims.TenantID = "" // the bypass attempt
	claims.RegisteredClaims = jwt.RegisteredClaims{
		Issuer:    env.tenantIssuer(),
		Audience:  jwt.ClaimStrings{auth.AudienceAPI},
		Subject:   env.userIDStr,
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(env.jwtSecret))
	if err != nil {
		t.Fatalf("sign no-tenant_id token: %v", err)
	}

	// Signed with the real tenant secret, so the signature itself is sound.
	// Without a tenant_id the key lookup fails before the issuer check is even
	// reached — a refusal by a different route, but a refusal either way. The
	// assertion is deliberately "rejected", not a specific sentinel: which of the
	// two guards fires first is an implementation detail, and pinning it would
	// make this test fail on a harmless reordering rather than on a real bypass.
	if _, err := env.svc.Verify(env.ctx, signed); err == nil {
		t.Error("Verify(no tenant_id) = nil error, want rejection")
	}
}

// TestJWTService_NoResolverKeepsGlobalIssuer pins the pre-#7 behaviour for any
// embedder — or test — that never wires a resolver. The migration must be opt-in
// at the wiring site, not something that changes under a caller who did nothing.
func TestJWTService_NoResolverKeepsGlobalIssuer(t *testing.T) {
	env := issuerFixture(t)
	plain := newTestJWTService(t, env.pool, testIssuer) // no WithTenantIssuers

	signed, err := plain.Sign(env.ctx, env.tenantID, auth.AudienceAPI, userClaims(env.userIDStr, env.tenantID))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if got := issuerOf(t, signed); got != testIssuer {
		t.Errorf("iss = %q, want the global %q when no resolver is wired", got, testIssuer)
	}
	if _, err := plain.Verify(env.ctx, signed); err != nil {
		t.Errorf("Verify: %v", err)
	}
}
