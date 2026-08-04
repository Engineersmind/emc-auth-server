package auth_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

// ---------------------------------------------------------------------------
// Issue #95 Phase 2/3: asymmetric signing, per-tenant keys, published JWKS.
//
// The property under test throughout: a verifier can confirm a token is genuine
// using only published public material, and cannot mint one. Under HS256 those
// two capabilities were the same thing.
// ---------------------------------------------------------------------------

// signingFixture returns a JWTService wired for RS256 plus the key service, the
// seed tenant's id, and the seed user's id.
func signingFixture(t *testing.T) (context.Context, *auth.JWTService, *auth.SigningKeyService, int64, string) {
	t.Helper()

	pool := testhelper.NewTestDB(t)
	testhelper.CleanupTables(t, pool)

	ctx := context.Background()
	logger := testhelper.TestLogger()
	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}

	var tenantID, userID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM tenants WHERE slug = 'emc' AND deleted_at IS NULL`).Scan(&tenantID); err != nil {
		t.Fatalf("fetch seed tenant: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT id FROM users WHERE email = 'admin@emc.local' AND deleted_at IS NULL`).Scan(&userID); err != nil {
		t.Fatalf("fetch seed user: %v", err)
	}

	// A real (non-zero) encryption key, so the test exercises actual encryption
	// rather than the development zero-key fallback.
	box, err := auth.NewSecretBox(strings.Repeat("ab", 32), "development", "JWT_SIGNING_KEY_ENCRYPTION_KEY_TEST", logger)
	if err != nil {
		t.Fatalf("NewSecretBox: %v", err)
	}
	keys, err := auth.NewSigningKeyService(pool, box, logger)
	if err != nil {
		t.Fatalf("NewSigningKeyService: %v", err)
	}

	jwtSvc := newTestJWTService(t, pool, testIssuer).WithSigningKeys(keys)
	return ctx, jwtSvc, keys, tenantID, strconv.FormatInt(userID, 10)
}

// TestSigningKeyService_RequiresSecretBox locks in the refusal to store private
// keys unencrypted. A nil box would otherwise be a silent downgrade to plaintext.
func TestSigningKeyService_RequiresSecretBox(t *testing.T) {
	if _, err := auth.NewSigningKeyService(nil, nil, testhelper.TestLogger()); err == nil {
		t.Error("NewSigningKeyService(nil box) error = nil, want refusal")
	}
}

// TestJWTService_SignsRS256WithThumbprintKID is the core Phase 2 contract: tokens
// are asymmetric, and their kid is the RFC 7638 thumbprint of the signing key, so
// a verifier can match header to published key deterministically.
func TestJWTService_SignsRS256WithThumbprintKID(t *testing.T) {
	ctx, jwtSvc, keys, tenantID, userIDStr := signingFixture(t)

	token, err := jwtSvc.Sign(ctx, tenantID, auth.AudienceAPI, userClaims(userIDStr, tenantID))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	parsed, _, err := jwt.NewParser().ParseUnverified(token, &auth.Claims{})
	if err != nil {
		t.Fatalf("ParseUnverified() error = %v", err)
	}
	if got := parsed.Header["alg"]; got != "RS256" {
		t.Errorf("alg = %v, want RS256", got)
	}

	active, err := keys.ActiveKey(ctx, tenantID)
	if err != nil {
		t.Fatalf("ActiveKey() error = %v", err)
	}
	if got := parsed.Header["kid"]; got != active.KID {
		t.Errorf("kid = %v, want %q (the active key's thumbprint)", got, active.KID)
	}

	// And it must still verify through the normal path.
	if _, err := jwtSvc.Verify(ctx, token); err != nil {
		t.Errorf("Verify() error = %v, want nil", err)
	}
}

// TestJWTService_Verify_AcceptsLegacyHS256 proves the migration is non-breaking.
// A token signed with the tenant's old shared secret and no kid — i.e. every token
// live at the moment Phase 2 deploys — must keep verifying, or the deploy logs out
// every active session.
func TestJWTService_Verify_AcceptsLegacyHS256(t *testing.T) {
	ctx, jwtSvc, _, tenantID, userIDStr := signingFixture(t)

	// Mint through a service with no key wiring: that is exactly the pre-#95 path.
	pool := testhelper.NewTestDB(t)
	legacySvc := newTestJWTService(t, pool, testIssuer)
	legacyToken, err := legacySvc.Sign(ctx, tenantID, auth.AudienceAPI, userClaims(userIDStr, tenantID))
	if err != nil {
		t.Fatalf("legacy Sign() error = %v", err)
	}

	if _, err := jwtSvc.Verify(ctx, legacyToken); err != nil {
		t.Errorf("Verify(legacy HS256 token) error = %v, want nil — Phase 2 must not invalidate live tokens", err)
	}
}

// TestJWTService_Verify_RejectsCrossTenantKID is the reason per-tenant keys were
// chosen over one server-wide pair.
//
// A token is minted for tenant A, then its tenant_id claim is rewritten to tenant
// B and re-signed with A's key. With a single shared key pair the signature would
// be genuine and only the tenant_id claim — which every consumer must remember to
// check — would stand between the attacker and B's data. With per-tenant keys, B's
// key set does not contain A's kid, so verification fails on key resolution.
func TestJWTService_Verify_RejectsCrossTenantKID(t *testing.T) {
	ctx, jwtSvc, keys, tenantA, userIDStr := signingFixture(t)

	pool := testhelper.NewTestDB(t)
	var tenantB int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenants (name, slug, jwt_secret, is_active)
		VALUES ('Other', 'other-95', $1, true)
		RETURNING id`, strings.Repeat("f", 64),
	).Scan(&tenantB); err != nil {
		t.Fatalf("insert second tenant: %v", err)
	}
	if _, err := keys.EnsureTenantKey(ctx, tenantB); err != nil {
		t.Fatalf("EnsureTenantKey(B): %v", err)
	}

	keyA, err := keys.EnsureTenantKey(ctx, tenantA)
	if err != nil {
		t.Fatalf("EnsureTenantKey(A): %v", err)
	}

	// Claims say tenant B; signature and kid are tenant A's.
	claims := userClaims(userIDStr, tenantB)
	tokenA, err := jwtSvc.Sign(ctx, tenantA, auth.AudienceAPI, userClaims(userIDStr, tenantA))
	if err != nil {
		t.Fatalf("Sign(A): %v", err)
	}
	// Reuse tenant A's registered claims (iss/aud/exp) so the forgery differs from
	// a genuine token in exactly one respect: the tenant_id it claims.
	parsedA, _, err := jwt.NewParser().ParseUnverified(tokenA, &auth.Claims{})
	if err != nil {
		t.Fatalf("ParseUnverified(tokenA): %v", err)
	}
	claimsA, ok := parsedA.Claims.(*auth.Claims)
	if !ok {
		t.Fatalf("parsed claims are %T, want *auth.Claims", parsedA.Claims)
	}
	claims.RegisteredClaims = claimsA.RegisteredClaims

	forged := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	forged.Header["kid"] = keyA.KID
	signed, err := forged.SignedString(keyA.Private)
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}

	if _, err := jwtSvc.Verify(ctx, signed); err == nil {
		t.Error("Verify(tenant A key, tenant B claim) error = nil — cross-tenant token was accepted")
	}
}

// TestSigningKeyService_JWKSNeverLeaksPrivateKey is the single most important
// assertion in this file. go-jose will happily serialise an *rsa.PrivateKey's
// private fields if handed one, which would publish signing authority to the
// internet at an unauthenticated endpoint.
func TestSigningKeyService_JWKSNeverLeaksPrivateKey(t *testing.T) {
	ctx, _, keys, tenantID, _ := signingFixture(t)

	if _, err := keys.EnsureTenantKey(ctx, tenantID); err != nil {
		t.Fatalf("EnsureTenantKey: %v", err)
	}
	set, err := keys.JWKS(ctx, tenantID)
	if err != nil {
		t.Fatalf("JWKS() error = %v", err)
	}
	body, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	doc := string(body)

	// RSA private JWK parameters, per RFC 7518 §6.3.2. Any of these appearing means
	// the private key is published.
	for _, param := range []string{`"d"`, `"p"`, `"q"`, `"dp"`, `"dq"`, `"qi"`} {
		if strings.Contains(doc, param) {
			t.Errorf("JWKS contains private RSA parameter %s — signing key is exposed:\n%s", param, doc)
		}
	}
	if strings.Contains(doc, "PRIVATE KEY") {
		t.Error("JWKS contains a PEM private key block")
	}
	// Sanity: it must actually contain the public key, or the test above passes
	// trivially on an empty document.
	if !strings.Contains(doc, `"n"`) || !strings.Contains(doc, `"kid"`) {
		t.Errorf("JWKS missing public modulus or kid — not a usable key set:\n%s", doc)
	}
}

// TestSigningKeyService_RotationDrill walks the full rotation contract, which is
// the part most likely to cause an outage if wrong.
func TestSigningKeyService_RotationDrill(t *testing.T) {
	ctx, jwtSvc, keys, tenantID, userIDStr := signingFixture(t)

	oldKey, err := keys.EnsureTenantKey(ctx, tenantID)
	if err != nil {
		t.Fatalf("EnsureTenantKey: %v", err)
	}
	tokenBefore, err := jwtSvc.Sign(ctx, tenantID, auth.AudienceAPI, userClaims(userIDStr, tenantID))
	if err != nil {
		t.Fatalf("Sign(before): %v", err)
	}

	// A rotation cannot complete before it is prepared — completing straight away
	// would activate a key no verifier has cached, rejecting live traffic.
	if _, err := keys.CompleteRotation(ctx, tenantID); err == nil {
		t.Error("CompleteRotation without PrepareRotation error = nil, want refusal")
	}

	next, err := keys.PrepareRotation(ctx, tenantID)
	if err != nil {
		t.Fatalf("PrepareRotation: %v", err)
	}

	t.Run("next key is published before it signs anything", func(t *testing.T) {
		if !jwksHasKID(t, ctx, keys, tenantID, next.KID) {
			t.Error("prepared key absent from JWKS — verifiers would reject its first token")
		}
		active, err := keys.ActiveKey(ctx, tenantID)
		if err != nil {
			t.Fatalf("ActiveKey: %v", err)
		}
		if active.KID != oldKey.KID {
			t.Errorf("active kid = %q, want %q — prepare must not activate", active.KID, oldKey.KID)
		}
	})

	t.Run("prepare is idempotent", func(t *testing.T) {
		again, err := keys.PrepareRotation(ctx, tenantID)
		if err != nil {
			t.Fatalf("PrepareRotation (2nd): %v", err)
		}
		if again.KID != next.KID {
			t.Errorf("second prepare made a new key %q, want the pending %q", again.KID, next.KID)
		}
	})

	promoted, err := keys.CompleteRotation(ctx, tenantID)
	if err != nil {
		t.Fatalf("CompleteRotation: %v", err)
	}
	if promoted.KID != next.KID {
		t.Errorf("promoted kid = %q, want %q", promoted.KID, next.KID)
	}

	t.Run("tokens from both sides of the rotation verify", func(t *testing.T) {
		if _, err := jwtSvc.Verify(ctx, tokenBefore); err != nil {
			t.Errorf("Verify(token signed before rotation) error = %v — rotation invalidated a live token", err)
		}
		tokenAfter, err := jwtSvc.Sign(ctx, tenantID, auth.AudienceAPI, userClaims(userIDStr, tenantID))
		if err != nil {
			t.Fatalf("Sign(after): %v", err)
		}
		if _, err := jwtSvc.Verify(ctx, tokenAfter); err != nil {
			t.Errorf("Verify(token signed after rotation) error = %v", err)
		}
		if kidOf(t, tokenAfter) != next.KID {
			t.Error("post-rotation token was not signed by the promoted key")
		}
	})

	t.Run("retired key stays published during its grace window", func(t *testing.T) {
		if !jwksHasKID(t, ctx, keys, tenantID, oldKey.KID) {
			t.Error("retired key dropped from JWKS immediately — tokens signed before rotation become unverifiable")
		}
	})

	t.Run("GC keeps an in-grace retired key", func(t *testing.T) {
		if _, err := keys.CollectGarbage(ctx, tenantID); err != nil {
			t.Fatalf("CollectGarbage: %v", err)
		}
		if !jwksHasKID(t, ctx, keys, tenantID, oldKey.KID) {
			t.Error("GC deleted a key still inside its grace window")
		}
	})
}

// jwksHasKID reports whether the tenant's published JWKS contains a kid.
func jwksHasKID(t *testing.T, ctx context.Context, keys *auth.SigningKeyService, tenantID int64, kid string) bool {
	t.Helper()

	set, err := keys.JWKS(ctx, tenantID)
	if err != nil {
		t.Fatalf("JWKS(): %v", err)
	}
	for _, k := range set.Keys {
		if k.KeyID == kid {
			return true
		}
	}
	return false
}

// TestJWTService_AllSignersEmitActiveKID covers every signing path, not just Sign.
//
// A signer that missed the shared helper would keep emitting HS256 with no kid, and
// nothing else would notice: its tokens would still verify through the legacy path
// right up until the Phase 4 cutover silently broke that one token type. This is the
// test that catches a forgotten Sign* method.
func TestJWTService_AllSignersEmitActiveKID(t *testing.T) {
	ctx, jwtSvc, keys, tenantID, userIDStr := signingFixture(t)

	active, err := keys.EnsureTenantKey(ctx, tenantID)
	if err != nil {
		t.Fatalf("EnsureTenantKey: %v", err)
	}

	accessToken, err := jwtSvc.Sign(ctx, tenantID, auth.AudienceAPI, userClaims(userIDStr, tenantID))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
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

	for _, tc := range []struct {
		name  string
		token string
	}{
		{"access token", accessToken},
		{"management token", mgmtToken},
		{"agent token", agentToken},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hdr := mustParseHeader(t, tc.token)
			if hdr["alg"] != "RS256" {
				t.Errorf("alg = %v, want RS256", hdr["alg"])
			}
			if hdr["kid"] != active.KID {
				t.Errorf("kid = %v, want %q (the tenant's active key)", hdr["kid"], active.KID)
			}
		})
	}

	t.Run("kid is stable across signings", func(t *testing.T) {
		second, err := jwtSvc.Sign(ctx, tenantID, auth.AudienceAPI, userClaims(userIDStr, tenantID))
		if err != nil {
			t.Fatalf("Sign() error = %v", err)
		}
		if kidOf(t, second) != kidOf(t, accessToken) {
			t.Error("kid changed between signings — a per-token kid is useless for key selection")
		}
	})
}

// TestJWTService_Phase4Cutover covers the one-way step that actually removes the
// forging risk (issue #95 Phase 4).
//
// Phases 2–3 let a tenant verify safely; they do NOT stop anyone holding a tenant's
// jwt_secret from minting a token for any user in that tenant. Only refusing HS256
// does. This test is therefore the security assertion of the whole issue.
func TestJWTService_Phase4Cutover(t *testing.T) {
	ctx, jwtSvc, keys, tenantID, userIDStr := signingFixture(t)

	if _, err := keys.EnsureTenantKey(ctx, tenantID); err != nil {
		t.Fatalf("EnsureTenantKey: %v", err)
	}

	// A token forged with the tenant's shared secret — exactly what a holder of
	// tenants.jwt_secret can produce today, including at super_admin.
	pool := testhelper.NewTestDB(t)
	var jwtSecret string
	if err := pool.QueryRow(ctx,
		`SELECT jwt_secret FROM tenants WHERE id = $1`, tenantID,
	).Scan(&jwtSecret); err != nil {
		t.Fatalf("fetch jwt_secret: %v", err)
	}
	claims := userClaims(userIDStr, tenantID)
	now := time.Now().UTC()
	claims.RegisteredClaims = jwt.RegisteredClaims{
		ID:        uuid.New().String(),
		Issuer:    testIssuer,
		Audience:  jwt.ClaimStrings{auth.AudienceAPI},
		Subject:   userIDStr,
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(auth.AccessTokenTTL)),
	}
	hs256Token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(jwtSecret))
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}

	rs256Token, err := jwtSvc.Sign(ctx, tenantID, auth.AudienceAPI, userClaims(userIDStr, tenantID))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	t.Run("during the migration window both verify", func(t *testing.T) {
		if _, err := jwtSvc.Verify(ctx, hs256Token); err != nil {
			t.Errorf("Verify(HS256) error = %v, want nil while legacy is allowed", err)
		}
		if _, err := jwtSvc.Verify(ctx, rs256Token); err != nil {
			t.Errorf("Verify(RS256) error = %v, want nil", err)
		}
	})

	// The cutover.
	jwtSvc.WithLegacyHS256(false)

	t.Run("after cutover HS256 is refused", func(t *testing.T) {
		if _, err := jwtSvc.Verify(ctx, hs256Token); err == nil {
			t.Error("Verify(HS256) error = nil after cutover — a holder of the tenant secret can still forge tokens")
		}
	})

	t.Run("after cutover RS256 still verifies", func(t *testing.T) {
		if _, err := jwtSvc.Verify(ctx, rs256Token); err != nil {
			t.Errorf("Verify(RS256) error = %v after cutover, want nil", err)
		}
	})

	// Signing must be unaffected: the cutover narrows verification only.
	t.Run("signing still works after cutover", func(t *testing.T) {
		fresh, err := jwtSvc.Sign(ctx, tenantID, auth.AudienceAPI, userClaims(userIDStr, tenantID))
		if err != nil {
			t.Fatalf("Sign after cutover: %v", err)
		}
		if _, err := jwtSvc.Verify(ctx, fresh); err != nil {
			t.Errorf("Verify(freshly signed) error = %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// PR #98 review fixes
// ---------------------------------------------------------------------------

// gcFixture returns the key service plus two tenants, each with an active key,
// so a sweep aimed at one can be checked for not touching the other.
func gcFixture(t *testing.T) (context.Context, *auth.SigningKeyService, *pgxpool.Pool, int64, int64) {
	t.Helper()

	ctx, _, keys, tenantA, _ := signingFixture(t)
	pool := testhelper.NewTestDB(t)

	var tenantB int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO tenants (name, slug, jwt_secret, is_active)
		 VALUES ('gc-other', 'gc-other', 'gc-other-secret', true) RETURNING id`,
	).Scan(&tenantB); err != nil {
		t.Fatalf("insert second tenant: %v", err)
	}

	for _, id := range []int64{tenantA, tenantB} {
		if _, err := keys.EnsureTenantKey(ctx, id); err != nil {
			t.Fatalf("EnsureTenantKey(%d): %v", id, err)
		}
	}
	return ctx, keys, pool, tenantA, tenantB
}

// retireKey adds a retired key to a tenant, backdated past the grace window so
// it is eligible for collection.
func retireKey(t *testing.T, ctx context.Context, pool *pgxpool.Pool, keys *auth.SigningKeyService, tenantID int64) string {
	t.Helper()

	key, err := keys.GenerateKey(ctx, tenantID, auth.KeyStatusNext)
	if err != nil {
		t.Fatalf("GenerateKey(next) for tenant %d: %v", tenantID, err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE signing_keys SET status = 'retired', retired_at = NOW() - $1::interval
		  WHERE tenant_id = $2 AND kid = $3`,
		fmt.Sprintf("%d seconds", int(auth.RetiredKeyGrace.Seconds())+3600), tenantID, key.KID,
	); err != nil {
		t.Fatalf("backdate retired key: %v", err)
	}
	return key.KID
}

func keyExists(t *testing.T, ctx context.Context, pool *pgxpool.Pool, kid string) bool {
	t.Helper()
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM signing_keys WHERE kid = $1`, kid).Scan(&n); err != nil {
		t.Fatalf("count signing_keys: %v", err)
	}
	return n > 0
}

// TestSigningKeyService_CollectGarbageIsTenantScoped is the regression guard for
// the unscoped DELETE: garbage collection aimed at one tenant must not reach
// another tenant's key material, whatever the grace predicate says.
func TestSigningKeyService_CollectGarbageIsTenantScoped(t *testing.T) {
	ctx, keys, pool, tenantA, tenantB := gcFixture(t)

	kidA := retireKey(t, ctx, pool, keys, tenantA)
	kidB := retireKey(t, ctx, pool, keys, tenantB)

	n, err := keys.CollectGarbage(ctx, tenantA)
	if err != nil {
		t.Fatalf("CollectGarbage(tenantA): %v", err)
	}
	if n != 1 {
		t.Errorf("deleted = %d, want 1", n)
	}
	if keyExists(t, ctx, pool, kidA) {
		t.Error("tenant A's expired key survived its own sweep")
	}
	if !keyExists(t, ctx, pool, kidB) {
		t.Error("tenant B's key was deleted by a sweep scoped to tenant A")
	}
}

// TestSigningKeyService_CollectGarbageRequiresTenants pins the fail-closed
// guard: an empty tenant list must not degrade into a delete-everything sweep.
func TestSigningKeyService_CollectGarbageRequiresTenants(t *testing.T) {
	ctx, keys, pool, tenantA, _ := gcFixture(t)
	kidA := retireKey(t, ctx, pool, keys, tenantA)

	n, err := keys.CollectGarbage(ctx)
	if !errors.Is(err, auth.ErrNoTenantsToCollect) {
		t.Errorf("CollectGarbage() error = %v, want ErrNoTenantsToCollect", err)
	}
	if n != 0 {
		t.Errorf("deleted = %d, want 0", n)
	}
	if !keyExists(t, ctx, pool, kidA) {
		t.Error("an unscoped call deleted keys — the guard did not hold")
	}
}

// TestSigningKeyService_CollectGarbageSkipsTenantsWithoutActiveKey covers the
// fail-safe: a tenant holding only retired keys is already broken, and deleting
// what is left would make every token it ever issued permanently unverifiable.
func TestSigningKeyService_CollectGarbageSkipsTenantsWithoutActiveKey(t *testing.T) {
	ctx, keys, pool, tenantA, _ := gcFixture(t)
	kid := retireKey(t, ctx, pool, keys, tenantA)

	// Retire the active key too, leaving the tenant with no active key at all.
	if _, err := pool.Exec(ctx,
		`UPDATE signing_keys SET status = 'retired', retired_at = NOW() - $1::interval
		  WHERE tenant_id = $2 AND status = 'active'`,
		fmt.Sprintf("%d seconds", int(auth.RetiredKeyGrace.Seconds())+3600), tenantA,
	); err != nil {
		t.Fatalf("retire active key: %v", err)
	}

	n, err := keys.CollectGarbage(ctx, tenantA)
	if err != nil {
		t.Fatalf("CollectGarbage: %v", err)
	}
	if n != 0 {
		t.Errorf("deleted = %d, want 0 — a tenant with no active key must be left alone", n)
	}
	if !keyExists(t, ctx, pool, kid) {
		t.Error("GC stripped the last keys from a tenant with no active key")
	}
}

// TestSigningKeyService_CollectGarbageAllTenantsSweepsEveryTenant pins that
// scoping the DELETE did not narrow what a full sweep actually collects.
func TestSigningKeyService_CollectGarbageAllTenantsSweepsEveryTenant(t *testing.T) {
	ctx, keys, pool, tenantA, tenantB := gcFixture(t)

	kidA := retireKey(t, ctx, pool, keys, tenantA)
	kidB := retireKey(t, ctx, pool, keys, tenantB)

	n, err := keys.CollectGarbageAllTenants(ctx)
	if err != nil {
		t.Fatalf("CollectGarbageAllTenants: %v", err)
	}
	if n != 2 {
		t.Errorf("deleted = %d, want 2", n)
	}
	if keyExists(t, ctx, pool, kidA) || keyExists(t, ctx, pool, kidB) {
		t.Error("a full sweep left an expired key behind")
	}
}

// TestSigningKeyService_PublishableKeysCarryNoPrivateHalf pins the split between
// the JWKS-facing key structs and the signing one.
//
// JWKS() already extracts only the public half, so this is not about the wire
// format — it is about what PublishableKeys hands to any future caller. When the
// active key's struct was shared between the two, every publishable entry held a
// live *rsa.PrivateKey, and one log line or struct marshal away from exposure.
func TestSigningKeyService_PublishableKeysCarryNoPrivateHalf(t *testing.T) {
	ctx, _, keys, tenantID, _ := signingFixture(t)

	active, err := keys.EnsureTenantKey(ctx, tenantID)
	if err != nil {
		t.Fatalf("EnsureTenantKey: %v", err)
	}
	if _, err := keys.PrepareRotation(ctx, tenantID); err != nil {
		t.Fatalf("PrepareRotation: %v", err)
	}

	published, err := keys.PublishableKeys(ctx, tenantID)
	if err != nil {
		t.Fatalf("PublishableKeys: %v", err)
	}
	if len(published) < 2 {
		t.Fatalf("published %d keys, want at least the active and next keys", len(published))
	}

	sawActive := false
	for _, k := range published {
		if k.KID == active.KID {
			sawActive = true
		}
		if k.Private != nil {
			t.Errorf("published key %q carries a private half", k.KID)
		}
		if k.Public == nil {
			t.Errorf("published key %q has no public half", k.KID)
		}
	}
	if !sawActive {
		t.Error("active key missing from the published set")
	}

	// The signing path must still get its private half — the split must not have
	// been achieved by simply dropping it everywhere.
	signer, err := keys.ActiveKey(ctx, tenantID)
	if err != nil {
		t.Fatalf("ActiveKey: %v", err)
	}
	if signer.Private == nil {
		t.Error("ActiveKey has no private half — the tenant can no longer sign")
	}
}
