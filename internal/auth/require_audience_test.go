package auth_test

// Tests for issue #132's verify-layer gate: REQUIRE_AUDIENCE refuses the legacy
// token shape outright, so the grant type comes from "gty" alone.
//
// #130 made the dual-read non-breaking by falling back to the legacy token-type
// "aud" when no "gty" is present. #132 closes that fallback — but GATES it
// rather than deleting it, because REQUIRE_AUDIENCE=false has to remain a
// working rollback for the whole migration. These tests pin both halves of that,
// since a rollback nobody tests is a rollback nobody has.

import (
	"errors"
	"testing"

	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// TestRequireAudience_GatesTheLegacyShapeBothWays is the issue #132 test
// "a token with no audience is refused when REQUIRE_AUDIENCE=true, and accepted
// when it is false (the rollback must be real)".
//
// Both directions are asserted on the SAME token, so the two outcomes cannot be
// explained by the fixture differing between them: the only thing that changes
// is the flag. A test that minted a fresh token per case could pass while the
// flag did nothing, which is the failure mode worth guarding against here.
func TestRequireAudience_GatesTheLegacyShapeBothWays(t *testing.T) {
	ctx, jwtSvc, tenantID, userIDStr, jwtSecret := audienceFixture(t)

	// The pre-#130 shape: no "gty", token type carried in "aud". This is what
	// every token minted before the #130 deploy looks like, and what is still in
	// circulation for up to RefreshTokenTTL afterwards.
	legacy := mintLegacyShape(t, jwtSecret, userIDStr, tenantID, auth.AudienceAPI)

	// Rollback position — the default, and the state the cutover must be able to
	// return to. The legacy token verifies through the fallback.
	jwtSvc.WithRequireAudience(false)
	if _, err := jwtSvc.Verify(ctx, legacy); err != nil {
		t.Fatalf("REQUIRE_AUDIENCE=false: Verify(legacy token) error = %v, want nil — "+
			"the rollback is not real if a legacy token cannot verify with the flag off", err)
	}

	// Cutover position. The same token is now refused.
	jwtSvc.WithRequireAudience(true)
	if _, err := jwtSvc.Verify(ctx, legacy); !errors.Is(err, auth.ErrUnexpectedAudience) {
		t.Errorf("REQUIRE_AUDIENCE=true: Verify(legacy token) error = %v, want ErrUnexpectedAudience", err)
	}

	// And back, because a one-way switch is not a rollback. Asserted explicitly
	// rather than assumed: the flag is read on every verify rather than latched
	// at construction, and this is what says so.
	jwtSvc.WithRequireAudience(false)
	if _, err := jwtSvc.Verify(ctx, legacy); err != nil {
		t.Errorf("REQUIRE_AUDIENCE back to false: Verify(legacy token) error = %v, want nil", err)
	}
}

// TestRequireAudience_LeavesGtyTokensAlone pins the other half of the contract:
// the flag closes the legacy fallback and nothing else.
//
// This is what makes the cutover survivable. If turning the flag on also
// disturbed migrated tokens, there would be no safe moment to turn it on at all
// — every consumer would have to be migrated AND the flag flipped in the same
// instant. Because it only refuses the shape that predates #130, an operator can
// flip it once the legacy counter reads zero and expect nothing else to move.
func TestRequireAudience_LeavesGtyTokensAlone(t *testing.T) {
	ctx, jwtSvc, tenantID, userIDStr, _ := audienceFixture(t)

	token, err := jwtSvc.Sign(ctx, tenantID, auth.AudienceAPI, auth.GrantPassword,
		userClaims(userIDStr, tenantID))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	for _, require := range []bool{false, true} {
		jwtSvc.WithRequireAudience(require)
		if _, err := jwtSvc.Verify(ctx, token); err != nil {
			t.Errorf("REQUIRE_AUDIENCE=%v: Verify(gty token) error = %v, want nil", require, err)
		}
	}
}

// TestRequireAudience_StillRefusesTheWrongGrant guards against the gate being
// written as a short-circuit that skips the grant check.
//
// The obvious wrong implementation returns "allowed" early when the flag is on
// and a gty is present, which would accept a client_credentials token on a
// human-only route — reopening issue #84 through the very change meant to
// tighten it. A machine token must stay refused by Verify with the flag on
// exactly as it is with the flag off.
func TestRequireAudience_StillRefusesTheWrongGrant(t *testing.T) {
	ctx, jwtSvc, tenantID, userIDStr, _ := audienceFixture(t)

	machine, err := jwtSvc.Sign(ctx, tenantID, auth.AudienceM2M, auth.GrantClientCredentials,
		userClaims(userIDStr, tenantID))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	jwtSvc.WithRequireAudience(true)
	if _, err := jwtSvc.Verify(ctx, machine); !errors.Is(err, auth.ErrUnexpectedAudience) {
		t.Errorf("Verify(client_credentials token) error = %v, want ErrUnexpectedAudience — "+
			"the audience gate must not bypass the grant check", err)
	}
	if _, err := jwtSvc.VerifyM2M(ctx, machine); err != nil {
		t.Errorf("VerifyM2M(client_credentials token) error = %v, want nil", err)
	}
}

// TestSignManagement_CarriesSelfAudience pins the #132 change that keeps API-key
// integrations working after the cutover.
//
// A management token is minted to be spent on THIS server's admin surface, which
// #132 restricts to AudienceSelf. It used to carry the legacy bare string
// "emc-auth-management", which the route policy reads as an un-migrated token and
// admits only while enforcement is off — so the moment REQUIRE_AUDIENCE went on,
// every API-key integration would lose the whole admin API at once. The insurance
// backfill script (prisma/emc-auth-backfill.ts) authenticates this way.
//
// Asserted on the audience claim rather than through a route, because the mint
// site is the thing that has to be right; the route policy is tested separately.
func TestSignManagement_CarriesSelfAudience(t *testing.T) {
	ctx, jwtSvc, tenantID, _, _ := audienceFixture(t)

	token, err := jwtSvc.SignManagement(ctx, &auth.APIKeyIdentity{
		KeyID:       1,
		TenantID:    tenantID,
		Name:        "backfill",
		Permissions: []string{"users:write"},
	})
	if err != nil {
		t.Fatalf("SignManagement: %v", err)
	}

	claims, err := jwtSvc.VerifyForAudience(ctx, token, auth.AdminGrants...)
	if err != nil {
		t.Fatalf("VerifyForAudience(AdminGrants): %v", err)
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != auth.AudienceSelf {
		t.Errorf("management token aud = %v, want [%s] — an API-key integration "+
			"would lose the admin API the moment REQUIRE_AUDIENCE went on",
			[]string(claims.Audience), auth.AudienceSelf)
	}
	if claims.Gty != auth.GrantAPIKey {
		t.Errorf("management token gty = %q, want %q", claims.Gty, auth.GrantAPIKey)
	}
}
