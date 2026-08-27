package auth_test

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// Issue #116, item 2 — origin uniqueness for passkey policy.
//
// /auth/passkey/login/begin takes no identifier at all (deliberately: it is what
// stops the endpoint being used to probe which accounts exist), so the Origin
// header is the only thing available to decide which relying party the ceremony
// runs as. Nothing stopped two unrelated scopes from claiming one origin, and
// loadByOrigin's LIMIT 1 then picked between them by lowest application_id.
//
// It could not leak across tenants — the browser only offers credentials bound
// to the chosen row's rp_id, and LoginComplete re-resolves policy from the
// credential's own scope — but it failed silently at every layer: the user's
// authenticator offers nothing and the server logs a generic verification
// failure.

// setOrigins is the shortest legal way to make a scope claim an origin: origins
// require an rp_id (constraint passkey_policies_origins_need_rp_id, migration
// 00072), so both always travel together.
func setOrigins(t *testing.T, f *passkeyFixture, tenantID *int64, appID *int64, rpID string, origins ...string) error {
	t.Helper()
	list := origins
	return firstErr(f.svc.Policy().SetPolicy(f.ctx, tenantID, appID, auth.PasskeyPolicyUpdate{
		RPID:    &rpID,
		Origins: &list,
	}))
}

func firstErr(_ *auth.PasskeyPolicyRecord, err error) error { return err }

// TestPasskeyOriginConflict_SecondTenantRefused is the core of item 2. Two
// tenants at the same specificity claiming one origin has no valid
// interpretation, so it is refused at write time rather than resolved
// arbitrarily at read time.
func TestPasskeyOriginConflict_SecondTenantRefused(t *testing.T) {
	f := newPasskeyFixture(t)

	var otherTenantID int64
	if err := f.pool.QueryRow(f.ctx, `
		INSERT INTO tenants (name, slug, jwt_secret, is_active)
		VALUES ($1, $2, 'test-secret-not-used-rs256-per-tenant-keys-are', true) RETURNING id
	`, "Other", fmt.Sprintf("other-%d", time.Now().UnixNano())).Scan(&otherTenantID); err != nil {
		t.Fatalf("insert second tenant: %v", err)
	}

	if err := setOrigins(t, f, &f.tenantID, nil, "acme.example.com", "https://acme.example.com"); err != nil {
		t.Fatalf("first claim should succeed: %v", err)
	}

	err := setOrigins(t, f, &otherTenantID, nil, "acme.example.com", "https://acme.example.com")
	if !errors.Is(err, auth.ErrPasskeyOriginConflict) {
		t.Fatalf("error = %v, want ErrPasskeyOriginConflict", err)
	}
	// The message has to name the holder. Without it an operator has to go
	// reading the table by hand, and this class of bug is expensive precisely
	// because it gives nobody anything to search for.
	if want := fmt.Sprintf("tenant %d", f.tenantID); !strings.Contains(err.Error(), want) {
		t.Errorf("error %q does not name the conflicting scope (%q)", err.Error(), want)
	}
	if !strings.Contains(err.Error(), "https://acme.example.com") {
		t.Errorf("error %q does not name the conflicting origin", err.Error())
	}
}

// TestPasskeyOriginConflict_SiblingApplicationsRefused covers the second
// same-specificity pair: two applications of one tenant.
func TestPasskeyOriginConflict_SiblingApplicationsRefused(t *testing.T) {
	f := newPasskeyFixture(t)
	appSvc := auth.NewApplicationService(f.pool, testhelper.TestLogger())

	ids := make([]int64, 0, 2)
	for i := 0; i < 2; i++ {
		app, err := appSvc.CreateApplication(f.ctx, f.tenantID,
			fmt.Sprintf("sibling-%d-%d", i, time.Now().UnixNano()), "web", nil)
		if err != nil {
			t.Fatalf("CreateApplication: %v", err)
		}
		id, err := strconv.ParseInt(app.ID, 10, 64)
		if err != nil {
			t.Fatalf("parse app id: %v", err)
		}
		ids = append(ids, id)
	}

	if err := setOrigins(t, f, &f.tenantID, &ids[0], "shared.example.com", "https://shared.example.com"); err != nil {
		t.Fatalf("first application claim should succeed: %v", err)
	}
	err := setOrigins(t, f, &f.tenantID, &ids[1], "shared.example.com", "https://shared.example.com")
	if !errors.Is(err, auth.ErrPasskeyOriginConflict) {
		t.Fatalf("error = %v, want ErrPasskeyOriginConflict for a sibling application", err)
	}
}

// TestPasskeyOriginConflict_CrossTenantApplicationRefused is the case a literal
// reading of "same specificity" would have let through: an application of one
// tenant against the tenant-level row of another. Different specificities, and
// still a genuine collision — which is why the rule is stated as "different
// resolution chains".
func TestPasskeyOriginConflict_CrossTenantApplicationRefused(t *testing.T) {
	f := newPasskeyFixture(t)

	var otherTenantID int64
	if err := f.pool.QueryRow(f.ctx, `
		INSERT INTO tenants (name, slug, jwt_secret, is_active)
		VALUES ($1, $2, 'test-secret-not-used-rs256-per-tenant-keys-are', true) RETURNING id
	`, "Cross", fmt.Sprintf("cross-%d", time.Now().UnixNano())).Scan(&otherTenantID); err != nil {
		t.Fatalf("insert second tenant: %v", err)
	}
	if err := setOrigins(t, f, &otherTenantID, nil, "cross.example.com", "https://cross.example.com"); err != nil {
		t.Fatalf("other tenant claim should succeed: %v", err)
	}

	appSvc := auth.NewApplicationService(f.pool, testhelper.TestLogger())
	app, err := appSvc.CreateApplication(f.ctx, f.tenantID,
		fmt.Sprintf("cross-app-%d", time.Now().UnixNano()), "web", nil)
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}
	appRowID, err := strconv.ParseInt(app.ID, 10, 64)
	if err != nil {
		t.Fatalf("parse app id: %v", err)
	}

	if err := setOrigins(t, f, &f.tenantID, &appRowID, "cross.example.com", "https://cross.example.com"); !errors.Is(err, auth.ErrPasskeyOriginConflict) {
		t.Fatalf("error = %v, want ErrPasskeyOriginConflict across tenants", err)
	}
}

// TestPasskeyOriginConflict_ApplicationMayOverrideItsOwnTenant is the guard on
// the other side, and the ticket's own third checkbox. An application and its
// tenant sit on one resolution chain, so sharing an origin is meaningful — it is
// what most-specific-wins exists for. Refusing it would break
// TestPasskeyPolicyMostSpecificWins and the per-application RP ID feature with
// it.
func TestPasskeyOriginConflict_ApplicationMayOverrideItsOwnTenant(t *testing.T) {
	f := newPasskeyFixture(t)
	appSvc := auth.NewApplicationService(f.pool, testhelper.TestLogger())
	app, err := appSvc.CreateApplication(f.ctx, f.tenantID,
		fmt.Sprintf("override-%d", time.Now().UnixNano()), "web", nil)
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}
	appRowID, err := strconv.ParseInt(app.ID, 10, 64)
	if err != nil {
		t.Fatalf("parse app id: %v", err)
	}

	const origin = "https://portal.example.com"
	if err := setOrigins(t, f, &f.tenantID, nil, "portal.example.com", origin); err != nil {
		t.Fatalf("tenant claim: %v", err)
	}
	if err := setOrigins(t, f, &f.tenantID, &appRowID, "app.portal.example.com", origin); err != nil {
		t.Fatalf("application override of its own tenant's origin was refused: %v", err)
	}

	// And it still resolves most-specific-first, so the override actually takes
	// effect rather than merely being permitted.
	policy, err := f.svc.Policy().ResolveByOrigin(f.ctx, origin)
	if err != nil {
		t.Fatalf("ResolveByOrigin: %v", err)
	}
	if policy.RPID != "app.portal.example.com" {
		t.Errorf("resolved rp_id = %q, want the application's %q", policy.RPID, "app.portal.example.com")
	}
}

// TestPasskeyOriginConflict_UpdatingOwnRowIsNotAConflict guards the obvious
// regression in a check like this: a row must not conflict with itself. Every
// PUT that keeps its existing origins goes through here.
func TestPasskeyOriginConflict_UpdatingOwnRowIsNotAConflict(t *testing.T) {
	f := newPasskeyFixture(t)

	if err := setOrigins(t, f, &f.tenantID, nil, "self.example.com", "https://self.example.com"); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := setOrigins(t, f, &f.tenantID, nil, "self.example.com", "https://self.example.com"); err != nil {
		t.Fatalf("rewriting the same origins on the same row was refused: %v", err)
	}
	if err := setOrigins(t, f, &f.tenantID, nil, "self.example.com",
		"https://self.example.com", "https://also.example.com"); err != nil {
		t.Fatalf("adding an origin to an existing row was refused: %v", err)
	}
}

// TestPasskeyOriginConflict_TriggerBlocksDirectWrite is the migration's half.
//
// SetPolicy's check gives an operator a readable sentence; it cannot bind a
// writer that never goes through Go. Support work, a data fix, and a migration
// all write this table by hand, and an invariant enforced only in the
// application is not an invariant.
func TestPasskeyOriginConflict_TriggerBlocksDirectWrite(t *testing.T) {
	f := newPasskeyFixture(t)

	var otherTenantID int64
	if err := f.pool.QueryRow(f.ctx, `
		INSERT INTO tenants (name, slug, jwt_secret, is_active)
		VALUES ($1, $2, 'test-secret-not-used-rs256-per-tenant-keys-are', true) RETURNING id
	`, "Direct", fmt.Sprintf("direct-%d", time.Now().UnixNano())).Scan(&otherTenantID); err != nil {
		t.Fatalf("insert second tenant: %v", err)
	}
	if err := setOrigins(t, f, &f.tenantID, nil, "direct.example.com", "https://direct.example.com"); err != nil {
		t.Fatalf("first claim: %v", err)
	}

	// Bypassing SetPolicy entirely, exactly as a psql session would.
	_, err := f.pool.Exec(f.ctx, `
		INSERT INTO passkey_policies (tenant_id, application_id, rp_id, origins)
		VALUES ($1, NULL, 'direct.example.com', ARRAY['https://direct.example.com'])
	`, otherTenantID)
	if err == nil {
		t.Fatal("a direct INSERT claiming a taken origin succeeded — the trigger from migration 00080 is not enforcing")
	}
	if !strings.Contains(err.Error(), "passkey origin conflict") {
		t.Errorf("error = %v, want the trigger's own message", err)
	}

	// An UPDATE that introduces the overlap must be caught too, not just an
	// INSERT: the trigger fires on both, and a check that only covered INSERT
	// would let the same state in through a second statement.
	if _, err := f.pool.Exec(f.ctx, `
		INSERT INTO passkey_policies (tenant_id, application_id, rp_id, origins)
		VALUES ($1, NULL, 'direct.example.com', ARRAY['https://unique.example.com'])
	`, otherTenantID); err != nil {
		t.Fatalf("insert with a free origin: %v", err)
	}
	if _, err := f.pool.Exec(f.ctx, `
		UPDATE passkey_policies SET origins = ARRAY['https://direct.example.com']
		WHERE tenant_id = $1 AND application_id IS NULL
	`, otherTenantID); err == nil {
		t.Fatal("an UPDATE claiming a taken origin succeeded — the trigger does not cover UPDATE")
	}
}
