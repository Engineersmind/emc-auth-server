package auth_test

import (
	"context"
	"testing"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/store"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// newSenderTestEnv wires an EmailSenderService against a real DB with the "emc"
// tenant seeded, plus one application to hang app-scoped senders off.
func newSenderTestEnv(t *testing.T) (*auth.EmailSenderService, int64, int64, context.Context) {
	t.Helper()
	pool := testhelper.NewTestDB(t)
	testhelper.CleanupTables(t, pool)
	logger := testhelper.TestLogger()
	ctx := context.Background()
	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}

	var tenantID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM tenants WHERE slug = 'emc'`).Scan(&tenantID); err != nil {
		t.Fatalf("tenant id: %v", err)
	}

	var appRowID int64
	err := pool.QueryRow(ctx, `
		INSERT INTO oauth_clients (tenant_id, name, app_type, client_id, scopes)
		VALUES ($1, 'Sender Test App', 'web', 'sender_test_client', '{}')
		RETURNING id
	`, tenantID).Scan(&appRowID)
	if err != nil {
		t.Fatalf("seed application: %v", err)
	}

	totpSvc, err := auth.NewTOTPService(pool, totpEnvKey(), logger)
	if err != nil {
		t.Fatalf("NewTOTPService: %v", err)
	}
	return auth.NewEmailSenderService(pool, totpSvc.EncryptionKey(), logger), tenantID, appRowID, ctx
}

// ─── Sender scope reporting ─────────────────────────────────────────────────
//
// "Sent OK" is misleading when an application with no sender of its own falls
// through to the tenant or global configuration: the admin believes they
// verified a per-app provider they never actually exercised.

func TestResolveScopeReportsGlobalWhenNothingConfigured(t *testing.T) {
	svc, tenantID, appRowID, ctx := newSenderTestEnv(t)

	_, scope, err := svc.ResolveWithScope(ctx, tenantID, &appRowID)
	if err != nil {
		t.Fatalf("ResolveScope: %v", err)
	}
	if scope != auth.SenderScopeGlobal {
		t.Errorf("scope = %q with no sender rows, want %q", scope, auth.SenderScopeGlobal)
	}
}

func TestResolveScopeReportsTenantFallthrough(t *testing.T) {
	svc, tenantID, appRowID, ctx := newSenderTestEnv(t)

	if _, err := svc.Upsert(ctx, tenantID, nil, auth.UpsertSenderInput{
		Provider: auth.SenderProviderSendGrid, FromAddress: "tenant@acme.com", APIKey: "SG.tenant-key",
	}, nil); err != nil {
		t.Fatalf("Upsert(tenant): %v", err)
	}

	// The application has no sender of its own, so a test "for the app" is
	// really exercising the tenant's configuration — and must say so.
	_, scope, err := svc.ResolveWithScope(ctx, tenantID, &appRowID)
	if err != nil {
		t.Fatalf("ResolveScope: %v", err)
	}
	if scope != auth.SenderScopeTenant {
		t.Errorf("scope = %q, want %q — the app has no sender of its own", scope, auth.SenderScopeTenant)
	}
}

func TestResolveScopeReportsApplicationWhenItHasItsOwn(t *testing.T) {
	svc, tenantID, appRowID, ctx := newSenderTestEnv(t)

	// Both levels configured — the application's own row must win.
	if _, err := svc.Upsert(ctx, tenantID, nil, auth.UpsertSenderInput{
		Provider: auth.SenderProviderSendGrid, FromAddress: "tenant@acme.com", APIKey: "SG.tenant-key",
	}, nil); err != nil {
		t.Fatalf("Upsert(tenant): %v", err)
	}
	if _, err := svc.Upsert(ctx, tenantID, &appRowID, auth.UpsertSenderInput{
		Provider: auth.SenderProviderSendGrid, FromAddress: "app@acme.com", APIKey: "SG.app-key",
	}, nil); err != nil {
		t.Fatalf("Upsert(app): %v", err)
	}

	_, scope, err := svc.ResolveWithScope(ctx, tenantID, &appRowID)
	if err != nil {
		t.Fatalf("ResolveScope: %v", err)
	}
	if scope != auth.SenderScopeApplication {
		t.Errorf("scope = %q, want %q", scope, auth.SenderScopeApplication)
	}

	// ResolveScope must agree with what Resolve actually picks, or the reported
	// scope is a lie. Resolve returns the app's credentials here.
	resolved, err := svc.Resolve(ctx, tenantID, &appRowID)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if resolved == nil || resolved.APIKey != "SG.app-key" {
		t.Errorf("Resolve picked %+v, but ResolveScope reported %q", resolved, scope)
	}
}

// ─── Credential trimming at the storage boundary ────────────────────────────

// A key pasted with a trailing newline is stored encrypted, so the whitespace
// is invisible in the DB and surfaces only as an unexplained 401 at send time.
func TestUpsertTrimsStoredCredentials(t *testing.T) {
	svc, tenantID, _, ctx := newSenderTestEnv(t)

	if _, err := svc.Upsert(ctx, tenantID, nil, auth.UpsertSenderInput{
		Provider:    auth.SenderProviderSendGrid,
		FromAddress: "no-reply@acme.com",
		APIKey:      "  SG.pasted-with-newline\n",
	}, nil); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	resolved, err := svc.Resolve(ctx, tenantID, nil)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if resolved.APIKey != "SG.pasted-with-newline" {
		t.Errorf("stored API key = %q, want it trimmed", resolved.APIKey)
	}
}

// A whitespace-only secret is "not supplied", not a secret made of spaces —
// otherwise creating a SendGrid sender with "   " would pass validation and
// then store nothing, producing a config that can never send.
func TestWhitespaceOnlyAPIKeyIsRejectedOnCreate(t *testing.T) {
	svc, tenantID, _, ctx := newSenderTestEnv(t)

	_, err := svc.Upsert(ctx, tenantID, nil, auth.UpsertSenderInput{
		Provider:    auth.SenderProviderSendGrid,
		FromAddress: "no-reply@acme.com",
		APIKey:      "   \n",
	}, nil)
	if err == nil {
		t.Fatal("a whitespace-only API key was accepted when creating a SendGrid sender")
	}
}

// TestResolveScopeDistinguishesOwnFromInherited is what the test endpoint's
// 409 guard depends on: it must be able to tell "this application has its own
// sender" from "this application would fall through to the tenant's". Reporting
// the wrong one either blocks a legitimate test or lets a green result vouch
// for a provider that was never exercised.
func TestResolveScopeDistinguishesOwnFromInherited(t *testing.T) {
	svc, tenantID, appRowID, ctx := newSenderTestEnv(t)

	// Tenant-only: an application-addressed test is inherited, not its own.
	if _, err := svc.Upsert(ctx, tenantID, nil, auth.UpsertSenderInput{
		Provider: auth.SenderProviderSendGrid, FromAddress: "tenant@acme.com", APIKey: "SG.tenant-key",
	}, nil); err != nil {
		t.Fatalf("Upsert(tenant): %v", err)
	}
	_, scope, err := svc.ResolveWithScope(ctx, tenantID, &appRowID)
	if err != nil {
		t.Fatalf("ResolveScope: %v", err)
	}
	if scope == auth.SenderScopeApplication {
		t.Fatal("an application with no sender of its own reported application scope — a test would wrongly vouch for it")
	}

	// Give the application its own sender: the same call must now report
	// application scope, so the guard stops blocking a legitimate test.
	if _, err := svc.Upsert(ctx, tenantID, &appRowID, auth.UpsertSenderInput{
		Provider: auth.SenderProviderSendGrid, FromAddress: "app@acme.com", APIKey: "SG.app-key",
	}, nil); err != nil {
		t.Fatalf("Upsert(app): %v", err)
	}
	_, scope, err = svc.ResolveWithScope(ctx, tenantID, &appRowID)
	if err != nil {
		t.Fatalf("ResolveScope: %v", err)
	}
	if scope != auth.SenderScopeApplication {
		t.Errorf("scope = %q after configuring the application, want %q", scope, auth.SenderScopeApplication)
	}

	// A tenant-addressed test still reports tenant scope — the application's
	// row must not leak upward into the tenant's answer.
	_, tenantScope, err := svc.ResolveWithScope(ctx, tenantID, nil)
	if err != nil {
		t.Fatalf("ResolveScope(tenant): %v", err)
	}
	if tenantScope != auth.SenderScopeTenant {
		t.Errorf("tenant scope = %q, want %q", tenantScope, auth.SenderScopeTenant)
	}
}

// TestResolveScopeIgnoresInactiveSender is the regression test for the bug that
// shipped in the first cut of this work (PR #91 review): scope was answered by
// Get(), which has no is_active filter, while the credentials came from
// Resolve(), which does. A DEACTIVATED application row therefore reported
// "application" scope while sending on the tenant's key — the response actively
// asserted a scope it had never exercised, and the 409 guard waved it through.
func TestResolveScopeIgnoresInactiveSender(t *testing.T) {
	svc, tenantID, appRowID, ctx := newSenderTestEnv(t)

	// Tenant sender active; the application has its own row but deactivated.
	if _, err := svc.Upsert(ctx, tenantID, nil, auth.UpsertSenderInput{
		Provider: auth.SenderProviderSendGrid, FromAddress: "tenant@acme.com", APIKey: "SG.tenant-key",
	}, nil); err != nil {
		t.Fatalf("Upsert(tenant): %v", err)
	}
	inactive := false
	if _, err := svc.Upsert(ctx, tenantID, &appRowID, auth.UpsertSenderInput{
		Provider: auth.SenderProviderSendGrid, FromAddress: "app@acme.com", APIKey: "SG.app-key",
		IsActive: &inactive,
	}, nil); err != nil {
		t.Fatalf("Upsert(app, inactive): %v", err)
	}

	cfg, scope, err := svc.ResolveWithScope(ctx, tenantID, &appRowID)
	if err != nil {
		t.Fatalf("ResolveWithScope: %v", err)
	}
	if scope == auth.SenderScopeApplication {
		t.Error("an inactive application sender reported application scope — the 409 guard would pass and the response would vouch for a provider that was never exercised")
	}
	if scope != auth.SenderScopeTenant {
		t.Errorf("scope = %q, want %q", scope, auth.SenderScopeTenant)
	}
	// The whole point: scope and credentials must come from the same row.
	if cfg == nil || cfg.APIKey != "SG.tenant-key" {
		t.Errorf("credentials = %+v but scope reported %q — the two disagree", cfg, scope)
	}
}

// Scope and credentials are returned from one query, so they cannot diverge.
// This asserts the pairing directly for every configuration shape.
func TestResolveWithScopePairsScopeToCredentials(t *testing.T) {
	svc, tenantID, appRowID, ctx := newSenderTestEnv(t)

	// Nothing configured → global, and no credentials at all.
	cfg, scope, err := svc.ResolveWithScope(ctx, tenantID, &appRowID)
	if err != nil {
		t.Fatalf("ResolveWithScope: %v", err)
	}
	if scope != auth.SenderScopeGlobal || cfg != nil {
		t.Errorf("nothing configured: scope=%q cfg=%+v, want global/nil", scope, cfg)
	}

	// Tenant only.
	if _, err := svc.Upsert(ctx, tenantID, nil, auth.UpsertSenderInput{
		Provider: auth.SenderProviderSendGrid, FromAddress: "tenant@acme.com", APIKey: "SG.tenant-key",
	}, nil); err != nil {
		t.Fatalf("Upsert(tenant): %v", err)
	}
	cfg, scope, err = svc.ResolveWithScope(ctx, tenantID, &appRowID)
	if err != nil {
		t.Fatalf("ResolveWithScope: %v", err)
	}
	if scope != auth.SenderScopeTenant || cfg == nil || cfg.APIKey != "SG.tenant-key" {
		t.Errorf("tenant only: scope=%q key=%v", scope, cfg)
	}

	// Application row wins once it exists and is active.
	if _, err := svc.Upsert(ctx, tenantID, &appRowID, auth.UpsertSenderInput{
		Provider: auth.SenderProviderSendGrid, FromAddress: "app@acme.com", APIKey: "SG.app-key",
	}, nil); err != nil {
		t.Fatalf("Upsert(app): %v", err)
	}
	cfg, scope, err = svc.ResolveWithScope(ctx, tenantID, &appRowID)
	if err != nil {
		t.Fatalf("ResolveWithScope: %v", err)
	}
	if scope != auth.SenderScopeApplication || cfg == nil || cfg.APIKey != "SG.app-key" {
		t.Errorf("app configured: scope=%q key=%v", scope, cfg)
	}

	// A tenant-addressed call still gets the tenant's row, not the app's.
	cfg, scope, err = svc.ResolveWithScope(ctx, tenantID, nil)
	if err != nil {
		t.Fatalf("ResolveWithScope(tenant): %v", err)
	}
	if scope != auth.SenderScopeTenant || cfg == nil || cfg.APIKey != "SG.tenant-key" {
		t.Errorf("tenant-addressed: scope=%q key=%v — the app row leaked upward", scope, cfg)
	}
}
