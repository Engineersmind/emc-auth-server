package auth

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// checkByName pulls one named check out of a test result.
func checkByName(t *testing.T, res *ProviderTestResult, name string) ProviderTestCheck {
	t.Helper()
	for _, c := range res.Checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("check %q not present in result %+v", name, res.Checks)
	return ProviderTestCheck{}
}

// TestProviderConfigDetailExposesSecretPresenceAndCallback covers the two
// fields the admin UI needs but must never get from a secret read-back:
// has_secret (so it can offer "leave blank to keep") and callback_url (the
// exact redirect URI to register in the provider console).
func TestProviderConfigDetailExposesSecretPresenceAndCallback(t *testing.T) {
	sg := newStubGoogle(t)
	env := newOAuthTestEnv(t, sg)
	ctx := context.Background()

	configs, err := env.svc.idpSvc.ListConfigs(ctx, env.tenantID, env.appRowID)
	if err != nil {
		t.Fatalf("ListConfigs: %v", err)
	}
	if len(configs) != 1 {
		t.Fatalf("got %d configs, want 1", len(configs))
	}
	got := configs[0]
	if !got.HasSecret {
		t.Error("has_secret = false, want true — the env seeds a client secret")
	}
	if want := "http://localhost:9090/oauth/google/callback"; got.CallbackURL != want {
		t.Errorf("callback_url = %q, want %q", got.CallbackURL, want)
	}
}

// TestUpsertWithoutSecretPreservesStoredSecret is the update path the UI
// relies on: an admin editing the redirect list must not have to re-enter the
// secret, and doing so must not blank it out.
func TestUpsertWithoutSecretPreservesStoredSecret(t *testing.T) {
	sg := newStubGoogle(t)
	env := newOAuthTestEnv(t, sg)
	ctx := context.Background()

	updated, err := env.svc.idpSvc.UpsertConfig(ctx, env.tenantID, env.appRowID, UpsertProviderConfigInput{
		Provider:      ProviderGoogle,
		ClientID:      "stub-google-client-id",
		ClientSecret:  "", // omitted — keep the stored one
		Enabled:       true,
		RedirectAllow: []string{env.redirect, "https://demo.example/other"},
	})
	if err != nil {
		t.Fatalf("UpsertConfig: %v", err)
	}
	if !updated.HasSecret {
		t.Error("has_secret = false after a secret-preserving update, want true")
	}
	if len(updated.RedirectAllow) != 2 {
		t.Errorf("redirect_allow = %v, want 2 entries", updated.RedirectAllow)
	}

	// The preserved secret must still be usable by the login flow itself.
	cfg, err := env.svc.idpSvc.getFlowConfig(ctx, env.appRowID, ProviderGoogle)
	if err != nil {
		t.Fatalf("getFlowConfig: %v", err)
	}
	if cfg.ClientSecret != "stub-google-client-secret" {
		t.Errorf("preserved secret = %q, want the originally stored value", cfg.ClientSecret)
	}
}

// TestTestConfigPassesForHealthyConfig asserts the happy path and, critically,
// that a green result still reports secret_verified = false — a passing test
// must not imply the client secret was proven correct.
func TestTestConfigPassesForHealthyConfig(t *testing.T) {
	sg := newStubGoogle(t)
	env := newOAuthTestEnv(t, sg)

	res, err := env.svc.TestConfig(context.Background(), env.tenantID, env.appRowID, ProviderGoogle)
	if err != nil {
		t.Fatalf("TestConfig: %v", err)
	}
	if !res.OK {
		t.Errorf("OK = false for a healthy config; checks = %+v", res.Checks)
	}
	if !res.Enabled {
		t.Error("Enabled = false, want true")
	}
	if res.SecretVerified {
		t.Error("secret_verified = true — no dry run can prove the client secret; it must stay false")
	}
	if !checkByName(t, res, "authorization_url").Passed {
		t.Error("authorization_url check failed against the stub issuer")
	}
}

// TestTestConfigFlagsDisabledAndEmptyAllowList covers the two misconfigurations
// the UI most needs named individually: a provider left disabled, and an empty
// redirect allow-list (which silently rejects every login attempt).
func TestTestConfigFlagsDisabledAndEmptyAllowList(t *testing.T) {
	sg := newStubGoogle(t)
	env := newOAuthTestEnv(t, sg)
	ctx := context.Background()

	if _, err := env.svc.idpSvc.UpsertConfig(ctx, env.tenantID, env.appRowID, UpsertProviderConfigInput{
		Provider:      ProviderGoogle,
		ClientID:      "stub-google-client-id",
		Enabled:       false,
		RedirectAllow: []string{},
	}); err != nil {
		t.Fatalf("UpsertConfig: %v", err)
	}

	res, err := env.svc.TestConfig(ctx, env.tenantID, env.appRowID, ProviderGoogle)
	if err != nil {
		t.Fatalf("TestConfig: %v", err)
	}
	if res.OK {
		t.Error("OK = true for a disabled config with no redirect targets")
	}
	if checkByName(t, res, "enabled").Passed {
		t.Error("enabled check passed for a disabled provider")
	}
	if checkByName(t, res, "redirect_allow").Passed {
		t.Error("redirect_allow check passed for an empty allow-list")
	}
	// A disabled provider must still be testable — that is the point: admins
	// validate the credentials BEFORE turning it on.
	if !checkByName(t, res, "config_stored").Passed {
		t.Error("config_stored check failed for a stored-but-disabled config")
	}
}

// TestTestConfigIsTenantScoped is the isolation guarantee behind the new
// tenant-nested routes: the app id comes from the URL there, so a foreign
// tenant must not be able to probe another tenant's provider setup.
func TestTestConfigIsTenantScoped(t *testing.T) {
	sg := newStubGoogle(t)
	env := newOAuthTestEnv(t, sg)

	const foreignTenantID = int64(-1) // cannot collide with a seeded tenant
	_, err := env.svc.TestConfig(context.Background(), foreignTenantID, env.appRowID, ProviderGoogle)
	if !errors.Is(err, ErrProviderNotConfigured) {
		t.Fatalf("cross-tenant TestConfig error = %v, want ErrProviderNotConfigured", err)
	}
}

// TestTestConfigUnknownProvider guards the path input before it reaches a
// driver lookup.
func TestTestConfigUnknownProvider(t *testing.T) {
	sg := newStubGoogle(t)
	env := newOAuthTestEnv(t, sg)

	_, err := env.svc.TestConfig(context.Background(), env.tenantID, env.appRowID, "facebook")
	if !errors.Is(err, ErrProviderNotSupported) {
		t.Fatalf("error = %v, want ErrProviderNotSupported", err)
	}
}

// ─── Cross-application isolation within one tenant ──────────────────────────
//
// The schema (unique on (application_id, provider)) and the application_id
// filter in every query are what keep one application's social login setup from
// touching another's. Nothing pinned that down, so a refactor that dropped an
// application_id predicate — the easy mistake, since tenant_id usually sits
// right next to it — would still have passed every other test in this package.
// These tests fail loudly if that isolation regresses.

// secondApp seeds an additional application in the SAME tenant as env. Cleanup
// is already covered: newOAuthTestEnv deletes the whole tenant subtree by
// tenant_id, which includes this row.
func secondApp(t *testing.T, env *oauthTestEnv) int64 {
	t.Helper()
	clientID := fmt.Sprintf("app_it_second_%d", time.Now().UnixNano())
	var appRowID int64
	err := env.pool.QueryRow(context.Background(), `
		INSERT INTO oauth_clients (tenant_id, name, app_type, client_id, scopes)
		VALUES ($1, 'IT App Two', 'web', $2, '{}')
		RETURNING id
	`, env.tenantID, clientID).Scan(&appRowID)
	if err != nil {
		t.Fatalf("seed second application: %v", err)
	}
	return appRowID
}

// configureGoogle points one application at its own Google credentials.
func configureGoogle(t *testing.T, env *oauthTestEnv, appRowID int64, clientID, secret, redirect string, enabled bool) {
	t.Helper()
	_, err := env.svc.idpSvc.UpsertConfig(context.Background(), env.tenantID, appRowID, UpsertProviderConfigInput{
		Provider:      ProviderGoogle,
		ClientID:      clientID,
		ClientSecret:  secret,
		Enabled:       enabled,
		RedirectAllow: []string{redirect},
	})
	if err != nil {
		t.Fatalf("configure google for application %d: %v", appRowID, err)
	}
}

// configFor fetches one application's config for a provider, failing when absent.
func configFor(t *testing.T, env *oauthTestEnv, appRowID int64, provider string) ProviderConfigDetail {
	t.Helper()
	configs, err := env.svc.idpSvc.ListConfigs(context.Background(), env.tenantID, appRowID)
	if err != nil {
		t.Fatalf("ListConfigs(app=%d): %v", appRowID, err)
	}
	for _, c := range configs {
		if c.Provider == provider {
			return c
		}
	}
	t.Fatalf("no %s config for application %d (got %d configs)", provider, appRowID, len(configs))
	return ProviderConfigDetail{}
}

// seedUserWithIdentity creates an app-scoped user holding BOTH a password and a
// linked identity, so an unlink is permitted (the last-login-method guard would
// otherwise refuse it).
func seedUserWithIdentity(t *testing.T, env *oauthTestEnv, appRowID int64, email, providerSub string) int64 {
	t.Helper()
	ctx := context.Background()
	var userID int64
	err := env.pool.QueryRow(ctx, `
		INSERT INTO users (tenant_id, application_id, email, is_active, email_verified)
		VALUES ($1, $2, $3, true, true)
		RETURNING id
	`, env.tenantID, appRowID, email).Scan(&userID)
	if err != nil {
		t.Fatalf("seed user %s: %v", email, err)
	}
	if _, err := env.pool.Exec(ctx, `
		INSERT INTO user_credentials (user_id, tenant_id, password_hash)
		VALUES ($1, $2, 'not-a-real-hash')
	`, userID, env.tenantID); err != nil {
		t.Fatalf("seed credentials for %s: %v", email, err)
	}
	if _, err := env.pool.Exec(ctx, `
		INSERT INTO user_identities
		    (user_id, tenant_id, application_id, provider, provider_sub, provider_email)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, userID, env.tenantID, appRowID, ProviderGoogle, providerSub, email); err != nil {
		t.Fatalf("seed identity for %s: %v", email, err)
	}
	return userID
}

// TestProviderConfigsAreIsolatedPerApplication is the core guarantee: two
// applications in ONE tenant hold entirely separate provider credentials.
func TestProviderConfigsAreIsolatedPerApplication(t *testing.T) {
	sg := newStubGoogle(t)
	env := newOAuthTestEnv(t, sg) // application one already has Google configured
	ctx := context.Background()
	appTwo := secondApp(t, env)

	const appTwoRedirect = "https://second.example/cb"
	configureGoogle(t, env, appTwo, "second-app-google-client-id", "second-app-google-client-secret", appTwoRedirect, true)

	// Each application reports its OWN credentials, not the other's.
	one := configFor(t, env, env.appRowID, ProviderGoogle)
	two := configFor(t, env, appTwo, ProviderGoogle)
	if one.ClientID == two.ClientID {
		t.Fatalf("both applications report client_id %q — configs are not per-application", one.ClientID)
	}
	if one.ClientID != "stub-google-client-id" {
		t.Errorf("app one client_id = %q, want the value it was configured with", one.ClientID)
	}
	if two.ClientID != "second-app-google-client-id" {
		t.Errorf("app two client_id = %q, want the value it was configured with", two.ClientID)
	}

	// A list for one application must never include another's rows.
	appTwoConfigs, err := env.svc.idpSvc.ListConfigs(ctx, env.tenantID, appTwo)
	if err != nil {
		t.Fatalf("ListConfigs(app two): %v", err)
	}
	if len(appTwoConfigs) != 1 {
		t.Errorf("app two sees %d configs, want exactly its own 1", len(appTwoConfigs))
	}

	// The decrypted secret the login flow uses is per-application too — this is
	// what would actually break logins if the scoping regressed.
	cfgOne, err := env.svc.idpSvc.getFlowConfig(ctx, env.appRowID, ProviderGoogle)
	if err != nil {
		t.Fatalf("getFlowConfig(app one): %v", err)
	}
	cfgTwo, err := env.svc.idpSvc.getFlowConfig(ctx, appTwo, ProviderGoogle)
	if err != nil {
		t.Fatalf("getFlowConfig(app two): %v", err)
	}
	if cfgOne.ClientSecret == cfgTwo.ClientSecret {
		t.Error("both applications resolve the same client secret at login time")
	}
	if len(cfgTwo.RedirectAllow) != 1 || cfgTwo.RedirectAllow[0] != appTwoRedirect {
		t.Errorf("app two redirect_allow = %v, want only its own entry", cfgTwo.RedirectAllow)
	}
}

// TestUpsertDoesNotTouchAnotherApplication proves a write is contained: the
// ON CONFLICT (application_id, provider) target can only ever be one app's row.
func TestUpsertDoesNotTouchAnotherApplication(t *testing.T) {
	sg := newStubGoogle(t)
	env := newOAuthTestEnv(t, sg)
	ctx := context.Background()
	appTwo := secondApp(t, env)

	configureGoogle(t, env, appTwo, "second-app-google-client-id", "second-app-google-client-secret", "https://second.example/cb", true)
	before := configFor(t, env, appTwo, ProviderGoogle)

	// Rewrite application one completely, including disabling it.
	configureGoogle(t, env, env.appRowID, "app-one-rotated-client-id", "app-one-rotated-secret", "https://first.example/rotated", false)

	after := configFor(t, env, appTwo, ProviderGoogle)
	if after.ClientID != before.ClientID {
		t.Errorf("app two client_id changed from %q to %q after editing app one", before.ClientID, after.ClientID)
	}
	if after.Enabled != before.Enabled {
		t.Errorf("app two enabled changed from %v to %v after disabling app one", before.Enabled, after.Enabled)
	}
	if len(after.RedirectAllow) != 1 || after.RedirectAllow[0] != before.RedirectAllow[0] {
		t.Errorf("app two redirect_allow changed from %v to %v", before.RedirectAllow, after.RedirectAllow)
	}
	// App two must still be able to start a login even though app one is off.
	if _, err := env.svc.idpSvc.getFlowConfig(ctx, appTwo, ProviderGoogle); err != nil {
		t.Errorf("app two can no longer resolve its config after app one was disabled: %v", err)
	}
}

// TestDeleteConfigLeavesOtherApplicationsWorking is the removal case an admin is
// most likely to worry about: turning a provider off for one application must
// not take it down for the rest of the tenant.
func TestDeleteConfigLeavesOtherApplicationsWorking(t *testing.T) {
	sg := newStubGoogle(t)
	env := newOAuthTestEnv(t, sg)
	ctx := context.Background()
	appTwo := secondApp(t, env)

	configureGoogle(t, env, appTwo, "second-app-google-client-id", "second-app-google-client-secret", "https://second.example/cb", true)

	if err := env.svc.idpSvc.DeleteConfig(ctx, env.tenantID, env.appRowID, ProviderGoogle); err != nil {
		t.Fatalf("delete app one config: %v", err)
	}

	// Application one is gone...
	if _, err := env.svc.idpSvc.getFlowConfig(ctx, env.appRowID, ProviderGoogle); !errors.Is(err, ErrProviderNotConfigured) {
		t.Errorf("app one getFlowConfig after delete = %v, want ErrProviderNotConfigured", err)
	}
	// ...and application two is untouched and still usable.
	if _, err := env.svc.idpSvc.getFlowConfig(ctx, appTwo, ProviderGoogle); err != nil {
		t.Errorf("app two lost its config when app one was deleted: %v", err)
	}
	if got := configFor(t, env, appTwo, ProviderGoogle).ClientID; got != "second-app-google-client-id" {
		t.Errorf("app two client_id = %q after deleting app one", got)
	}
	// Re-deleting the same application's config is a clean miss, not a hit on
	// another application's row.
	if err := env.svc.idpSvc.DeleteConfig(ctx, env.tenantID, env.appRowID, ProviderGoogle); !errors.Is(err, ErrProviderNotConfigured) {
		t.Errorf("re-delete = %v, want ErrProviderNotConfigured", err)
	}
}

// TestSameProviderAccountIsSeparatePerApplication covers the identity side: one
// Google account signing into two applications of the same tenant produces two
// independent users, and unlinking in one leaves the other linked.
func TestSameProviderAccountIsSeparatePerApplication(t *testing.T) {
	sg := newStubGoogle(t)
	env := newOAuthTestEnv(t, sg)
	ctx := context.Background()
	appTwo := secondApp(t, env)

	// The SAME provider_sub in both applications — permitted precisely because
	// user_identities is unique on (tenant, application, provider, sub).
	const sharedSub = "shared-google-sub-123"
	userOne := seedUserWithIdentity(t, env, env.appRowID, "shared+one@example.com", sharedSub)
	userTwo := seedUserWithIdentity(t, env, appTwo, "shared+two@example.com", sharedSub)
	if userOne == userTwo {
		t.Fatal("the same Google account resolved to one user across two applications")
	}

	// Unlink in application one only.
	if err := env.svc.idpSvc.UnlinkUserIdentity(ctx, env.tenantID, userOne, ProviderGoogle); err != nil {
		t.Fatalf("unlink app one identity: %v", err)
	}

	oneIdentities, err := env.svc.idpSvc.ListUserIdentities(ctx, env.tenantID, userOne)
	if err != nil {
		t.Fatalf("list app one identities: %v", err)
	}
	if len(oneIdentities) != 0 {
		t.Errorf("app one user still has %d identities after unlink", len(oneIdentities))
	}

	twoIdentities, err := env.svc.idpSvc.ListUserIdentities(ctx, env.tenantID, userTwo)
	if err != nil {
		t.Fatalf("list app two identities: %v", err)
	}
	if len(twoIdentities) != 1 {
		t.Fatalf("app two user has %d identities, want its 1 to survive the other app's unlink", len(twoIdentities))
	}
	if twoIdentities[0].Provider != ProviderGoogle {
		t.Errorf("app two identity provider = %q, want google", twoIdentities[0].Provider)
	}
}
