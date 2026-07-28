package auth

import (
	"context"
	"errors"
	"testing"
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
