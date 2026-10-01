package config

import "testing"

// TestLoad_SecureDefaults_L05 pins GHSA-jv2c-x735-vff7: the legacy issuer and
// the audience backstop both default to the STRICT posture, and only the
// exact opt-in/opt-out strings open a migration window.
func TestLoad_SecureDefaults_L05(t *testing.T) {
	t.Run("unset vars enforce by default", func(t *testing.T) {
		cfg := Load()
		if cfg.JWTAllowLegacyIssuer {
			t.Error("JWTAllowLegacyIssuer = true with JWT_ALLOW_LEGACY_ISSUER unset — " +
				"legacy global issuer must be opt-in, not opt-out")
		}
		if !cfg.RequireAudience {
			t.Error("RequireAudience = false with REQUIRE_AUDIENCE unset — " +
				"the audience backstop must default on")
		}
	})

	t.Run("explicit migration windows", func(t *testing.T) {
		t.Setenv("JWT_ALLOW_LEGACY_ISSUER", "true")
		t.Setenv("REQUIRE_AUDIENCE", "false")
		cfg := Load()
		if !cfg.JWTAllowLegacyIssuer {
			t.Error("JWT_ALLOW_LEGACY_ISSUER=true must re-enable legacy issuer verification")
		}
		if cfg.RequireAudience {
			t.Error("REQUIRE_AUDIENCE=false must keep the rollback working")
		}
	})

	t.Run("typos fail strict", func(t *testing.T) {
		t.Setenv("JWT_ALLOW_LEGACY_ISSUER", "ture")
		t.Setenv("REQUIRE_AUDIENCE", "flase")
		cfg := Load()
		if cfg.JWTAllowLegacyIssuer {
			t.Error("misspelled JWT_ALLOW_LEGACY_ISSUER must not widen verification")
		}
		if !cfg.RequireAudience {
			t.Error("misspelled REQUIRE_AUDIENCE must not disable the backstop")
		}
	})
}
