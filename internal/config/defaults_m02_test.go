package config

import (
	"os"
	"testing"
)

// TestLoad_SecureDefaults_M02 pins GHSA-4x5m-3gph-938r (M-02): legacy HS256
// verification is opt-IN, and only the exact string "true" opens the migration
// window. Unset, empty, mistyped, or differently-cased values all enforce the
// strict posture.
//
// SECURITY PIN: this is the Phase 4 default. If Load() ever reverts to opt-out,
// every deployment that never set JWT_ALLOW_LEGACY_HS256 silently re-accepts
// symmetric tokens — and a tenant jwt_secret holder can mint a token for any
// user in that tenant, including super_admin. The JWT tests cannot catch that
// regression: they configure JWTService by hand via WithLegacyHS256, never
// through Load(), so without this test the flip ships green.
func TestLoad_SecureDefaults_M02(t *testing.T) {
	cases := []struct {
		name string
		set  bool
		val  string
		want bool
	}{
		{"unset enforces by default", false, "", false},
		{"empty string enforces", true, "", false},
		{"explicit false enforces", true, "false", false},
		{"misspelled true fails strict", true, "ture", false},
		{"yes is not true", true, "yes", false},
		{"1 is not true", true, "1", false},
		{"mixed case is not true", true, "True", false},
		{"upper case is not true", true, "TRUE", false},
		{"exact true opens the migration window", true, "true", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.set {
				t.Setenv("JWT_ALLOW_LEGACY_HS256", tc.val)
			} else {
				// why: "unset" must be genuinely unset — a CI environment that
				// happens to export the variable must not flip the assertion.
				// t.Setenv registers the restore; Unsetenv does the unsetting.
				t.Setenv("JWT_ALLOW_LEGACY_HS256", "")
				_ = os.Unsetenv("JWT_ALLOW_LEGACY_HS256")
			}
			cfg := Load()
			if cfg.JWTAllowLegacyHS256 != tc.want {
				t.Errorf("JWTAllowLegacyHS256 = %v, want %v — only the exact string "+
					"\"true\" may open the HS256 migration window",
					cfg.JWTAllowLegacyHS256, tc.want)
			}
		})
	}
}
