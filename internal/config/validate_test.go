package config

import "testing"

// With the portal on cookie sessions the CSRF middleware fails closed, so these
// two settings are the difference between a working deploy and every
// cookie-authenticated write on the API returning 403. Refuse to boot instead.
func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name: "development tolerates an empty cookie domain",
			cfg:  Config{Env: "development"},
		},
		{
			name: "production with both set",
			cfg:  Config{Env: "production", CookieDomain: ".engineersmind.com", GlobalCORSOrigins: []string{"https://admin.engineersmind.com"}},
		},
		{
			name:    "production without a cookie domain",
			cfg:     Config{Env: "production", GlobalCORSOrigins: []string{"https://admin.engineersmind.com"}},
			wantErr: true,
		},
		{
			name:    "staging without a cookie domain",
			cfg:     Config{Env: "staging", GlobalCORSOrigins: []string{"https://admin.engineersmind.com"}},
			wantErr: true,
		},
		{
			name:    "production with a wildcard CORS origin",
			cfg:     Config{Env: "production", CookieDomain: ".engineersmind.com", GlobalCORSOrigins: []string{"https://admin.engineersmind.com", "*"}},
			wantErr: true,
		},
		{
			// A misspelled ENV must not silently get the lax development
			// posture — security branches compare against "production".
			name:    "unrecognised ENV is rejected",
			cfg:     Config{Env: "prod"},
			wantErr: true,
		},
		{
			name: "test env is accepted",
			cfg:  Config{Env: "test"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if (err != nil) != tc.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

// TestLoad_EnvDefaultsToProduction locks in GHSA-vgf9-64q8-gj87 (M-03): an
// unset ENV must resolve to the strict posture, not development. A deploy that
// forgets ENV then trips Validate()'s COOKIE_DOMAIN requirement instead of
// silently shipping lax cookies, no CSRF check, and no HTTPS redirect.
func TestLoad_EnvDefaultsToProduction(t *testing.T) {
	t.Setenv("ENV", "")
	cfg := Load()
	if cfg.Env != "production" {
		t.Errorf("unset ENV: Env = %q, want %q", cfg.Env, "production")
	}
}
