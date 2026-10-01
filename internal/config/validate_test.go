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
			// The CSRF allowlist reads this list, so empty is not "no CORS" —
			// it is every cookie write 403ing at runtime, including login.
			name:    "production without any global CORS origin",
			cfg:     Config{Env: "production", CookieDomain: ".engineersmind.com"},
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
