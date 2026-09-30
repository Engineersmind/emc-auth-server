package config

import "testing"

// realTOTPKey is a non-zero 32-byte hex key; its value is irrelevant here.
const realTOTPKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// With the portal on cookie sessions the CSRF middleware fails closed, so the
// cookie domain and CORS settings are the difference between a working deploy
// and every cookie-authenticated write on the API returning 403. A missing or
// all-zero TOTP key encrypts secrets at rest under a public key
// (GHSA-92p3-fj5f-8gx7). Refuse to boot instead.
func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name: "development tolerates an empty cookie domain and TOTP key",
			cfg:  Config{Env: "development"},
		},
		{
			name: "test tolerates an empty cookie domain and TOTP key",
			cfg:  Config{Env: "test"},
		},
		{
			name:    "misspelled ENV is refused rather than treated as development",
			cfg:     Config{Env: "prodution"},
			wantErr: true,
		},
		{
			name:    "empty ENV is refused",
			cfg:     Config{Env: ""},
			wantErr: true,
		},
		{
			name: "production with everything set",
			cfg:  Config{Env: "production", CookieDomain: ".engineersmind.com", GlobalCORSOrigins: []string{"https://admin.engineersmind.com"}, TOTPEncryptionKey: realTOTPKey},
		},
		{
			name:    "production without a cookie domain",
			cfg:     Config{Env: "production", GlobalCORSOrigins: []string{"https://admin.engineersmind.com"}, TOTPEncryptionKey: realTOTPKey},
			wantErr: true,
		},
		{
			name:    "staging without a cookie domain",
			cfg:     Config{Env: "staging", GlobalCORSOrigins: []string{"https://admin.engineersmind.com"}, TOTPEncryptionKey: realTOTPKey},
			wantErr: true,
		},
		{
			name:    "production with a wildcard CORS origin",
			cfg:     Config{Env: "production", CookieDomain: ".engineersmind.com", GlobalCORSOrigins: []string{"https://admin.engineersmind.com", "*"}, TOTPEncryptionKey: realTOTPKey},
			wantErr: true,
		},
		{
			name:    "production without a TOTP key",
			cfg:     Config{Env: "production", CookieDomain: ".engineersmind.com", GlobalCORSOrigins: []string{"https://admin.engineersmind.com"}},
			wantErr: true,
		},
		{
			name:    "staging without a TOTP key",
			cfg:     Config{Env: "staging", CookieDomain: ".engineersmind.com", GlobalCORSOrigins: []string{"https://admin.engineersmind.com"}},
			wantErr: true,
		},
		{
			name:    "production with the all-zero dev TOTP key",
			cfg:     Config{Env: "production", CookieDomain: ".engineersmind.com", GlobalCORSOrigins: []string{"https://admin.engineersmind.com"}, TOTPEncryptionKey: "0000000000000000000000000000000000000000000000000000000000000000"},
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
