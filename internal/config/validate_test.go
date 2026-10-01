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
			cfg:  Config{Env: "development", DatabaseURL: "postgres://u:p@localhost/db?sslmode=disable"},
		},
		{
			name: "production with both set",
			cfg:  Config{Env: "production", DatabaseURL: "postgres://u:p@db/db?sslmode=require", CookieDomain: ".engineersmind.com", GlobalCORSOrigins: []string{"https://admin.engineersmind.com"}},
		},
		{
			name:    "empty DATABASE_URL is rejected in every environment",
			cfg:     Config{Env: "development"},
			wantErr: true,
		},
		{
			// GHSA-jv2c-x735-vff7 (L-06): plaintext transport to the database
			// must not be reachable by default in production.
			name:    "sslmode=disable is rejected in production",
			cfg:     Config{Env: "production", DatabaseURL: "postgres://u:p@db/db?sslmode=disable", CookieDomain: ".engineersmind.com", GlobalCORSOrigins: []string{"https://admin.engineersmind.com"}},
			wantErr: true,
		},
		{
			// L-06 review: a missing sslmode is not safe — pgx defaults to
			// "prefer", which silently falls back to an unencrypted hop.
			name:    "missing sslmode is rejected in production",
			cfg:     Config{Env: "production", DatabaseURL: "postgres://u:p@db/db", CookieDomain: ".engineersmind.com", GlobalCORSOrigins: []string{"https://admin.engineersmind.com"}},
			wantErr: true,
		},
		{
			name:    "sslmode=prefer is rejected in production",
			cfg:     Config{Env: "production", DatabaseURL: "postgres://u:p@db/db?sslmode=prefer", CookieDomain: ".engineersmind.com", GlobalCORSOrigins: []string{"https://admin.engineersmind.com"}},
			wantErr: true,
		},
		{
			name:    "sslmode=allow is rejected in staging",
			cfg:     Config{Env: "staging", DatabaseURL: "host=db user=u password=p sslmode=allow", CookieDomain: ".engineersmind.com", GlobalCORSOrigins: []string{"https://admin.engineersmind.com"}},
			wantErr: true,
		},
		{
			name: "keyword DSN with verify-full passes in production",
			cfg:  Config{Env: "production", DatabaseURL: "host=db user=u password=p sslmode=verify-full", CookieDomain: ".engineersmind.com", GlobalCORSOrigins: []string{"https://admin.engineersmind.com"}},
		},
		{
			name:    "production without a cookie domain",
			cfg:     Config{Env: "production", DatabaseURL: "postgres://u:p@db/db?sslmode=require", GlobalCORSOrigins: []string{"https://admin.engineersmind.com"}},
			wantErr: true,
		},
		{
			name:    "staging without a cookie domain",
			cfg:     Config{Env: "staging", DatabaseURL: "postgres://u:p@db/db?sslmode=require", GlobalCORSOrigins: []string{"https://admin.engineersmind.com"}},
			wantErr: true,
		},
		{
			name:    "production with a wildcard CORS origin",
			cfg:     Config{Env: "production", DatabaseURL: "postgres://u:p@db/db?sslmode=require", CookieDomain: ".engineersmind.com", GlobalCORSOrigins: []string{"https://admin.engineersmind.com", "*"}},
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
