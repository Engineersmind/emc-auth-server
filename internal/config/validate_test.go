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
			name: "production with everything set",
			cfg:  Config{Env: "production", CookieDomain: ".engineersmind.com", GlobalCORSOrigins: []string{"https://admin.engineersmind.com"}, TrustedProxies: []string{"172.18.0.0/16"}},
		},
		// TRUSTED_PROXIES (GHSA-3rxg-g9v9-4gh8): empty in production means every
		// request resolves to the Docker gateway and all users share one bucket.
		{
			name:    "production without trusted proxies",
			cfg:     Config{Env: "production", CookieDomain: ".engineersmind.com", GlobalCORSOrigins: []string{"https://admin.engineersmind.com"}},
			wantErr: true,
		},
		{
			name:    "production with a malformed trusted proxy",
			cfg:     Config{Env: "production", CookieDomain: ".engineersmind.com", GlobalCORSOrigins: []string{"https://admin.engineersmind.com"}, TrustedProxies: []string{"172.18.0.1"}},
			wantErr: true,
		},
		{
			name:    "production trusting every address",
			cfg:     Config{Env: "production", CookieDomain: ".engineersmind.com", GlobalCORSOrigins: []string{"https://admin.engineersmind.com"}, TrustedProxies: []string{"0.0.0.0/0"}},
			wantErr: true,
		},
		// An overbroad-but-not-/0 range is the same spoofing hole at a slightly
		// smaller scale: DEPLOYMENT.md calls even a /8 dangerous for this purpose.
		{
			name:    "production trusting a /1 range",
			cfg:     Config{Env: "production", CookieDomain: ".engineersmind.com", GlobalCORSOrigins: []string{"https://admin.engineersmind.com"}, TrustedProxies: []string{"128.0.0.0/1"}},
			wantErr: true,
		},
		{
			name:    "production trusting a /8 range",
			cfg:     Config{Env: "production", CookieDomain: ".engineersmind.com", GlobalCORSOrigins: []string{"https://admin.engineersmind.com"}, TrustedProxies: []string{"10.0.0.0/8"}},
			wantErr: true,
		},
		// A stray slash is a typo, not a range: the value must reach
		// TrustedProxyNets untouched and fail there, not be silently repaired.
		{
			name:    "production with a double-slashed proxy range",
			cfg:     Config{Env: "production", CookieDomain: ".engineersmind.com", GlobalCORSOrigins: []string{"https://admin.engineersmind.com"}, TrustedProxies: []string{"172.18.0.0/16/"}},
			wantErr: true,
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

// TRUSTED_PROXIES holds CIDRs, not origins: the trailing-slash strip that
// getEnvList applies to URLs must not run on it. A typo like "172.18.0.0/16/"
// has to reach TrustedProxyNets intact and fail there — silently trimming it
// to a valid range would boot a misconfigured deployment.
func TestLoad_TrustedProxiesKeepsTheTrailingSlash(t *testing.T) {
	t.Setenv("TRUSTED_PROXIES", "172.18.0.0/16/, 10.1.0.0/24")
	cfg := Load()
	if len(cfg.TrustedProxies) != 2 || cfg.TrustedProxies[0] != "172.18.0.0/16/" {
		t.Fatalf("TrustedProxies = %v, want the malformed entry preserved verbatim", cfg.TrustedProxies)
	}
	if _, err := cfg.TrustedProxyNets(); err == nil {
		t.Error("TrustedProxyNets accepted the double-slashed range")
	}
}
