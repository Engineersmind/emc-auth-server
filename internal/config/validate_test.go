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
	// goodDSN satisfies the DATABASE_URL-required check (GHSA-hv5j-m2r7-r4cr)
	// so each case actually reaches the rule it is named for.
	const goodDSN = "postgres://u:p@db/db?sslmode=require"
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name: "development tolerates an empty cookie domain and TOTP key",
			cfg:  Config{Env: "development", DatabaseURL: "postgres://u:p@localhost/db?sslmode=disable"},
		},
		{
			name: "test tolerates an empty cookie domain and TOTP key",
			cfg:  Config{Env: "test", DatabaseURL: "postgres://u:p@localhost/db?sslmode=disable"},
		},
		{
			name:    "empty DATABASE_URL is rejected in every environment",
			cfg:     Config{Env: "development"},
			wantErr: true,
		},
		{
			name:    "misspelled ENV is refused rather than treated as development",
			cfg:     Config{Env: "prodution", DatabaseURL: goodDSN},
			wantErr: true,
		},
		{
			name:    "empty ENV is refused",
			cfg:     Config{Env: "", DatabaseURL: goodDSN},
			wantErr: true,
		},
		{
			name: "production with everything set",
			cfg:  Config{Env: "production", DatabaseURL: goodDSN, CookieDomain: ".engineersmind.com", GlobalCORSOrigins: []string{"https://admin.engineersmind.com"}, TOTPEncryptionKey: realTOTPKey, TrustedProxies: []string{"172.18.0.0/16"}},
		},
		// GHSA-hv5j-m2r7-r4cr (L-06): plaintext transport to the database must
		// not be reachable by default in production — the parsed sslmode must
		// be require/verify-ca/verify-full, not merely "not the word disable".
		{
			name:    "sslmode=disable is rejected in production",
			cfg:     Config{Env: "production", DatabaseURL: "postgres://u:p@db/db?sslmode=disable", CookieDomain: ".engineersmind.com", GlobalCORSOrigins: []string{"https://admin.engineersmind.com"}, TOTPEncryptionKey: realTOTPKey, TrustedProxies: []string{"172.18.0.0/16"}},
			wantErr: true,
		},
		{
			name:    "missing sslmode (defaults to prefer) is rejected in production",
			cfg:     Config{Env: "production", DatabaseURL: "postgres://u:p@db/db", CookieDomain: ".engineersmind.com", GlobalCORSOrigins: []string{"https://admin.engineersmind.com"}, TOTPEncryptionKey: realTOTPKey, TrustedProxies: []string{"172.18.0.0/16"}},
			wantErr: true,
		},
		{
			name:    "sslmode=prefer is rejected in production",
			cfg:     Config{Env: "production", DatabaseURL: "postgres://u:p@db/db?sslmode=prefer", CookieDomain: ".engineersmind.com", GlobalCORSOrigins: []string{"https://admin.engineersmind.com"}, TOTPEncryptionKey: realTOTPKey, TrustedProxies: []string{"172.18.0.0/16"}},
			wantErr: true,
		},
		{
			name: "keyword DSN with sslmode=require is accepted in production",
			cfg:  Config{Env: "production", DatabaseURL: "host=db user=u password=p dbname=db sslmode=require", CookieDomain: ".engineersmind.com", GlobalCORSOrigins: []string{"https://admin.engineersmind.com"}, TOTPEncryptionKey: realTOTPKey, TrustedProxies: []string{"172.18.0.0/16"}},
		},
		{
			name:    "keyword DSN with sslmode=disable is rejected in production",
			cfg:     Config{Env: "production", DatabaseURL: "host=db user=u password=p dbname=db sslmode=disable", CookieDomain: ".engineersmind.com", GlobalCORSOrigins: []string{"https://admin.engineersmind.com"}, TOTPEncryptionKey: realTOTPKey, TrustedProxies: []string{"172.18.0.0/16"}},
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
			cfg:     Config{Env: "production", DatabaseURL: goodDSN, GlobalCORSOrigins: []string{"https://admin.engineersmind.com"}, TOTPEncryptionKey: realTOTPKey, TrustedProxies: []string{"172.18.0.0/16"}},
			wantErr: true,
		},
		{
			name:    "staging without a cookie domain",
			cfg:     Config{Env: "staging", DatabaseURL: goodDSN, GlobalCORSOrigins: []string{"https://admin.engineersmind.com"}, TOTPEncryptionKey: realTOTPKey, TrustedProxies: []string{"172.18.0.0/16"}},
			wantErr: true,
		},
		{
			name:    "production with a wildcard CORS origin",
			cfg:     Config{Env: "production", DatabaseURL: goodDSN, CookieDomain: ".engineersmind.com", GlobalCORSOrigins: []string{"https://admin.engineersmind.com", "*"}, TOTPEncryptionKey: realTOTPKey, TrustedProxies: []string{"172.18.0.0/16"}},
			wantErr: true,
		},
		{
			name:    "production without a TOTP key",
			cfg:     Config{Env: "production", DatabaseURL: goodDSN, CookieDomain: ".engineersmind.com", GlobalCORSOrigins: []string{"https://admin.engineersmind.com"}, TrustedProxies: []string{"172.18.0.0/16"}},
			wantErr: true,
		},
		{
			name:    "staging without a TOTP key",
			cfg:     Config{Env: "staging", DatabaseURL: goodDSN, CookieDomain: ".engineersmind.com", GlobalCORSOrigins: []string{"https://admin.engineersmind.com"}, TrustedProxies: []string{"172.18.0.0/16"}},
			wantErr: true,
		},
		{
			name:    "production with the all-zero dev TOTP key",
			cfg:     Config{Env: "production", DatabaseURL: goodDSN, CookieDomain: ".engineersmind.com", GlobalCORSOrigins: []string{"https://admin.engineersmind.com"}, TOTPEncryptionKey: "0000000000000000000000000000000000000000000000000000000000000000", TrustedProxies: []string{"172.18.0.0/16"}},
			wantErr: true,
		},
		// TRUSTED_PROXIES (GHSA-3rxg-g9v9-4gh8): empty in production means every
		// request resolves to the Docker gateway and all users share one bucket.
		// Each case below carries a real TOTPEncryptionKey so it actually reaches
		// and exercises the TrustedProxies check, rather than incidentally
		// passing because of the earlier, unrelated TOTP-key failure.
		{
			name:    "production without trusted proxies",
			cfg:     Config{Env: "production", DatabaseURL: goodDSN, CookieDomain: ".engineersmind.com", GlobalCORSOrigins: []string{"https://admin.engineersmind.com"}, TOTPEncryptionKey: realTOTPKey},
			wantErr: true,
		},
		{
			name:    "production with a malformed trusted proxy",
			cfg:     Config{Env: "production", DatabaseURL: goodDSN, CookieDomain: ".engineersmind.com", GlobalCORSOrigins: []string{"https://admin.engineersmind.com"}, TOTPEncryptionKey: realTOTPKey, TrustedProxies: []string{"172.18.0.1"}},
			wantErr: true,
		},
		{
			name:    "production trusting every address",
			cfg:     Config{Env: "production", DatabaseURL: goodDSN, CookieDomain: ".engineersmind.com", GlobalCORSOrigins: []string{"https://admin.engineersmind.com"}, TOTPEncryptionKey: realTOTPKey, TrustedProxies: []string{"0.0.0.0/0"}},
			wantErr: true,
		},
		// An overbroad-but-not-/0 range is the same spoofing hole at a slightly
		// smaller scale: DEPLOYMENT.md calls even a /8 dangerous for this purpose.
		{
			name:    "production trusting a /1 range",
			cfg:     Config{Env: "production", DatabaseURL: goodDSN, CookieDomain: ".engineersmind.com", GlobalCORSOrigins: []string{"https://admin.engineersmind.com"}, TOTPEncryptionKey: realTOTPKey, TrustedProxies: []string{"128.0.0.0/1"}},
			wantErr: true,
		},
		{
			name:    "production trusting a /8 range",
			cfg:     Config{Env: "production", DatabaseURL: goodDSN, CookieDomain: ".engineersmind.com", GlobalCORSOrigins: []string{"https://admin.engineersmind.com"}, TOTPEncryptionKey: realTOTPKey, TrustedProxies: []string{"10.0.0.0/8"}},
			wantErr: true,
		},
		// A stray slash is a typo, not a range: the value must reach
		// TrustedProxyNets untouched and fail there, not be silently repaired.
		{
			name:    "production with a double-slashed proxy range",
			cfg:     Config{Env: "production", DatabaseURL: goodDSN, CookieDomain: ".engineersmind.com", GlobalCORSOrigins: []string{"https://admin.engineersmind.com"}, TOTPEncryptionKey: realTOTPKey, TrustedProxies: []string{"172.18.0.0/16/"}},
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
