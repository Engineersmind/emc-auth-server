package config

import "testing"

// PASSWORDLESS_CODE_HMAC_KEY is only demanded when the feature is switched on,
// so an upgrade that does not enable it needs no new variable.
func TestValidate_PasswordlessKey(t *testing.T) {
	const goodDSN = "postgres://u:p@db/db?sslmode=require"
	prod := func(mut func(*Config)) Config {
		c := Config{
			Env: "production", DatabaseURL: goodDSN, CookieDomain: ".engineersmind.com",
			GlobalCORSOrigins: []string{"https://admin.engineersmind.com"},
			TOTPEncryptionKey: realTOTPKey, TrustedProxies: []string{"172.18.0.0/16"},
		}
		mut(&c)
		return c
	}
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{"off needs no key", prod(func(c *Config) {}), false},
		{"on without key is refused", prod(func(c *Config) { c.PasswordlessEnabled = true }), true},
		{"on with all-zero key is refused", prod(func(c *Config) {
			c.PasswordlessEnabled = true
			c.PasswordlessCodeHMACKey = "0000000000000000000000000000000000000000000000000000000000000000"
		}), true},
		{"on with short key is refused", prod(func(c *Config) {
			c.PasswordlessEnabled = true
			c.PasswordlessCodeHMACKey = "abcd"
		}), true},
		{"on with non-hex key is refused", prod(func(c *Config) {
			c.PasswordlessEnabled = true
			c.PasswordlessCodeHMACKey = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
		}), true},
		{"on with a real key is accepted", prod(func(c *Config) {
			c.PasswordlessEnabled = true
			c.PasswordlessCodeHMACKey = realTOTPKey
		}), false},
		{"development never needs the key", Config{
			Env: "development", DatabaseURL: "postgres://u:p@localhost/db?sslmode=disable", PasswordlessEnabled: true,
		}, false},
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

func TestPasswordlessEnabledDefaultsOff(t *testing.T) {
	t.Setenv("PASSWORDLESS_ENABLED", "")
	cfg := Load()
	if cfg.PasswordlessEnabled {
		t.Error("PasswordlessEnabled must default to false")
	}
}
