package config

import (
	"os"
	"strconv"
	"strings"
)

// Config holds all application configuration loaded from environment variables.
type Config struct {
	Port        string
	DatabaseURL string
	RedisURL    string
	LogLevel    string
	Env         string
	JWTIssuer   string

	// SMTP configuration for password reset emails (RESET-01).
	// In development (Env=development), emails are logged to console instead.
	SMTPHost     string
	SMTPPort     int
	SMTPFrom     string
	SMTPUsername string
	SMTPPassword string

	// AppBaseURL is prepended to the reset token link in emails.
	// Example: "https://auth.emc.local"
	AppBaseURL string

	// TOTPEncryptionKey is a 32-byte hex-encoded key used to AES-256-GCM encrypt
	// TOTP secrets at rest. Generate with: openssl rand -hex 32
	// Required when TOTP is used. Must be exactly 64 hex characters.
	TOTPEncryptionKey string

	// OAuthClientSecretEncryptionKey is a 32-byte hex-encoded key used to
	// AES-256-GCM encrypt social-login provider client secrets at rest
	// (identity_provider_configs.client_secret_enc). Generate with:
	// openssl rand -hex 32. Unlike TOTP's key there is NO zero-key fallback
	// in production — the server refuses to start (issue #64).
	OAuthClientSecretEncryptionKey string

	// OAuthClientSecretEncryptionKeyPrevious enables zero-downtime key
	// rotation: set the NEW key as OAUTH_CLIENT_SECRET_ENCRYPTION_KEY and the
	// old one here. Decryption falls back to this key; rows re-encrypt under
	// the new key on their next admin write. Remove once rotation completes.
	OAuthClientSecretEncryptionKeyPrevious string

	// CookieDomain sets the Domain attribute on auth cookies.
	// Leave empty for localhost development (browser scopes to current host).
	// In production set to the shared parent domain, e.g. ".engineersmind.com",
	// so both app.engineersmind.com and auth.engineersmind.com can read the cookies.
	CookieDomain string

	// GlobalCORSOrigins are the allowed browser origins for slug-less endpoints
	// (e.g. /auth/login) whose tenant isn't known until after authentication, so
	// per-tenant CORS lookups don't apply. Comma-separated via GLOBAL_CORS_ORIGINS.
	GlobalCORSOrigins []string
}

// Load reads configuration from environment variables with sensible defaults.
func Load() *Config {
	smtpPort, _ := strconv.Atoi(getEnv("SMTP_PORT", "587"))
	return &Config{
		Port:                                   getEnv("PORT", "9090"),
		DatabaseURL:                            getEnv("DATABASE_URL", "postgres://emc_auth:password@localhost:5433/emc_auth?sslmode=disable"),
		RedisURL:                               getEnv("REDIS_URL", "redis://localhost:6379/0"),
		LogLevel:                               getEnv("LOG_LEVEL", "info"),
		Env:                                    getEnv("ENV", "development"),
		JWTIssuer:                              getEnv("JWT_ISSUER", "https://auth.emc.local"),
		SMTPHost:                               getEnv("SMTP_HOST", ""),
		SMTPPort:                               smtpPort,
		SMTPFrom:                               getEnv("SMTP_FROM", "no-reply@emc.local"),
		SMTPUsername:                           getEnv("SMTP_USERNAME", ""),
		SMTPPassword:                           getEnv("SMTP_PASSWORD", ""),
		AppBaseURL:                             getEnv("APP_BASE_URL", "http://localhost:9090"),
		TOTPEncryptionKey:                      getEnv("TOTP_ENCRYPTION_KEY", ""),
		OAuthClientSecretEncryptionKey:         getEnv("OAUTH_CLIENT_SECRET_ENCRYPTION_KEY", ""),
		OAuthClientSecretEncryptionKeyPrevious: getEnv("OAUTH_CLIENT_SECRET_ENCRYPTION_KEY_PREVIOUS", ""),
		CookieDomain:                           getEnv("COOKIE_DOMAIN", ""),
		GlobalCORSOrigins:                      getEnvList("GLOBAL_CORS_ORIGINS", ""),
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// getEnvList parses a comma-separated env var into a trimmed, non-empty slice.
// Trailing slashes are stripped since browser Origin headers never include a path.
func getEnvList(key, fallback string) []string {
	raw := getEnv(key, fallback)
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(p), "/"))
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
