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
	// SMTPTLS overrides TLS mode for the global sender: "ssl" (implicit TLS,
	// port 465), "starttls" (mandatory, port 587), "opportunistic", or "none"
	// (local relays only). Empty derives from the port. Set via SMTP_TLS.
	SMTPTLS string

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

	// GeoIPDatabasePath points to a MaxMind GeoLite2/GeoIP2-City .mmdb file used
	// to enrich audit rows with a coarse location. Empty (the default) disables
	// geo enrichment — the .mmdb is licensed and not shipped with the server.
	// Set via GEOIP_DATABASE_PATH.
	GeoIPDatabasePath string

	// UntrustedIPCIDRs is an optional denylist of CIDR ranges flagged as
	// untrusted in the audit risk assessment (Auth0's UntrustedIP signal).
	// Comma-separated via UNTRUSTED_IP_CIDRS; empty disables the check.
	UntrustedIPCIDRs []string

	// AuditCaptureResponseBody controls whether the (redacted) HTTP response
	// body is stored on audit rows. Values: "off" | "failures" | "all".
	// Default "failures" — failure bodies are just error envelopes (no PII),
	// while success bodies (which can carry PII) are not stored unless "all".
	// Set via AUDIT_CAPTURE_RESPONSE_BODY.
	AuditCaptureResponseBody string

	// AuditRetentionDays is the retention window for audit_logs, enforced by a
	// background purge worker. 0 (default) disables automatic purging — logs
	// are kept indefinitely. Set via AUDIT_RETENTION_DAYS.
	AuditRetentionDays int

	// AuditSIEMWebhookURL, when set, streams every persisted audit event as a
	// JSON POST to this URL (Datadog/Splunk/S3-proxy/generic webhook). Empty
	// disables streaming. Must be https and resolve to a public IP — private,
	// loopback, and link-local targets are rejected at startup (SSRF guard).
	// Set via AUDIT_SIEM_WEBHOOK_URL.
	AuditSIEMWebhookURL string

	// AuditSIEMWebhookSecret, when set, signs every outbound SIEM payload with
	// HMAC-SHA256 in the X-EMC-Audit-Signature header so the receiver can
	// authenticate the stream. Empty leaves payloads unsigned. Set via
	// AUDIT_SIEM_WEBHOOK_SECRET.
	AuditSIEMWebhookSecret string
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
		SMTPTLS:                                getEnv("SMTP_TLS", ""),
		AppBaseURL:                             getEnv("APP_BASE_URL", "http://localhost:9090"),
		TOTPEncryptionKey:                      getEnv("TOTP_ENCRYPTION_KEY", ""),
		OAuthClientSecretEncryptionKey:         getEnv("OAUTH_CLIENT_SECRET_ENCRYPTION_KEY", ""),
		OAuthClientSecretEncryptionKeyPrevious: getEnv("OAUTH_CLIENT_SECRET_ENCRYPTION_KEY_PREVIOUS", ""),
		CookieDomain:                           getEnv("COOKIE_DOMAIN", ""),
		GlobalCORSOrigins:                      getEnvList("GLOBAL_CORS_ORIGINS", ""),
		GeoIPDatabasePath:                      getEnv("GEOIP_DATABASE_PATH", ""),
		UntrustedIPCIDRs:                       getEnvList("UNTRUSTED_IP_CIDRS", ""),
		AuditCaptureResponseBody:               getEnv("AUDIT_CAPTURE_RESPONSE_BODY", "failures"),
		AuditRetentionDays:                     mustAtoi(getEnv("AUDIT_RETENTION_DAYS", "0")),
		AuditSIEMWebhookURL:                    getEnv("AUDIT_SIEM_WEBHOOK_URL", ""),
		AuditSIEMWebhookSecret:                 getEnv("AUDIT_SIEM_WEBHOOK_SECRET", ""),
	}
}

// mustAtoi parses an integer env value, returning 0 on any parse error so a
// malformed value disables the feature rather than crashing startup.
func mustAtoi(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
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
