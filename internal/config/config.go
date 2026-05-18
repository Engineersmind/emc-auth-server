package config

import (
	"os"
	"strconv"
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
}

// Load reads configuration from environment variables with sensible defaults.
func Load() *Config {
	smtpPort, _ := strconv.Atoi(getEnv("SMTP_PORT", "587"))
	return &Config{
		Port:         getEnv("PORT", "8080"),
		DatabaseURL:  getEnv("DATABASE_URL", "postgres://emc_auth:password@localhost:5432/emc_auth?sslmode=disable"),
		RedisURL:     getEnv("REDIS_URL", "redis://localhost:6379/0"),
		LogLevel:     getEnv("LOG_LEVEL", "info"),
		Env:          getEnv("ENV", "development"),
		JWTIssuer:    getEnv("JWT_ISSUER", "https://auth.emc.local"),
		SMTPHost:     getEnv("SMTP_HOST", ""),
		SMTPPort:     smtpPort,
		SMTPFrom:     getEnv("SMTP_FROM", "no-reply@emc.local"),
		SMTPUsername: getEnv("SMTP_USERNAME", ""),
		SMTPPassword: getEnv("SMTP_PASSWORD", ""),
		AppBaseURL:        getEnv("APP_BASE_URL", "http://localhost:8080"),
		TOTPEncryptionKey: getEnv("TOTP_ENCRYPTION_KEY", ""),
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
