package config

import "os"

// Config holds all application configuration loaded from environment variables.
type Config struct {
	Port        string
	DatabaseURL string
	RedisURL    string
	LogLevel    string
	Env         string
	JWTIssuer   string
}

// Load reads configuration from environment variables with sensible defaults.
func Load() *Config {
	return &Config{
		Port:        getEnv("PORT", "8080"),
		DatabaseURL: getEnv("DATABASE_URL", "postgres://emc_auth:password@localhost:5432/emc_auth?sslmode=disable"),
		RedisURL:    getEnv("REDIS_URL", "redis://localhost:6379/0"),
		LogLevel:    getEnv("LOG_LEVEL", "info"),
		Env:         getEnv("ENV", "development"),
		JWTIssuer:   getEnv("JWT_ISSUER", "https://auth.emc.local"),
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
