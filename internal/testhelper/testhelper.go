// Package testhelper provides shared test infrastructure for integration tests.
// All helpers use real PostgreSQL and Redis connections — no mocks.
// Tests skip gracefully when DATABASE_URL or REDIS_URL are not set.
package testhelper

import (
	"context"
	"io"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"

	"github.com/engineersmind/emc-auth-server/internal/store"
	"github.com/engineersmind/emc-auth-server/migrations"
)

// NewTestDB creates a pgxpool.Pool connected to DATABASE_URL.
// Skips the test if DATABASE_URL is not set.
// Runs migrations automatically and registers pool.Close in t.Cleanup.
func NewTestDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set — skipping DB integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logger := TestLogger()
	pool, err := store.NewDB(ctx, dsn, logger)
	if err != nil {
		t.Fatalf("testhelper.NewTestDB: connect failed: %v", err)
	}
	t.Cleanup(pool.Close)

	MustMigrate(t, pool)
	return pool
}

// NewTestRedis creates a redis.Client connected to REDIS_URL.
// Skips the test if REDIS_URL is not set.
// Registers rdb.Close in t.Cleanup.
func NewTestRedis(t *testing.T) *redis.Client {
	t.Helper()
	redisURL := os.Getenv("REDIS_URL")
	if redisURL == "" {
		t.Skip("REDIS_URL not set — skipping Redis integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	logger := TestLogger()
	rdb, err := store.NewRedis(ctx, redisURL, logger)
	if err != nil {
		t.Fatalf("testhelper.NewTestRedis: connect failed: %v", err)
	}
	t.Cleanup(func() {
		_ = rdb.Close()
	})
	return rdb
}

// MustMigrate runs all goose migrations against the pool.
// Safe to call multiple times — goose is idempotent.
// Calls t.Fatal on error.
func MustMigrate(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	logger := TestLogger()
	if err := store.RunMigrations(ctx, pool, migrations.FS, logger); err != nil {
		t.Fatalf("testhelper.MustMigrate: %v", err)
	}
}

// CleanupTables registers a t.Cleanup callback that TRUNCATEs all test-owned
// tables in cascade order. Safe to call from any test to reset state between runs.
func CleanupTables(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		// Truncate in dependency order with CASCADE to satisfy FK constraints.
		_, err := pool.Exec(ctx, `
			TRUNCATE TABLE
				audit_logs,
				agent_registrations,
				app_rate_limits,
				totp_secrets,
				api_keys,
				password_reset_tokens,
				refresh_tokens,
				user_credentials,
				user_permissions,
				role_permissions,
				users,
				roles,
				permissions,
				tenants
			CASCADE
		`)
		if err != nil {
			t.Logf("testhelper.CleanupTables: truncate warning: %v", err)
		}
	})
}

// TestLogger returns a zerolog.Logger that discards all output.
// Use this in tests to avoid noisy log output.
func TestLogger() zerolog.Logger {
	return zerolog.New(io.Discard)
}
