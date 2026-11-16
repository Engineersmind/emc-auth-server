package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	"github.com/engineersmind/emc-auth-server/internal/metrics"
)

// NewDB creates a pgxpool.Pool configured for the auth server workload.
// It pings the database to verify connectivity before returning.
// Retries up to 10 times with 1-second delay to handle slow container startup.
func NewDB(ctx context.Context, databaseURL string, logger zerolog.Logger) (*pgxpool.Pool, error) {
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse database URL: %w", err)
	}

	// Auth workload: many short-lived reads (JWT validation, user lookup)
	config.MaxConns = 25
	config.MinConns = 5
	config.MaxConnLifetime = 1 * time.Hour
	config.MaxConnLifetimeJitter = 5 * time.Minute
	config.MaxConnIdleTime = 15 * time.Minute
	config.HealthCheckPeriod = 1 * time.Minute

	var pool *pgxpool.Pool

	// Retry loop for container startup race condition
	for attempt := 1; attempt <= 10; attempt++ {
		pool, err = pgxpool.NewWithConfig(ctx, config)
		if err != nil {
			logger.Warn().Int("attempt", attempt).Err(err).Msg("database connection failed, retrying")
			time.Sleep(1 * time.Second)
			continue
		}

		if pingErr := pool.Ping(ctx); pingErr != nil {
			pool.Close()
			logger.Warn().Int("attempt", attempt).Err(pingErr).Msg("database ping failed, retrying")
			time.Sleep(1 * time.Second)
			continue
		}

		// Advertise the pool to the emc_auth_db_pool_* collector only once it
		// has actually pinged — a pool that never connected is never exported.
		// The first pool claims the registration; later pools do not replace it.
		metrics.SetDBPool(pool)
		logger.Info().
			Int32("max_conns", config.MaxConns).
			Int32("min_conns", config.MinConns).
			Msg("database connected")
		return pool, nil
	}

	return nil, fmt.Errorf("database connection failed after 10 attempts: %w", err)
}

// CloseDB closes the pgxpool.Pool.
func CloseDB(pool *pgxpool.Pool) {
	if pool != nil {
		// Clear BEFORE Close: a closed pool's Stat still answers, and the
		// emc_auth_db_pool_* series would keep reporting its final snapshot
		// forever. CompareAndSwap inside ClearDBPool means this only clears
		// the registration when this pool is the one being served.
		metrics.ClearDBPool(pool)
		pool.Close()
	}
}
