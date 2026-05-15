package store

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
)

// NewRedis creates a go-redis client configured for the auth server workload.
// Retries up to 10 times with 1-second delay for container startup.
func NewRedis(ctx context.Context, redisURL string, logger zerolog.Logger) (*redis.Client, error) {
	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("parse redis URL: %w", err)
	}

	opt.PoolSize = 10
	opt.MinIdleConns = 3
	opt.DialTimeout = 5 * time.Second
	opt.ReadTimeout = 3 * time.Second
	opt.WriteTimeout = 3 * time.Second
	opt.MaxRetries = 3

	rdb := redis.NewClient(opt)

	// Retry loop for container startup race condition
	for attempt := 1; attempt <= 10; attempt++ {
		if pingErr := rdb.Ping(ctx).Err(); pingErr != nil {
			logger.Warn().Int("attempt", attempt).Err(pingErr).Msg("redis ping failed, retrying")
			time.Sleep(1 * time.Second)
			continue
		}

		logger.Info().
			Int("pool_size", opt.PoolSize).
			Msg("redis connected")
		return rdb, nil
	}

	return nil, fmt.Errorf("redis connection failed after 10 attempts")
}

// CloseRedis closes the go-redis client.
func CloseRedis(rdb *redis.Client) {
	if rdb != nil {
		_ = rdb.Close()
	}
}
