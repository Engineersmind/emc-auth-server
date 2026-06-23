package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
)

const (
	// DefaultRequestsPerMinute is applied when no app-specific limit exists.
	DefaultRequestsPerMinute = 60
	// DefaultBurst allows short spikes above the per-minute limit.
	DefaultBurst = 10
	// AppLimitCacheTTL is how long the per-app limit is cached in Redis.
	// Admin changes take effect within this window without a server restart.
	AppLimitCacheTTL = 60 * time.Second
)

// AppRateLimit holds the rate limit config for a single app_id.
type AppRateLimit struct {
	AppID              string    `json:"app_id"`
	TenantID           string    `json:"tenant_id"`
	RequestsPerMinute  int       `json:"requests_per_minute"`
	Burst              int       `json:"burst"`
	Description        string    `json:"description"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

// AppRateLimitService manages per-application rate limit configurations.
type AppRateLimitService struct {
	pool      *pgxpool.Pool
	redisCli  *redis.Client
	logger    zerolog.Logger
}

// NewAppRateLimitService creates an AppRateLimitService.
func NewAppRateLimitService(pool *pgxpool.Pool, redisCli *redis.Client, logger zerolog.Logger) *AppRateLimitService {
	return &AppRateLimitService{pool: pool, redisCli: redisCli, logger: logger}
}

// CreateAppLimit creates a new per-app rate limit config.
func (s *AppRateLimitService) CreateAppLimit(ctx context.Context, tenantID uuid.UUID, appID string, rpm, burst int, description string) (*AppRateLimit, error) {
	if appID == "" {
		return nil, fmt.Errorf("app_id is required")
	}
	if rpm <= 0 {
		rpm = DefaultRequestsPerMinute
	}
	if burst <= 0 {
		burst = DefaultBurst
	}

	var limit AppRateLimit
	err := s.pool.QueryRow(ctx, `
		INSERT INTO app_rate_limits (app_id, tenant_id, requests_per_minute, burst, description)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING app_id, tenant_id, requests_per_minute, burst, description, created_at, updated_at
	`, appID, tenantID, rpm, burst, description).Scan(
		&limit.AppID, &limit.TenantID, &limit.RequestsPerMinute,
		&limit.Burst, &limit.Description, &limit.CreatedAt, &limit.UpdatedAt,
	)
	if err != nil {
		if containsErrMsg(err, "unique") || containsErrMsg(err, "duplicate") {
			return nil, fmt.Errorf("app_id %q already has a rate limit config", appID)
		}
		return nil, fmt.Errorf("create app_rate_limit: %w", err)
	}

	s.invalidateCache(ctx, appID)
	return &limit, nil
}

// ListAppLimits returns all rate limit configs for a tenant.
func (s *AppRateLimitService) ListAppLimits(ctx context.Context, tenantID uuid.UUID) ([]AppRateLimit, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT app_id, tenant_id, requests_per_minute, burst, description, created_at, updated_at
		FROM app_rate_limits
		WHERE tenant_id = $1 AND deleted_at IS NULL
		ORDER BY app_id
	`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list app_rate_limits: %w", err)
	}
	defer rows.Close()

	var limits []AppRateLimit
	for rows.Next() {
		var l AppRateLimit
		if err := rows.Scan(&l.AppID, &l.TenantID, &l.RequestsPerMinute, &l.Burst,
			&l.Description, &l.CreatedAt, &l.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan app_rate_limit: %w", err)
		}
		limits = append(limits, l)
	}
	if limits == nil {
		limits = []AppRateLimit{}
	}
	return limits, rows.Err()
}

// UpdateAppLimit changes the rate limit for an existing app_id (tenant-scoped).
func (s *AppRateLimitService) UpdateAppLimit(ctx context.Context, tenantID uuid.UUID, appID string, rpm, burst int, description string) (*AppRateLimit, error) {
	if rpm <= 0 {
		rpm = DefaultRequestsPerMinute
	}
	if burst <= 0 {
		burst = DefaultBurst
	}

	var limit AppRateLimit
	err := s.pool.QueryRow(ctx, `
		UPDATE app_rate_limits
		SET requests_per_minute = $3, burst = $4, description = $5, updated_at = NOW()
		WHERE app_id = $1 AND tenant_id = $2 AND deleted_at IS NULL
		RETURNING app_id, tenant_id, requests_per_minute, burst, description, created_at, updated_at
	`, appID, tenantID, rpm, burst, description).Scan(
		&limit.AppID, &limit.TenantID, &limit.RequestsPerMinute,
		&limit.Burst, &limit.Description, &limit.CreatedAt, &limit.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("app_id %q not found for this tenant", appID)
		}
		return nil, fmt.Errorf("update app_rate_limit: %w", err)
	}

	s.invalidateCache(ctx, appID)
	return &limit, nil
}

// DeleteAppLimit removes a rate limit config. The app falls back to the default limit.
func (s *AppRateLimitService) DeleteAppLimit(ctx context.Context, tenantID uuid.UUID, appID string) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE app_rate_limits SET deleted_at = NOW(), updated_at = NOW()
		WHERE app_id = $1 AND tenant_id = $2 AND deleted_at IS NULL
	`, appID, tenantID)
	if err != nil {
		return fmt.Errorf("delete app_rate_limit: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("app_id %q not found for this tenant", appID)
	}
	s.invalidateCache(ctx, appID)
	return nil
}

// GetLimit returns the rate limit for an app_id. Uses Redis cache (60s TTL).
// Falls back to default if no config exists. Safe to call on every request.
func (s *AppRateLimitService) GetLimit(ctx context.Context, appID string) (rpm, burst int) {
	if appID == "" {
		return DefaultRequestsPerMinute, DefaultBurst
	}

	// Try cache first.
	cacheKey := appLimitCacheKey(appID)
	data, err := s.redisCli.Get(ctx, cacheKey).Bytes()
	if err == nil {
		var cached struct {
			RPM   int `json:"rpm"`
			Burst int `json:"burst"`
		}
		if json.Unmarshal(data, &cached) == nil && cached.RPM > 0 {
			return cached.RPM, cached.Burst
		}
	}

	// Cache miss — query DB.
	var dbRPM, dbBurst int
	dbErr := s.pool.QueryRow(ctx, `
		SELECT requests_per_minute, burst FROM app_rate_limits
		WHERE app_id = $1 AND deleted_at IS NULL
	`, appID).Scan(&dbRPM, &dbBurst)

	if dbErr != nil || dbRPM <= 0 {
		dbRPM = DefaultRequestsPerMinute
		dbBurst = DefaultBurst
	}

	// Write to cache.
	payload, _ := json.Marshal(map[string]int{"rpm": dbRPM, "burst": dbBurst})
	s.redisCli.Set(ctx, cacheKey, payload, AppLimitCacheTTL) //nolint:errcheck

	return dbRPM, dbBurst
}

func (s *AppRateLimitService) invalidateCache(ctx context.Context, appID string) {
	if err := s.redisCli.Del(ctx, appLimitCacheKey(appID)).Err(); err != nil {
		s.logger.Warn().Err(err).Str("app_id", appID).Msg("failed to invalidate app rate limit cache")
	}
}

func appLimitCacheKey(appID string) string {
	return "rate:app:" + appID
}

func containsErrMsg(err error, sub string) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
