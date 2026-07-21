package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
)

// ErrAppLimitNotFound is returned by GetAppLimit when the application has no
// custom rate limit configured (it runs at the server default).
var ErrAppLimitNotFound = errors.New("no rate limit configured for application")

const (
	DefaultRequestsPerMinute = 60
	DefaultBurst             = 10
	AppLimitCacheTTL         = 60 * time.Second
)

// AppRateLimit holds the rate limit config for a single application.
// ApplicationID is the numeric oauth_clients.id — the same identifier carried
// by the JWT `app_id` claim and the /tenants/:tid/applications/:appID routes.
type AppRateLimit struct {
	ApplicationID     int64     `json:"application_id"`
	TenantID          int64     `json:"tenant_id"`
	RequestsPerMinute int       `json:"requests_per_minute"`
	Burst             int       `json:"burst"`
	Description       string    `json:"description"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// AppRateLimitService manages per-application rate limit configurations.
type AppRateLimitService struct {
	pool     *pgxpool.Pool
	redisCli *redis.Client
	logger   zerolog.Logger
}

// NewAppRateLimitService creates an AppRateLimitService.
func NewAppRateLimitService(pool *pgxpool.Pool, redisCli *redis.Client, logger zerolog.Logger) *AppRateLimitService {
	return &AppRateLimitService{pool: pool, redisCli: redisCli, logger: logger}
}

// SetAppLimit upserts the single rate limit config for one application within a
// tenant. applicationID is the numeric oauth_clients.id. Creating and updating
// share this path because there is at most one live limit per (tenant, app).
func (s *AppRateLimitService) SetAppLimit(ctx context.Context, tenantID, applicationID int64, rpm, burst int, description string) (*AppRateLimit, error) {
	if applicationID <= 0 {
		return nil, fmt.Errorf("application_id is required")
	}
	if rpm <= 0 {
		rpm = DefaultRequestsPerMinute
	}
	// An unspecified burst follows the rate rather than jumping to the global
	// default — a caller who sets "2 requests/minute" and no burst expects a
	// hard cap near 2, not a 10-request head start.
	if burst <= 0 {
		burst = rpm
	}

	var limit AppRateLimit
	err := s.pool.QueryRow(ctx, `
		INSERT INTO app_rate_limits (application_id, tenant_id, requests_per_minute, burst, description)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (tenant_id, application_id) WHERE deleted_at IS NULL
		DO UPDATE SET requests_per_minute = EXCLUDED.requests_per_minute,
		              burst = EXCLUDED.burst,
		              description = EXCLUDED.description,
		              updated_at = NOW()
		RETURNING application_id, tenant_id, requests_per_minute, burst, description, created_at, updated_at
	`, applicationID, tenantID, rpm, burst, description).Scan(
		&limit.ApplicationID, &limit.TenantID, &limit.RequestsPerMinute,
		&limit.Burst, &limit.Description, &limit.CreatedAt, &limit.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("set app_rate_limit: %w", err)
	}

	s.invalidateCache(ctx, tenantID, applicationID)
	return &limit, nil
}

// GetAppLimit returns the configured limit for one application, or pgx.ErrNoRows
// when none is set (the app then runs at the server default).
func (s *AppRateLimitService) GetAppLimit(ctx context.Context, tenantID, applicationID int64) (*AppRateLimit, error) {
	var limit AppRateLimit
	err := s.pool.QueryRow(ctx, `
		SELECT application_id, tenant_id, requests_per_minute, burst, description, created_at, updated_at
		FROM app_rate_limits
		WHERE application_id = $1 AND tenant_id = $2 AND deleted_at IS NULL
	`, applicationID, tenantID).Scan(
		&limit.ApplicationID, &limit.TenantID, &limit.RequestsPerMinute,
		&limit.Burst, &limit.Description, &limit.CreatedAt, &limit.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrAppLimitNotFound
		}
		return nil, fmt.Errorf("get app_rate_limit: %w", err)
	}
	return &limit, nil
}

// ListAppLimits returns all rate limit configs for a tenant.
func (s *AppRateLimitService) ListAppLimits(ctx context.Context, tenantID int64) ([]AppRateLimit, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT application_id, tenant_id, requests_per_minute, burst, description, created_at, updated_at
		FROM app_rate_limits
		WHERE tenant_id = $1 AND deleted_at IS NULL
		ORDER BY application_id
	`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list app_rate_limits: %w", err)
	}
	defer rows.Close()

	var limits []AppRateLimit
	for rows.Next() {
		var l AppRateLimit
		if err := rows.Scan(&l.ApplicationID, &l.TenantID, &l.RequestsPerMinute, &l.Burst,
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

// DeleteAppLimit removes a rate limit config; the app falls back to the default.
func (s *AppRateLimitService) DeleteAppLimit(ctx context.Context, tenantID, applicationID int64) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE app_rate_limits SET deleted_at = NOW(), updated_at = NOW()
		WHERE application_id = $1 AND tenant_id = $2 AND deleted_at IS NULL
	`, applicationID, tenantID)
	if err != nil {
		return fmt.Errorf("delete app_rate_limit: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("application %d not found for this tenant", applicationID)
	}
	s.invalidateCache(ctx, tenantID, applicationID)
	return nil
}

// GetLimit returns the rpm/burst for an application within a tenant, using a
// 60s Redis cache. Falls back to DefaultRequestsPerMinute/DefaultBurst when no
// custom config exists or on cache/DB error (fail-open).
func (s *AppRateLimitService) GetLimit(ctx context.Context, tenantID, applicationID int64) (rpm, burst int) {
	if applicationID <= 0 {
		return DefaultRequestsPerMinute, DefaultBurst
	}

	cacheKey := appLimitCacheKey(tenantID, applicationID)
	if data, err := s.redisCli.Get(ctx, cacheKey).Bytes(); err == nil {
		var cached struct {
			RPM   int `json:"rpm"`
			Burst int `json:"burst"`
		}
		if json.Unmarshal(data, &cached) == nil && cached.RPM > 0 {
			return cached.RPM, cached.Burst
		}
	}

	var dbRPM, dbBurst int
	dbErr := s.pool.QueryRow(ctx, `
		SELECT requests_per_minute, burst FROM app_rate_limits
		WHERE application_id = $1 AND tenant_id = $2 AND deleted_at IS NULL
	`, applicationID, tenantID).Scan(&dbRPM, &dbBurst)

	if dbErr != nil || dbRPM <= 0 {
		dbRPM = DefaultRequestsPerMinute
		dbBurst = DefaultBurst
	}

	payload, _ := json.Marshal(map[string]int{"rpm": dbRPM, "burst": dbBurst})
	s.redisCli.Set(ctx, cacheKey, payload, AppLimitCacheTTL) //nolint:errcheck

	return dbRPM, dbBurst
}

// GetLimitForClientID resolves a public client_id to its owning application and
// returns that application's tenant id, numeric id, and effective limit. It is
// the pre-auth counterpart of GetLimit for the Basic-auth endpoints (token /
// apps login), where the caller is identified by client_id rather than a JWT.
//
// ok is false when the client_id does not map to a live application — the
// caller should then skip per-app limiting (only the per-IP limiter applies).
// The client_id→(tenant, app) mapping is cached (60s TTL); the rpm/burst come
// from GetLimit, which owns its own cache + invalidation, so a limit change
// takes effect without a separate client-keyed invalidation.
func (s *AppRateLimitService) GetLimitForClientID(ctx context.Context, clientID string) (tenantID, applicationID int64, rpm, burst int, ok bool) {
	if clientID == "" {
		return 0, 0, 0, 0, false
	}

	mapKey := "rate:applimit:cmap:" + clientID
	if data, err := s.redisCli.Get(ctx, mapKey).Bytes(); err == nil {
		var cached struct {
			TenantID int64 `json:"t"`
			AppID    int64 `json:"a"`
		}
		if json.Unmarshal(data, &cached) == nil && cached.AppID > 0 {
			rpm, burst = s.GetLimit(ctx, cached.TenantID, cached.AppID)
			return cached.TenantID, cached.AppID, rpm, burst, true
		}
	}

	err := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id FROM oauth_clients
		WHERE client_id = $1 AND deleted_at IS NULL
	`, clientID).Scan(&applicationID, &tenantID)
	if err != nil {
		// Unknown/deleted client — nothing to key a per-app limit on.
		return 0, 0, 0, 0, false
	}

	payload, _ := json.Marshal(map[string]int64{"t": tenantID, "a": applicationID})
	s.redisCli.Set(ctx, mapKey, payload, AppLimitCacheTTL) //nolint:errcheck

	rpm, burst = s.GetLimit(ctx, tenantID, applicationID)
	return tenantID, applicationID, rpm, burst, true
}

// invalidateCache deletes the single deterministic cache key for this
// (tenant, application). Because the key is fully derived from the pair, an
// update/delete reliably clears it — no stale-key window.
func (s *AppRateLimitService) invalidateCache(ctx context.Context, tenantID, applicationID int64) {
	if err := s.redisCli.Del(ctx, appLimitCacheKey(tenantID, applicationID)).Err(); err != nil {
		s.logger.Warn().Err(err).
			Int64("tenant_id", tenantID).Int64("application_id", applicationID).
			Msg("failed to invalidate app rate limit cache")
	}
}

func appLimitCacheKey(tenantID, applicationID int64) string {
	return "rate:applimit:" + strconv.FormatInt(tenantID, 10) + ":" + strconv.FormatInt(applicationID, 10)
}
