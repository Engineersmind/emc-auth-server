package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
)

const (
	// TenantCORSCacheTTL is how long allowed origins are cached per tenant slug.
	// Admin updates take effect within this window.
	TenantCORSCacheTTL = 60 * time.Second

	// tenantSlugHeader matches what tenantSlugFromCtx in handlers reads.
	tenantSlugHeader = "X-Tenant-Slug"
)

// TenantCORSService loads per-tenant CORS allowed origins from DB (Redis-cached).
type TenantCORSService struct {
	pool     *pgxpool.Pool
	redisCli *redis.Client
	logger   zerolog.Logger
}

// NewTenantCORSService creates a TenantCORSService.
func NewTenantCORSService(pool *pgxpool.Pool, redisCli *redis.Client, logger zerolog.Logger) *TenantCORSService {
	return &TenantCORSService{pool: pool, redisCli: redisCli, logger: logger}
}

// GetOrigins returns the allowed CORS origins for a tenant slug.
// Returns nil (no CORS restriction applied) if the slug is empty or not found.
func (s *TenantCORSService) GetOrigins(ctx context.Context, tenantSlug string) []string {
	if tenantSlug == "" {
		return nil
	}

	cacheKey := "cors:tenant:" + tenantSlug
	if data, err := s.redisCli.Get(ctx, cacheKey).Bytes(); err == nil {
		var origins []string
		if json.Unmarshal(data, &origins) == nil {
			return origins
		}
	}

	// Cache miss — query DB.
	var origins []string
	err := s.pool.QueryRow(ctx, `
		SELECT cors_origins FROM tenants WHERE slug = $1 AND is_active = true
	`, tenantSlug).Scan(&origins)
	if err != nil {
		// Not found or DB error — no CORS.
		return nil
	}

	// Populate cache.
	if payload, err := json.Marshal(origins); err == nil {
		s.redisCli.Set(ctx, cacheKey, payload, TenantCORSCacheTTL) //nolint:errcheck
	}
	return origins
}

// InvalidateCache removes the cached origins for a tenant slug.
func (s *TenantCORSService) InvalidateCache(ctx context.Context, tenantSlug string) {
	if err := s.redisCli.Del(ctx, "cors:tenant:"+tenantSlug).Err(); err != nil {
		s.logger.Warn().Err(err).Str("slug", tenantSlug).Msg("failed to invalidate CORS cache")
	}
}

// TenantCORS returns middleware that applies per-tenant CORS headers.
//
// CORS origins are loaded from the tenant's cors_origins DB column (Redis-cached).
// The tenant is identified by the X-Tenant-Slug request header.
//
// Behaviour:
//   - No X-Tenant-Slug or empty cors_origins → no CORS headers set (pass through).
//   - Valid Origin present in tenant's list → standard CORS headers applied.
//   - Preflight (OPTIONS) → 204 with CORS headers; request chain stops.
//   - Unknown origin → 403 Forbidden (with CORS violation body).
func TenantCORS(svc *TenantCORSService) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			slug := c.Request().Header.Get(tenantSlugHeader)
			origins := svc.GetOrigins(c.Request().Context(), slug)

			// No configured origins — skip CORS handling entirely.
			if len(origins) == 0 {
				return next(c)
			}

			requestOrigin := c.Request().Header.Get("Origin")
			if requestOrigin == "" {
				// Non-browser request — proceed without CORS headers.
				return next(c)
			}

			// Check whether the request origin is in the allowed list.
			allowed := false
			for _, o := range origins {
				if o == requestOrigin {
					allowed = true
					break
				}
			}

			if !allowed {
				return c.JSON(http.StatusForbidden, map[string]string{
					"error": "origin not allowed",
				})
			}

			// Apply CORS response headers.
			h := c.Response().Header()
			h.Set("Access-Control-Allow-Origin", requestOrigin)
			h.Set("Access-Control-Allow-Credentials", "true")
			h.Set("Vary", "Origin")

			// Handle preflight.
			if c.Request().Method == http.MethodOptions {
				reqMethod := c.Request().Header.Get("Access-Control-Request-Method")
				reqHeaders := c.Request().Header.Get("Access-Control-Request-Headers")
				if reqMethod != "" {
					h.Set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
				}
				if reqHeaders != "" {
					h.Set("Access-Control-Allow-Headers", reqHeaders)
				}
				h.Set("Access-Control-Max-Age", "86400")
				return c.NoContent(http.StatusNoContent)
			}

			return next(c)
		}
	}
}
