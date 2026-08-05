package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
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

	// globalOrigins are the allowed origins for slug-less requests (e.g.
	// /auth/login), which have no tenant to look up a per-tenant list by.
	// Set via WithGlobalOrigins.
	globalOrigins []string
}

// NewTenantCORSService creates a TenantCORSService.
func NewTenantCORSService(pool *pgxpool.Pool, redisCli *redis.Client, logger zerolog.Logger) *TenantCORSService {
	return &TenantCORSService{pool: pool, redisCli: redisCli, logger: logger}
}

// WithGlobalOrigins sets the allowed origins used for requests that carry no
// X-Tenant-Slug header (the tenant isn't known yet, so no per-tenant list applies).
// An empty list is valid but means every slug-less endpoint (e.g. /auth/login)
// will send no CORS headers at all — browser-based cross-origin calls to those
// endpoints will be blocked client-side even though server-to-server calls are
// unaffected. Logged loudly here so that isn't a silent deployment surprise.
func (s *TenantCORSService) WithGlobalOrigins(origins []string) *TenantCORSService {
	s.globalOrigins = origins
	if len(origins) == 0 {
		s.logger.Warn().Msg("GLOBAL_CORS_ORIGINS is empty — slug-less endpoints (e.g. /auth/login) will send no CORS headers, so browser-based cross-origin calls to them will be blocked")
	}
	return s
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

// headerListContains reports whether name (case-insensitive) appears in a
// comma-separated header list, e.g. the value of Access-Control-Request-Headers.
func headerListContains(list, name string) bool {
	for _, h := range strings.Split(list, ",") {
		if strings.EqualFold(strings.TrimSpace(h), name) {
			return true
		}
	}
	return false
}

// wellKnownSuffix is the path suffix of the published JWKS document.
const wellKnownSuffix = "/.well-known/jwks.json"

// isPublicCORSExempt reports whether a path serves public, credential-free
// material that any origin may read, and so must bypass origin enforcement.
//
// Matched on suffix rather than a prefix or exact string because the JWKS path is
// tenant-scoped (/tenants/{slug}/.well-known/jwks.json) and the slug is arbitrary.
// Deliberately narrow: only this exact document, so the exemption cannot be
// widened by a crafted path such as /.well-known/jwks.json/../../admin.
func isPublicCORSExempt(path string) bool {
	return strings.HasSuffix(path, wellKnownSuffix)
}

// TenantCORS returns middleware that applies per-tenant CORS headers.
//
// CORS origins are loaded from the tenant's cors_origins DB column (Redis-cached).
// The tenant is identified by the X-Tenant-Slug request header, when present.
//
// Behaviour:
//   - X-Tenant-Slug present → that tenant's configured cors_origins apply.
//   - X-Tenant-Slug absent (e.g. /auth/login, which resolves its tenant
//     internally from email/password and never sends this header) → the
//     service's global allow-list applies instead (see WithGlobalOrigins).
//   - Preflight (OPTIONS) that announces X-Tenant-Slug via
//     Access-Control-Request-Headers → browsers never send a custom header's
//     *value* during preflight, only its name, so slug is unavoidably empty
//     here even for a tenant-scoped call. Reflect the origin permissively for
//     this preflight response only; the real request (which does carry the
//     header) still gets strict per-tenant origin enforcement below.
//   - No origins resolved either way → no CORS headers set (pass through).
//   - Valid Origin present in the resolved list → standard CORS headers applied.
//   - Preflight (OPTIONS) → 204 with CORS headers; request chain stops.
//   - Unknown origin → 403 Forbidden (with CORS violation body).
func TenantCORS(svc *TenantCORSService) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			req := c.Request()

			// Publicly-fetchable endpoints are exempt (issue #95). This
			// middleware is mounted via e.Use, so it applies to every route: with
			// a non-empty GLOBAL_CORS_ORIGINS, a browser sending an Origin that is
			// not on that list gets a hard 403 "origin not allowed" below. For
			// /.well-known/jwks.json — whose entire purpose is to be fetched by
			// arbitrary relying parties we have never heard of — that is exactly
			// wrong: it would make browser-side token verification impossible for
			// every tenant not manually added to a server-wide env var.
			//
			// Safe because these responses carry no credentials and no
			// tenant-specific data beyond public key material. The handler sets
			// Access-Control-Allow-Origin: * itself.
			//
			// Server-to-server fetches send no Origin and already passed cleanly;
			// this exemption is specifically about browsers.
			if isPublicCORSExempt(req.URL.Path) {
				return next(c)
			}

			isPreflight := req.Method == http.MethodOptions
			slug := req.Header.Get(tenantSlugHeader)
			requestOrigin := req.Header.Get("Origin")

			announcesTenantSlug := isPreflight &&
				headerListContains(req.Header.Get("Access-Control-Request-Headers"), tenantSlugHeader)

			if slug == "" && announcesTenantSlug {
				if requestOrigin == "" {
					return next(c)
				}
				h := c.Response().Header()
				h.Set("Access-Control-Allow-Origin", requestOrigin)
				h.Set("Access-Control-Allow-Credentials", "true")
				h.Set("Vary", "Origin")
				h.Set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
				if reqHeaders := req.Header.Get("Access-Control-Request-Headers"); reqHeaders != "" {
					h.Set("Access-Control-Allow-Headers", reqHeaders)
				}
				h.Set("Access-Control-Max-Age", "86400")
				return c.NoContent(http.StatusNoContent)
			}

			var origins []string
			if slug == "" {
				origins = svc.globalOrigins
			} else {
				origins = svc.GetOrigins(req.Context(), slug)
			}

			// No configured origins — skip CORS handling entirely.
			if len(origins) == 0 {
				return next(c)
			}

			if requestOrigin == "" {
				// Non-browser request — proceed without CORS headers.
				return next(c)
			}

			// Check whether the request origin is in the allowed list.
			// A "*" entry means all origins are permitted (wildcard mode).
			wildcard := false
			allowed := false
			for _, o := range origins {
				if o == "*" {
					wildcard = true
					allowed = true
					break
				}
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
			if wildcard {
				// Wildcard mode: browsers do not allow credentials with "*".
				h.Set("Access-Control-Allow-Origin", "*")
			} else {
				h.Set("Access-Control-Allow-Origin", requestOrigin)
				h.Set("Access-Control-Allow-Credentials", "true")
				h.Set("Vary", "Origin")
			}

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
