package middleware

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"

	"github.com/engineersmind/emc-auth-server/internal/api/paths"
)

const (
	// TenantCORSCacheTTL is how long a per-origin CORS decision is cached.
	// Admin updates take effect within this window, and the admin write path
	// clears the affected entries so the usual case is immediate.
	TenantCORSCacheTTL = 60 * time.Second
)

// TenantCORSService answers whether a browser origin is permitted, from the
// tenants table (Redis-cached).
type TenantCORSService struct {
	pool     *pgxpool.Pool
	redisCli *redis.Client
	logger   zerolog.Logger

	// globalOrigins are deployment-wide allowed origins, consulted before any
	// database lookup. Set via WithGlobalOrigins.
	globalOrigins []string
}

// NewTenantCORSService creates a TenantCORSService.
// corsAllowedMethods is the method list echoed on every preflight.
//
// One constant rather than two literals because it WAS two literals, and they
// were both missing PATCH — so the API's first PATCH route (passkey rename,
// issue #112) preflighted successfully and then the browser refused to send the
// request, which looks exactly like a broken handler and is not.
//
// Any method used by a route in routes.go must appear here. A missing one fails
// only in a browser, only cross-origin, and never in curl or the Go tests.
const corsAllowedMethods = "GET,POST,PUT,PATCH,DELETE,OPTIONS"

func NewTenantCORSService(pool *pgxpool.Pool, redisCli *redis.Client, logger zerolog.Logger) *TenantCORSService {
	return &TenantCORSService{pool: pool, redisCli: redisCli, logger: logger}
}

// WithGlobalOrigins sets the deployment-wide allowed origins, consulted before
// any per-tenant list.
// An empty list is valid: an origin can still be permitted by a tenant's own
// cors_origins. It is logged because a deployment with neither configured sends
// no CORS headers at all, blocking every browser-based cross-origin call while
// server-to-server calls keep working — a confusing failure to debug.
func (s *TenantCORSService) WithGlobalOrigins(origins []string) *TenantCORSService {
	s.globalOrigins = origins
	if len(origins) == 0 {
		s.logger.Warn().Msg("GLOBAL_CORS_ORIGINS is empty — only origins listed in a tenant's cors_origins will be allowed")
	}
	return s
}

// IsOriginAllowed reports whether any active tenant permits this browser origin.
//
// This is the question CORS actually asks, and it needs no tenant identifier
// from the caller. The middleware previously read X-Tenant-Slug to pick a
// tenant's origin list, which put a machine-facing identifier — the tenant's
// OIDC issuer path — into the contract of every browser request. Worse, a
// preflight OPTIONS carries no body and no credentials, so the header was the
// only thing a browser could send, and any client that forgot it silently fell
// back to the global list.
//
// Resolving from the Origin removes that entirely: the browser already sends the
// one value the decision depends on.
//
// The check deliberately does not identify WHICH tenant matched. CORS decides
// only whether a browser origin may talk to this server at all; which tenant the
// caller belongs to is settled later by the token or client credentials, and is
// enforced by every handler independently. Two tenants sharing a staging domain
// is therefore not a conflict — both permit the origin, and neither gains access
// to the other's data by saying so.
//
// Per-application origins are the planned direction: those will be scoped to a
// client_id rather than a tenant, and will resolve the same way — ask whether
// the origin is permitted, not who is asking. The signature is shaped for that,
// taking the origin alone.
func (s *TenantCORSService) IsOriginAllowed(ctx context.Context, origin string) bool {
	if origin == "" {
		return false
	}

	cacheKey := "cors:origin:" + origin
	if v, err := s.redisCli.Get(ctx, cacheKey).Result(); err == nil {
		return v == "1"
	}

	// cors_origins is a text[]; @> is the containment operator, which a GIN
	// index on that column can answer directly.
	var allowed bool
	err := s.pool.QueryRow(ctx, `
		SELECT EXISTS (
		    SELECT 1 FROM tenants
		    WHERE is_active = true AND deleted_at IS NULL
		      AND cors_origins @> ARRAY[$1]::text[]
		)
	`, origin).Scan(&allowed)
	if err != nil {
		// Fail closed on a database error: a CORS decision made without data is
		// not a decision, and wrongly allowing an origin is the harmful
		// direction. The global allow-list still applies at the call site, so a
		// configured deployment keeps working through a brief outage.
		s.logger.Warn().Err(err).Str("origin", origin).
			Msg("cors: origin lookup failed — treating as not tenant-allowed")
		return false
	}

	val := "0"
	if allowed {
		val = "1"
	}
	s.redisCli.Set(ctx, cacheKey, val, TenantCORSCacheTTL) //nolint:errcheck
	return allowed
}

// InvalidateOriginCache clears the cached decision for one origin. Called when a
// tenant's origin list changes.
func (s *TenantCORSService) InvalidateOriginCache(ctx context.Context, origins ...string) {
	for _, o := range origins {
		if o == "" {
			continue
		}
		if err := s.redisCli.Del(ctx, "cors:origin:"+o).Err(); err != nil {
			s.logger.Warn().Err(err).Str("origin", o).Msg("failed to invalidate CORS origin cache")
		}
	}
}

// isPublicCORSExempt reports whether a path serves public, credential-free
// material that any origin may read, and so must bypass origin enforcement.
//
// The two suffixes come from internal/api/paths, derived there from the same
// route templates the router registers and the OIDC discovery document
// publishes. They used to be spelled out here as local constants, which meant
// moving an endpoint could silently drop its CORS exemption with no compile-time
// signal — a browser-side client would then get a 403 at step one and never
// reach the jwks_uri the exemption exists for. This package cannot import
// handlers (handlers imports this one), which is why the shared package exists.
//
// Discovery is exempt for the same reason as JWKS and in the same breath: a
// browser-side client fetches discovery first and follows its jwks_uri second,
// so exempting only the second half would break the flow at step one.
//
// Matched on suffix rather than a prefix or exact string because both paths are
// tenant-scoped (/tenants/{slug}/.well-known/...) and the slug is arbitrary.
// Deliberately narrow: only these exact documents, so the exemption cannot be
// widened by a crafted path such as /.well-known/jwks.json/../../admin.
func isPublicCORSExempt(path string) bool {
	return strings.HasSuffix(path, paths.JWKSSuffix) ||
		strings.HasSuffix(path, paths.DiscoverySuffix)
}

// TenantCORS returns middleware that applies per-tenant CORS headers.
//
// The decision is made from the request's Origin, which is the only thing it
// depends on and the one value a browser always sends.
//
// This replaced a lookup keyed on the X-Tenant-Slug header. That was wrong twice
// over: it put the tenant's OIDC issuer identifier into the contract of every
// browser request, and a preflight OPTIONS carries only a header's NAME, never
// its value — so the slug was unavoidably empty on exactly the request that had
// to be answered first. An entire branch existed to reflect the origin
// permissively for such preflights, which is the shape of a workaround for a key
// that should not have been required.
//
// Behaviour:
//   - Origin permitted by the global allow-list → allowed, no database round trip.
//   - Otherwise, if any active tenant lists it in cors_origins → allowed.
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

			requestOrigin := req.Header.Get("Origin")

			// Resolved from the Origin, not from X-Tenant-Slug.
			//
			// The header used to select which tenant's origin list to consult,
			// which was wrong twice over. It put the tenant's OIDC issuer
			// identifier into the contract of every browser request; and a
			// preflight OPTIONS carries no body and no credentials, so a client
			// that did not send it silently fell back to the global list — the
			// per-tenant configuration quietly did nothing. An entire branch
			// existed here to paper over preflights that merely ANNOUNCED the
			// header without a value, which is the shape of a workaround for a
			// key that should never have been required.
			//
			// The browser already sends the one value the decision depends on.
			//
			// Global origins are still consulted first: they are deployment-wide
			// configuration and answer without a database round trip. The
			// per-tenant lookup runs only when the global list does not already
			// permit the origin.
			//
			// Planned: per-application origins scoped to a client_id will resolve
			// the same way — ask whether the origin is permitted, never who is
			// asking. Tenant identity is settled by the token or client
			// credentials afterwards, and enforced by every handler on its own.
			origins := svc.globalOrigins
			if requestOrigin != "" && !originListAllows(origins, requestOrigin) &&
				svc.IsOriginAllowed(req.Context(), requestOrigin) {
				// A tenant permits it; treat it as allowed for the rest of this
				// decision without needing to know which tenant.
				origins = append(append([]string{}, origins...), requestOrigin)
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
					h.Set("Access-Control-Allow-Methods", corsAllowedMethods)
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

// originListAllows reports whether a configured origin list already permits an
// origin, treating "*" as permitting everything.
//
// Used to skip the per-tenant lookup when the global list has already answered:
// the global list is deployment configuration held in memory, so consulting it
// first keeps the common case free of a database round trip.
func originListAllows(origins []string, origin string) bool {
	for _, o := range origins {
		if o == "*" || o == origin {
			return true
		}
	}
	return false
}
