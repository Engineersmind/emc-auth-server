package middleware

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"

	"github.com/engineersmind/emc-auth-server/internal/api/paths"
	"github.com/engineersmind/emc-auth-server/internal/auth"
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

// corsScope identifies which tenant's cors_origins governs a request.
//
// The scope is resolved from the request itself — see requestCORSScope for the
// ordering — and is deliberately not a value the caller picks freely: a
// credential's tenant_id claim scopes its own request, so an origin listed by
// tenant A cannot earn credentialed access for a request authenticating as
// tenant B (GHSA-8jgj-mwx4-q9wr).
type corsScope struct {
	tenantID int64  // credential-scoped: this tenant's list applies
	slug     string // credentialess but tenant-named: that tenant's list applies
	any      bool   // credentialess and unnamed: any active tenant may match
	deny     bool   // credentialed but tenant unreadable: per-tenant never applies
}

// cachePrefix namespaces the Redis decision per scope so an "allowed for
// tenant A" answer cannot be replayed for tenant B.
func (s corsScope) cachePrefix() string {
	switch {
	case s.tenantID != 0:
		return "cors:origin:t" + strconv.FormatInt(s.tenantID, 10) + ":"
	case s.slug != "":
		return "cors:origin:s" + s.slug + ":"
	default:
		return "cors:origin:*:"
	}
}

// requestCORSScope resolves which tenant's cors_origins governs this request.
//
// The resolution order is the trust order:
//
//  1. A presented credential decides whose data the request can reach, so it
//     decides the scope. The tenant_id claim is read WITHOUT signature
//     verification — the same trust model as auth's keyfunc tenant scoping
//     (jwt.go: naming a different tenant only makes the lookup miss; the
//     request still has to survive JWTRequired afterwards to reach anything).
//     A credential that carries no readable tenant — a malformed token, or an
//     API key, whose tenant is not exposed in the header — fails closed:
//     per-tenant origins never apply to it.
//  2. A credentialess request names its tenant through the route's :slug path
//     parameter or the X-Tenant-Slug header. The value is client-chosen, but
//     the response it could reach carries no credentials, so narrowing the
//     allowlist to the named tenant is strict improvement over any-tenant.
//  3. A credentialess request naming no tenant at all (a preflight OPTIONS —
//     which per spec never carries credentials — or a cross-origin login from
//     a tenant frontend) falls back to the any-tenant check. That answer can
//     only ever authorize an unauthenticated response, so it cannot expose one
//     tenant's data to another's origin.
func requestCORSScope(c echo.Context) corsScope {
	req := c.Request()

	if raw, ok := bearerToken(c); ok && raw != "" {
		return scopeFromToken(raw)
	}
	if cookie, err := c.Cookie(AccessTokenCookie); err == nil && cookie.Value != "" {
		return scopeFromToken(cookie.Value)
	}
	if req.Header.Get(APIKeyHeader) != "" ||
		strings.HasPrefix(req.Header.Get("Authorization"), "ApiKey ") {
		return corsScope{deny: true}
	}

	if slug := c.Param("slug"); slug != "" {
		return corsScope{slug: slug}
	}
	if slug := req.Header.Get("X-Tenant-Slug"); slug != "" {
		return corsScope{slug: slug}
	}
	return corsScope{any: true}
}

// scopeFromToken scopes a credentialed request to the token's tenant_id claim.
// An unparseable token or a missing/invalid claim fails closed.
func scopeFromToken(token string) corsScope {
	var claims auth.Claims
	if _, _, err := gojwt.NewParser().ParseUnverified(token, &claims); err != nil {
		return corsScope{deny: true}
	}
	if tenantID, err := strconv.ParseInt(claims.TenantID, 10, 64); err == nil {
		return corsScope{tenantID: tenantID}
	}
	return corsScope{deny: true}
}

// IsOriginAllowed reports whether the tenant identified by scope permits this
// browser origin — and only that tenant.
//
// GHSA-8jgj-mwx4-q9wr: the previous implementation asked whether ANY active
// tenant lists the origin, so one tenant whitelisting an origin granted that
// origin credentialed cross-origin access to every other tenant's API. The
// check is now scoped to the tenant the request's credential authenticates to
// (requestCORSScope); an origin on tenant A's list no longer authorizes a
// request carrying tenant B's session.
//
// scope.any — used only when the request carries no credential and names no
// tenant — retains the broad check, because a credentialess response is the
// most such a request can produce.
func (s *TenantCORSService) IsOriginAllowed(ctx context.Context, origin string, scope corsScope) bool {
	if origin == "" || scope.deny {
		return false
	}

	cacheKey := scope.cachePrefix() + origin
	if v, err := s.redisCli.Get(ctx, cacheKey).Result(); err == nil {
		return v == "1"
	}

	// cors_origins is a text[]; @> is the containment operator, which a GIN
	// index on that column can answer directly.
	var allowed bool
	var err error
	switch {
	case scope.tenantID != 0:
		err = s.pool.QueryRow(ctx, `
			SELECT EXISTS (
			    SELECT 1 FROM tenants
			    WHERE id = $2 AND is_active = true AND deleted_at IS NULL
			      AND cors_origins @> ARRAY[$1]::text[]
			)
		`, origin, scope.tenantID).Scan(&allowed)
	case scope.slug != "":
		err = s.pool.QueryRow(ctx, `
			SELECT EXISTS (
			    SELECT 1 FROM tenants
			    WHERE slug = $2 AND is_active = true AND deleted_at IS NULL
			      AND cors_origins @> ARRAY[$1]::text[]
			)
		`, origin, scope.slug).Scan(&allowed)
	default:
		err = s.pool.QueryRow(ctx, `
			SELECT EXISTS (
			    SELECT 1 FROM tenants
			    WHERE is_active = true AND deleted_at IS NULL
			      AND cors_origins @> ARRAY[$1]::text[]
			)
		`, origin).Scan(&allowed)
	}
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

// InvalidateOriginCache clears every scoped cached decision for one origin.
// Called when a tenant's origin list changes. Decisions are keyed per scope
// (cors:origin:<scope>:<origin>), so clearing takes a SCAN over the
// cors:origin:*: keyspace — small, and the write path is rare.
func (s *TenantCORSService) InvalidateOriginCache(ctx context.Context, origins ...string) {
	for _, o := range origins {
		if o == "" {
			continue
		}
		var cursor uint64
		for {
			keys, next, err := s.redisCli.Scan(ctx, cursor, "cors:origin:*:"+o, 100).Result()
			if err != nil {
				s.logger.Warn().Err(err).Str("origin", o).Msg("failed to invalidate CORS origin cache")
				break
			}
			if len(keys) > 0 {
				s.redisCli.Del(ctx, keys...) //nolint:errcheck
			}
			if next == 0 {
				break
			}
			cursor = next
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
// The decision depends on the request's Origin and on which tenant the request
// can reach (requestCORSScope): the credential it carries, the tenant it names,
// or — for credentialess, unnamed requests such as preflights — any tenant's
// list. Scoping the per-tenant check to the credential's own tenant is what
// keeps tenant A's origin list from authorizing credentialed requests that
// authenticate as tenant B (GHSA-8jgj-mwx4-q9wr).
//
// Behaviour:
//   - Origin permitted by the global allow-list → allowed, no database round trip.
//   - Otherwise, if the tenant the request is scoped to lists it in
//     cors_origins → allowed. The scope is the credential's tenant_id claim
//     for authenticated requests (GHSA-8jgj-mwx4-q9wr), the named slug for
//     credentialess tenant-scoped requests, or any active tenant only for
//     requests that carry no credential and name no tenant — the most such a
//     request can ever yield is an unauthenticated response.
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

			// Global origins are consulted first: they are deployment-wide
			// configuration and answer without a database round trip. The
			// per-tenant lookup runs only when the global list does not already
			// permit the origin — and is scoped to the tenant this request can
			// actually reach (requestCORSScope), never "any tenant"
			// (GHSA-8jgj-mwx4-q9wr).
			origins := svc.globalOrigins
			if requestOrigin != "" && !originListAllows(origins, requestOrigin) &&
				svc.IsOriginAllowed(req.Context(), requestOrigin, requestCORSScope(c)) {
				// The scoped tenant permits it; treat the origin as allowed
				// for the rest of this decision.
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
