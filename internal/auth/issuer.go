package auth

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/sync/singleflight"
)

// TenantIssuerResolver maps a tenant to its OpenID Connect issuer identifier
// (issue #7).
//
// Why per-tenant at all. OIDC ties three things to a single identifier: the
// "iss" claim in the token, the discovery document's location
// ({iss}/.well-known/openid-configuration), and the jwks_uri named inside that
// document — whose keys must verify tokens carrying that iss. Signing keys have
// been per-tenant since issue #95, but iss was one global JWT_ISSUER value. A
// standards-compliant relying party following discovery from that global issuer
// would find one jwks_uri and be unable to verify any token, because there is no
// single key set. Making iss per-tenant is what closes that loop, and it is the
// same model Auth0 uses (one issuer per tenant).
//
// The alternative — keep one issuer and publish an aggregate JWKS containing
// every tenant's keys — was rejected deliberately: it would let one tenant's
// verifier accept another tenant's tokens, destroying the isolation property
// #95 exists to provide, and it would make the full tenant list public.
type TenantIssuerResolver struct {
	pool *pgxpool.Pool

	// baseURL is the public origin of this auth server, without a trailing
	// slash, e.g. "https://auth.emc.local".
	baseURL string

	mu    sync.RWMutex
	cache map[int64]tenantIssuerEntry

	// loading collapses concurrent misses for the same tenant into one query,
	// mirroring SigningKeyService. Issuer resolution sits on the mint path of
	// every token and on the verify path of every request, so an uncached
	// implementation would add a DB read to both.
	loading singleflight.Group
}

// tenantIssuerEntry is one tenant's cached issuer.
type tenantIssuerEntry struct {
	issuer   string
	loadedAt time.Time
}

// tenantIssuerCacheTTL bounds how long a resolved issuer is reused before being
// re-read. Matched to signingKeyCacheTTL so the two caches backing a single
// token cannot disagree for longer than one another.
const tenantIssuerCacheTTL = 5 * time.Minute

// tenantIssuerLoadTimeout caps a shared load so one slow query cannot pin every
// caller waiting behind it.
const tenantIssuerLoadTimeout = 3 * time.Second

// ErrEmptyIssuerBaseURL is returned when no base URL is configured. As with
// ErrEmptyIssuer, this fails at construction rather than producing tokens whose
// iss is a bare path.
var ErrEmptyIssuerBaseURL = errors.New("jwt: issuer base URL must not be empty")

// ErrUnknownTenantIssuer is returned when a tenant id resolves to no tenant row.
var ErrUnknownTenantIssuer = errors.New("jwt: no issuer for tenant")

// NewTenantIssuerResolver builds the resolver. baseURL should be the public
// origin of this auth server — the host a relying party will actually fetch
// discovery and JWKS from.
func NewTenantIssuerResolver(pool *pgxpool.Pool, baseURL string) (*TenantIssuerResolver, error) {
	trimmed := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if trimmed == "" {
		return nil, ErrEmptyIssuerBaseURL
	}
	return &TenantIssuerResolver{
		pool:    pool,
		baseURL: trimmed,
		cache:   make(map[int64]tenantIssuerEntry),
	}, nil
}

// IssuerForSlug builds the issuer string for a tenant slug without touching the
// database.
//
// Path-based ({base}/tenants/{slug}) rather than subdomain-based
// (https://{slug}.auth.example.com), because the JWKS endpoint shipped in #95 is
// already at /tenants/{slug}/.well-known/jwks.json. Keeping the same shape means
// the issuer, its discovery document, and its key set are one contiguous URL
// space, and it needs no wildcard DNS or wildcard TLS certificate to deploy.
func (r *TenantIssuerResolver) IssuerForSlug(slug string) string {
	return r.baseURL + "/tenants/" + slug
}

// BaseURL returns the configured origin, for handlers that build sibling URLs
// (discovery, jwks_uri, userinfo) from the same root.
func (r *TenantIssuerResolver) BaseURL() string {
	return r.baseURL
}

// Issuer returns the OIDC issuer for a tenant, loading and caching the slug.
//
// The lookup deliberately does NOT filter on is_active. An issuer is an identity,
// not an authorization decision: whether a deactivated tenant's callers may still
// act is enforced where it belongs (tenantSecret refuses inactive tenants on the
// legacy path, and the tenant guards on admin routes). Filtering here would
// instead make every already-issued token for that tenant fail issuer validation
// the moment the tenant is deactivated — a different and much blunter effect than
// the one intended, applied at verification time.
func (r *TenantIssuerResolver) Issuer(ctx context.Context, tenantID int64) (string, error) {
	r.mu.RLock()
	entry, ok := r.cache[tenantID]
	r.mu.RUnlock()
	if ok && time.Since(entry.loadedAt) < tenantIssuerCacheTTL {
		return entry.issuer, nil
	}

	loaded, err, _ := r.loading.Do(strconv.FormatInt(tenantID, 10), func() (any, error) {
		// context.WithoutCancel for the same reason SigningKeyService uses it: the
		// first caller disconnecting must not cancel a load that other in-flight
		// requests are waiting on.
		loadCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), tenantIssuerLoadTimeout)
		defer cancel()

		var slug string
		queryErr := r.pool.QueryRow(loadCtx,
			`SELECT slug FROM tenants WHERE id = $1 AND deleted_at IS NULL`,
			tenantID,
		).Scan(&slug)
		if errors.Is(queryErr, pgx.ErrNoRows) {
			return nil, fmt.Errorf("%w: tenant %d", ErrUnknownTenantIssuer, tenantID)
		}
		if queryErr != nil {
			return nil, fmt.Errorf("resolve issuer for tenant %d: %w", tenantID, queryErr)
		}
		if slug == "" {
			return nil, fmt.Errorf("%w: tenant %d has an empty slug", ErrUnknownTenantIssuer, tenantID)
		}

		issuer := r.IssuerForSlug(slug)
		// Only successful resolutions are cached. The tenant id reaching this
		// function on the verify path comes from a token claim, so caching misses
		// would let a caller cycling ids grow the map without bound — the same
		// reasoning that keeps SigningKeyService from caching empty key sets.
		r.mu.Lock()
		r.cache[tenantID] = tenantIssuerEntry{issuer: issuer, loadedAt: time.Now()}
		r.mu.Unlock()
		return issuer, nil
	})
	if err != nil {
		return "", err
	}
	issuer, ok := loaded.(string)
	if !ok {
		return "", fmt.Errorf("tenant issuer cache: unexpected %T from shared load", loaded)
	}
	return issuer, nil
}

// Invalidate drops a tenant's cached issuer so the next lookup re-reads it.
//
// Tenant slugs are not mutable through any current code path, so this exists for
// the cases outside them: a slug corrected directly in SQL, or a restored backup.
// Without it such a change would take up to tenantIssuerCacheTTL to appear, and
// tokens minted in that window would carry an issuer that no longer matches the
// tenant's JWKS URL.
func (r *TenantIssuerResolver) Invalidate(tenantID int64) {
	r.mu.Lock()
	delete(r.cache, tenantID)
	r.mu.Unlock()
}
