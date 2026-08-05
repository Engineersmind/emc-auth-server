package handlers

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog"

	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// JWKSHandler publishes each tenant's public signing keys as a JSON Web Key Set
// (issue #95, Phase 3), so any party can verify an EMC access token offline with
// a standard JWT library and zero ability to mint one.
//
// This is the endpoint that makes asymmetric signing useful. Without it a tenant
// still has to be handed tenants.jwt_secret to validate a token, which is signing
// authority for that whole tenant.
type JWKSHandler struct {
	pool   *pgxpool.Pool
	keys   *auth.SigningKeyService
	logger zerolog.Logger
}

// NewJWKSHandler builds the handler.
func NewJWKSHandler(pool *pgxpool.Pool, keys *auth.SigningKeyService, logger zerolog.Logger) *JWKSHandler {
	return &JWKSHandler{pool: pool, keys: keys, logger: logger}
}

// jwksCacheMaxAge is the Cache-Control max-age advertised to verifiers, in
// seconds.
//
// 300s is a deliberate compromise. Too long and a rotation takes ages to
// propagate to every verifier; too short and every consumer refetches constantly,
// turning our JWKS endpoint into a hard dependency on their request path. Five
// minutes also matches the server's own key cache TTL, so a verifier is never
// told to cache longer than we do.
const jwksCacheMaxAge = 300

// GetTenantJWKS serves GET /tenants/:slug/.well-known/jwks.json.
//
// Per-tenant by path because a tenant's keys must be separately addressable: the
// point of per-tenant key pairs is that Acme's public key cannot verify Globex's
// token, and that property is only usable if Acme's verifier can fetch Acme's keys
// specifically. EMC identifies tenants by the X-Tenant-Slug header everywhere
// else, but a browser or JWKS library fetching a URL cannot send a custom header,
// so the slug has to live in the path.
//
// @Summary     Tenant JWKS (public signing keys)
// @Description Public keys for verifying this tenant's access tokens. Contains the active key, any pre-published next key, and recently retired keys. Never contains private key material.
// @Tags        system
// @Produce     json
// @Param       slug  path  string  true  "Tenant slug"
// @Success     200   {object}  map[string]interface{}
// @Failure     404   {object}  map[string]string
// @Router      /tenants/{slug}/.well-known/jwks.json [get]
func (h *JWKSHandler) GetTenantJWKS(c echo.Context) error {
	slug := c.Param("slug")
	if slug == "" {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "tenant not found"})
	}

	ctx := c.Request().Context()

	var tenantID int64
	err := h.pool.QueryRow(ctx,
		`SELECT id FROM tenants WHERE slug = $1 AND is_active = true AND deleted_at IS NULL`,
		slug,
	).Scan(&tenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		// Same generic 404 for "no such tenant" and "tenant disabled" — this is an
		// unauthenticated endpoint and should not confirm which tenants exist.
		return c.JSON(http.StatusNotFound, map[string]string{"error": "tenant not found"})
	}
	if err != nil {
		h.logger.Error().Err(err).Str("slug", slug).Msg("jwks: resolve tenant failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "internal error"})
	}

	set, err := h.keys.JWKS(ctx, tenantID)
	if err != nil {
		h.logger.Error().Err(err).Int64("tenant_id", tenantID).Msg("jwks: build key set failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "internal error"})
	}

	body, err := json.Marshal(set)
	if err != nil {
		h.logger.Error().Err(err).Msg("jwks: marshal key set failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "internal error"})
	}

	// CORS: public key material is not origin-sensitive, and the entire purpose of
	// this endpoint is to be fetched by arbitrary relying parties. Set the wildcard
	// explicitly here so the value is right even though TenantCORS skips this path
	// (see the exemption in middleware/cors.go) — belt and braces, because a
	// regression that reinstated a 403 here would break every browser-side verifier
	// with no signal on our side.
	h.setPublicHeaders(c, body)

	// ETag lets a verifier revalidate cheaply. A 304 costs us almost nothing, which
	// matters because libraries refetch JWKS on every unknown kid.
	if match := c.Request().Header.Get("If-None-Match"); match != "" && match == c.Response().Header().Get("ETag") {
		return c.NoContent(http.StatusNotModified)
	}

	return c.JSONBlob(http.StatusOK, body)
}

// setPublicHeaders applies the caching and CORS headers a public JWKS needs.
func (h *JWKSHandler) setPublicHeaders(c echo.Context, body []byte) {
	sum := sha256.Sum256(body)
	etag := `"` + base64.RawURLEncoding.EncodeToString(sum[:16]) + `"`

	head := c.Response().Header()
	head.Set("Access-Control-Allow-Origin", "*")
	head.Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	head.Set("Cache-Control", "public, max-age="+strconv.Itoa(jwksCacheMaxAge))
	head.Set("ETag", etag)
	head.Set("Content-Type", "application/json")
}
