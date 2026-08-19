package handlers

import (
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog"

	"github.com/engineersmind/emc-auth-server/internal/api/paths"
	"github.com/engineersmind/emc-auth-server/internal/audit"
	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// SigningKeyHandler exposes signing-key rotation to tenant operators (issue #95).
//
// Rotation exists as an endpoint because a rotation mechanism nobody can invoke is
// not a rotation mechanism. Before this, the documented remedy for a compromised
// signing secret was to edit the tenants row in the database by hand
// (docs/DEPLOYMENT.md:213), and no UPDATE of that column existed anywhere in the
// codebase — the secret was effectively write-once and immortal.
type SigningKeyHandler struct {
	pool *pgxpool.Pool
	keys *auth.SigningKeyService
	// appBaseURL is the public origin the JWKS endpoint is served from. Used to
	// return an absolute jwks_url so an operator never has to assemble it by hand.
	// APP_BASE_URL is authoritative for this, not JWT_ISSUER — see the startup
	// mismatch warning in routes.go.
	appBaseURL string
	audit      *audit.Logger
	logger     zerolog.Logger
}

// NewSigningKeyHandler builds the handler.
func NewSigningKeyHandler(pool *pgxpool.Pool, keys *auth.SigningKeyService, appBaseURL string, auditLog *audit.Logger, logger zerolog.Logger) *SigningKeyHandler {
	return &SigningKeyHandler{
		pool:       pool,
		keys:       keys,
		appBaseURL: strings.TrimRight(appBaseURL, "/"),
		audit:      auditLog,
		logger:     logger,
	}
}

// SigningKeyInfo describes one key in an API response.
//
// There is no private-key field, and there must never be one. The struct is the
// enforcement point: a handler cannot accidentally serialise key material it has
// no field for.
type SigningKeyInfo struct {
	KID         string     `json:"kid"`
	Algorithm   string     `json:"algorithm"`
	Status      string     `json:"status"`
	CreatedAt   time.Time  `json:"created_at"`
	ActivatedAt *time.Time `json:"activated_at,omitempty"`
	RetiredAt   *time.Time `json:"retired_at,omitempty"`
}

// SigningKeyListResponse is the body of the list and rotate endpoints.
type SigningKeyListResponse struct {
	// JWKSURL is where verifiers should fetch these keys. Returned so an operator
	// never has to construct it by hand or guess the scheme.
	JWKSURL string           `json:"jwks_url"`
	Keys    []SigningKeyInfo `json:"keys"`
}

// signingKeyTenant resolves the tenant whose keys this request may touch.
//
// Non-Negotiable #4: the tenant id comes from the verified JWT, never from the
// body, a query parameter, or a path segment — so an operator cannot rotate
// another tenant's signing keys by editing a request. Reuses the package's
// existing claimsFromCtx/tenantIDFromClaims helpers rather than re-reading the
// context key, so there is one definition of "who is calling".
func signingKeyTenant(c echo.Context) (int64, bool) {
	claims, ok := claimsFromCtx(c)
	if !ok {
		return 0, false
	}
	id, err := tenantIDFromClaims(claims)
	if err != nil || id <= 0 {
		return 0, false
	}
	return id, true
}

// ListSigningKeys serves GET /api/v1/signing-keys.
//
// @Summary     List this tenant's JWT signing keys
// @Description Public metadata for the tenant's signing keys. Never returns private key material.
// @Tags        admin
// @Security    BearerAuth
// @Produce     json
// @Success     200  {object}  SigningKeyListResponse
// @Failure     401  {object}  map[string]string
// @Router      /api/v1/signing-keys [get]
func (h *SigningKeyHandler) ListSigningKeys(c echo.Context) error {
	tenantID, ok := signingKeyTenant(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}

	keys, err := h.keys.PublishableKeys(c.Request().Context(), tenantID)
	if err != nil {
		h.logger.Error().Err(err).Int64("tenant_id", tenantID).Msg("list signing keys failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "internal error"})
	}
	return c.JSON(http.StatusOK, h.response(c, tenantID, keys))
}

// PrepareSigningKeyRotation serves POST /api/v1/signing-keys/prepare.
//
// Step 1 of 2. Generates the incoming key and publishes it in JWKS WITHOUT signing
// anything, then stops. This split is the whole reason rotation here is
// zero-downtime: verifiers cache JWKS, so if a key's first token arrived before the
// key appeared in the published set, every verifier with a warm cache would reject
// that token until it refetched. Publishing first removes that window.
//
// Idempotent — calling it twice returns the same pending key rather than churning
// through key material.
//
// @Summary     Prepare a signing-key rotation
// @Description Generates and publishes the next signing key without activating it. Wait for verifier caches to pick it up (see Cache-Control on the JWKS endpoint), then call the complete endpoint.
// @Tags        admin
// @Security    BearerAuth
// @Produce     json
// @Success     200  {object}  SigningKeyListResponse
// @Failure     401  {object}  map[string]string
// @Router      /api/v1/signing-keys/prepare [post]
func (h *SigningKeyHandler) PrepareSigningKeyRotation(c echo.Context) error {
	tenantID, ok := signingKeyTenant(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	ctx := c.Request().Context()

	key, err := h.keys.PrepareRotation(ctx, tenantID)
	if err != nil {
		h.logger.Error().Err(err).Int64("tenant_id", tenantID).Msg("prepare signing key rotation failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "internal error"})
	}

	h.record(c, tenantID, "signing_key.rotation_prepared", key.KID)

	keys, err := h.keys.PublishableKeys(ctx, tenantID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "internal error"})
	}
	return c.JSON(http.StatusOK, h.response(c, tenantID, keys))
}

// CompleteSigningKeyRotation serves POST /api/v1/signing-keys/complete.
//
// Step 2 of 2. Promotes the prepared key to active and retires the outgoing one,
// which stays published for auth.RetiredKeyGrace so tokens signed seconds before
// the switch remain verifiable. No live token is invalidated.
//
// Fails if no prepared key exists, rather than silently generating and activating
// one in a single step — that shortcut is exactly the rejection window the
// two-step flow avoids.
//
// @Summary     Complete a signing-key rotation
// @Description Activates the prepared key and retires the current one. The retired public key stays published until its grace window elapses, so no live token breaks.
// @Tags        admin
// @Security    BearerAuth
// @Produce     json
// @Success     200  {object}  SigningKeyListResponse
// @Failure     401  {object}  map[string]string
// @Failure     409  {object}  map[string]string
// @Router      /api/v1/signing-keys/complete [post]
func (h *SigningKeyHandler) CompleteSigningKeyRotation(c echo.Context) error {
	tenantID, ok := signingKeyTenant(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	ctx := c.Request().Context()

	key, err := h.keys.CompleteRotation(ctx, tenantID)
	if err != nil {
		// 409 rather than 500: the usual cause is calling complete without prepare,
		// which is a sequencing mistake by the caller, not a server fault.
		h.logger.Warn().Err(err).Int64("tenant_id", tenantID).Msg("complete signing key rotation failed")
		return c.JSON(http.StatusConflict, map[string]string{
			"error": "no prepared signing key to activate — call /api/v1/signing-keys/prepare first and allow verifier caches to refresh",
		})
	}

	h.record(c, tenantID, "signing_key.rotated", key.KID)

	keys, err := h.keys.PublishableKeys(ctx, tenantID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "internal error"})
	}
	return c.JSON(http.StatusOK, h.response(c, tenantID, keys))
}

// response maps internal keys to the public shape, dropping private material.
func (h *SigningKeyHandler) response(c echo.Context, tenantID int64, keys []*auth.SigningKey) SigningKeyListResponse {
	out := SigningKeyListResponse{Keys: make([]SigningKeyInfo, 0, len(keys))}
	for _, k := range keys {
		out.Keys = append(out.Keys, SigningKeyInfo{
			KID:         k.KID,
			Algorithm:   k.Algorithm,
			Status:      k.Status,
			CreatedAt:   k.CreatedAt,
			ActivatedAt: k.ActivatedAt,
			RetiredAt:   k.RetiredAt,
		})
	}
	out.JWKSURL = h.jwksURL(c, tenantID)
	return out
}

// jwksURL builds the absolute URL a verifier should fetch for this tenant.
//
// The slug is read from the database rather than from the request context: an
// earlier version used a "tenant_slug" context key that no middleware ever sets,
// so the field silently returned "" — caught only by exercising the endpoint for
// real. Returning a blank URL from the very field meant to save operators from
// guessing it would have been worse than useless.
func (h *SigningKeyHandler) jwksURL(c echo.Context, tenantID int64) string {
	var slug string
	if err := h.pool.QueryRow(c.Request().Context(),
		// Same predicate as GetTenantJWKS. Without it this field would hand an
		// operator a URL that 404s, because the endpoint it points at refuses
		// deactivated and soft-deleted tenants.
		`SELECT slug FROM tenants WHERE id = $1 AND is_active = true AND deleted_at IS NULL`, tenantID,
	).Scan(&slug); err != nil || slug == "" {
		h.logger.Warn().Err(err).Int64("tenant_id", tenantID).Msg("signing keys: could not resolve tenant slug for jwks_url")
		return ""
	}
	// Built from the same route constant the router registers and the discovery
	// document publishes, not assembled by hand. This value is handed to an
	// operator through the admin API, so a hand-built copy that drifted would
	// send them to a 404 and look like a broken endpoint rather than a stale
	// string.
	return h.appBaseURL + paths.TenantPath(paths.TenantJWKS, slug)
}

// record writes a fire-and-forget audit event. Key rotation is a
// security-relevant administrative action and must leave a trail, but per the
// project's audit philosophy a logging failure must never fail the operation.
func (h *SigningKeyHandler) record(c echo.Context, tenantID int64, action, kid string) {
	if h.audit == nil {
		return
	}
	h.audit.Log(c.Request().Context(), audit.Event{
		TenantID:     &tenantID,
		Action:       action,
		ResourceType: "signing_key",
		ResourceID:   kid,
		Status:       audit.StatusSuccess,
		IPAddress:    c.RealIP(),
		UserAgent:    c.Request().UserAgent(),
		Metadata:     map[string]any{"kid": kid},
	})
}
