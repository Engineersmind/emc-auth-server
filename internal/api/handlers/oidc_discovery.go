package handlers

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/labstack/echo/v4"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/metrics"
)

// Endpoint paths advertised by the discovery document.
//
// These constants are the SINGLE definition of each path: routes.go registers
// the route from the same constant that this document publishes. That is not
// tidiness — it is the correctness property of the whole ticket. A discovery
// document is authoritative to a relying party: an OIDC client library trusts
// what it reads here over anything in its own configuration, so a document that
// disagrees with the router is worse than no document at all, because the
// failure surfaces inside someone else's SDK long after the path was moved.
//
// The two tenant-scoped paths carry Echo's ":slug" placeholder so the router and
// the document cannot diverge on the prefix either; tenantPath substitutes it.
const (
	// PathOAuthAuthorize is the OAuth 2.0 authorization endpoint (issue #6).
	PathOAuthAuthorize = "/oauth/authorize"
	// PathOAuthToken is the RFC 6749 token endpoint (issue #6). Not
	// /auth/token, which survives only as a documented-deprecated JSON alias.
	PathOAuthToken = "/oauth/token"
	// PathOAuthUserInfo is the OIDC UserInfo endpoint (issue #7a).
	PathOAuthUserInfo = "/oauth/userinfo"
	// PathOAuthRevoke is the RFC 7009 revocation endpoint (issue #6).
	PathOAuthRevoke = "/oauth/revoke"
	// PathTenantJWKS is the per-tenant JWKS endpoint (issue #95).
	PathTenantJWKS = "/tenants/:slug/.well-known/jwks.json"
	// PathTenantDiscovery is this document's own location (issue #7b).
	PathTenantDiscovery = "/tenants/:slug/.well-known/openid-configuration"
)

// tenantPath substitutes a concrete slug into one of the ":slug" route
// templates above, so an absolute URL in the document is derived from the exact
// string the router was registered with.
func tenantPath(template, slug string) string {
	return strings.Replace(template, ":slug", slug, 1)
}

// discoveryCacheMaxAge is the Cache-Control max-age for the discovery document,
// in seconds.
//
// Matched to jwksCacheMaxAge deliberately. The two are fetched as a pair — a
// client reads discovery, then follows jwks_uri — and telling a client to cache
// one substantially longer than the other means it can hold a document naming a
// jwks_uri it has already been told to re-read, or vice versa. Neither is
// dangerous, but keeping them equal removes the question.
const discoveryCacheMaxAge = jwksCacheMaxAge

// Outcome labels for metrics.OIDCDiscoveryRequests. Declared as constants
// because a typo in a label string does not fail — it silently creates a second
// parallel time series that nobody is alerting on. Keep in step with the
// documented set on the metric.
const (
	discoveryOutcomeServed        = "served"
	discoveryOutcomeNotModified   = "not_modified"
	discoveryOutcomeUnknownTenant = "unknown_tenant"
	discoveryOutcomeError         = "error"
)

// OIDCDiscoveryDocument is the OpenID Provider Metadata of OIDC Discovery 1.0
// §3, for one tenant.
//
// Every value is read from the code that already enforces it rather than
// written here from the specification, so the document cannot claim a
// capability the server does not have. Where the server implements nothing, the
// field is ABSENT rather than empty — see the omissions noted on the builder.
type OIDCDiscoveryDocument struct {
	// Issuer must be byte-identical to the "iss" claim of every token this
	// tenant issues. This is the one field a conformant client hard-fails on:
	// go-oidc, openid-client, MSAL and Spring Security all compare the string
	// they fetched discovery from against this value and refuse a mismatch.
	Issuer string `json:"issuer"`

	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserInfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	RevocationEndpoint    string `json:"revocation_endpoint"`

	ScopesSupported        []string `json:"scopes_supported"`
	ResponseTypesSupported []string `json:"response_types_supported"`
	ResponseModesSupported []string `json:"response_modes_supported"`
	GrantTypesSupported    []string `json:"grant_types_supported"`

	// CodeChallengeMethodsSupported advertises S256 and nothing else. This is a
	// security statement, not an omission: pkce.go refuses "plain" outright, and
	// a document offering it would invite a client to negotiate down to a method
	// that provides no protection against the attacker PKCE exists to stop.
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`

	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`

	// SubjectTypesSupported is ["public"] because "sub" is the raw user id, the
	// same value for every client (see UserInfoResponse.Subject). Advertising
	// "pairwise" would be a false claim about a privacy property we do not have.
	SubjectTypesSupported []string `json:"subject_types_supported"`

	ClaimsSupported []string `json:"claims_supported"`

	// The three *_supported booleans below are stated explicitly as false rather
	// than omitted. Omission means "use the default", and a client reading a
	// document with no opinion may probe the feature anyway; an explicit false
	// stops the request being made at all.
	ClaimsParameterSupported     bool `json:"claims_parameter_supported"`
	RequestParameterSupported    bool `json:"request_parameter_supported"`
	RequestURIParameterSupported bool `json:"request_uri_parameter_supported"`
}

// buildDiscoveryDocument assembles one tenant's metadata.
//
// base is the public origin without a trailing slash; slug is a tenant slug
// already proven to exist.
//
// Deliberately absent, each because advertising it would be a false claim that
// sends a conformant client to a 404:
//
//	end_session_endpoint, check_session_iframe  RP-Initiated Logout and Session
//	                                            Management are not implemented
//	introspection_endpoint                      RFC 7662 introspection does not
//	                                            exist (revocation does, and is
//	                                            advertised)
//	registration_endpoint                       Dynamic Client Registration is
//	                                            not implemented; #8 is an
//	                                            admin-managed client API, which
//	                                            is a different thing
//	acr_values_supported                        no ACR concept
func buildDiscoveryDocument(base, slug string) OIDCDiscoveryDocument {
	return OIDCDiscoveryDocument{
		Issuer: base + tenantPath("/tenants/:slug", slug),

		AuthorizationEndpoint: base + PathOAuthAuthorize,
		TokenEndpoint:         base + PathOAuthToken,
		UserInfoEndpoint:      base + PathOAuthUserInfo,
		JWKSURI:               base + tenantPath(PathTenantJWKS, slug),
		RevocationEndpoint:    base + PathOAuthRevoke,

		// The four reserved OIDC scopes from application.go. Permission scopes
		// (resource:action) share that column but are not advertised here: they
		// are an internal authorization vocabulary, not something an OIDC client
		// should discover and request.
		ScopesSupported: []string{
			auth.ScopeOpenID,
			auth.ScopeProfile,
			auth.ScopeEmail,
			auth.ScopeOfflineAccess,
		},

		// Code flow only. No implicit, no hybrid — neither is implemented, and
		// both are discouraged by OAuth 2.1 regardless.
		ResponseTypesSupported: []string{"code"},
		ResponseModesSupported: []string{"query"},

		// Mirrors the switch in OAuthTokenHandler.Token.
		GrantTypesSupported: []string{
			"authorization_code",
			"refresh_token",
			"client_credentials",
		},

		CodeChallengeMethodsSupported: []string{auth.PKCEMethodS256},

		// Mirrors clientCredentialsFromRequest (Basic header, then form body)
		// plus "none" for public clients, which authenticate with PKCE alone.
		TokenEndpointAuthMethodsSupported: []string{
			"client_secret_basic",
			"client_secret_post",
			"none",
		},

		IDTokenSigningAlgValuesSupported: []string{"RS256"},
		SubjectTypesSupported:            []string{"public"},

		// The union of IDTokenClaims and UserInfoResponse. A claim appears here
		// only if some scope or flow can actually produce it.
		ClaimsSupported: []string{
			"sub", "iss", "aud", "exp", "iat",
			"email", "email_verified",
			"name", "given_name", "family_name",
			"updated_at",
			"nonce", "auth_time", "at_hash",
		},

		ClaimsParameterSupported:     false,
		RequestParameterSupported:    false,
		RequestURIParameterSupported: false,
	}
}

// Discovery serves GET /tenants/:slug/.well-known/openid-configuration.
//
// Per-tenant by path, not global, and this is forced rather than chosen. OIDC
// Discovery §4.3 requires the "issuer" inside the document to equal the issuer
// of the tokens exactly, and since issue #7a that value is per-tenant
// ({base}/tenants/{slug}). A single global document names exactly one issuer,
// so it would validate for one tenant and hard-fail for every other, and would
// publish a single jwks_uri, defeating the per-tenant key isolation #95 exists
// to provide. Sitting at {issuer}/.well-known/openid-configuration is also what
// makes discovery work the standard way: a relying party is handed the issuer
// URL, appends the well-known suffix, and everything resolves.
//
// An unknown slug returns 404 — the same generic response as the sibling JWKS
// route, and technically a tenant-existence oracle. Accepted knowingly: tenant
// slugs already appear in the "iss" of every issued token and in that same JWKS
// URL, so nothing is revealed that was not already public, and the alternative
// (200 with a fabricated document) would hand a client a document it caches and
// then verifies tokens against.
//
// @Summary     OIDC discovery document
// @Description OpenID Provider Metadata for one tenant (OIDC Discovery 1.0 §3). Public and unauthenticated. Point an OIDC client at {base}/tenants/{slug} as its issuer and it will fetch this and configure itself. Cacheable — supports ETag / If-None-Match.
// @Tags        oidc
// @Produce     json
// @Param       slug  path  string  true  "Tenant slug"
// @Success     200   {object}  OIDCDiscoveryDocument
// @Success     304   "Not Modified — document unchanged since the supplied ETag"
// @Failure     404   {object}  map[string]string
// @Failure     500   {object}  map[string]string
// @Router      /tenants/{slug}/.well-known/openid-configuration [get]
func (h *OIDCHandler) Discovery(c echo.Context) error {
	slug := c.Param("slug")
	if slug == "" {
		metrics.OIDCDiscoveryRequests.WithLabelValues(discoveryOutcomeUnknownTenant).Inc()
		return c.JSON(http.StatusNotFound, map[string]string{"error": "tenant not found"})
	}

	// Checked before the tenant lookup, not after: a nil resolver is a wiring
	// error that no request can recover from, so there is no reason to spend a
	// database round-trip discovering the tenant exists before failing on it.
	if h.issuers == nil {
		metrics.OIDCDiscoveryRequests.WithLabelValues(discoveryOutcomeError).Inc()
		h.logger.Error().Str("slug", slug).Msg("oidc discovery: no issuer resolver configured")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "internal error"})
	}

	ctx := c.Request().Context()

	// Same lookup and same generic 404 as jwks.go: an unauthenticated endpoint
	// should not distinguish "no such tenant" from "tenant disabled".
	//
	// The slug is confirmed against the database rather than simply echoed into
	// the issuer string. Without this, any slug at all would yield a 200 with a
	// well-formed document, and a client that mistyped its issuer would be
	// configured against a tenant that does not exist — failing much later, at
	// the first token verification, with no clue as to why.
	var tenantID int64
	err := h.pool.QueryRow(ctx,
		`SELECT id FROM tenants WHERE slug = $1 AND is_active = true AND deleted_at IS NULL`,
		slug,
	).Scan(&tenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		metrics.OIDCDiscoveryRequests.WithLabelValues(discoveryOutcomeUnknownTenant).Inc()
		return c.JSON(http.StatusNotFound, map[string]string{"error": "tenant not found"})
	}
	if err != nil {
		// Fail closed with a 5xx. Never fall through to a document built on a
		// default or empty issuer: clients cache discovery, so a wrong issuer
		// outlives the outage that produced it.
		metrics.OIDCDiscoveryRequests.WithLabelValues(discoveryOutcomeError).Inc()
		h.logger.Error().Err(err).Str("slug", slug).Msg("oidc discovery: resolve tenant failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "internal error"})
	}

	doc := buildDiscoveryDocument(h.issuers.BaseURL(), slug)

	body, err := json.Marshal(doc)
	if err != nil {
		metrics.OIDCDiscoveryRequests.WithLabelValues(discoveryOutcomeError).Inc()
		h.logger.Error().Err(err).Str("slug", slug).Msg("oidc discovery: marshal document failed")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "internal error"})
	}

	h.setDiscoveryHeaders(c, body)

	// Every OIDC client fetches discovery at process start, so a fleet restart
	// is a synchronised burst. A 304 answers it without touching the tenants
	// table again on the client's side of the cache.
	if match := c.Request().Header.Get("If-None-Match"); match != "" && match == c.Response().Header().Get("ETag") {
		metrics.OIDCDiscoveryRequests.WithLabelValues(discoveryOutcomeNotModified).Inc()
		return c.NoContent(http.StatusNotModified)
	}

	metrics.OIDCDiscoveryRequests.WithLabelValues(discoveryOutcomeServed).Inc()
	return c.JSONBlob(http.StatusOK, body)
}

// setDiscoveryHeaders applies the caching and CORS headers a public discovery
// document needs.
//
// Wildcard CORS for the same reason jwks.go sets it: the document is specified
// to be fetched by arbitrary relying parties, including browser-side ones, and
// it contains nothing origin-sensitive.
func (h *OIDCHandler) setDiscoveryHeaders(c echo.Context, body []byte) {
	sum := sha256.Sum256(body)
	etag := `"` + base64.RawURLEncoding.EncodeToString(sum[:16]) + `"`

	head := c.Response().Header()
	head.Set("Access-Control-Allow-Origin", "*")
	head.Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	head.Set("Cache-Control", "public, max-age="+strconv.Itoa(discoveryCacheMaxAge))
	head.Set("ETag", etag)
	head.Set("Content-Type", "application/json")
}
