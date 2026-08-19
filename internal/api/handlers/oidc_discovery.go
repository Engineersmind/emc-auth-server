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

	"github.com/engineersmind/emc-auth-server/internal/api/paths"
	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/metrics"
)

// Endpoint paths advertised by the discovery document.
//
// The values now live in internal/api/paths, which is the single definition of
// each path for every layer that needs one — the router here, and the CORS
// middleware that must exempt the two public documents. Middleware cannot import
// this package (handlers already imports middleware), so it kept private copies
// of the well-known suffixes and nothing but a reviewer's memory tied them to
// these values.
//
// Why it matters that there is exactly one definition: a discovery document is
// authoritative to a relying party — an OIDC client library trusts what it reads
// here over anything in its own configuration — so a document that disagrees with
// the router is worse than no document at all, because the failure surfaces
// inside someone else's SDK long after the path was moved.
//
// These names are retained as aliases rather than replaced at every call site:
// routes.go and the tests already reference them, and the point of the change is
// to remove a duplicate definition, not to rename what is already correct.
const (
	PathOAuthAuthorize  = paths.OAuthAuthorize
	PathOAuthToken      = paths.OAuthToken
	PathOAuthUserInfo   = paths.OAuthUserInfo
	PathOAuthRevoke     = paths.OAuthRevoke
	PathTenantJWKS      = paths.TenantJWKS
	PathTenantDiscovery = paths.TenantDiscovery
)

// tenantPath substitutes a concrete slug into one of the ":slug" route
// templates above, so an absolute URL in the document is derived from the exact
// string the router was registered with.
func tenantPath(template, slug string) string {
	return paths.TenantPath(template, slug)
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

	// The ETag is computed once, from the body, and both the header and the
	// If-None-Match comparison below read that one value. Setting the header and
	// then reading it back to compare against would work — the body is
	// deterministic, so the digest is too — but it reads as the response
	// validating itself, and it would silently stop matching the moment anything
	// between here and there rewrote the header.
	etag := discoveryETag(body)
	h.setDiscoveryHeaders(c, etag)

	// Every OIDC client fetches discovery at process start, so a fleet restart
	// is a synchronised burst. A 304 answers it without touching the tenants
	// table again on the client's side of the cache.
	if ifNoneMatch(c.Request().Header.Get("If-None-Match"), etag) {
		metrics.OIDCDiscoveryRequests.WithLabelValues(discoveryOutcomeNotModified).Inc()
		return c.NoContent(http.StatusNotModified)
	}

	metrics.OIDCDiscoveryRequests.WithLabelValues(discoveryOutcomeServed).Inc()
	return c.JSONBlob(http.StatusOK, body)
}

// discoveryETag derives the validator from the document body, so it changes if
// and only if the bytes a client would receive change.
func discoveryETag(body []byte) string {
	sum := sha256.Sum256(body)
	return `"` + base64.RawURLEncoding.EncodeToString(sum[:16]) + `"`
}

// ifNoneMatch evaluates an If-None-Match header against the current validator
// per RFC 9110 §13.1.2, rather than comparing the raw header to it.
//
// Three things the exact-string comparison this replaces got wrong. None of them
// can serve stale or wrong data — the only consequence is a 200 with the full
// body where a 304 would have done — but all three are conformance failures on
// the one endpoint whose caching behaviour this ticket deliberately designed, and
// every OIDC client in existence revalidates it on process start:
//
//   - "*" matches any existing representation. The document exists whenever this
//     runs, so "*" is always a match.
//   - The field is a LIST: `If-None-Match: "a", "b"`. Intermediaries and some
//     client stacks send more than one candidate, and a whole-header comparison
//     matches none of them.
//   - Comparison is the WEAK function, so a validator a cache has weakened to
//     `W/"a"` still matches our strong `"a"`. Our own ETags are always strong;
//     it is what arrives that may not be.
//
// Deliberately not tolerant of a missing quote pair. An entity-tag is quoted by
// grammar, so an unquoted value is a malformed request rather than a validator
// worth guessing at, and treating `abc` as `"abc"` would mean a 304 for a
// candidate the client never actually sent.
func ifNoneMatch(header, etag string) bool {
	header = strings.TrimSpace(header)
	if header == "" {
		return false
	}
	if header == "*" {
		return true
	}
	for _, candidate := range strings.Split(header, ",") {
		if weakETagEqual(candidate, etag) {
			return true
		}
	}
	return false
}

// weakETagEqual compares one candidate entity-tag against ours using RFC 9110
// §8.8.3.2 weak comparison: strip any "W/" prefix from either side, then require
// the opaque quoted forms to be byte-identical.
func weakETagEqual(candidate, etag string) bool {
	return strings.TrimPrefix(strings.TrimSpace(candidate), "W/") ==
		strings.TrimPrefix(etag, "W/")
}

// setDiscoveryHeaders applies the caching and CORS headers a public discovery
// document needs. etag comes from discoveryETag and is passed in rather than
// recomputed, so the header and the If-None-Match comparison cannot disagree.
//
// Wildcard CORS for the same reason jwks.go sets it: the document is specified
// to be fetched by arbitrary relying parties, including browser-side ones, and
// it contains nothing origin-sensitive.
func (h *OIDCHandler) setDiscoveryHeaders(c echo.Context, etag string) {
	head := c.Response().Header()
	head.Set("Access-Control-Allow-Origin", "*")
	head.Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	head.Set("Cache-Control", "public, max-age="+strconv.Itoa(discoveryCacheMaxAge))
	head.Set("ETag", etag)
	head.Set("Content-Type", "application/json")
}
