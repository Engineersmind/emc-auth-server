// Package paths holds the endpoint paths that more than one layer needs to agree
// on.
//
// It exists because of a dependency direction, not a preference for tidiness.
// The router (internal/api), the handlers that publish these paths in the OIDC
// discovery document (internal/api/handlers), and the CORS middleware that must
// exempt two of them (internal/api/middleware) all need the same strings — but
// handlers already imports middleware, so middleware cannot import handlers
// back. Before this package, middleware kept its own private copies of the
// well-known suffixes, and nothing but a reviewer's memory tied them to the
// canonical values.
//
// The property this protects is the load-bearing one of issue #7b. A discovery
// document is AUTHORITATIVE to a relying party: an OIDC client library trusts
// what it reads there over anything in its own configuration. So a document that
// disagrees with the running router is worse than no document at all — the
// failure surfaces inside someone else's SDK, long after the path was moved. The
// same is true one layer down: if the CORS exemption stops matching the route, a
// browser-side client gets a 403 at step one and never reaches the jwks_uri the
// exemption was written for.
//
// With every consumer importing these constants, moving an endpoint is a
// single-line edit that the compiler propagates. Nothing here may be
// re-declared elsewhere.
package paths

import "strings"

// OAuth 2.0 / OIDC endpoint paths, registered by the router and published
// verbatim by the discovery document.
const (
	// OAuthAuthorize is the OAuth 2.0 authorization endpoint (issue #6).
	OAuthAuthorize = "/oauth/authorize"
	// OAuthToken is the RFC 6749 token endpoint (issue #6). Not /auth/token,
	// which survives only as a documented-deprecated JSON alias.
	OAuthToken = "/oauth/token"
	// OAuthUserInfo is the OIDC UserInfo endpoint (issue #7a).
	OAuthUserInfo = "/oauth/userinfo"
	// OAuthRevoke is the RFC 7009 revocation endpoint (issue #6).
	OAuthRevoke = "/oauth/revoke"
)

// Tenant-scoped public documents.
//
// Both carry Echo's ":slug" placeholder so the router and the discovery document
// cannot diverge on the prefix either. TenantPath substitutes it.
const (
	// TenantJWKS is the per-tenant JWKS endpoint (issue #95).
	TenantJWKS = "/tenants/:slug/.well-known/jwks.json"
	// TenantDiscovery is the per-tenant OIDC discovery document (issue #7b).
	TenantDiscovery = "/tenants/:slug/.well-known/openid-configuration"
)

// Suffixes of the two public, credential-free documents.
//
// Derived from the route templates above rather than written out a second time,
// which is the entire point of this package: a change to TenantJWKS or
// TenantDiscovery reaches the CORS exemption without anyone remembering to
// update it.
var (
	// JWKSSuffix is the trailing path of the JWKS document.
	JWKSSuffix = suffixAfterSlug(TenantJWKS)
	// DiscoverySuffix is the trailing path of the discovery document.
	DiscoverySuffix = suffixAfterSlug(TenantDiscovery)
)

// TenantPath substitutes a concrete slug into one of the ":slug" route
// templates, so an absolute URL in the discovery document is derived from the
// exact string the router was registered with.
func TenantPath(template, slug string) string {
	return strings.Replace(template, ":slug", slug, 1)
}

// suffixAfterSlug returns the portion of a tenant-scoped template that follows
// the ":slug" placeholder — "/.well-known/jwks.json" for TenantJWKS.
//
// Suffix matching is what the CORS exemption needs, because the slug is
// arbitrary and cannot be matched literally. Panics on a template with no
// placeholder: these are compile-time constants in this same file, so a miss
// means the constant was edited into a shape this function cannot describe, and
// failing at init is the only way that gets noticed. Returning the whole string
// instead would silently make the exemption match every path.
func suffixAfterSlug(template string) string {
	_, suffix, found := strings.Cut(template, ":slug")
	if !found {
		panic("paths: tenant-scoped template has no :slug placeholder: " + template)
	}
	return suffix
}
