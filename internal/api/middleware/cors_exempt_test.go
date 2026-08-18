package middleware

import (
	"strings"
	"testing"

	"github.com/engineersmind/emc-auth-server/internal/api/paths"
)

// ---------------------------------------------------------------------------
// CORS exemption vs the real route paths — from the Copilot review on PR #111.
//
// This package used to declare its own copies of the two well-known suffixes, so
// moving either endpoint could drop its CORS exemption with nothing failing at
// compile time. The consequence is not theoretical: a browser-side OIDC client
// fetches discovery first and follows its jwks_uri second, so losing the
// exemption means a 403 at step one and the client never reaches the key set.
//
// The suffixes are now derived in internal/api/paths from the same route
// templates the router registers. These tests are the runtime half of that
// guarantee — a compiler cannot check that a SUFFIX still describes a TEMPLATE.
// ---------------------------------------------------------------------------

// concreteTenantPath renders a route template with a real slug, the way an actual
// request arrives.
func concreteTenantPath(template string) string {
	return paths.TenantPath(template, "acme")
}

func TestPublicCORSExempt_MatchesTheRegisteredRoutes(t *testing.T) {
	// Built from the route constants, not typed out: a literal here would be a
	// fourth copy of the path and would keep passing after a rename, which is the
	// whole failure being guarded against.
	for _, tc := range []struct{ name, template string }{
		{"jwks", paths.TenantJWKS},
		{"discovery", paths.TenantDiscovery},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := concreteTenantPath(tc.template)
			if !isPublicCORSExempt(path) {
				t.Fatalf("%s is a public document but is not CORS-exempt: %q", tc.name, path)
			}
			// Any slug, not just a tidy one — the exemption is suffix-matched
			// precisely because the slug is arbitrary.
			for _, slug := range []string{"a", "tenant-with-dashes", "T3nant123"} {
				if p := paths.TenantPath(tc.template, slug); !isPublicCORSExempt(p) {
					t.Errorf("slug %q not exempt: %q", slug, p)
				}
			}
		})
	}
}

func TestPublicCORSExempt_StaysNarrow(t *testing.T) {
	// The exemption bypasses origin enforcement, so over-matching is the dangerous
	// direction. Everything here must be refused.
	for _, path := range []string{
		"/api/v1/users",
		"/auth/login",
		"/oauth/token",
		"/oauth/authorize",
		"/tenants/acme/applications",
		// A crafted path that merely CONTAINS a well-known suffix must not be
		// exempt — suffix matching is what makes this hold, and it is called out
		// in isPublicCORSExempt's own comment.
		"/tenants/acme/.well-known/jwks.json/../../admin",
		"/tenants/acme/.well-known/jwks.json/extra",
		"/tenants/acme/.well-known/openid-configuration/nested",
		// Near-misses on the document names themselves.
		"/tenants/acme/.well-known/jwks",
		"/tenants/acme/.well-known/openid-config",
		"",
	} {
		if isPublicCORSExempt(path) {
			t.Errorf("path is exempt but must not be: %q", path)
		}
	}
}

func TestPathSuffixes_DescribeTheirTemplates(t *testing.T) {
	// The derivation in internal/api/paths must actually produce a suffix OF the
	// template. If suffixAfterSlug ever returned the whole string, isPublicCORSExempt
	// would match nothing real while every assertion above still looked sane.
	for _, tc := range []struct{ name, template, suffix string }{
		{"jwks", paths.TenantJWKS, paths.JWKSSuffix},
		{"discovery", paths.TenantDiscovery, paths.DiscoverySuffix},
	} {
		if !strings.HasSuffix(tc.template, tc.suffix) {
			t.Errorf("%s: %q is not a suffix of %q", tc.name, tc.suffix, tc.template)
		}
		if strings.Contains(tc.suffix, ":slug") {
			t.Errorf("%s: suffix still carries the placeholder: %q", tc.name, tc.suffix)
		}
		if tc.suffix == tc.template {
			t.Errorf("%s: suffix is the whole template, so nothing was stripped: %q",
				tc.name, tc.suffix)
		}
	}

	// The two documents must not share a suffix, or one exemption would silently
	// cover the other and a single rename could go unnoticed.
	if paths.JWKSSuffix == paths.DiscoverySuffix {
		t.Fatal("JWKS and discovery resolve to the same suffix")
	}
}
