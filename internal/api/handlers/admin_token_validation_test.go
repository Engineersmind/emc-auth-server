package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/labstack/echo/v4"

	"encoding/json"
	"github.com/engineersmind/emc-auth-server/internal/admin"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
	"reflect"
	"strings"
	"testing"

	"github.com/engineersmind/emc-auth-server/internal/api/paths"
	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// TestUpdateApplicationRequest_HasNoAudienceField is the HTTP-layer mirror of
// TestAppUpdate_HasNoAudienceField in the auth package.
//
// The service-layer test cannot catch this one: a handler may accept a field
// the service does not have and quietly drop it, which is exactly what a
// well-meaning "let the form edit the audience" change would produce.
func TestUpdateApplicationRequest_HasNoAudienceField(t *testing.T) {
	typ := reflect.TypeOf(UpdateApplicationRequest{})
	if _, ok := typ.FieldByName("Audience"); ok {
		t.Fatal("UpdateApplicationRequest has an Audience field: the identifier is immutable by " +
			"design and every resource server validating it would break on a change. " +
			"See migration 00087 and issue #131 §4.")
	}
	// Same guard on create: the audience is generated server-side from the
	// tenant and application slugs, never supplied by the caller. A caller-set
	// value would let a tenant choose its own identifier, which is the reserved
	// -namespace escalation that CHECK constraint exists to stop.
	if _, ok := reflect.TypeOf(CreateApplicationRequest{}).FieldByName("Audience"); ok {
		t.Fatal("CreateApplicationRequest has an Audience field: audiences are generated, not " +
			"chosen, so a tenant could otherwise register one in a reserved namespace")
	}
}

// TestTokenValidationConfig_SerialisesEveryField guards the wire contract.
//
// An integrator pastes these values into a JWT library, so a renamed or dropped
// key is a silently broken copy-paste rather than a compile error. The issuer
// especially: audiences are unique per TENANT rather than globally, so a
// consumer that receives an audience and no issuer is being handed the unsafe
// half of the pair.
func TestTokenValidationConfig_SerialisesEveryField(t *testing.T) {
	blob, err := json.Marshal(auth.TokenValidationConfig{
		Audience:     "api://emc/payroll",
		Issuer:       "https://auth.example.com/tenants/emc",
		JWKSURI:      "https://auth.example.com/tenants/emc/.well-known/jwks.json",
		DiscoveryURI: "https://auth.example.com/tenants/emc/.well-known/openid-configuration",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(blob, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"audience", "issuer", "jwks_uri", "discovery_uri"} {
		if v, ok := decoded[key]; !ok || v == "" {
			t.Errorf("token_validation is missing %q — an integrator copying this block would "+
				"configure an incomplete verification", key)
		}
	}
}

// TestAppDetail_TokenValidationOmittedWhenAbsent pins the omitempty.
//
// A block naming an issuer alongside an empty audience is worse than no block:
// it reads as a complete configuration while validating nothing. An application
// created before per-application audiences existed has no audience, and the
// correct answer there is silence.
func TestAppDetail_TokenValidationOmittedWhenAbsent(t *testing.T) {
	blob, err := json.Marshal(auth.AppDetail{ID: "1", Name: "Legacy"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(blob), "token_validation") {
		t.Error("token_validation was serialised on an application that has none")
	}
}

// ─── attachTokenValidation, exercised rather than restated ──────────────────

/*
 * Replaces TestTokenValidationConfig_URIsDerivedFromCanonicalPaths, which built
 * a TokenValidationConfig from the same `issuer + paths.*Suffix` expression it
 * then asserted. That is circular: a wrong tenant, an omitted block or a bad
 * concatenation inside attachTokenValidation left it green, because the handler
 * was never called.
 *
 * These drive the real method against a real resolver, so the assertions are
 * about what an integrator receives.
 */

// newIssuerEnv returns a handler wired to a resolver for one seeded tenant.
// servingBase is APP_BASE_URL; empty means "not configured".
func newIssuerEnv(t *testing.T, issuerBase, servingBase string) (*AdminHandler, int64, string) {
	t.Helper()
	pool := testhelper.NewTestDB(t)
	logger := testhelper.TestLogger()
	ctx := context.Background()
	t.Cleanup(func() { testhelper.CleanupTables(t, pool) })

	slug := fmt.Sprintf("tv-%d", time.Now().UnixNano())
	var tenantID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenants (slug, name, is_active, jwt_secret)
		VALUES ($1, $1, true, 'token-validation-fixture')
		RETURNING id
	`, slug).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}

	resolver, err := auth.NewTenantIssuerResolver(pool, issuerBase)
	if err != nil {
		t.Fatalf("NewTenantIssuerResolver: %v", err)
	}
	h := NewAdminHandler(admin.New(pool, nil, logger), nil, logger).
		WithIssuers(resolver, servingBase)
	return h, tenantID, slug
}

// attach drives the real method and returns what it produced.
func attach(t *testing.T, h *AdminHandler, tenantID int64, audience string) *auth.AppDetail {
	t.Helper()
	ec := echo.New()
	c := ec.NewContext(httptest.NewRequest(http.MethodGet, "/", nil), httptest.NewRecorder())
	app := &auth.AppDetail{Audience: audience}
	h.attachTokenValidation(c, tenantID, app)
	return app
}

// The single-host case: issuer and serving origin agree, so the documents sit
// under the issuer and a relying party handed only `iss` can discover them.
func TestAttachTokenValidation_BuildsDocumentURLsForOneHost(t *testing.T) {
	const base = "https://auth.example.com"
	h, tenantID, slug := newIssuerEnv(t, base, base)

	app := attach(t, h, tenantID, "api://acme/payroll")
	if app.TokenValidation == nil {
		t.Fatal("no token_validation block — an integrator is left to guess the issuer and key set")
	}
	tv := app.TokenValidation

	wantIssuer := base + "/tenants/" + slug
	if tv.Issuer != wantIssuer {
		t.Errorf("issuer = %q, want %q — the wrong tenant here sends a verifier to another tenant's keys", tv.Issuer, wantIssuer)
	}
	if got, want := tv.JWKSURI, wantIssuer+paths.JWKSSuffix; got != want {
		t.Errorf("jwks_uri = %q, want %q", got, want)
	}
	if got, want := tv.DiscoveryURI, wantIssuer+paths.DiscoverySuffix; got != want {
		t.Errorf("discovery_uri = %q, want %q", got, want)
	}
	if tv.Audience != "api://acme/payroll" {
		t.Errorf("audience = %q, want the application's own", tv.Audience)
	}
}

/*
 * Split hosts: the defect this fix addresses.
 *
 * OIDC_ISSUER_BASE_URL and APP_BASE_URL may differ, and warnIssuerHostMismatch
 * states plainly that "JWKS is served from APP_BASE_URL". Building the document
 * URLs from the ISSUER therefore advertised endpoints on a host this server
 * does not answer on, and an integrator following them could not fetch the keys
 * at all — worse than omitting the block, since its whole purpose is to save
 * them guessing.
 *
 * The issuer keeps its own value: it is an identifier compared against the
 * `iss` claim, not a location, and rewriting it to match the document host
 * would break verification instead.
 */
func TestAttachTokenValidation_ServesDocumentsFromTheServingHost(t *testing.T) {
	const issuerBase = "https://id.example.com"
	const servingBase = "https://auth-internal.example.net"
	h, tenantID, slug := newIssuerEnv(t, issuerBase, servingBase)

	tv := attach(t, h, tenantID, "api://acme/payroll").TokenValidation
	if tv == nil {
		t.Fatal("no token_validation block")
	}

	if tv.Issuer != issuerBase+"/tenants/"+slug {
		t.Errorf("issuer = %q, want it rooted at the ISSUER base — it identifies the token, not the document host", tv.Issuer)
	}
	wantDocs := servingBase + "/tenants/" + slug
	if got, want := tv.JWKSURI, wantDocs+paths.JWKSSuffix; got != want {
		t.Errorf("jwks_uri = %q, want %q — a verifier fetching the issuer-rooted URL reaches a host this server does not serve", got, want)
	}
	if got, want := tv.DiscoveryURI, wantDocs+paths.DiscoverySuffix; got != want {
		t.Errorf("discovery_uri = %q, want %q", got, want)
	}
}

// With APP_BASE_URL unset there is nothing better to use, so the issuer origin
// stands — correct for the single-host deployment that omits it.
func TestAttachTokenValidation_FallsBackToTheIssuerOrigin(t *testing.T) {
	const issuerBase = "https://id.example.com"
	h, tenantID, slug := newIssuerEnv(t, issuerBase, "")

	tv := attach(t, h, tenantID, "api://acme/payroll").TokenValidation
	if tv == nil {
		t.Fatal("no token_validation block")
	}
	if got, want := tv.JWKSURI, issuerBase+"/tenants/"+slug+paths.JWKSSuffix; got != want {
		t.Errorf("jwks_uri = %q, want %q", got, want)
	}
}

// A trailing slash on APP_BASE_URL must not produce a doubled separator: the
// resulting URL 404s, and it is the kind of value an operator pastes from a
// browser bar.
func TestAttachTokenValidation_ToleratesATrailingSlash(t *testing.T) {
	h, tenantID, slug := newIssuerEnv(t, "https://id.example.com", "https://auth.example.net/")

	tv := attach(t, h, tenantID, "api://acme/payroll").TokenValidation
	if tv == nil {
		t.Fatal("no token_validation block")
	}
	if strings.Contains(strings.TrimPrefix(tv.JWKSURI, "https://"), "//") {
		t.Errorf("jwks_uri = %q contains a doubled slash", tv.JWKSURI)
	}
	if got, want := tv.JWKSURI, "https://auth.example.net/tenants/"+slug+paths.JWKSSuffix; got != want {
		t.Errorf("jwks_uri = %q, want %q", got, want)
	}
}

// No audience means nothing to validate against, so the correct answer is
// silence rather than a block naming an issuer and an empty audience.
func TestAttachTokenValidation_OmittedWithoutAnAudience(t *testing.T) {
	h, tenantID, _ := newIssuerEnv(t, "https://id.example.com", "https://id.example.com")

	if tv := attach(t, h, tenantID, "").TokenValidation; tv != nil {
		t.Errorf("token_validation present for an application with no audience: %+v", tv)
	}
}
