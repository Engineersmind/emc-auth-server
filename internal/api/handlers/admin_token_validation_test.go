package handlers

import (
	"encoding/json"
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

// TestTokenValidationConfig_URIsDerivedFromCanonicalPaths pins the one thing a
// consumer of this block cannot check for itself.
//
// The whole reason the server assembles token_validation rather than letting a
// console build it is that the issuer format and the well-known paths belong
// here. That argument only holds if this block is built from the same constants
// the routes are registered with — a literal "/.well-known/jwks.json" typed in
// by hand would reintroduce exactly the drift it exists to prevent, and would
// keep passing until someone changed the route.
func TestTokenValidationConfig_URIsDerivedFromCanonicalPaths(t *testing.T) {
	const issuer = "https://auth.example.com/tenants/emc"

	cfg := auth.TokenValidationConfig{
		Audience:     "api://emc/payroll",
		Issuer:       issuer,
		JWKSURI:      issuer + paths.JWKSSuffix,
		DiscoveryURI: issuer + paths.DiscoverySuffix,
	}

	// Both documents must sit under the issuer. That containment is what lets a
	// relying party be handed nothing but the issuer URL and configure itself,
	// and it is the property a wrong base URL would break.
	if !strings.HasPrefix(cfg.JWKSURI, issuer+"/") {
		t.Errorf("jwks_uri %q does not sit under the issuer %q", cfg.JWKSURI, issuer)
	}
	if !strings.HasPrefix(cfg.DiscoveryURI, issuer+"/") {
		t.Errorf("discovery_uri %q does not sit under the issuer %q", cfg.DiscoveryURI, issuer)
	}

	// The suffixes are cut from TenantJWKS / TenantDiscovery, so these assertions
	// fail if either route template is renamed without this block following.
	if got := cfg.JWKSURI; got != issuer+"/.well-known/jwks.json" {
		t.Errorf("jwks_uri = %q, want the canonical JWKS path under the issuer", got)
	}
	if got := cfg.DiscoveryURI; got != issuer+"/.well-known/openid-configuration" {
		t.Errorf("discovery_uri = %q, want the canonical discovery path under the issuer", got)
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
