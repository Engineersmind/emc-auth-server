package handlers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/store"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// ---------------------------------------------------------------------------
// Issue #7b: GET /tenants/:slug/.well-known/openid-configuration.
//
// The property under test is not "the JSON has the right keys" — it is that a
// relying party handed nothing but an issuer URL ends up able to verify a token
// this server minted. That chain is issuer → discovery → jwks_uri → key → token,
// and every link is exercised below, the last one by go-oidc rather than by us.
//
// Everything here runs against a real database and a real HTTP server, because
// the failure this ticket prevents is a document that disagrees with the running
// router — which a handler-only test, calling the handler directly, cannot see.
// ---------------------------------------------------------------------------

// discoveryEnv is a running auth server: real routes, real signing keys, and a
// base URL that is the server's own address, so an issuer minted into a token is
// a URL that can actually be fetched.
type discoveryEnv struct {
	t        *testing.T
	ctx      context.Context
	pool     *pgxpool.Pool
	server   *httptest.Server
	echo     *echo.Echo
	jwtSvc   *auth.JWTService
	base     string
	tenantID int64
	slug     string
	userID   string
}

// newDiscoveryEnv seeds the database and starts a server exposing exactly the
// two routes that make up the discovery chain.
//
// The listener is created before the handler so the base URL is known up front:
// the resolver must be built with the server's real address, or the document
// would advertise an issuer nobody can reach and the go-oidc gate below would be
// testing a fiction.
func newDiscoveryEnv(t *testing.T) *discoveryEnv {
	t.Helper()

	pool := testhelper.NewTestDB(t)
	testhelper.CleanupTables(t, pool)

	ctx := context.Background()
	logger := testhelper.TestLogger()
	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}

	env := &discoveryEnv{t: t, ctx: ctx, pool: pool, slug: "emc"}

	var userID int64
	if err := pool.QueryRow(ctx,
		`SELECT id FROM tenants WHERE slug = 'emc' AND deleted_at IS NULL`,
	).Scan(&env.tenantID); err != nil {
		t.Fatalf("fetch seed tenant: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`SELECT id FROM users WHERE email = 'admin@emc.local' AND deleted_at IS NULL`,
	).Scan(&userID); err != nil {
		t.Fatalf("fetch seed user: %v", err)
	}
	env.userID = strconv.FormatInt(userID, 10)

	srv := httptest.NewUnstartedServer(nil)
	env.base = "http://" + srv.Listener.Addr().String()

	resolver, err := auth.NewTenantIssuerResolver(pool, env.base)
	if err != nil {
		t.Fatalf("NewTenantIssuerResolver: %v", err)
	}

	// A real encryption key rather than the development zero-key fallback, so
	// the RS256 path under test is the production one.
	box, err := auth.NewSecretBox(strings.Repeat("ab", 32), "development",
		"JWT_SIGNING_KEY_ENCRYPTION_KEY_TEST", logger)
	if err != nil {
		t.Fatalf("NewSecretBox: %v", err)
	}
	keys, err := auth.NewSigningKeyService(pool, box, logger)
	if err != nil {
		t.Fatalf("NewSigningKeyService: %v", err)
	}

	jwtSvc, err := auth.NewJWTService(pool, "https://legacy.invalid")
	if err != nil {
		t.Fatalf("NewJWTService: %v", err)
	}
	env.jwtSvc = jwtSvc.WithSigningKeys(keys).WithTenantIssuers(resolver)

	e := echo.New()
	oidcHandler := NewOIDCHandler(pool, resolver, logger)
	jwksHandler := NewJWKSHandler(pool, keys, logger)
	// Registered from the same constants routes.go uses. If those change, this
	// test server changes with them — which is the point of the constants.
	e.GET(PathTenantDiscovery, oidcHandler.Discovery)
	e.GET(PathTenantJWKS, jwksHandler.GetTenantJWKS)
	env.echo = e

	srv.Config.Handler = e
	srv.Start()
	t.Cleanup(srv.Close)
	env.server = srv

	return env
}

// issuerURL is the issuer a client would be configured with for this tenant.
func (e *discoveryEnv) issuerURL() string {
	return e.base + "/tenants/" + e.slug
}

// httpResult is a fully-read response. The body is consumed and closed inside
// get, so no caller holds an open one — a test that fails mid-assertion would
// otherwise leak a connection into the next test.
type httpResult struct {
	status int
	header http.Header
	body   []byte
}

// get issues a GET against the fixture's own test server.
//
// Every request in this file goes through here so there is exactly one place
// that reads and closes a body.
func (e *discoveryEnv) get(url, ifNoneMatch string) httpResult {
	e.t.Helper()

	req, err := http.NewRequestWithContext(e.ctx, http.MethodGet, url, nil)
	if err != nil {
		e.t.Fatalf("build request for %s: %v", url, err)
	}
	if ifNoneMatch != "" {
		req.Header.Set("If-None-Match", ifNoneMatch)
	}

	// #nosec G704 -- url is always derived from e.base, which is this test
	// server's own listener address. There is no external input here.
	resp, err := e.server.Client().Do(req)
	if err != nil {
		e.t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		e.t.Fatalf("read body of %s: %v", url, err)
	}
	return httpResult{status: resp.StatusCode, header: resp.Header, body: body}
}

// fetchDocument GETs a tenant's discovery document and decodes it.
func (e *discoveryEnv) fetchDocument(slug string) (OIDCDiscoveryDocument, httpResult) {
	e.t.Helper()

	res := e.get(e.base+tenantPath(PathTenantDiscovery, slug), "")

	var doc OIDCDiscoveryDocument
	if res.status == http.StatusOK {
		if err := json.Unmarshal(res.body, &doc); err != nil {
			e.t.Fatalf("decode document: %v", err)
		}
	}
	return doc, res
}

// signAccessToken mints a real user access token for the fixture's tenant.
func (e *discoveryEnv) signAccessToken() string {
	e.t.Helper()

	token, err := e.jwtSvc.Sign(e.ctx, e.tenantID, auth.AudienceAPI, &auth.Claims{
		UserID:   e.userID,
		TenantID: strconv.FormatInt(e.tenantID, 10),
		Email:    "admin@emc.local",
		Role:     "super_admin",
	})
	if err != nil {
		e.t.Fatalf("Sign: %v", err)
	}
	return token
}

// parseUnverified reads a token's header and claims without checking the
// signature. These tests assert on what was MINTED, which is a different
// question from whether it verifies — and verifying here would need the very
// key set one of the tests is trying to prove is reachable.
func parseUnverified(t *testing.T, token string) (*jwt.Token, jwt.MapClaims) {
	t.Helper()

	claims := jwt.MapClaims{}
	parsed, _, err := jwt.NewParser().ParseUnverified(token, claims)
	if err != nil {
		t.Fatalf("ParseUnverified: %v", err)
	}
	return parsed, claims
}

// unverifiedIssuer returns a token's "iss" claim.
func unverifiedIssuer(t *testing.T, token string) string {
	t.Helper()

	_, claims := parseUnverified(t, token)
	iss, ok := claims["iss"].(string)
	if !ok {
		t.Fatalf("token has no string iss claim: %v", claims["iss"])
	}
	return iss
}

// unverifiedKID returns a token's "kid" header.
func unverifiedKID(t *testing.T, token string) string {
	t.Helper()

	parsed, _ := parseUnverified(t, token)
	kid, ok := parsed.Header["kid"].(string)
	if !ok {
		t.Fatalf("token has no string kid header: %v", parsed.Header["kid"])
	}
	return kid
}

// TestDiscovery_IssuerMatchesTokenIssuer is the assertion the whole ticket rests
// on.
//
// OIDC Discovery §4.3 requires the document's "issuer" to equal the issuer of
// the tokens exactly, and every conformant client compares the two byte for
// byte. Comparing against a REAL minted token rather than a recomputed string
// is deliberate: recomputing the expected value from the same helper the handler
// uses would let both drift together and still pass.
func TestDiscovery_IssuerMatchesTokenIssuer(t *testing.T) {
	env := newDiscoveryEnv(t)

	doc, res := env.fetchDocument(env.slug)
	if res.status != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.status)
	}

	tokenIssuer := unverifiedIssuer(t, env.signAccessToken())
	if doc.Issuer != tokenIssuer {
		t.Errorf("document issuer = %q, token iss = %q — a conformant OIDC client "+
			"hard-fails on any difference between these", doc.Issuer, tokenIssuer)
	}
	if doc.Issuer != env.issuerURL() {
		t.Errorf("issuer = %q, want %q (the URL discovery was fetched from)",
			doc.Issuer, env.issuerURL())
	}
}

// TestDiscovery_EndpointsResolve checks every advertised URL against the routes
// actually registered on the router, rather than against a second hardcoded
// list. A hardcoded list would be a copy of the document and would agree with it
// by construction; the router is the only independent authority on what exists.
func TestDiscovery_EndpointsResolve(t *testing.T) {
	env := newDiscoveryEnv(t)

	// The routes this test server mounts are only the two well-known ones — the
	// full router is assembled in package api, which handlers cannot import
	// without a cycle. So the OAuth endpoints are checked against the same
	// constants routes.go registers them from, and the two tenant-scoped ones
	// against the live route table.
	registered := make(map[string]bool)
	for _, r := range env.echo.Routes() {
		registered[r.Path] = true
	}

	doc, _ := env.fetchDocument(env.slug)

	tenantScoped := map[string]string{
		"jwks_uri": doc.JWKSURI,
	}
	for field, advertised := range tenantScoped {
		path := strings.TrimPrefix(advertised, env.base)
		template := strings.Replace(path, "/tenants/"+env.slug+"/", "/tenants/:slug/", 1)
		if !registered[template] {
			t.Errorf("%s advertises %q, which maps to unregistered route %q",
				field, advertised, template)
		}
	}

	fixed := map[string]string{
		"authorization_endpoint": PathOAuthAuthorize,
		"token_endpoint":         PathOAuthToken,
		"userinfo_endpoint":      PathOAuthUserInfo,
		"revocation_endpoint":    PathOAuthRevoke,
	}
	advertised := map[string]string{
		"authorization_endpoint": doc.AuthorizationEndpoint,
		"token_endpoint":         doc.TokenEndpoint,
		"userinfo_endpoint":      doc.UserInfoEndpoint,
		"revocation_endpoint":    doc.RevocationEndpoint,
	}
	for field, wantPath := range fixed {
		want := env.base + wantPath
		if advertised[field] != want {
			t.Errorf("%s = %q, want %q", field, advertised[field], want)
		}
	}
}

// TestDiscovery_JWKSURIServesThisTenantsKeys walks the chain a relying party
// walks: read jwks_uri out of the document, fetch it, and confirm the key set
// returned contains the kid that signed a token for this tenant.
//
// Without this, discovery and JWKS can each be individually correct and still
// not compose — which is precisely the pre-#7a failure mode.
func TestDiscovery_JWKSURIServesThisTenantsKeys(t *testing.T) {
	env := newDiscoveryEnv(t)

	token := env.signAccessToken()
	kid := unverifiedKID(t, token)

	doc, _ := env.fetchDocument(env.slug)

	// Fetched by following the document's own jwks_uri, not by rebuilding the
	// URL — following it is what a relying party does, and rebuilding it here
	// would skip the very step under test.
	res := env.get(doc.JWKSURI, "")
	if res.status != http.StatusOK {
		t.Fatalf("jwks_uri %q returned %d, want 200 — the document advertises a "+
			"URL that does not serve keys", doc.JWKSURI, res.status)
	}

	var set struct {
		Keys []struct {
			KID string `json:"kid"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(res.body, &set); err != nil {
		t.Fatalf("decode jwks: %v", err)
	}
	for _, k := range set.Keys {
		if k.KID == kid {
			return
		}
	}
	t.Errorf("jwks_uri served %d keys, none with kid %q — the key that signed "+
		"this tenant's token is not reachable from its discovery document",
		len(set.Keys), kid)
}

// TestDiscovery_PerTenantIsolation pins the Option A decision (2026-08-06)
// against a later "simplification" to a single global document.
//
// Two tenants must produce two documents with different issuers AND different
// jwks_uris. A global document could satisfy neither: it names one issuer, so it
// is wrong for every tenant but one, and it names one jwks_uri, which would let
// one tenant's verifier accept another tenant's tokens — destroying the
// isolation property per-tenant keys exist to provide (#95).
func TestDiscovery_PerTenantIsolation(t *testing.T) {
	env := newDiscoveryEnv(t)

	var otherID int64
	if err := env.pool.QueryRow(env.ctx, `
		INSERT INTO tenants (name, slug, jwt_secret, is_active)
		VALUES ('Discovery Other', 'discovery-other', 'other-secret', true)
		RETURNING id`,
	).Scan(&otherID); err != nil {
		t.Fatalf("insert second tenant: %v", err)
	}

	first, firstRes := env.fetchDocument(env.slug)
	second, secondRes := env.fetchDocument("discovery-other")

	if firstRes.status != http.StatusOK || secondRes.status != http.StatusOK {
		t.Fatalf("status = %d / %d, want 200 for both",
			firstRes.status, secondRes.status)
	}
	if first.Issuer == second.Issuer {
		t.Errorf("both tenants advertise issuer %q; per-tenant issuers are what "+
			"make discovery resolvable at all (Option A, 2026-08-06)", first.Issuer)
	}
	if first.JWKSURI == second.JWKSURI {
		t.Errorf("both tenants advertise jwks_uri %q; a shared key set would let "+
			"one tenant's verifier accept another tenant's tokens", first.JWKSURI)
	}
	// The endpoints that are genuinely server-wide must NOT differ, or a client
	// would be configured to post codes to a per-tenant URL that does not exist.
	if first.TokenEndpoint != second.TokenEndpoint {
		t.Errorf("token_endpoint differs across tenants: %q vs %q",
			first.TokenEndpoint, second.TokenEndpoint)
	}
}

// TestDiscovery_UnknownSlugReturns404 pins the fail-closed behaviour. Returning
// 200 with a document built from an unverified slug would configure a client
// that mistyped its issuer against a tenant that does not exist — and it would
// cache the result.
func TestDiscovery_UnknownSlugReturns404(t *testing.T) {
	env := newDiscoveryEnv(t)

	_, res := env.fetchDocument("no-such-tenant")
	if res.status != http.StatusNotFound {
		t.Errorf("status = %d, want 404", res.status)
	}
}

// TestDiscovery_InactiveTenantReturns404 covers the second arm of the same
// lookup: a deactivated tenant is indistinguishable from a missing one on this
// unauthenticated endpoint, matching the sibling JWKS route.
func TestDiscovery_InactiveTenantReturns404(t *testing.T) {
	env := newDiscoveryEnv(t)

	if _, err := env.pool.Exec(env.ctx, `
		INSERT INTO tenants (name, slug, jwt_secret, is_active)
		VALUES ('Discovery Disabled', 'discovery-disabled', 'disabled-secret', false)`,
	); err != nil {
		t.Fatalf("insert inactive tenant: %v", err)
	}

	_, res := env.fetchDocument("discovery-disabled")
	if res.status != http.StatusNotFound {
		t.Errorf("status = %d, want 404", res.status)
	}
}

// TestDiscovery_AdvertisesOnlyS256 guards against PKCE downgrade. pkce.go
// refuses "plain" outright; a document offering it would invite a client to
// negotiate down to a method that gives no protection against the attacker PKCE
// exists to stop. Copying a sample document off the internet is the realistic
// way this regresses.
func TestDiscovery_AdvertisesOnlyS256(t *testing.T) {
	env := newDiscoveryEnv(t)

	doc, _ := env.fetchDocument(env.slug)

	want := []string{auth.PKCEMethodS256}
	if len(doc.CodeChallengeMethodsSupported) != 1 ||
		doc.CodeChallengeMethodsSupported[0] != want[0] {
		t.Errorf("code_challenge_methods_supported = %v, want %v — the server "+
			"refuses every other method, so advertising one is a false claim",
			doc.CodeChallengeMethodsSupported, want)
	}
}

// TestDiscovery_OmitsUnimplementedEndpoints fails loudly if someone pads the
// document to "look complete". Every field asserted absent here names a feature
// that does not exist; advertising one sends a conformant client to a 404 inside
// its own SDK, far from the cause.
func TestDiscovery_OmitsUnimplementedEndpoints(t *testing.T) {
	env := newDiscoveryEnv(t)

	res := env.get(env.base+tenantPath(PathTenantDiscovery, env.slug), "")

	// Decoded into a map, not the struct: the struct cannot represent a field it
	// does not declare, so decoding into it would make this test unfalsifiable.
	var raw map[string]any
	if err := json.Unmarshal(res.body, &raw); err != nil {
		t.Fatalf("decode: %v", err)
	}

	for _, field := range []string{
		"end_session_endpoint",
		"check_session_iframe",
		"introspection_endpoint",
		"registration_endpoint",
		"acr_values_supported",
	} {
		if _, present := raw[field]; present {
			t.Errorf("document advertises %q, which this server does not implement", field)
		}
	}

	// The negative capability flags are the opposite case: present, and false.
	for _, field := range []string{
		"claims_parameter_supported",
		"request_parameter_supported",
		"request_uri_parameter_supported",
	} {
		value, present := raw[field]
		if !present {
			t.Errorf("%q is absent; state it explicitly as false so a client does "+
				"not probe the feature", field)
			continue
		}
		if value != false {
			t.Errorf("%q = %v, want false", field, value)
		}
	}
}

// TestDiscovery_CachesWithETag covers the revalidation path. Every OIDC client
// fetches discovery on process start, so a fleet restart is a synchronised
// burst; without a cheap 304 that burst lands on the tenants table.
func TestDiscovery_CachesWithETag(t *testing.T) {
	env := newDiscoveryEnv(t)

	url := env.base + tenantPath(PathTenantDiscovery, env.slug)

	first := env.get(url, "")

	etag := first.header.Get("ETag")
	if etag == "" {
		t.Fatal("no ETag on the first response; clients cannot revalidate")
	}
	if cc := first.header.Get("Cache-Control"); !strings.Contains(cc, "max-age=") {
		t.Errorf("Cache-Control = %q, want a public max-age", cc)
	}
	if origin := first.header.Get("Access-Control-Allow-Origin"); origin != "*" {
		t.Errorf("Access-Control-Allow-Origin = %q, want * — browser-side clients "+
			"fetch discovery from arbitrary origins", origin)
	}

	second := env.get(url, etag)
	if second.status != http.StatusNotModified {
		t.Errorf("revalidation status = %d, want 304", second.status)
	}
	if len(second.body) != 0 {
		t.Errorf("304 carried a %d-byte body; it must be empty", len(second.body))
	}
}

// TestDiscovery_GoOIDCProviderAutoConfigures is the gate that is not us grading
// our own homework.
//
// github.com/coreos/go-oidc is a third-party, spec-implementing library and
// already a direct dependency. It is pointed at nothing but the issuer URL; it
// fetches the discovery document itself, enforces the issuer match itself,
// resolves jwks_uri itself, and verifies a real ID token minted by SignIDToken.
// Every assertion in this file above is our own reading of the specification.
// This one is somebody else's.
func TestDiscovery_GoOIDCProviderAutoConfigures(t *testing.T) {
	env := newDiscoveryEnv(t)

	const clientID = "discovery-conformance-client"

	accessToken := env.signAccessToken()
	idToken, err := env.jwtSvc.SignIDToken(env.ctx,
		auth.IDTokenParams{
			TenantID:      env.tenantID,
			ClientID:      clientID,
			GrantedScopes: []string{auth.ScopeOpenID, auth.ScopeEmail},
			Nonce:         "conformance-nonce",
			AccessToken:   accessToken,
		},
		auth.IDTokenSubject{
			UserID:        env.userID,
			Email:         "admin@emc.local",
			EmailVerified: true,
		},
	)
	if err != nil {
		t.Fatalf("SignIDToken: %v", err)
	}

	ctx := oidc.ClientContext(env.ctx, env.server.Client())

	// This single call is the whole gate: it GETs
	// {issuer}/.well-known/openid-configuration and refuses if the document's
	// issuer is not byte-identical to the URL it was given.
	provider, err := oidc.NewProvider(ctx, env.issuerURL())
	if err != nil {
		t.Fatalf("oidc.NewProvider(%q): %v — a standard OIDC client cannot "+
			"auto-configure against this server", env.issuerURL(), err)
	}

	verified, err := provider.Verifier(&oidc.Config{ClientID: clientID}).Verify(ctx, idToken)
	if err != nil {
		t.Fatalf("verify ID token via the discovered jwks_uri: %v", err)
	}

	if verified.Subject != env.userID {
		t.Errorf("sub = %q, want %q", verified.Subject, env.userID)
	}
	if verified.Issuer != env.issuerURL() {
		t.Errorf("iss = %q, want %q", verified.Issuer, env.issuerURL())
	}

	var claims struct {
		Nonce         string `json:"nonce"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}
	if err := verified.Claims(&claims); err != nil {
		t.Fatalf("read claims: %v", err)
	}
	if claims.Nonce != "conformance-nonce" {
		t.Errorf("nonce = %q, want %q", claims.Nonce, "conformance-nonce")
	}
	if claims.Email != "admin@emc.local" || !claims.EmailVerified {
		t.Errorf("email claims = %q/%v, want admin@emc.local/true",
			claims.Email, claims.EmailVerified)
	}
}
