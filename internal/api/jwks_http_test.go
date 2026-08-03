package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"

	"github.com/engineersmind/emc-auth-server/internal/api/handlers"
	mw "github.com/engineersmind/emc-auth-server/internal/api/middleware"
	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/store"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// ---------------------------------------------------------------------------
// Issue #95 Phase 3: the published JWKS endpoint, tested over real HTTP through
// the real middleware stack.
//
// The middleware interaction is the point. TenantCORS is mounted with e.Use, so it
// runs on every route including this one, and with a non-empty GLOBAL_CORS_ORIGINS
// it answers an unknown Origin with a hard 403. For an endpoint whose whole purpose
// is being fetched by relying parties we have never heard of, that would make
// browser-side verification impossible for everyone not manually added to a
// server-wide env var. A unit test on the handler alone would not catch it.
// ---------------------------------------------------------------------------

const jwksTestSlug = "emc"

// jwksTestServer boots an Echo instance mounting the JWKS route behind the same
// TenantCORS middleware routes.go applies, with a deliberately restrictive global
// origin list so the 403 path is live if the exemption regresses.
func jwksTestServer(t *testing.T) (*echo.Echo, *auth.SigningKeyService, int64) {
	t.Helper()

	pool := testhelper.NewTestDB(t)
	testhelper.CleanupTables(t, pool)

	ctx := context.Background()
	logger := testhelper.TestLogger()
	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}

	var tenantID int64
	if err := pool.QueryRow(ctx,
		`SELECT id FROM tenants WHERE slug = $1 AND deleted_at IS NULL`, jwksTestSlug,
	).Scan(&tenantID); err != nil {
		t.Fatalf("fetch seed tenant: %v", err)
	}

	box, err := auth.NewSecretBox(strings.Repeat("ab", 32), "development", "TEST_KEY", logger)
	if err != nil {
		t.Fatalf("NewSecretBox: %v", err)
	}
	keys, err := auth.NewSigningKeyService(pool, box, logger)
	if err != nil {
		t.Fatalf("NewSigningKeyService: %v", err)
	}
	if _, err := keys.EnsureTenantKey(ctx, tenantID); err != nil {
		t.Fatalf("EnsureTenantKey: %v", err)
	}

	e := echo.New()
	// A non-empty global list containing an origin that is NOT the one the test
	// sends: this is the exact configuration that produced the 403 hazard.
	corsSvc := mw.NewTenantCORSService(pool, nil, logger).
		WithGlobalOrigins([]string{"https://console.emc.local"})
	e.Use(mw.TenantCORS(corsSvc))

	h := handlers.NewJWKSHandler(pool, keys, logger)
	e.GET("/tenants/:slug/.well-known/jwks.json", h.GetTenantJWKS, mw.JWKSRateLimiter())

	return e, keys, tenantID
}

// TestJWKS_HostileOriginIsNotForbidden is the acceptance criterion from the issue:
// fetching JWKS with an Origin not in GLOBAL_CORS_ORIGINS must not 403.
func TestJWKS_HostileOriginIsNotForbidden(t *testing.T) {
	e, _, _ := jwksTestServer(t)

	for _, origin := range []string{
		"https://some-tenant-we-never-heard-of.example.com",
		"https://evil.example.com",
		"null", // sandboxed iframe / file:// — a real browser value
	} {
		t.Run(origin, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/tenants/"+jwksTestSlug+"/.well-known/jwks.json", nil)
			req.Header.Set("Origin", origin)
			e.ServeHTTP(rec, req)

			if rec.Code == http.StatusForbidden {
				t.Fatalf("status = 403 %q — TenantCORS is blocking the public JWKS; browser-side verifiers cannot work", rec.Body.String())
			}
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200. body=%s", rec.Code, rec.Body.String())
			}
			if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
				t.Errorf("Access-Control-Allow-Origin = %q, want %q — public key material is not origin-sensitive", got, "*")
			}
		})
	}
}

// TestJWKS_ResponseShape covers the cacheability contract and, most importantly,
// that no private key material reaches the wire.
func TestJWKS_ResponseShape(t *testing.T) {
	e, _, _ := jwksTestServer(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/tenants/"+jwksTestSlug+"/.well-known/jwks.json", nil)
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()

	t.Run("no private key material on the wire", func(t *testing.T) {
		// RFC 7518 §6.3.2 private RSA parameters.
		for _, param := range []string{`"d"`, `"p"`, `"q"`, `"dp"`, `"dq"`, `"qi"`} {
			if strings.Contains(body, param) {
				t.Errorf("response contains private RSA parameter %s:\n%s", param, body)
			}
		}
		if strings.Contains(body, "PRIVATE KEY") {
			t.Error("response contains a PEM private key block")
		}
	})

	t.Run("is a usable key set", func(t *testing.T) {
		var set struct {
			Keys []struct {
				Kid string `json:"kid"`
				Kty string `json:"kty"`
				Alg string `json:"alg"`
				Use string `json:"use"`
				N   string `json:"n"`
				E   string `json:"e"`
			} `json:"keys"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &set); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(set.Keys) == 0 {
			t.Fatal("JWKS has no keys")
		}
		k := set.Keys[0]
		if k.Kty != "RSA" || k.Alg != "RS256" || k.Use != "sig" || k.Kid == "" || k.N == "" || k.E == "" {
			t.Errorf("key is not a complete RS256 signing JWK: %+v", k)
		}
	})

	t.Run("is cacheable and revalidatable", func(t *testing.T) {
		etag := rec.Header().Get("ETag")
		if etag == "" {
			t.Fatal("no ETag — verifiers cannot revalidate cheaply")
		}
		if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "max-age=") {
			t.Errorf("Cache-Control = %q, want a max-age", cc)
		}

		rec2 := httptest.NewRecorder()
		req2 := httptest.NewRequest(http.MethodGet, "/tenants/"+jwksTestSlug+"/.well-known/jwks.json", nil)
		req2.Header.Set("If-None-Match", etag)
		e.ServeHTTP(rec2, req2)
		if rec2.Code != http.StatusNotModified {
			t.Errorf("conditional GET status = %d, want 304", rec2.Code)
		}
	})
}

// TestJWKS_UnknownTenantIs404 keeps the endpoint from confirming which tenants
// exist — it is unauthenticated.
func TestJWKS_UnknownTenantIs404(t *testing.T) {
	e, _, _ := jwksTestServer(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/tenants/no-such-tenant/.well-known/jwks.json", nil)
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

// TestJWKS_ThirdPartyVerificationInSeparateProcess is the decisive acceptance
// criterion from the issue: a real access token must verify in a DIFFERENT process,
// in a DIFFERENT language, using ONLY the published JWKS — no shared secret.
//
// That is the whole point of the feature. Every other test here verifies with our
// own Go code, which could pass even if the published document were subtly wrong
// (a mis-encoded modulus, a kid that does not match, a wrong alg). This one cannot:
// it hands Node nothing but the token and the JWKS URL's contents.
//
// Node's built-in crypto is used deliberately instead of the `jose` npm package —
// it needs no install, so the test runs anywhere Node exists and cannot rot when a
// dependency changes. crypto.createPublicKey({format:'jwk'}) is the same JWK
// import path every third-party library builds on.
func TestJWKS_ThirdPartyVerificationInSeparateProcess(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed — skipping cross-language verification")
	}

	e, keys, tenantID := jwksTestServer(t)
	ctx := context.Background()

	pool := testhelper.NewTestDB(t)
	jwtSvc, err := auth.NewJWTService(pool, "https://auth.emc.local")
	if err != nil {
		t.Fatalf("NewJWTService: %v", err)
	}
	jwtSvc = jwtSvc.WithSigningKeys(keys)

	var userID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM users WHERE email = 'admin@emc.local' AND deleted_at IS NULL`).Scan(&userID); err != nil {
		t.Fatalf("fetch seed user: %v", err)
	}

	token, err := jwtSvc.Sign(ctx, tenantID, auth.AudienceAPI, &auth.Claims{
		UserID:      "1",
		TenantID:    "1",
		Email:       "admin@emc.local",
		Role:        "super_admin",
		Permissions: []string{"admin:access"},
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Fetch the JWKS exactly as an external verifier would — over HTTP, from the
	// published endpoint, not from the key service directly.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/tenants/"+jwksTestSlug+"/.well-known/jwks.json", nil)
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("fetch JWKS: status %d", rec.Code)
	}

	dir := t.TempDir()
	jwksPath := filepath.Join(dir, "jwks.json")
	tokenPath := filepath.Join(dir, "token.txt")
	scriptPath := filepath.Join(dir, "verify.js")

	if err := os.WriteFile(jwksPath, rec.Body.Bytes(), 0o600); err != nil {
		t.Fatalf("write jwks: %v", err)
	}
	if err := os.WriteFile(tokenPath, []byte(token), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	if err := os.WriteFile(scriptPath, []byte(nodeVerifyScript), 0o600); err != nil {
		t.Fatalf("write script: %v", err)
	}

	out, err := exec.Command(node, scriptPath, tokenPath, jwksPath).CombinedOutput()
	if err != nil {
		t.Fatalf("third-party verification FAILED — a real JWT consumer cannot verify our tokens from the published JWKS.\nnode output:\n%s", out)
	}
	if !strings.Contains(string(out), "VERIFIED") {
		t.Fatalf("node did not report success:\n%s", out)
	}
	t.Logf("node verification: %s", strings.TrimSpace(string(out)))
}

// nodeVerifyScript verifies an RS256 JWT against a JWKS using only Node built-ins.
//
// It deliberately re-implements what a JWT library does, step by step, so a failure
// points at which part of our published document is wrong: kid matching, JWK
// import, signature check, then claims.
const nodeVerifyScript = `
const crypto = require('crypto');
const fs = require('fs');

const token = fs.readFileSync(process.argv[2], 'utf8').trim();
const jwks  = JSON.parse(fs.readFileSync(process.argv[3], 'utf8'));

const [h, p, s] = token.split('.');
if (!h || !p || !s) { console.error('malformed JWT'); process.exit(1); }

const header  = JSON.parse(Buffer.from(h, 'base64url').toString());
const payload = JSON.parse(Buffer.from(p, 'base64url').toString());

if (header.alg !== 'RS256') { console.error('alg is ' + header.alg + ', expected RS256'); process.exit(1); }
if (!header.kid)            { console.error('token has no kid');                          process.exit(1); }

// Select the key by kid — the reason kid exists.
const jwk = (jwks.keys || []).find(k => k.kid === header.kid);
if (!jwk) {
  console.error('no JWKS key matches token kid ' + header.kid +
                '; published kids: ' + (jwks.keys || []).map(k => k.kid).join(','));
  process.exit(1);
}

// Import the published public key. Fails loudly if n/e are mis-encoded.
let key;
try {
  key = crypto.createPublicKey({ key: jwk, format: 'jwk' });
} catch (e) {
  console.error('cannot import published JWK: ' + e.message);
  process.exit(1);
}

const ok = crypto.verify('RSA-SHA256', Buffer.from(h + '.' + p), key,
                         Buffer.from(s, 'base64url'));
if (!ok) { console.error('SIGNATURE INVALID'); process.exit(1); }

// A verifier must also be able to rely on the claims it will authorize against.
if (!payload.exp || payload.exp <= Math.floor(Date.now() / 1000)) {
  console.error('token already expired'); process.exit(1);
}
if (payload.aud !== 'emc-auth-api' && !(Array.isArray(payload.aud) && payload.aud.includes('emc-auth-api'))) {
  console.error('unexpected aud: ' + JSON.stringify(payload.aud)); process.exit(1);
}
if (!payload.tenant_id) { console.error('no tenant_id claim'); process.exit(1); }

// Prove the kid really is the RFC 7638 thumbprint of the published key: a verifier
// can recompute it independently, which a random kid would not allow.
const tp = crypto.createHash('sha256')
  .update(JSON.stringify({ e: jwk.e, kty: jwk.kty, n: jwk.n }))
  .digest('base64url');
if (tp !== jwk.kid) {
  console.error('kid is not the RFC 7638 thumbprint: got ' + jwk.kid + ', computed ' + tp);
  process.exit(1);
}

console.log('VERIFIED kid=' + header.kid + ' sub=' + payload.sub +
            ' tenant=' + payload.tenant_id + ' aud=' + JSON.stringify(payload.aud) +
            ' thumbprint=OK');
`
