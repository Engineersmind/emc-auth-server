package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/labstack/echo/v4"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/store"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// ---------------------------------------------------------------------------
// Issue #96: GET /api/v1/auth/apps/me — the app_id boundary, enforced server-side.
//
// The contract under test is narrow and specific: given a token that has ALREADY
// passed signature/tenant/expiry/audience verification (jwtRenew does that, and
// this route is mounted behind the same middleware as /auth/me), does the handler
// correctly decide whether that token was issued FOR the application presenting
// it?
//
// Tests set claims directly via c.Set("user", …), which is exactly what jwtRenew
// does. That isolates the one thing #96 adds instead of re-testing middleware
// that is already covered elsewhere.
// ---------------------------------------------------------------------------

// appMeFixture creates two applications in the SAME tenant — the configuration
// where cross-application token reuse becomes possible, and the case the old
// consumer-side check existed to catch.
type appMeFixture struct {
	handler  *AuthHandler
	tenantID int64
	appA     *auth.AppResult // the "correct" application
	appB     *auth.AppResult // a sibling application in the same tenant
	otherApp *auth.AppResult // an application in a DIFFERENT tenant
}

func newAppMeFixture(t *testing.T) *appMeFixture {
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
		`SELECT id FROM tenants WHERE slug = 'emc' AND deleted_at IS NULL`,
	).Scan(&tenantID); err != nil {
		t.Fatalf("fetch seed tenant: %v", err)
	}

	// A second tenant, for the cross-tenant case.
	var otherTenantID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenants (name, slug, jwt_secret, is_active)
		VALUES ('Other96', 'other-96', $1, true)
		RETURNING id`, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	).Scan(&otherTenantID); err != nil {
		t.Fatalf("insert second tenant: %v", err)
	}

	appSvc := auth.NewApplicationService(pool, logger)
	mk := func(tid int64, name string) *auth.AppResult {
		app, err := appSvc.CreateApplication(ctx, tid, name, "web", nil)
		if err != nil {
			t.Fatalf("CreateApplication(%s): %v", name, err)
		}
		return app
	}

	jwtSvc := auth.NewJWTService(pool, "https://auth.emc.local")
	authSvc := auth.NewAuthService(pool, jwtSvc, logger)

	h := NewAuthHandler(authSvc, nil, nil, logger).
		WithApplications(appSvc).
		WithJWT(jwtSvc)

	return &appMeFixture{
		handler:  h,
		tenantID: tenantID,
		appA:     mk(tenantID, "pm-app-a"),
		appB:     mk(tenantID, "pm-app-b"),
		otherApp: mk(otherTenantID, "pm-app-other-tenant"),
	}
}

// claimsFor builds the claim set jwtRenew would have placed in the context for a
// token minted through the given application.
func claimsFor(tenantID int64, appID string) *auth.Claims {
	return &auth.Claims{
		UserID:      "42",
		TenantID:    strconv.FormatInt(tenantID, 10),
		AppID:       appID,
		Email:       "user@example.com",
		Role:        "user",
		Permissions: []string{},
	}
}

// callAppMe invokes the handler with the given claims and client credentials.
// Passing nil claims models an unauthenticated request; empty clientID models a
// missing X-Client-Authorization header.
func (f *appMeFixture) callAppMe(t *testing.T, claims *auth.Claims, clientID, clientSecret string) *httptest.ResponseRecorder {
	t.Helper()

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/apps/me", nil)
	if clientID != "" || clientSecret != "" {
		req.Header.Set(appClientAuthHeader,
			"Basic "+base64.StdEncoding.EncodeToString([]byte(clientID+":"+clientSecret)))
	}
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	if claims != nil {
		c.Set("user", claims) // what jwtRenew does on success
	}

	if err := f.handler.AppMe(c); err != nil {
		t.Fatalf("AppMe returned a transport error: %v", err)
	}
	return rec
}

// TestAppMe_AppScopeEnforcement is the acceptance matrix from issue #96.
func TestAppMe_AppScopeEnforcement(t *testing.T) {
	f := newAppMeFixture(t)
	appAID := f.appA.ID

	t.Run("correct application and matching token → 200", func(t *testing.T) {
		rec := f.callAppMe(t, claimsFor(f.tenantID, appAID), f.appA.ClientID, f.appA.ClientSecret)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200. body=%s", rec.Code, rec.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if body["email"] != "user@example.com" {
			t.Errorf("email = %v, want the /auth/me payload shape", body["email"])
		}
	})

	// THE core case. Two applications, one tenant, one token. Before #96 this
	// returned 200 — the server had nothing to compare app_id against.
	t.Run("token from a DIFFERENT app in the SAME tenant → 401", func(t *testing.T) {
		rec := f.callAppMe(t, claimsFor(f.tenantID, appAID), f.appB.ClientID, f.appB.ClientSecret)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401 — application A's token was accepted by application B", rec.Code)
		}
	})

	t.Run("token from a different tenant → 401", func(t *testing.T) {
		rec := f.callAppMe(t, claimsFor(f.tenantID, appAID), f.otherApp.ClientID, f.otherApp.ClientSecret)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	})

	// First-party admin and browser tokens carry an empty app_id by design. If
	// empty were treated as "matches anything", this endpoint would look enforced
	// while accepting exactly the tokens it must refuse.
	t.Run("empty app_id (first-party admin token) → 401", func(t *testing.T) {
		rec := f.callAppMe(t, claimsFor(f.tenantID, ""), f.appA.ClientID, f.appA.ClientSecret)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401 — a first-party token must not pass an app-scoped endpoint", rec.Code)
		}
	})

	t.Run("wrong client secret → 401", func(t *testing.T) {
		rec := f.callAppMe(t, claimsFor(f.tenantID, appAID), f.appA.ClientID, "not-the-secret")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	})

	t.Run("unknown client_id → 401", func(t *testing.T) {
		rec := f.callAppMe(t, claimsFor(f.tenantID, appAID), "app_does_not_exist", "whatever")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	})

	t.Run("missing client credentials → 401", func(t *testing.T) {
		rec := f.callAppMe(t, claimsFor(f.tenantID, appAID), "", "")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	})

	t.Run("no verified token → 401", func(t *testing.T) {
		rec := f.callAppMe(t, nil, f.appA.ClientID, f.appA.ClientSecret)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	})
}

// TestAppMe_RejectionsAreIndistinguishable is the no-oracle guarantee, carried
// over from #84's philosophy.
//
// If "wrong application" looked different from "bad client secret", the endpoint
// would become a probe: a caller holding a token could enumerate client_ids and
// learn which application the token belongs to. Every rejection must be
// byte-identical.
func TestAppMe_RejectionsAreIndistinguishable(t *testing.T) {
	f := newAppMeFixture(t)
	appAID := f.appA.ID

	cases := []struct {
		name                   string
		claims                 *auth.Claims
		clientID, clientSecret string
	}{
		{"wrong app", claimsFor(f.tenantID, appAID), f.appB.ClientID, f.appB.ClientSecret},
		{"wrong secret", claimsFor(f.tenantID, appAID), f.appA.ClientID, "wrong"},
		{"unknown client", claimsFor(f.tenantID, appAID), "app_nope", "wrong"},
		{"empty app_id", claimsFor(f.tenantID, ""), f.appA.ClientID, f.appA.ClientSecret},
		{"cross tenant", claimsFor(f.tenantID, appAID), f.otherApp.ClientID, f.otherApp.ClientSecret},
		{"no credentials", claimsFor(f.tenantID, appAID), "", ""},
	}

	var reference string
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := f.callAppMe(t, tc.claims, tc.clientID, tc.clientSecret)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", rec.Code)
			}
			body := rec.Body.String()
			if i == 0 {
				reference = body
				// Confirm the shape is the documented one, not just self-consistent.
				if !jsonHasCode(t, body, "token_invalid") {
					t.Errorf(`body = %s, want code "token_invalid"`, body)
				}
				return
			}
			if body != reference {
				t.Errorf("rejection body differs between reasons — this is an oracle.\n got: %s\nwant: %s", body, reference)
			}
		})
	}
}

func jsonHasCode(t *testing.T, body, want string) bool {
	t.Helper()

	var parsed map[string]string
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		t.Fatalf("unmarshal %q: %v", body, err)
	}
	return parsed["code"] == want
}

// TestAppMe_UnconfiguredAppServiceFailsClosed covers the misconfiguration path.
// An endpoint whose only purpose is to perform a check must refuse rather than
// serve when it cannot perform it.
func TestAppMe_UnconfiguredAppServiceFailsClosed(t *testing.T) {
	h := NewAuthHandler(nil, nil, nil, testhelper.TestLogger()) // no WithApplications

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/apps/me", nil)
	req.Header.Set(appClientAuthHeader, "Basic "+base64.StdEncoding.EncodeToString([]byte("app_x:secret")))
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set("user", claimsFor(1, "1"))

	if err := h.AppMe(c); err != nil {
		t.Fatalf("AppMe transport error: %v", err)
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 — must fail closed when app scope cannot be checked", rec.Code)
	}
}

// TestClientCredentialsFromHeader covers the parser now that it reads an
// arbitrary header. The Authorization-specific behaviour is already covered by
// TestClientCredentialsFromBasicAuth; this pins the generalisation, in particular
// that the two headers do not read each other.
func TestClientCredentialsFromHeader(t *testing.T) {
	valid := "Basic " + base64.StdEncoding.EncodeToString([]byte("app_abc:s3cret"))

	t.Run("reads the named header", func(t *testing.T) {
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set(appClientAuthHeader, valid)
		c := e.NewContext(req, httptest.NewRecorder())

		id, secret, ok, err := clientCredentialsFromHeader(c, appClientAuthHeader)
		if err != nil || !ok {
			t.Fatalf("ok=%v err=%v, want ok with no error", ok, err)
		}
		if id != "app_abc" || secret != "s3cret" {
			t.Errorf("got (%q, %q), want (app_abc, s3cret)", id, secret)
		}
	})

	// The whole reason a second header exists: Authorization is occupied by the
	// user's Bearer token, and the two must not be confused for each other.
	t.Run("does not read Authorization when asked for the client header", func(t *testing.T) {
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set(echo.HeaderAuthorization, valid) // credentials in the WRONG header
		c := e.NewContext(req, httptest.NewRecorder())

		if _, _, ok, err := clientCredentialsFromHeader(c, appClientAuthHeader); ok || err != nil {
			t.Errorf("ok=%v err=%v — must not fall back to Authorization", ok, err)
		}
	})

	t.Run("ignores a Bearer value in the client header", func(t *testing.T) {
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set(appClientAuthHeader, "Bearer some.jwt.token")
		c := e.NewContext(req, httptest.NewRecorder())

		if _, _, ok, err := clientCredentialsFromHeader(c, appClientAuthHeader); ok || err != nil {
			t.Errorf("ok=%v err=%v, want not-present with no error", ok, err)
		}
	})
}

// TestAppMe_RejectsMachineTokens closes a hole that only exists because audience
// validation is not in place yet (#84).
//
// On this branch every token type is minted with the same aud
// ("emc-auth-server"), so audience cannot tell a client_credentials service token
// from a real login — that is the #84 bug. A service token carries a valid
// app_id, so presented with its OWN application's credentials it would satisfy
// every other check here and receive a user profile for an identity that has no
// user: empty email, user_id holding a client id.
//
// The endpoint answers "who is the signed-in person". A token representing no
// person must be refused.
func TestAppMe_RejectsMachineTokens(t *testing.T) {
	f := newAppMeFixture(t)

	// The shape IssueServiceToken produces: role "service", empty email,
	// user_id = client_id, and a legitimate app_id.
	serviceClaims := &auth.Claims{
		UserID:      f.appA.ClientID,
		TenantID:    strconv.FormatInt(f.tenantID, 10),
		AppID:       f.appA.ID,
		Email:       "",
		Role:        "service",
		Permissions: []string{"users:read"},
	}

	t.Run("service token with its own app credentials → 401", func(t *testing.T) {
		rec := f.callAppMe(t, serviceClaims, f.appA.ClientID, f.appA.ClientSecret)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401 — a machine token received a user profile", rec.Code)
		}
	})

	// Email is the general form of the same check: any token with no user
	// identity behind it, whatever its role happens to say.
	t.Run("token with empty email → 401", func(t *testing.T) {
		noEmail := claimsFor(f.tenantID, f.appA.ID)
		noEmail.Email = ""
		rec := f.callAppMe(t, noEmail, f.appA.ClientID, f.appA.ClientSecret)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	})
}
