package middleware_test

// Tests for issue #132's route audience policy: the server's API is two
// surfaces, and the boundary has to hold in both directions.
//
// These are the two assertions the issue calls out as the ones that stand
// between the cutover and an outage:
//
//	GET /auth/me accepts a token whose audience is api://<some-tenant-app>,
//	NOT api://emc-auth. This single test is what stands between the cutover
//	and a 401 on every EMC Insurance request.
//
//	The same token is refused by an admin route.
//
// Driven through real JWTRequired + real minted tokens rather than by injecting
// claims, because the thing under test is the composition: the policy reads
// claims that the JWT guard published, and a test that set them itself could
// pass while the real mounting order was wrong.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/labstack/echo/v4"

	mw "github.com/engineersmind/emc-auth-server/internal/api/middleware"
	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/store"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// TestRouteAudiencePolicy_BoundaryHoldsBothWays is issue #132's route split.
//
// The two directions are asserted against the SAME two tokens, so an outcome
// cannot be explained by the fixtures differing: only the route changes.
func TestRouteAudiencePolicy_BoundaryHoldsBothWays(t *testing.T) {
	pool := testhelper.NewTestDB(t)
	logger := testhelper.TestLogger()
	ctx := t.Context()

	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}
	t.Cleanup(func() { testhelper.CleanupTables(t, pool) })

	var tenantID int64
	if err := pool.QueryRow(ctx,
		`SELECT id FROM tenants WHERE slug = 'emc' AND deleted_at IS NULL`).Scan(&tenantID); err != nil {
		t.Fatalf("fetch seed tenant: %v", err)
	}

	audSvc := auth.NewAudienceService(pool, logger)
	appSvc := auth.NewApplicationService(pool, logger).WithAudiences(audSvc)

	// A tenant-owned application, standing in for EMC Insurance's app 4. Its
	// audience is assigned by the server, exactly as migration 00087 assigns one
	// to every existing client — the integrator never chooses it.
	//
	// The name is uniquified because the audience unique index is GLOBAL, not
	// per-tenant, so a fixed name collides across parallel packages.
	appName := fmt.Sprintf("aud132-policy-%d", time.Now().UnixNano())
	app, err := appSvc.CreateApplication(ctx, tenantID, appName, "m2m", nil)
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}
	if app.Audience == "" {
		t.Fatalf("CreateApplication returned no audience — fixture cannot test the policy")
	}

	jwtSvc, err := auth.NewJWTService(pool, "https://auth.emc.local")
	if err != nil {
		t.Fatalf("NewJWTService: %v", err)
	}

	sign := func(t *testing.T, audience string) string {
		t.Helper()
		token, err := jwtSvc.Sign(ctx, tenantID, audience, auth.GrantPassword, &auth.Claims{
			UserID:   "1",
			TenantID: fmt.Sprint(tenantID),
			Email:    "policy@example.com",
			Role:     "user",
		})
		if err != nil {
			t.Fatalf("Sign(%s): %v", audience, err)
		}
		return token
	}

	// The insurance case: a token whose audience is the tenant's own API.
	tenantToken := sign(t, app.Audience)
	// The console case: a first-party portal session, which #131 assigns
	// AudienceSelf server-side because it carries no client_id.
	selfToken := sign(t, auth.AudienceSelf)

	// Mounted exactly as routes.go mounts them — the guard first so it publishes
	// claims, then the policy. requireGlobal is false, which is the state PR A
	// deploys in: the policy still judges a REAL audience, and only an
	// audience-less token is left to the flags.
	guard := mw.JWTRequired(jwtSvc, auth.HumanGrants...)
	ok := func(c echo.Context) error { return c.NoContent(http.StatusOK) }

	e := echo.New()
	e.GET("/api/v1/auth/me", ok, guard, mw.RequireTenantAudience(audSvc, false))
	e.GET("/api/v1/users", ok, guard, mw.RequireSelfAudience(audSvc, false))

	call := func(t *testing.T, path, token string) int {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+token)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		return rec.Code
	}

	tests := []struct {
		name  string
		path  string
		token string
		want  int
		why   string
	}{
		{
			name: "tenant audience on an identity route", path: "/api/v1/auth/me",
			token: tenantToken, want: http.StatusOK,
			why: "the identity endpoints exist FOR app-scoped tokens; every authenticated " +
				"request emc-insurance-platform makes passes through this one",
		},
		{
			name: "tenant audience on an admin route", path: "/api/v1/users",
			token: tenantToken, want: http.StatusUnauthorized,
			why: "a token minted for a tenant's own API must never reach this server's " +
				"management surface — this is the isolation #132 exists to enforce",
		},
		{
			name: "self audience on an admin route", path: "/api/v1/users",
			token: selfToken, want: http.StatusOK,
			why: "the console authenticates by first-party cookie flow and is assigned " +
				"AudienceSelf; refusing it here locks operators out of the console",
		},
		{
			name: "self audience on an identity route", path: "/api/v1/auth/me",
			token: selfToken, want: http.StatusOK,
			why: "an operator asking who they are must not be refused by the policy that " +
				"protects their own console",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := call(t, tc.path, tc.token); got != tc.want {
				t.Errorf("GET %s = %d, want %d\n  %s", tc.path, got, tc.want, tc.why)
			}
		})
	}
}

// TestClientRequiresAudience_SoftDeletedClientEnforces pins the one place
// #132's per-client read inverts what "no rows" normally means.
//
// From the PR #137 review: the query gained `deleted_at IS NULL` to match the
// convention every other oauth_clients read in that file follows. That predicate
// changes what absence means — a soft-deleted application used to return its
// stored flag and now matches nothing — so reading absence as "this client did
// not opt in" would ACCEPT an audience-less token minted by an application that
// has since been deleted. A predicate added for tidiness would have opened a
// fail-open.
//
// The asymmetry with AudienceInTenant is the thing worth a test rather than only
// a comment: there, "not found" already means refuse, so the same filter fails
// closed on its own. Identical SQL, opposite safety outcomes, and nothing in the
// type system says so.
func TestClientRequiresAudience_SoftDeletedClientEnforces(t *testing.T) {
	pool := testhelper.NewTestDB(t)
	logger := testhelper.TestLogger()
	ctx := t.Context()

	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}
	t.Cleanup(func() { testhelper.CleanupTables(t, pool) })

	var tenantID int64
	if err := pool.QueryRow(ctx,
		`SELECT id FROM tenants WHERE slug = 'emc' AND deleted_at IS NULL`).Scan(&tenantID); err != nil {
		t.Fatalf("fetch seed tenant: %v", err)
	}

	audSvc := auth.NewAudienceService(pool, logger)
	appSvc := auth.NewApplicationService(pool, logger).WithAudiences(audSvc)

	app, err := appSvc.CreateApplication(ctx,
		tenantID, fmt.Sprintf("aud132-softdel-%d", time.Now().UnixNano()), "m2m", nil)
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}
	appRowID, err := strconv.ParseInt(app.ID, 10, 64)
	if err != nil {
		t.Fatalf("parse app id %q: %v", app.ID, err)
	}

	// Live and not opted in — the ordinary case, and the one that must stay false
	// or every consumer would be enforcing before an operator flipped anything.
	required, err := audSvc.ClientRequiresAudience(ctx, tenantID, appRowID)
	if err != nil {
		t.Fatalf("ClientRequiresAudience(live): %v", err)
	}
	if required {
		t.Error("a live client with require_audience=false reports enforcing; " +
			"the per-client rollout would be on for everyone before it was flipped")
	}

	// Soft-delete it. The row still exists and still carries require_audience =
	// false, so a query without the deleted_at predicate would keep saying "not
	// enforcing".
	if _, err := pool.Exec(ctx,
		`UPDATE oauth_clients SET deleted_at = NOW() WHERE id = $1`, appRowID); err != nil {
		t.Fatalf("soft-delete client: %v", err)
	}

	required, err = audSvc.ClientRequiresAudience(ctx, tenantID, appRowID)
	if err != nil {
		t.Fatalf("ClientRequiresAudience(soft-deleted): %v", err)
	}
	if !required {
		t.Error("a soft-deleted client reports NOT enforcing — an audience-less token " +
			"minted by a deleted application would be accepted. Absence must enforce.")
	}

	// A different tenant asking about the same row gets the same fail-closed
	// answer, which is what the tenant_id predicate is for.
	required, err = audSvc.ClientRequiresAudience(ctx, tenantID+99999, appRowID)
	if err != nil {
		t.Fatalf("ClientRequiresAudience(wrong tenant): %v", err)
	}
	if !required {
		t.Error("a row read under the wrong tenant_id reports NOT enforcing; " +
			"the app-scoping predicate must fail closed like every other absence")
	}
}

// TestRouteAudiencePolicy_RefusesAnotherTenantsAudience pins why
// AudienceInTenant is scoped by tenant_id rather than checking the audience
// alone.
//
// A global existence check would answer "yes, some application owns this
// identifier" and admit a token from one tenant presenting another tenant's
// audience — which is #95's isolation property destroyed by the very change
// meant to add one. The token here is signed by the presenting tenant's own key,
// so it is genuinely valid; only the audience belongs elsewhere.
func TestRouteAudiencePolicy_RefusesAnotherTenantsAudience(t *testing.T) {
	pool := testhelper.NewTestDB(t)
	logger := testhelper.TestLogger()
	ctx := t.Context()

	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}
	t.Cleanup(func() { testhelper.CleanupTables(t, pool) })

	var tenantID int64
	if err := pool.QueryRow(ctx,
		`SELECT id FROM tenants WHERE slug = 'emc' AND deleted_at IS NULL`).Scan(&tenantID); err != nil {
		t.Fatalf("fetch seed tenant: %v", err)
	}

	audSvc := auth.NewAudienceService(pool, logger)
	jwtSvc, err := auth.NewJWTService(pool, "https://auth.emc.local")
	if err != nil {
		t.Fatalf("NewJWTService: %v", err)
	}

	// A well-formed identifier that no application in this tenant owns.
	foreign := "api://someone-else/their-api"
	token, err := jwtSvc.Sign(ctx, tenantID, foreign, auth.GrantPassword, &auth.Claims{
		UserID:   "1",
		TenantID: fmt.Sprint(tenantID),
		Email:    "foreign@example.com",
		Role:     "user",
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	e := echo.New()
	e.GET("/api/v1/auth/me", func(c echo.Context) error { return c.NoContent(http.StatusOK) },
		mw.JWTRequired(jwtSvc, auth.HumanGrants...), mw.RequireTenantAudience(audSvc, false))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	req.Header.Set(echo.HeaderAuthorization, "Bearer "+token)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("GET /auth/me with a foreign audience = %d, want 401 — the tenant scope "+
			"on AudienceInTenant is what keeps one tenant's audience from satisfying "+
			"another tenant's route", rec.Code)
	}
}
