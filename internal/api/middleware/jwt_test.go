package middleware_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/engineersmind/emc-auth-server/internal/api/middleware"
	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/metrics"
	"github.com/engineersmind/emc-auth-server/internal/store"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// jwtEnv seeds the DB and returns a JWTService plus the seed tenant/user ids.
func jwtEnv(t *testing.T) (*auth.JWTService, int64, string) {
	t.Helper()
	pool := testhelper.NewTestDB(t)
	testhelper.CleanupTables(t, pool)
	logger := testhelper.TestLogger()

	ctx := context.Background()
	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}
	var tenantID, userID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM tenants WHERE slug = 'emc' AND deleted_at IS NULL`).Scan(&tenantID); err != nil {
		t.Fatalf("fetch seed tenant: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT id FROM users WHERE email = 'admin@emc.local' AND deleted_at IS NULL`).Scan(&userID); err != nil {
		t.Fatalf("fetch seed user: %v", err)
	}

	jwtSvc, err := auth.NewJWTService(pool, "https://auth.emc.local")
	if err != nil {
		t.Fatalf("NewJWTService: %v", err)
	}

	return jwtSvc, tenantID, strconv.FormatInt(userID, 10)
}

// runWithBearerOn registers path on a real Echo router, guards it with mw, and
// sends one Bearer request through it. Returns the status and the "code" field
// of the JSON error body (empty when the request was allowed through).
//
// A registered route (rather than a bare echo.NewContext) matters: middleware
// reads c.Path() for the metric's route label, and c.Path() is the route
// template — empty unless the router actually matched a registered route.
func runWithBearerOn(mw echo.MiddlewareFunc, path, token string) (int, string) {
	e := echo.New()
	e.GET(path, func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
	}, mw)

	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	var body map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec.Code, body["code"]
}

// runWithBearer is the common case: an admin-style route path.
func runWithBearer(mw echo.MiddlewareFunc, token string) (int, string) {
	return runWithBearerOn(mw, "/api/v1/tenants", token)
}

// TestJWTRequired_AudienceGate is the route-level half of issue #84: the
// grant allow-list a route is mounted with decides which token types may
// reach it at all, before any permission check runs.
//
// The two rows that matter most: a service (M2M) token is accepted on admin
// routes — machine clients are legitimate callers there, so excluding it would
// break the client_credentials integration path — yet the same token is refused
// on user self-service routes, which assume a real user.
func TestJWTRequired_AudienceGate(t *testing.T) {
	jwtSvc, tenantID, userIDStr := jwtEnv(t)
	ctx := context.Background()

	claims := func() *auth.Claims {
		return &auth.Claims{
			UserID:      userIDStr,
			TenantID:    strconv.FormatInt(tenantID, 10),
			Email:       "admin@emc.local",
			Role:        "super_admin",
			Permissions: []string{"admin:access"},
		}
	}

	sign := func(grant string) string {
		token, err := jwtSvc.Sign(ctx, tenantID, auth.AudienceAPI, grant, claims())
		if err != nil {
			t.Fatalf("Sign(%s): %v", grant, err)
		}
		return token
	}

	userToken := sign(auth.GrantPassword)
	m2mToken := sign(auth.GrantClientCredentials)
	// An unknown grant, standing in for what "emc-auth-server" used to stand in
	// for: a validly signed token this server's route policy cannot place. It
	// must be refused everywhere rather than falling through to a default.
	legacyToken := sign("emc-auth-unknown-grant")

	mgmtToken, err := jwtSvc.SignManagement(ctx, &auth.APIKeyIdentity{
		KeyID:       7,
		TenantID:    tenantID,
		Name:        "ci-key",
		Permissions: []string{"apps:read"},
	})
	if err != nil {
		t.Fatalf("SignManagement: %v", err)
	}

	agentToken, err := jwtSvc.SignAgent(ctx, &auth.AgentIdentity{
		AgentID:  uuid.New(),
		TenantID: tenantID,
		Name:     "report-bot",
	})
	if err != nil {
		t.Fatalf("SignAgent: %v", err)
	}

	// Mirrors the real wiring in routes.go — the same named sets, not a copy of
	// their contents, so a grant added to auth.HumanGrants is exercised here
	// automatically instead of drifting out of sync with the routes.
	adminGrants := middleware.Grants(auth.HumanGrants, auth.AdminGrants, auth.MachineGrants)
	userGrants := auth.HumanGrants

	tests := []struct {
		name     string
		grants   []string
		token    string
		wantCode int
	}{
		{"admin route accepts user token", adminGrants, userToken, http.StatusOK},
		{"admin route accepts management token", adminGrants, mgmtToken, http.StatusOK},
		{"admin route accepts m2m token", adminGrants, m2mToken, http.StatusOK},
		{"admin route rejects agent token", adminGrants, agentToken, http.StatusUnauthorized},
		{"admin route rejects unknown grant", adminGrants, legacyToken, http.StatusUnauthorized},

		{"user route accepts user token", userGrants, userToken, http.StatusOK},
		{"user route rejects m2m token", userGrants, m2mToken, http.StatusUnauthorized},
		{"user route rejects management token", userGrants, mgmtToken, http.StatusUnauthorized},
		{"user route rejects agent token", userGrants, agentToken, http.StatusUnauthorized},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mw := middleware.JWTRequired(jwtSvc, tc.grants...)
			status, code := runWithBearer(mw, tc.token)
			if status != tc.wantCode {
				t.Errorf("status = %d (code %q), want %d", status, code, tc.wantCode)
			}
			// A wrong-audience rejection must be indistinguishable from any
			// other bad token, so a caller cannot probe token types.
			if tc.wantCode == http.StatusUnauthorized && code != "token_invalid" {
				t.Errorf("error code = %q, want %q", code, "token_invalid")
			}
		})
	}
}

// TestAudienceRejection_IsCounted guards the observability wiring on BOTH
// middlewares. JWTRenew (user self-service routes) is the one that matters most
// — a machine token tried on /me is the strongest replay signal — and it was
// initially missed because only JWTRequired incremented the counter.
func TestAudienceRejection_IsCounted(t *testing.T) {
	jwtSvc, tenantID, userIDStr := jwtEnv(t)

	m2mToken, err := jwtSvc.Sign(context.Background(), tenantID, auth.AudienceM2M, auth.GrantClientCredentials, &auth.Claims{
		UserID:   userIDStr,
		TenantID: strconv.FormatInt(tenantID, 10),
		Role:     "service",
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// A wrong-audience token is rejected before either middleware reaches the
	// refresh-rotation path, so JWTRenew's service/Redis/audit dependencies are
	// never touched here and can be nil.
	mws := map[string]echo.MiddlewareFunc{
		"JWTRequired": middleware.JWTRequired(jwtSvc, auth.HumanGrants...),
		"JWTRenew": middleware.JWTRenew(
			jwtSvc, nil, nil, middleware.CookieConfig{}, nil, testhelper.TestLogger(),
		),
	}

	for name, mw := range mws {
		t.Run(name, func(t *testing.T) {
			route := "/api/v1/audience-metric-probe/" + name
			counter := metrics.TokenAudienceRejections.WithLabelValues(auth.GrantClientCredentials, route)
			before := testutil.ToFloat64(counter)

			status, code := runWithBearerOn(mw, route, m2mToken)
			if status != http.StatusUnauthorized || code != "token_invalid" {
				t.Fatalf("status = %d code = %q, want 401 token_invalid", status, code)
			}

			after := testutil.ToFloat64(counter)
			if after != before+1 {
				t.Errorf("counter = %v, want %v (rejection was not recorded)", after, before+1)
			}
		})
	}
}

// TestJWTRequired_NoAudiencesFailsClosed pins that mounting the middleware
// without declaring audiences denies every request rather than accepting all of
// them — a misconfiguration must not silently disable the gate.
func TestJWTRequired_NoAudiencesFailsClosed(t *testing.T) {
	jwtSvc, tenantID, userIDStr := jwtEnv(t)

	token, err := jwtSvc.Sign(context.Background(), tenantID, auth.AudienceAPI, auth.GrantPassword, &auth.Claims{
		UserID:   userIDStr,
		TenantID: strconv.FormatInt(tenantID, 10),
		Email:    "admin@emc.local",
		Role:     "super_admin",
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	status, code := runWithBearer(middleware.JWTRequired(jwtSvc), token)
	if status != http.StatusUnauthorized {
		t.Errorf("status = %d (code %q), want %d", status, code, http.StatusUnauthorized)
	}
}

// TestJWTRequired_EmitsBearerChallenge covers RFC 6750 §3 on the path that
// actually rejects most requests: the middleware.
//
// This gap survived a full ticket. handlers/oidc_test.go asserts the challenge
// too, but it calls the handler directly with empty claims — so it exercised
// the one path that already set the header, while the common rejection (a token
// of the wrong audience, refused by JWTRequired before the handler runs) emitted
// no challenge at all. A Postman run against the real route found it. The lesson
// is in the shape of the test, not the fix: a handler-only test cannot see what
// the middleware in front of it does.
func TestJWTRequired_EmitsBearerChallenge(t *testing.T) {
	jwtSvc, tenantID, userIDStr := jwtEnv(t)
	ctx := context.Background()

	// A machine token: validly signed, wrong audience for a user route.
	m2m, err := jwtSvc.Sign(ctx, tenantID, auth.AudienceM2M, auth.GrantClientCredentials, &auth.Claims{
		UserID:   userIDStr,
		TenantID: strconv.FormatInt(tenantID, 10),
		Email:    "svc@emc.local",
		Role:     "service",
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// challengeFor sends one request and returns status + the challenge header.
	challengeFor := func(token string) (int, string) {
		e := echo.New()
		e.GET("/oauth/userinfo", func(c echo.Context) error {
			return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
		}, middleware.JWTRequired(jwtSvc, auth.HumanGrants...))

		req := httptest.NewRequest(http.MethodGet, "/oauth/userinfo", nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		return rec.Code, rec.Header().Get("WWW-Authenticate")
	}

	t.Run("wrong audience", func(t *testing.T) {
		status, challenge := challengeFor(m2m)
		if status != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", status)
		}
		if challenge == "" {
			t.Fatal("401 carries no WWW-Authenticate; RFC 6750 §3 requires one, " +
				"and clients that read it will retry the dead token instead of re-authenticating")
		}
		if !strings.Contains(challenge, `error="invalid_token"`) {
			t.Errorf("challenge = %q, want error=\"invalid_token\"", challenge)
		}
		// Issue #84: the challenge must not reveal that the token was merely of
		// the wrong TYPE. That is the oracle the generic JSON body withholds.
		for _, leak := range []string{"audience", "aud", auth.AudienceM2M} {
			if strings.Contains(strings.ToLower(challenge), strings.ToLower(leak)) {
				t.Errorf("challenge %q leaks %q — it must be indistinguishable "+
					"from any other invalid token", challenge, leak)
			}
		}
	})

	t.Run("no credential at all", func(t *testing.T) {
		status, challenge := challengeFor("")
		if status != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", status)
		}
		if !strings.HasPrefix(challenge, "Bearer ") {
			t.Errorf("challenge = %q, want a Bearer challenge", challenge)
		}
		// RFC 6750 §3.1: with no credential there is no failed credential to
		// describe, so the challenge SHOULD NOT carry an error code.
		if strings.Contains(challenge, "error=") {
			t.Errorf("challenge = %q; §3.1 says omit the error code when the "+
				"request carried no authentication information", challenge)
		}
	})

	t.Run("garbage token", func(t *testing.T) {
		status, challenge := challengeFor("not.a.jwt")
		if status != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", status)
		}
		if !strings.Contains(challenge, `error="invalid_token"`) {
			t.Errorf("challenge = %q, want error=\"invalid_token\"", challenge)
		}
	})

	// RFC 6750 §3, from the Copilot review on PR #111. Asserted on all three
	// rejection shapes rather than one, because they leave unauthorized() by
	// different call sites and a header set on only some of them is the failure
	// mode worth catching. Every rejection is a 401 regardless of cause, so a
	// cached one would answer a different caller's request with this caller's
	// authentication outcome.
	t.Run("cache directives on every rejection", func(t *testing.T) {
		for _, tc := range []struct{ name, token string }{
			{"wrong audience", m2m},
			{"no credential at all", ""},
			{"garbage token", "not.a.jwt"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				e := echo.New()
				e.GET("/oauth/userinfo", func(c echo.Context) error {
					return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
				}, middleware.JWTRequired(jwtSvc, auth.HumanGrants...))

				req := httptest.NewRequest(http.MethodGet, "/oauth/userinfo", nil)
				if tc.token != "" {
					req.Header.Set("Authorization", "Bearer "+tc.token)
				}
				rec := httptest.NewRecorder()
				e.ServeHTTP(rec, req)

				if rec.Code != http.StatusUnauthorized {
					t.Fatalf("status = %d, want 401", rec.Code)
				}
				if got := rec.Header().Get("Cache-Control"); got != "no-store" {
					t.Errorf("Cache-Control = %q, want \"no-store\"", got)
				}
				if got := rec.Header().Get("Pragma"); got != "no-cache" {
					t.Errorf("Pragma = %q, want \"no-cache\"", got)
				}
			})
		}
	})
}
