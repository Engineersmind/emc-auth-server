package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog"

	"github.com/engineersmind/emc-auth-server/internal/api"
	"github.com/engineersmind/emc-auth-server/internal/api/handlers"
	"github.com/engineersmind/emc-auth-server/internal/store"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// TestIntrospect_GatedByOrganizationsSwitch drives the real router with
// ORGANIZATIONS_ENABLED off and on. Introspection ships with Organizations: off,
// POST /oauth/introspect is not registered and discovery does not advertise it,
// so a deploy with the switch off adds no public endpoint and leaves every
// integrator's discovery document unchanged. On, both appear together.
//
// why: #180
func TestIntrospect_GatedByOrganizationsSwitch(t *testing.T) {
	pool := testhelper.NewTestDB(t)
	// RegisterRoutes backfills a signing key for every tenant; see
	// console_forgot_password_test.go for why the tables are reset first.
	testhelper.CleanupTables(t, pool)
	rdb := testhelper.NewTestRedis(t)
	ctx := context.Background()
	if err := store.RunSeed(ctx, pool, testhelper.TestLogger()); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}

	const base = "http://localhost:8080"

	for _, tc := range []struct {
		name    string
		enabled bool
	}{
		{"organizations off", false},
		{"organizations on", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := echo.New()
			stop := api.RegisterRoutes(e, api.Deps{
				Logger: zerolog.New(os.Stderr).Level(zerolog.FatalLevel), Pool: pool, Redis: rdb,
				Config: api.RoutesConfig{
					JWTIssuer: "https://auth.test", Env: "test",
					AppBaseURL: base, OIDCIssuerBaseURL: base,
					OrganizationsEnabled: tc.enabled,
				},
			})
			defer stop()

			registered := false
			for _, r := range e.Routes() {
				if r.Method == http.MethodPost && r.Path == handlers.PathOAuthIntrospect {
					registered = true
				}
			}
			if registered != tc.enabled {
				t.Errorf("POST %s registered = %v, want %v", handlers.PathOAuthIntrospect, registered, tc.enabled)
			}

			req := httptest.NewRequest(http.MethodPost, handlers.PathOAuthIntrospect, strings.NewReader("token=x"))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
			req.RemoteAddr = "192.0.2.180:40000"
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, req)
			routed := rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed
			if routed != tc.enabled {
				t.Errorf("POST %s: status %d, want routed=%v (404/405 only when off)",
					handlers.PathOAuthIntrospect, rec.Code, tc.enabled)
			}

			req = httptest.NewRequest(http.MethodGet, "/tenants/emc/.well-known/openid-configuration", nil)
			req.RemoteAddr = "192.0.2.180:40000"
			rec = httptest.NewRecorder()
			e.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("discovery: status %d, want 200: %s", rec.Code, rec.Body.String())
			}
			var doc map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
				t.Fatalf("decode discovery: %v", err)
			}
			got, advertised := doc["introspection_endpoint"]
			if advertised != tc.enabled {
				t.Errorf("discovery advertises introspection_endpoint = %v (present %v), want present %v",
					got, advertised, tc.enabled)
			}
			if tc.enabled && got != base+handlers.PathOAuthIntrospect {
				t.Errorf("introspection_endpoint = %v, want %q", got, base+handlers.PathOAuthIntrospect)
			}
		})
	}
}
