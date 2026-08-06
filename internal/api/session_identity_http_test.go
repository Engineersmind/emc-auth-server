package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"

	mw "github.com/engineersmind/emc-auth-server/internal/api/middleware"
	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/store"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// The scenario this exists for, end to end over real HTTP with real signed
// tokens:
//
//	an operator signs in as an admin, opens the dashboard, then in the same
//	browser accepts an invitation and signs in as the invited user. The second
//	login overwrites emc_access_token for the whole origin. The admin tab is
//	still open and still rendering admin UI, but everything it now sends carries
//	the invited user's cookie.
//
// Nothing is wrong with that cookie and authorization stays correct, so no
// existing guard has any reason to complain. What is wrong is the attribution:
// the write lands in the audit log against the wrong person. The tab's
// X-Session-User assertion is what makes the mismatch detectable.
func TestSessionIdentityGuard_OverHTTP(t *testing.T) {
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

	jwtSvc, err := auth.NewJWTService(pool, "https://auth.emc.local")
	if err != nil {
		t.Fatalf("NewJWTService: %v", err)
	}

	// The two identities sharing one browser. Ids are what the guard compares;
	// the email is what the refusal reports back so the UI can name the switch.
	const adminUserID = "101"
	invited := &auth.Claims{
		UserID:   "202",
		TenantID: strconv.FormatInt(tenantID, 10),
		Email:    "invited@example.com",
		Role:     "member",
	}
	invitedToken, err := jwtSvc.Sign(ctx, tenantID, auth.AudienceAPI, invited)
	if err != nil {
		t.Fatalf("sign invited-user token: %v", err)
	}

	// Mounted exactly as the admin group is in routes.go: JWTRequired, no bearer
	// header, credential arriving purely by cookie.
	e := echo.New()
	e.POST("/api/v1/tenants/:tid/users", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"created": "yes"})
	}, mw.JWTRequired(jwtSvc, auth.AudienceAPI))
	e.GET("/api/v1/tenants/:tid/users", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"listed": "yes"})
	}, mw.JWTRequired(jwtSvc, auth.AudienceAPI))

	// call issues a request carrying the invited user's session cookie — the
	// state the browser is actually in after the second login.
	call := func(t *testing.T, method, assertedUser string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, "/api/v1/tenants/1/users", nil)
		req.AddCookie(&http.Cookie{Name: mw.AccessTokenCookie, Value: invitedToken})
		if assertedUser != "" {
			req.Header.Set(mw.SessionUserHeader, assertedUser)
		}
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		return rec
	}

	t.Run("stale admin tab is refused without naming anyone", func(t *testing.T) {
		rec := call(t, http.MethodPost, adminUserID)
		if rec.Code != http.StatusConflict {
			t.Fatalf("status = %d, want 409 — the write executed as the wrong user", rec.Code)
		}
		var body map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode body %q: %v", rec.Body.String(), err)
		}
		if body["code"] != "session_identity_changed" {
			t.Errorf("code = %q, want session_identity_changed", body["code"])
		}
		// The person reading the resulting message is at the stale tab, who on a
		// shared machine is not whoever just signed in.
		if strings.Contains(rec.Body.String(), invited.Email) {
			t.Errorf("refusal disclosed the new identity: %s", rec.Body.String())
		}
	})

	t.Run("the tab that reloaded proceeds", func(t *testing.T) {
		if rec := call(t, http.MethodPost, invited.UserID); rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200 — a correctly-oriented tab must not be blocked (%s)", rec.Code, rec.Body.String())
		}
	})

	t.Run("a client that sends no assertion is unaffected", func(t *testing.T) {
		if rec := call(t, http.MethodPost, ""); rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200 — non-participating clients must keep working", rec.Code)
		}
	})

	t.Run("reads are never blocked", func(t *testing.T) {
		if rec := call(t, http.MethodGet, adminUserID); rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200 — a stale read is self-correcting", rec.Code)
		}
	})

	t.Run("bearer clients are out of scope", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/1/users", nil)
		req.Header.Set("Authorization", "Bearer "+invitedToken)
		req.Header.Set(mw.SessionUserHeader, adminUserID)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200 — a Bearer token cannot be swapped by another tab", rec.Code)
		}
	})
}
