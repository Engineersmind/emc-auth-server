package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"

	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// One browser has one cookie jar, so signing in as a second user silently
// replaces the session in every open tab. A tab still showing the admin
// dashboard then issues writes carrying the second user's cookie — correctly
// authorized, but attributed to the wrong actor in the audit trail.
//
// X-Session-User is how a tab declares who it believes it is. These tests pin
// both halves of the contract: a stale belief is refused, and everything that is
// not a participating browser session is left completely alone.
func TestCheckSessionIdentity(t *testing.T) {
	claims := &auth.Claims{UserID: "42", Email: "owner@example.com"}

	t.Run("stale belief on a write is refused", func(t *testing.T) {
		rec, reached := runIdentityGuard(t, claims, http.MethodPost, true, "7")

		if reached {
			t.Fatal("handler ran — a write was executed while attributed to the wrong user")
		}
		if rec.Code != http.StatusConflict {
			t.Fatalf("status = %d, want 409", rec.Code)
		}
		var body map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode body %q: %v", rec.Body.String(), err)
		}
		if body["code"] != "session_identity_changed" {
			t.Errorf("code = %q, want session_identity_changed", body["code"])
		}
		// Whoever reads the resulting message is looking at the STALE tab, and on
		// a shared machine that is not the person who just signed in. Naming the
		// new identity would disclose their address to the previous occupant.
		for _, field := range []string{"current_email", "email", "user_id"} {
			if _, present := body[field]; present {
				t.Errorf("response carries %q — the refusal must not identify anyone", field)
			}
		}
		if strings.Contains(rec.Body.String(), claims.Email) {
			t.Errorf("response body leaks the signed-in address: %s", rec.Body.String())
		}
	})

	t.Run("every mutating method is covered", func(t *testing.T) {
		for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
			rec, reached := runIdentityGuard(t, claims, method, true, "7")
			if reached || rec.Code != http.StatusConflict {
				t.Errorf("%s: status = %d reached = %v, want 409 and no handler", method, rec.Code, reached)
			}
		}
	})

	// Each of these must pass through untouched. They are the reason the check is
	// narrow: it can only ever refuse, so anything it misjudges is a broken client.
	passes := []struct {
		name      string
		method    string
		viaCookie bool
		asserted  string
	}{
		{"matching belief", http.MethodPost, true, "42"},
		// Absent header = a client that does not participate: older frontend
		// builds, curl, server-to-server. Must keep working.
		{"no header at all", http.MethodPost, true, ""},
		// A Bearer client holds its token explicitly; no other tab can swap it
		// underneath, so the mismatch this guards against is unreachable.
		{"bearer client with a stale header", http.MethodPost, false, "7"},
		// A stale read is self-correcting on the next identity check; only writes
		// are irreversible.
		{"read with a stale header", http.MethodGet, true, "7"},
		{"HEAD with a stale header", http.MethodHead, true, "7"},
	}
	for _, tc := range passes {
		t.Run(tc.name+" passes", func(t *testing.T) {
			rec, reached := runIdentityGuard(t, claims, tc.method, tc.viaCookie, tc.asserted)
			if !reached {
				t.Fatalf("request was blocked (status %d) — this case must pass through", rec.Code)
			}
		})
	}
}

// The auth source is published so the guard can tell a browser session from a
// Bearer client. Downstream code may come to rely on it, so pin both values.
func TestProceedAuthenticated_PublishesAuthSource(t *testing.T) {
	claims := &auth.Claims{UserID: "42"}

	for _, tc := range []struct {
		viaCookie bool
		want      string
	}{
		{true, authSourceCookie},
		{false, authSourceBearer},
	} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants", nil)
		c := echo.New().NewContext(req, httptest.NewRecorder())

		var got any
		err := proceedAuthenticated(c, claims, tc.viaCookie, func(c echo.Context) error {
			got = c.Get(authSourceKey)
			if c.Get(userContextKey) != claims {
				t.Error("claims were not published to the handler")
			}
			return c.NoContent(http.StatusOK)
		})
		if err != nil {
			t.Fatalf("proceedAuthenticated: %v", err)
		}
		if got != tc.want {
			t.Errorf("auth source = %v, want %q", got, tc.want)
		}
	}
}

// runIdentityGuard drives proceedAuthenticated and reports the response plus
// whether the handler ran. An empty asserted value sends no header at all.
func runIdentityGuard(t *testing.T, claims *auth.Claims, method string, viaCookie bool, asserted string) (*httptest.ResponseRecorder, bool) {
	t.Helper()

	req := httptest.NewRequest(method, "/api/v1/tenants/1/users", nil)
	if asserted != "" {
		req.Header.Set(SessionUserHeader, asserted)
	}
	rec := httptest.NewRecorder()
	c := echo.New().NewContext(req, rec)

	reached := false
	err := proceedAuthenticated(c, claims, viaCookie, func(c echo.Context) error {
		reached = true
		return c.NoContent(http.StatusOK)
	})
	if err != nil {
		t.Fatalf("proceedAuthenticated returned error: %v", err)
	}
	return rec, reached
}
