package handlers

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"

	mw "github.com/engineersmind/emc-auth-server/internal/api/middleware"
)

// fakeAccessToken builds an unsigned JWT-shaped string whose payload carries the
// given claims. setAuthCookies only reads the payload (via claimsFromToken) to
// decide whether a session is application-scoped, so no signature is needed.
func fakeAccessToken(t *testing.T, claims map[string]string) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	return "header." + base64.RawURLEncoding.EncodeToString(payload) + ".signature"
}

// The portal authenticates with cookies; applications authenticate with
// Authorization: Bearer. That split is enforced in setAuthCookies rather than at
// each call site, so these tests pin it directly — an application-scoped login
// must never receive an ambient credential its integrator did not ask for and
// does not manage.
func TestSetAuthCookies_OnlyForFirstPartySessions(t *testing.T) {
	tests := []struct {
		name        string
		claims      map[string]string
		wantCookies bool
	}{
		{
			// Portal login via /auth/session, and tenant-level /auth/login:
			// issueTokenPair leaves app_id empty for these.
			name:        "first-party session gets cookies",
			claims:      map[string]string{"tenant_id": "1", "user_id": "42"},
			wantCookies: true,
		},
		{
			// /auth/apps/login, /auth/apps/register, magic-link verify — the
			// client_id/client_secret flows. Tokens go in the response body only.
			name:        "application-scoped session gets none",
			claims:      map[string]string{"tenant_id": "1", "user_id": "42", "app_id": "7"},
			wantCookies: false,
		},
		{
			// The back door worth closing: an app-scoped login that stops for MFA
			// completes on the shared /auth/login/otp endpoint. It must not pick
			// up cookies on the way through just because that handler is shared
			// with the first-party flow.
			name:        "app-scoped MFA continuation gets none",
			claims:      map[string]string{"tenant_id": "1", "user_id": "42", "app_id": "12"},
			wantCookies: false,
		},
		{
			// An empty claim is not an application context — treat as first-party
			// rather than silently withholding the portal's session.
			name:        "empty app_id is first-party",
			claims:      map[string]string{"tenant_id": "1", "user_id": "42", "app_id": ""},
			wantCookies: true,
		},
	}

	cfg := mw.BuildCookieConfig("production", ".engineersmind.com")

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			c := echo.New().NewContext(httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil), rec)

			setAuthCookies(c, fakeAccessToken(t, tc.claims), "refresh-token", cfg)

			cookies := rec.Result().Cookies()
			if tc.wantCookies {
				if len(cookies) != 2 {
					t.Fatalf("got %d cookies, want 2 (access + refresh)", len(cookies))
				}
				return
			}
			if len(cookies) != 0 {
				names := make([]string, 0, len(cookies))
				for _, ck := range cookies {
					names = append(names, ck.Name)
				}
				t.Errorf("application-scoped login was issued cookies %v — end-user sessions must be header-only", names)
			}
		})
	}
}
