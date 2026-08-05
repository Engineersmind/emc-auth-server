package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog"

	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// The management portal sends no Authorization header at all — every admin API
// call is authenticated by the emc_access_token cookie alone. These tests pin
// the credential *sourcing* in both guards: that a cookie-only request is read
// as an authentication attempt rather than rejected as anonymous.
//
// A deliberately malformed token is enough to prove sourcing and keeps these
// tests DB-free: JWTService.Verify fails at ParseUnverified, before it looks up
// the tenant secret, so a nil pool is never dereferenced. The distinction being
// asserted is token_missing (no credential found) vs token_invalid (a credential
// was found in the cookie and handed to Verify).
func TestJWTGuards_ReadAccessTokenFromCookie(t *testing.T) {
	// Issuer must be non-empty: #84 made NewJWTService reject an empty one so that
	// iss verification cannot be silently disabled by a misconfigured deploy.
	jwtSvc, err := auth.NewJWTService(nil, "https://auth.emc.local")
	if err != nil {
		t.Fatalf("NewJWTService: %v", err)
	}

	guards := map[string]echo.MiddlewareFunc{
		// Guards adminGroup: /tenants, /applications, /audit-logs, /agents, …
		"JWTRequired": JWTRequired(jwtSvc),
		// Guards /auth/me, which is how the portal resolves its session on load.
		"JWTRenew": JWTRenew(jwtSvc, nil, nil, BuildCookieConfig("development", ""), nil, zerolog.Nop()),
	}

	for name, guard := range guards {
		t.Run(name, func(t *testing.T) {
			t.Run("no credential at all is token_missing", func(t *testing.T) {
				code, body := runGuard(t, guard, nil)
				if code != http.StatusUnauthorized {
					t.Fatalf("status = %d, want 401", code)
				}
				if body["code"] != "token_missing" {
					t.Errorf("code = %q, want token_missing", body["code"])
				}
			})

			t.Run("cookie alone is consulted", func(t *testing.T) {
				cookie := &http.Cookie{Name: AccessTokenCookie, Value: "not-a-jwt"}
				code, body := runGuard(t, guard, cookie)
				if code != http.StatusUnauthorized {
					t.Fatalf("status = %d, want 401", code)
				}
				// token_invalid (not token_missing) proves the cookie was found
				// and passed to Verify. If this ever regresses to token_missing,
				// every portal API call breaks.
				if body["code"] != "token_invalid" {
					t.Errorf("code = %q, want token_invalid — the access cookie was not read", body["code"])
				}
			})
		})
	}
}

// runGuard invokes a guard on GET /api/v1/tenants with no Authorization header,
// optionally attaching a cookie, and returns the status and decoded JSON body.
func runGuard(t *testing.T, guard echo.MiddlewareFunc, cookie *http.Cookie) (int, map[string]string) {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants", nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	c := echo.New().NewContext(req, rec)

	reached := false
	handler := guard(func(c echo.Context) error {
		reached = true
		return c.NoContent(http.StatusOK)
	})
	if err := handler(c); err != nil {
		t.Fatalf("guard returned error: %v", err)
	}
	if reached {
		t.Fatal("guard admitted a request bearing no valid credential")
	}

	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body %q: %v", rec.Body.String(), err)
	}
	return rec.Code, body
}
