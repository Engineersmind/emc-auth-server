package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
)

// The access cookie must reach every /api/v1 route — the management portal
// authenticates /api/v1/tenants, /api/v1/applications, … with it, not just
// /api/v1/auth. The refresh cookie must stay narrow so the 30-day credential is
// not attached to ordinary API traffic.
func TestBuildAuthCookies_Paths(t *testing.T) {
	cookies := BuildAuthCookies("access", "refresh", BuildCookieConfig("production", ".engineersmind.com"))

	byName := map[string]*http.Cookie{}
	for _, c := range cookies {
		byName[c.Name] = c
	}

	if got := byName[AccessTokenCookie].Path; got != "/api/v1" {
		t.Errorf("access cookie Path = %q, want /api/v1", got)
	}
	if got := byName[RefreshTokenCookie].Path; got != "/api/v1/auth" {
		t.Errorf("refresh cookie Path = %q, want /api/v1/auth", got)
	}
	for name, c := range byName {
		if !c.HttpOnly {
			t.Errorf("%s: HttpOnly must be set", name)
		}
		if !c.Secure {
			t.Errorf("%s: Secure must be set in production", name)
		}
		if c.SameSite != http.SameSiteNoneMode {
			t.Errorf("%s: SameSite = %v, want None in production", name, c.SameSite)
		}
	}
}

// A deletion whose Path differs from the original leaves the cookie in place
// (RFC 6265 §5.2.3), so logout would silently fail to sign the user out.
func TestClearAuthCookies_PathsMatchBuild(t *testing.T) {
	cfg := BuildCookieConfig("production", ".engineersmind.com")

	built := map[string]string{}
	for _, c := range BuildAuthCookies("a", "r", cfg) {
		built[c.Name] = c.Path
	}

	rec := httptest.NewRecorder()
	c := echo.New().NewContext(httptest.NewRequest(http.MethodPost, "/api/v1/auth/session/logout", nil), rec)
	ClearAuthCookies(c, cfg)

	cleared := map[string]string{}
	for _, c := range rec.Result().Cookies() {
		if c.MaxAge != -1 {
			t.Errorf("%s: MaxAge = %d, want -1", c.Name, c.MaxAge)
		}
		cleared[c.Name] = c.Path
	}

	for name, path := range built {
		if cleared[name] != path {
			t.Errorf("%s: cleared Path = %q, but set with %q — cookie would survive logout", name, cleared[name], path)
		}
	}
}

func TestCookieCSRF(t *testing.T) {
	prodCfg := BuildCookieConfig("production", ".engineersmind.com")

	tests := []struct {
		name       string
		cfg        CookieConfig
		method     string
		origin     string
		cookie     bool
		authHeader string
		wantStatus int
	}{
		{
			name:       "cookie write from trusted origin passes",
			cfg:        prodCfg,
			method:     http.MethodPost,
			origin:     "https://admin.engineersmind.com",
			cookie:     true,
			wantStatus: http.StatusOK,
		},
		{
			name:       "cookie write from attacker origin is rejected",
			cfg:        prodCfg,
			method:     http.MethodPost,
			origin:     "https://evil.example.com",
			cookie:     true,
			wantStatus: http.StatusForbidden,
		},
		{
			// The label-boundary check: a suffix match alone would accept this.
			name:       "lookalike domain is rejected",
			cfg:        prodCfg,
			method:     http.MethodPost,
			origin:     "https://evil-engineersmind.com",
			cookie:     true,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "safe method is never blocked",
			cfg:        prodCfg,
			method:     http.MethodGet,
			origin:     "https://evil.example.com",
			cookie:     true,
			wantStatus: http.StatusOK,
		},
		{
			// A tenant's own app calling with an explicit Bearer token and no
			// cookie is not forgeable by a third-party page, so the allow-list
			// must not apply.
			name:       "bearer client with no cookie from any origin passes",
			cfg:        prodCfg,
			method:     http.MethodPost,
			origin:     "https://some-tenant-app.com",
			authHeader: "Bearer eyJabc",
			wantStatus: http.StatusOK,
		},
		{
			// Bypass attempt: smuggle an Authorization header past preflight so a
			// bearer exemption would waive the Origin check, while the browser
			// still attaches the victim's cookies. The cookie must win.
			name:       "garbage bearer alongside victim cookie is still checked",
			cfg:        prodCfg,
			method:     http.MethodPost,
			origin:     "https://evil.example.com",
			cookie:     true,
			authHeader: "Bearer eyJnot-a-real-token",
			wantStatus: http.StatusForbidden,
		},
		{
			// No ambient credential to abuse — keeps /auth/login reachable.
			name:       "no auth cookie passes",
			cfg:        prodCfg,
			method:     http.MethodPost,
			origin:     "https://some-tenant-app.com",
			wantStatus: http.StatusOK,
		},
		{
			// SameSite=Lax already blocks cross-site sends in development.
			name:       "development is inert",
			cfg:        BuildCookieConfig("development", ""),
			method:     http.MethodPost,
			origin:     "https://evil.example.com",
			cookie:     true,
			wantStatus: http.StatusOK,
		},
		{
			// Fail-closed: ENV=production with COOKIE_DOMAIN unset must not
			// degrade into accepting every origin.
			name:       "missing cookie domain fails closed",
			cfg:        BuildCookieConfig("production", ""),
			method:     http.MethodPost,
			origin:     "https://admin.engineersmind.com",
			cookie:     true,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "opaque origin is rejected",
			cfg:        prodCfg,
			method:     http.MethodPost,
			origin:     "null",
			cookie:     true,
			wantStatus: http.StatusForbidden,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/api/v1/tenants", nil)
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			if tc.authHeader != "" {
				req.Header.Set("Authorization", tc.authHeader)
			}
			if tc.cookie {
				req.AddCookie(&http.Cookie{Name: AccessTokenCookie, Value: "token"})
			}

			rec := httptest.NewRecorder()
			c := echo.New().NewContext(req, rec)

			handler := CookieCSRF(tc.cfg)(func(c echo.Context) error {
				return c.NoContent(http.StatusOK)
			})
			if err := handler(c); err != nil {
				t.Fatalf("handler returned error: %v", err)
			}

			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
		})
	}
}
