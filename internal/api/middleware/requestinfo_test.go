package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"

	"github.com/engineersmind/emc-auth-server/internal/api/middleware"
	"github.com/engineersmind/emc-auth-server/internal/requestctx"
)

func requestInfoFor(t *testing.T, headers map[string]string) requestctx.RequestInfo {
	t.Helper()
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/auth/verify-email", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	c := e.NewContext(req, httptest.NewRecorder())

	var got requestctx.RequestInfo
	h := middleware.RequestInfo()(func(c echo.Context) error {
		got = requestctx.FromContext(c.Request().Context())
		return nil
	})
	if err := h(c); err != nil {
		t.Fatal(err)
	}
	return got
}

// A request that presents application credentials is a backend, not the user, on
// every route — including the ones AppS2S does not guard — so its address and HTTP
// client are never presented as the user's device or location.
func TestRequestInfo_ApplicationCredentialsAreNotTheUser(t *testing.T) {
	cases := []struct {
		name      string
		headers   map[string]string
		wantTrust bool
	}{
		{"direct browser request", nil, true},
		{"bearer token is still the user's own client", map[string]string{echo.HeaderAuthorization: "Bearer abc"}, true},
		{"basic credentials mean a backend", map[string]string{echo.HeaderAuthorization: "Basic Zm9vOmJhcg=="}, false},
		{"scheme is case-insensitive", map[string]string{echo.HeaderAuthorization: "basic Zm9vOmJhcg=="}, false},
		// Routes that need the user's own Bearer token carry the application's
		// credentials in X-Client-Authorization instead.
		{"credentials in X-Client-Authorization", map[string]string{
			echo.HeaderAuthorization:    "Bearer user-token",
			middleware.ClientAuthHeader: "Basic Zm9vOmJhcg==",
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := requestInfoFor(t, tc.headers)
			if got.Trusted != tc.wantTrust || got.UserAgentTrusted != tc.wantTrust {
				t.Errorf("Trusted=%v UserAgentTrusted=%v, want both %v", got.Trusted, got.UserAgentTrusted, tc.wantTrust)
			}
			if got.UserAgent != "Mozilla/5.0" {
				t.Errorf("the User-Agent must still be recorded for session attribution, got %q", got.UserAgent)
			}
		})
	}
}
