package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog"

	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// Issue #177: malformed state / code_challenge must be rejected with 400
// before any DB or Redis work, so a zero-value service is enough here.
func TestOAuthLogin_RejectsMalformedBinding(t *testing.T) {
	h := NewOAuthHandler(&auth.OAuthLoginService{}, nil, nil, zerolog.Nop())
	e := echo.New()

	tests := []struct {
		name  string
		query url.Values
	}{
		{"oversized state", url.Values{"state": {strings.Repeat("a", 513)}}},
		{"control char in state", url.Values{"state": {"a\nb"}}},
		{"short code_challenge", url.Values{"code_challenge": {"abc"}}},
		{"plain method", url.Values{"code_challenge": {strings.Repeat("A", 43)}, "code_challenge_method": {"plain"}}},
		{"method without challenge", url.Values{"code_challenge_method": {"S256"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := tt.query
			q.Set("client_id", "any-client")
			req := httptest.NewRequest(http.MethodGet, "/oauth/google/login?"+q.Encode(), nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.SetParamNames("provider")
			c.SetParamValues("google")

			err := h.Login(c)
			he, ok := err.(*echo.HTTPError)
			if !ok || he.Code != http.StatusBadRequest {
				t.Fatalf("err = %v, want 400 HTTPError", err)
			}
		})
	}
}
