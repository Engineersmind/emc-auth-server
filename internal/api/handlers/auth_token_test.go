package handlers

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog"
)

// newTokenContext builds an echo.Context for POST /api/v1/auth/token with the
// given JSON body and optional Authorization header.
func newTokenContext(body, authHeader string) (echo.Context, *httptest.ResponseRecorder) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/token", strings.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	if authHeader != "" {
		req.Header.Set(echo.HeaderAuthorization, authHeader)
	}
	rec := httptest.NewRecorder()
	return e.NewContext(req, rec), rec
}

func basicHeader(id, secret string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(id+":"+secret))
}

func TestClientCredentialsFromBasicAuth(t *testing.T) {
	tests := []struct {
		name       string
		header     string
		wantID     string
		wantSecret string
		wantOK     bool
		wantErr    bool
	}{
		{"valid header", basicHeader("app_abc", "s3cret"), "app_abc", "s3cret", true, false},
		{"no header", "", "", "", false, false},
		{"bearer header ignored", "Bearer some.jwt.token", "", "", false, false},
		{"bad base64", "Basic %%%not-base64%%%", "", "", false, true},
		{"missing colon", "Basic " + base64.StdEncoding.EncodeToString([]byte("no-colon-here")), "", "", false, true},
		{"empty client_id", basicHeader("", "secret"), "", "", false, true},
		{"empty secret", basicHeader("app_abc", ""), "", "", false, true},
		// RFC 6749 allows colons inside the secret — only the first splits.
		{"colon in secret", basicHeader("app_abc", "se:cr:et"), "app_abc", "se:cr:et", true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := newTokenContext(`{}`, tt.header)
			id, secret, ok, err := clientCredentialsFromBasicAuth(c)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if id != tt.wantID || secret != tt.wantSecret {
				t.Errorf("credentials = (%q, %q), want (%q, %q)", id, secret, tt.wantID, tt.wantSecret)
			}
		})
	}
}

// TestToken_CredentialResolution exercises the handler's credential and
// grant_type validation without a database: a request that resolves valid
// credentials reaches the appSvc==nil guard (503), anything malformed stops
// at 400 first.
func TestToken_CredentialResolution(t *testing.T) {
	h := &AuthHandler{logger: zerolog.Nop()} // appSvc nil — resolution paths only

	tests := []struct {
		name       string
		body       string
		authHeader string
		wantStatus int
	}{
		{
			name:       "basic auth with grant_type in body reaches service boundary",
			body:       `{"grant_type":"client_credentials"}`,
			authHeader: basicHeader("app_abc", "s3cret"),
			wantStatus: http.StatusServiceUnavailable,
		},
		{
			name:       "json body credentials are rejected with guidance",
			body:       `{"grant_type":"client_credentials","client_id":"app_abc","client_secret":"s3cret"}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "body credentials rejected even alongside a valid basic header",
			body:       `{"grant_type":"client_credentials","client_id":"app_abc","client_secret":"s3cret"}`,
			authHeader: basicHeader("app_abc", "s3cret"),
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "malformed basic header is rejected",
			body:       `{"grant_type":"client_credentials"}`,
			authHeader: "Basic !!!",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "wrong grant_type is rejected",
			body:       `{"grant_type":"password"}`,
			authHeader: basicHeader("app_abc", "s3cret"),
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "missing authorization header rejected",
			body:       `{"grant_type":"client_credentials"}`,
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, rec := newTokenContext(tt.body, tt.authHeader)
			if err := h.Token(c); err != nil {
				t.Fatalf("Token() returned error: %v", err)
			}
			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d (body: %s)", rec.Code, tt.wantStatus, rec.Body.String())
			}
		})
	}
}
