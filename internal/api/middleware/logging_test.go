package middleware

import "testing"

func TestScrubURI(t *testing.T) {
	tests := []struct {
		name string
		uri  string
		want string
	}{
		{"oauth callback query redacted", "/oauth/google/callback?code=4/secret&state=abc", "/oauth/google/callback?[redacted]"},
		{"oauth login query redacted", "/oauth/google/login?client_id=app_x&redirect=https%3A%2F%2Fa", "/oauth/google/login?[redacted]"},
		{"oauth path without query unchanged", "/oauth/google/login", "/oauth/google/login"},
		{"non-oauth path untouched", "/api/v1/auth/login?x=1", "/api/v1/auth/login?x=1"},
		{"saml path untouched", "/saml/login?tenant=1", "/saml/login?tenant=1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := scrubURI(tt.uri); got != tt.want {
				t.Fatalf("scrubURI(%q) = %q, want %q", tt.uri, got, tt.want)
			}
		})
	}
}
