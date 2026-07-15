package auth

import (
	"context"
	"net/url"
	"strings"
	"testing"
)

func TestSplitDisplayName(t *testing.T) {
	tests := []struct {
		name        string
		displayName string
		login       string
		wantFirst   string
		wantLast    string
	}{
		{"first and last", "Ada Lovelace", "ada", "Ada", "Lovelace"},
		{"single word", "Ada", "ada", "Ada", ""},
		{"multi-part last name", "Ada King Lovelace", "ada", "Ada", "King Lovelace"},
		{"null name falls back to login", "", "octocat", "octocat", ""},
		{"whitespace-only name falls back to login", "   ", "octocat", "octocat", ""},
		{"surrounding whitespace trimmed", "  Ada Lovelace  ", "ada", "Ada", "Lovelace"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			first, last := splitDisplayName(tt.displayName, tt.login)
			if first != tt.wantFirst || last != tt.wantLast {
				t.Fatalf("splitDisplayName(%q, %q) = (%q, %q), want (%q, %q)",
					tt.displayName, tt.login, first, last, tt.wantFirst, tt.wantLast)
			}
		})
	}
}

func TestGitHubAuthCodeURL(t *testing.T) {
	d := newGitHubDriver()
	cfg := &flowConfig{ClientID: "gh-client-id", ClientSecret: "gh-secret"}

	authURL, err := d.authCodeURL(context.Background(), cfg, "http://localhost:9090/oauth/github/callback", "state-123", "verifier-abc")
	if err != nil {
		t.Fatalf("authCodeURL: %v", err)
	}
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("parse auth url: %v", err)
	}

	if !strings.HasPrefix(authURL, githubAuthorizeURL) {
		t.Fatalf("auth URL %q does not start with %q", authURL, githubAuthorizeURL)
	}
	q := u.Query()
	if got := q.Get("client_id"); got != "gh-client-id" {
		t.Fatalf("client_id = %q", got)
	}
	if got := q.Get("state"); got != "state-123" {
		t.Fatalf("state = %q", got)
	}
	if got := q.Get("redirect_uri"); got != "http://localhost:9090/oauth/github/callback" {
		t.Fatalf("redirect_uri = %q", got)
	}
	// user:email is load-bearing: without it /user/emails is forbidden and
	// private-email users could never pass the verification gate.
	scope := q.Get("scope")
	if !strings.Contains(scope, "read:user") || !strings.Contains(scope, "user:email") {
		t.Fatalf("scope = %q, want read:user and user:email", scope)
	}
}
