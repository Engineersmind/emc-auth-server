package auth_test

import (
	"errors"
	"reflect"
	"testing"

	"github.com/engineersmind/emc-auth-server/internal/auth"
)

func TestResolveRedirectURI_ExactMatchOnly(t *testing.T) {
	client := &auth.AuthzClient{
		RedirectURIs: []string{
			"https://app.example.com/callback",
			"http://localhost:3000/cb",
		},
	}

	// Every rejected case below is a real-world redirect_uri bypass. RFC 6749
	// §3.1.2.3 requires exact matching precisely because each of these has been
	// used to steal authorization codes from servers that relaxed it.
	tests := []struct {
		name      string
		requested string
		want      string
		wantErr   bool
	}{
		{"exact match", "https://app.example.com/callback", "https://app.example.com/callback", false},
		{"second entry", "http://localhost:3000/cb", "http://localhost:3000/cb", false},

		{"suffix-extension attack", "https://app.example.com/callback.evil.com", "", true},
		{"path-append attack", "https://app.example.com/callback/../../evil", "", true},
		{"subdomain attack", "https://evil.app.example.com/callback", "", true},
		{"domain-suffix attack", "https://app.example.com.evil.test/callback", "", true},
		{"added query string", "https://app.example.com/callback?next=evil", "", true},
		{"added fragment", "https://app.example.com/callback#x", "", true},
		{"scheme downgrade", "http://app.example.com/callback", "", true},
		{"trailing slash", "https://app.example.com/callback/", "", true},
		{"case difference in path", "https://app.example.com/CALLBACK", "", true},
		{"unrelated host", "https://evil.test/cb", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := auth.ResolveRedirectURI(client, tt.requested)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ResolveRedirectURI(%q) error = %v, wantErr %v", tt.requested, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("ResolveRedirectURI(%q) = %q, want %q", tt.requested, got, tt.want)
			}
		})
	}
}

func TestResolveRedirectURI_OmittedParameter(t *testing.T) {
	// RFC 6749 §3.1.2.3 permits omitting redirect_uri only when exactly one is
	// registered. With several, guessing which was meant is how codes get
	// delivered to the wrong endpoint.
	one := &auth.AuthzClient{RedirectURIs: []string{"https://only.example.com/cb"}}
	got, err := auth.ResolveRedirectURI(one, "")
	if err != nil || got != "https://only.example.com/cb" {
		t.Errorf("single registered URI: got (%q, %v), want the URI and no error", got, err)
	}

	many := &auth.AuthzClient{RedirectURIs: []string{"https://a.test/cb", "https://b.test/cb"}}
	if _, err := auth.ResolveRedirectURI(many, ""); !errors.Is(err, auth.ErrRedirectURINotRegistered) {
		t.Errorf("multiple registered URIs with none requested: error = %v, want ErrRedirectURINotRegistered", err)
	}

	none := &auth.AuthzClient{}
	if _, err := auth.ResolveRedirectURI(none, "https://x.test/cb"); !errors.Is(err, auth.ErrNoRedirectURIsRegistered) {
		t.Errorf("no registered URIs: error = %v, want ErrNoRedirectURIsRegistered", err)
	}
}

func TestFilterScopes(t *testing.T) {
	tests := []struct {
		name       string
		requested  []string
		registered []string
		want       []string
	}{
		{
			name:       "unregistered scopes are dropped, not rejected",
			requested:  []string{"openid", "email", "admin:all"},
			registered: []string{"openid", "email", "profile"},
			want:       []string{"openid", "email"},
		},
		{
			name:       "requested order is preserved",
			requested:  []string{"email", "openid"},
			registered: []string{"openid", "email"},
			want:       []string{"email", "openid"},
		},
		{
			name:       "duplicates collapse",
			requested:  []string{"openid", "openid", "email"},
			registered: []string{"openid", "email"},
			want:       []string{"openid", "email"},
		},
		{
			// Fail closed. A client with no registered scopes granting
			// everything would make a forgotten registration field the most
			// permissive configuration possible.
			name:       "no registered scopes grants nothing",
			requested:  []string{"openid", "email"},
			registered: nil,
			want:       []string{},
		},
		{
			name:       "nothing requested grants nothing",
			requested:  nil,
			registered: []string{"openid"},
			want:       []string{},
		},
		{
			name:       "empty strings ignored",
			requested:  []string{"", "openid"},
			registered: []string{"openid"},
			want:       []string{"openid"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := auth.FilterScopes(tt.requested, tt.registered)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FilterScopes(%v, %v) = %v, want %v", tt.requested, tt.registered, got, tt.want)
			}
		})
	}
}

func TestParseScopeParam(t *testing.T) {
	// RFC 6749 §3.3 defines the scope parameter as space-delimited. Real
	// clients send single spaces, but form decoding and hand-built URLs produce
	// tabs and runs of spaces; Fields handles all of them.
	got := auth.ParseScopeParam("  openid   profile\temail ")
	want := []string{"openid", "profile", "email"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ParseScopeParam() = %v, want %v", got, want)
	}
	if len(auth.ParseScopeParam("")) != 0 {
		t.Error("ParseScopeParam(\"\") must return no scopes")
	}
}

func TestAllowsGrant(t *testing.T) {
	// grant_types has existed since migration 00032 and was never read until
	// issue #6. The empty case must stay permissive so a row written before
	// enforcement does not lose a grant it was already using; the column
	// default constrains every new row normally.
	tests := []struct {
		name   string
		grants []string
		ask    string
		want   bool
	}{
		{"listed grant allowed", []string{"authorization_code", "refresh_token"}, "authorization_code", true},
		{"unlisted grant refused", []string{"authorization_code"}, "client_credentials", false},
		{"empty list is permissive (pre-enforcement rows)", nil, "client_credentials", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := auth.AllowsGrant(&auth.AuthzClient{GrantTypes: tt.grants}, tt.ask)
			if got != tt.want {
				t.Errorf("AllowsGrant(%v, %q) = %v, want %v", tt.grants, tt.ask, got, tt.want)
			}
		})
	}
}

func TestHasScope(t *testing.T) {
	granted := []string{"openid", "email"}
	if !auth.HasScope(granted, "openid") {
		t.Error("HasScope() must find a granted scope")
	}
	if auth.HasScope(granted, "profile") {
		t.Error("HasScope() must not find an ungranted scope")
	}
	if auth.HasScope(nil, "openid") {
		t.Error("HasScope(nil) must be false")
	}
}

func TestComputeAtHash_IsLeftHalf(t *testing.T) {
	// OIDC Core §3.1.3.6: at_hash is the LEFT HALF of the digest, base64url.
	// For RS256 that is the leading 16 bytes of SHA-256, which encodes to 22
	// characters. Sending the whole digest (43 characters) is a mistake every
	// conformant client rejects, and it is invisible without this assertion
	// because the value still looks like a plausible hash.
	got := auth.ComputeAtHash("some.access.token")
	if len(got) != 22 {
		t.Errorf("ComputeAtHash() = %q (%d chars), want 22 — the left half of SHA-256 in base64url", got, len(got))
	}
}

func TestIsOIDCScope(t *testing.T) {
	// The reason this exists: validateScopes requires resource:action, which
	// rejects every one of these — including the values migration 00032 sets
	// as the column DEFAULT.
	for _, s := range []string{"openid", "profile", "email", "offline_access"} {
		if !auth.IsOIDCScope(s) {
			t.Errorf("IsOIDCScope(%q) = false, want true", s)
		}
	}
	// Closed allow-list: a near-miss must not be silently accepted and then
	// release no claims, which reads as missing data rather than a typo.
	for _, s := range []string{"prof1le", "openid ", "OPENID", "users:read", ""} {
		if auth.IsOIDCScope(s) {
			t.Errorf("IsOIDCScope(%q) = true, want false", s)
		}
	}
}
