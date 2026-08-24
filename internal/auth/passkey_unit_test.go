package auth_test

import (
	"testing"

	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// ---------------------------------------------------------------------------
// Unit tests — no database, no Redis. These cover the two pieces of pure logic
// that a security review would look at first: how an origin is canonicalised
// before it is compared against an allow-list, and how an AAGUID becomes a
// label.
// ---------------------------------------------------------------------------

// TestNormalizeOrigin covers the shapes a real Origin or Referer header arrives
// in, and — more importantly — the shapes that must NOT normalise to something
// that matches an allow-list entry.
func TestNormalizeOrigin(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain https", "https://acme.com", "https://acme.com"},
		{"with port", "https://acme.com:8443", "https://acme.com:8443"},
		{"trailing slash", "https://acme.com/", "https://acme.com"},
		{"uppercase host", "https://ACME.com", "https://acme.com"},
		{"surrounding space", "  https://acme.com  ", "https://acme.com"},
		{"loopback http", "http://localhost:5173", "http://localhost:5173"},

		// A Referer is a URL, not an origin. Trimmed to the origin rather than
		// rejected: the alternative is comparing "https://a.com/login" against
		// "https://a.com" and calling it a mismatch.
		{"referer with path", "https://acme.com/login?next=%2Fhome", "https://acme.com"},
		{"referer with fragment", "https://acme.com#top", "https://acme.com"},

		// Everything below must be empty, which every caller treats as "not
		// allowed". A value we cannot parse is not a value to match loosely.
		{"empty", "", ""},
		{"opaque null origin", "null", ""},
		{"no scheme", "acme.com", ""},
		{"file scheme", "file:///tmp/evil.html", ""},
		{"javascript scheme", "javascript:alert(1)", ""},
		{"data scheme", "data:text/html,<h1>hi", ""},
		{"scheme only", "https://", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := auth.NormalizeOrigin(tc.in); got != tc.want {
				t.Errorf("NormalizeOrigin(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestPasskeyPolicyAllowsOriginIsExact proves the allow-list comparison is exact.
// Prefix or suffix matching here is the entire attack: "https://acme.com.evil.net"
// ends with the tenant's domain, and "https://acme.com" is a prefix of
// "https://acme.com.evil.net".
func TestPasskeyPolicyAllowsOriginIsExact(t *testing.T) {
	p := auth.PasskeyPolicy{Origins: []string{"https://acme.com", "https://app.acme.com:8443"}}

	for _, ok := range []string{"https://acme.com", "https://app.acme.com:8443"} {
		if !p.AllowsOrigin(ok) {
			t.Errorf("AllowsOrigin(%q) = false, want true", ok)
		}
	}
	for _, bad := range []string{
		"",
		"http://acme.com",           // scheme differs
		"https://acme.com:443",      // explicit default port is a different origin string
		"https://acme.com.evil.net", // suffix attack
		"https://evil.net/acme.com", // not even an origin
		"https://sub.acme.com",      // a subdomain is not the registered origin
		"https://app.acme.com",      // right host, missing port
		"https://app.acme.com:9443", // right host, wrong port
	} {
		if p.AllowsOrigin(bad) {
			t.Errorf("AllowsOrigin(%q) = true, want false", bad)
		}
	}
}

// TestAuthenticatorName proves the embedded FIDO registry resolves real AAGUIDs
// and, just as importantly, that an unknown or absent one is a normal empty
// answer rather than an error or a placeholder.
func TestAuthenticatorName(t *testing.T) {
	known := map[string]string{
		"08987058-cadc-4b81-b6e1-30de50dcbe96": "Windows Hello",
		"fbfc3007-154e-4ecc-8c0b-6e020557d7bd": "Apple Passwords",
		"ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4": "Google Password Manager",
	}
	for id, want := range known {
		raw := parseAAGUID(t, id)
		if got := auth.AuthenticatorName(raw); got != want {
			t.Errorf("AuthenticatorName(%s) = %q, want %q", id, got, want)
		}
		if got := auth.AAGUIDString(raw); got != id {
			t.Errorf("AAGUIDString(%s) = %q, want the canonical form", id, got)
		}
	}

	// The all-zero AAGUID is what an authenticator returns under the 'none'
	// attestation we request, so it is the COMMON case, not an edge case. Both
	// helpers must report it as absent.
	zero := make([]byte, 16)
	if got := auth.AuthenticatorName(zero); got != "" {
		t.Errorf("AuthenticatorName(zero) = %q, want empty", got)
	}
	if got := auth.AAGUIDString(zero); got != "" {
		t.Errorf("AAGUIDString(zero) = %q, want empty", got)
	}

	// Malformed input must not panic or invent a name.
	for _, bad := range [][]byte{nil, {}, {0x01}, make([]byte, 15), make([]byte, 17)} {
		if got := auth.AuthenticatorName(bad); got != "" {
			t.Errorf("AuthenticatorName(%d bytes) = %q, want empty", len(bad), got)
		}
	}

	// An AAGUID that is well-formed but not in the registry is unnamed, not an
	// error — a stale registry costs a label and nothing else.
	unknown := parseAAGUID(t, "ffffffff-ffff-4fff-bfff-ffffffffffff")
	if got := auth.AuthenticatorName(unknown); got != "" {
		t.Errorf("AuthenticatorName(unknown) = %q, want empty", got)
	}
	if got := auth.AAGUIDString(unknown); got == "" {
		t.Error("AAGUIDString(unknown) was empty; an unrecognised AAGUID must still be reportable")
	}
}

// parseAAGUID decodes canonical UUID text into the 16 raw bytes the column
// stores.
func parseAAGUID(t *testing.T, s string) []byte {
	t.Helper()
	return mustDecodeAAGUID(t, s)
}
