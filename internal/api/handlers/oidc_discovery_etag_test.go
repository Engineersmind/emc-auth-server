package handlers

import (
	"testing"

	"github.com/engineersmind/emc-auth-server/internal/api/paths"
)

// ---------------------------------------------------------------------------
// If-None-Match handling (RFC 9110 §13.1.2) — from the Copilot review on PR #111.
//
// The exact-string comparison this replaced could only ever fail one way: a 200
// with the full body where a 304 would have done. No stale data, no security
// consequence. It is still worth getting right, because every OIDC client
// revalidates this document on process start and the caching behaviour is
// something this ticket designed on purpose.
//
// Pure unit tests: the parsing is a total function of two strings, so driving a
// database and an HTTP server to reach it would only make the table harder to
// read. The route-level 304 path is already covered by
// TestDiscovery_ETagYields304.
// ---------------------------------------------------------------------------

func TestIfNoneMatch(t *testing.T) {
	const etag = `"kZ3v9Qb1"`

	cases := []struct {
		name   string
		header string
		want   bool
		why    string
	}{
		{
			name:   "exact match",
			header: etag,
			want:   true,
			why:    "the common case: a client echoing back what we sent",
		},
		{
			name:   "absent header",
			header: "",
			want:   false,
			why:    "no validator offered, so there is nothing to compare",
		},
		{
			name:   "wildcard",
			header: "*",
			want:   true,
			why:    "* matches any existing representation, and the document always exists here",
		},
		{
			name:   "list containing ours",
			header: `"other", ` + etag,
			want:   true,
			why:    "the field is a list; a whole-header comparison matched none of its members",
		},
		{
			name:   "list containing ours first",
			header: etag + `, "other"`,
			want:   true,
			why:    "position in the list must not matter",
		},
		{
			name:   "list without ours",
			header: `"other", "different"`,
			want:   false,
			why:    "a list of candidates that are all stale is still stale",
		},
		{
			name:   "weak validator matches our strong one",
			header: `W/` + etag,
			want:   true,
			why:    "RFC 9110 §8.8.3.2: If-None-Match uses the WEAK comparison function",
		},
		{
			name:   "weak validator inside a list",
			header: `"other", W/` + etag,
			want:   true,
			why:    "both relaxations have to hold at once, which is how a real proxy sends it",
		},
		{
			name:   "surrounding whitespace",
			header: "  " + etag + "  ",
			want:   true,
			why:    "OWS around the field value is legal and must not defeat the match",
		},
		{
			name:   "whitespace after the list separator",
			header: `"other",   ` + etag,
			want:   true,
			why:    "OWS after a comma is legal; this is the shape most clients actually emit",
		},
		{
			name:   "different etag",
			header: `"totally-different"`,
			want:   false,
			why:    "a stale validator must produce a 200 with the current body",
		},
		{
			name:   "unquoted value is not an entity-tag",
			header: "kZ3v9Qb1",
			want:   false,
			why: "an entity-tag is quoted by grammar; guessing at an unquoted one would " +
				"mean answering 304 for a candidate the client never sent",
		},
		{
			name:   "wildcard must be alone to count",
			header: `"other", *`,
			want:   false,
			why:    "* is only legal as the entire field value, not as a list member",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ifNoneMatch(tc.header, etag); got != tc.want {
				t.Errorf("ifNoneMatch(%q, %q) = %v, want %v — %s",
					tc.header, etag, got, tc.want, tc.why)
			}
		})
	}
}

func TestDiscoveryETag_ChangesWithTheBody(t *testing.T) {
	// The validator has to be a function of the bytes a client receives, or a 304
	// would tell a client its cached copy is current when it is not — the one
	// failure mode in this area that actually serves wrong data.
	if discoveryETag([]byte(`{"issuer":"a"}`)) == discoveryETag([]byte(`{"issuer":"b"}`)) {
		t.Fatal("two different documents share an ETag")
	}
	if discoveryETag([]byte(`{"issuer":"a"}`)) != discoveryETag([]byte(`{"issuer":"a"}`)) {
		t.Fatal("the same document produced two ETags; 304 would never fire")
	}
	// Quoted per the entity-tag grammar, so the value we emit is one our own
	// comparison would accept back.
	if e := discoveryETag([]byte(`{}`)); len(e) < 3 || e[0] != '"' || e[len(e)-1] != '"' {
		t.Fatalf("ETag %q is not a quoted entity-tag", e)
	}
}

// ---------------------------------------------------------------------------
// Path constants — the other half of the Copilot review.
// ---------------------------------------------------------------------------

func TestPathAliasesTrackTheSharedPackage(t *testing.T) {
	// These aliases exist so the #7b diff did not have to rename every call site.
	// If one is ever re-pointed at a literal, the duplicate definition this change
	// removed is back and nothing else would notice.
	for _, tc := range []struct{ name, alias, canonical string }{
		{"authorize", PathOAuthAuthorize, paths.OAuthAuthorize},
		{"token", PathOAuthToken, paths.OAuthToken},
		{"userinfo", PathOAuthUserInfo, paths.OAuthUserInfo},
		{"revoke", PathOAuthRevoke, paths.OAuthRevoke},
		{"jwks", PathTenantJWKS, paths.TenantJWKS},
		{"discovery", PathTenantDiscovery, paths.TenantDiscovery},
	} {
		if tc.alias != tc.canonical {
			t.Errorf("%s: handlers alias = %q, paths = %q", tc.name, tc.alias, tc.canonical)
		}
	}
}
