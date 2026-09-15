package handlers

import (
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

// TestAuthTokenDeprecationHeaders_OnEveryResponse pins the property that makes
// the deprecation safe to ship: the markers are advisory metadata attached to
// every response, and nothing else about the response moves.
//
// The "every response" half is the one worth a test. Headers set just before a
// success would be invisible to exactly the integrator who most needs them —
// the one whose credentials are wrong and who is reading a 401 — so the handler
// writes them before any validation can return, and this asserts that for the
// error paths too, not only the happy one.
func TestAuthTokenDeprecationHeaders_OnEveryResponse(t *testing.T) {
	h := &AuthHandler{logger: zerolog.Nop()} // appSvc nil — no database needed

	// Each case is a DIFFERENT exit from the handler: the earliest 400, a later
	// 400, and the far-side 503 reached only once credentials resolve. If the
	// call were ever moved below one of these returns, that case fails.
	tests := []struct {
		name       string
		body       string
		authHeader string
		wantStatus int
	}{
		{
			name:       "credentials resolve, reaches service boundary",
			body:       `{"grant_type":"client_credentials"}`,
			authHeader: basicHeader("app_abc", "s3cret"),
			wantStatus: http.StatusServiceUnavailable,
		},
		{
			name:       "rejected before credentials are read",
			body:       `{"grant_type":"client_credentials","client_id":"app_abc","client_secret":"s3cret"}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "rejected on grant_type",
			body:       `{"grant_type":"password"}`,
			authHeader: basicHeader("app_abc", "s3cret"),
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "rejected on a malformed authorization header",
			body:       `{"grant_type":"client_credentials"}`,
			authHeader: "Basic !!!",
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, rec := newTokenContext(tt.body, tt.authHeader)
			if err := h.Token(c); err != nil {
				t.Fatalf("Token() returned error: %v", err)
			}

			// The status is asserted here as well as in
			// TestToken_CredentialResolution, deliberately: this test is the one
			// that would be edited if the headers ever changed, so it should fail
			// on its own if such an edit altered an outcome.
			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d — deprecation must not change behaviour (body: %s)",
					rec.Code, tt.wantStatus, rec.Body.String())
			}

			// Deprecation is an RFC 9745 Date structured field: "@" then a Unix
			// timestamp. Asserting it PARSES, rather than matching the literal
			// string, is what catches a regression to the pre-RFC "true" that a
			// conforming client would reject.
			dep := rec.Header().Get("Deprecation")
			if !strings.HasPrefix(dep, "@") {
				t.Fatalf("Deprecation = %q, want an RFC 9745 @<unix-timestamp>", dep)
			}
			if _, err := strconv.ParseInt(strings.TrimPrefix(dep, "@"), 10, 64); err != nil {
				t.Errorf("Deprecation = %q, not parseable as a Unix timestamp: %v", dep, err)
			}

			// Sunset is an RFC 8594 IMF-fixdate, the same shape as Expires.
			sunset := rec.Header().Get("Sunset")
			parsed, err := time.Parse(http.TimeFormat, sunset)
			if err != nil {
				t.Errorf("Sunset = %q, not an IMF-fixdate: %v", sunset, err)
			} else if !parsed.After(authTokenDeprecatedAt) {
				t.Errorf("Sunset %s is not after the deprecation date %s — consumers would be "+
					"told the endpoint is already gone", sunset, authTokenDeprecatedAt)
			}

			// The successor relation is the machine-readable half: it is how a
			// client discovers what to call instead without reading prose.
			link := rec.Header().Get("Link")
			if !strings.Contains(link, `rel="successor-version"`) {
				t.Errorf("Link = %q, missing rel=\"successor-version\"", link)
			}
			if !strings.Contains(link, "<"+PathOAuthToken+">") {
				t.Errorf("Link = %q, does not name the replacement %s", link, PathOAuthToken)
			}
			if !strings.Contains(link, `rel="deprecation"`) {
				t.Errorf("Link = %q, missing rel=\"deprecation\" migration guide", link)
			}
		})
	}
}

// TestAuthTokenDeprecation_ResponseBodyUnchanged guards the other half of
// "non-breaking": a client that ignores the new headers must see exactly the
// payload it saw before.
//
// Headers are invisible to a client that does not look for them, but a body
// that gained a "deprecated" field would break any consumer doing strict
// decoding — so the absence of one is asserted rather than assumed.
func TestAuthTokenDeprecation_ResponseBodyUnchanged(t *testing.T) {
	h := &AuthHandler{logger: zerolog.Nop()}

	c, rec := newTokenContext(`{"grant_type":"password"}`, basicHeader("app_abc", "s3cret"))
	if err := h.Token(c); err != nil {
		t.Fatalf("Token() returned error: %v", err)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "unsupported grant_type") {
		t.Errorf("body = %s, want the unchanged grant_type error", body)
	}
	for _, leaked := range []string{"deprecat", "Deprecat", "sunset", "Sunset"} {
		if strings.Contains(body, leaked) {
			t.Errorf("body = %s, leaked %q — deprecation belongs in headers, not the payload",
				body, leaked)
		}
	}
}
