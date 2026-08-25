package middleware

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// The preflight method list vs the methods the API actually serves.
//
// From a live failure during issue #112 testing. The passkey rename endpoint
// (PATCH /auth/me/passkeys/:id) was the API's first PATCH route, and
// Access-Control-Allow-Methods had only GET,POST,PUT,DELETE,OPTIONS. The
// preflight answered 204 — so the server looked healthy — and the browser then
// refused to send the request at all. From the client it is indistinguishable
// from a broken handler.
//
// This class of bug is invisible to everything else we run:
//
//   - curl does not preflight, so the endpoint tests pass.
//   - the Go handler tests call the handler directly, so they pass.
//   - the preflight itself returns 204, so no log line records a rejection.
//
// It fails only in a browser, only cross-origin, and only silently. Hence a
// test whose whole job is to assert one string contains another.
// ---------------------------------------------------------------------------

// apiMethods is every HTTP method the router registers a route for.
//
// Add to this list when a route introduces a new method — the test then tells
// you to add it to corsAllowedMethods too, at build time rather than in
// somebody's DevTools console.
var apiMethods = []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}

func TestCORSAllowedMethodsCoversEveryMethodTheAPIServes(t *testing.T) {
	allowed := strings.Split(corsAllowedMethods, ",")
	have := make(map[string]bool, len(allowed))
	for _, m := range allowed {
		have[strings.ToUpper(strings.TrimSpace(m))] = true
	}

	for _, m := range apiMethods {
		if !have[m] {
			t.Errorf("corsAllowedMethods = %q, missing %s — a browser will preflight "+
				"successfully and then refuse to send the request, which looks exactly "+
				"like a broken handler", corsAllowedMethods, m)
		}
	}
}

// TestCORSAllowedMethodsIsWellFormed guards the format rather than the content.
// A stray space makes a browser's comparison miss, and the symptom is again a
// request that is simply never sent.
func TestCORSAllowedMethodsIsWellFormed(t *testing.T) {
	if strings.Contains(corsAllowedMethods, " ") {
		t.Errorf("corsAllowedMethods = %q contains a space; browsers compare tokens exactly", corsAllowedMethods)
	}
	if strings.HasPrefix(corsAllowedMethods, ",") || strings.HasSuffix(corsAllowedMethods, ",") {
		t.Errorf("corsAllowedMethods = %q has a dangling comma", corsAllowedMethods)
	}
	if !strings.Contains(corsAllowedMethods, "OPTIONS") {
		t.Error("corsAllowedMethods must include OPTIONS — the preflight method itself")
	}
}
