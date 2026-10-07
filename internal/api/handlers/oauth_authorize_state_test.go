package handlers

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// ---------------------------------------------------------------------------
// Missing-state rejection at the route — GHSA-6fcw-g2xw-v42w (L-05).
//
// RFC 6749 §4.1.1 marks state RECOMMENDED, not required, which is why the
// handler originally warned and continued. But a client that omits state has
// no way to bind the callback to the request it started — the CSRF defence for
// the redirect leg. Only first-party clients ever reach this point (the
// consent gate refuses third-party), so the operator controls every client
// that could be affected and OAUTH_REQUIRE_STATE defaults ON.
// ---------------------------------------------------------------------------

// authorizeNoState drives GET /oauth/authorize over HTTP with every required
// parameter except state, using the fixture's SSO cookie.
func authorizeNoState(t *testing.T, f *nonceFixture, h *OAuthAuthorizeHandler) *url.URL {
	t.Helper()

	sum := sha256.Sum256([]byte("verifier-" + uniqueSuffix()))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	q := url.Values{}
	q.Set("client_id", f.clientID)
	q.Set("redirect_uri", f.redirectURI)
	q.Set("response_type", "code")
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	// Deliberately no state.

	e := echo.New()
	e.GET("/oauth/authorize", h.Authorize)
	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
	req.AddCookie(f.cookie)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 to the registered redirect_uri", rec.Code)
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location %q: %v", rec.Header().Get("Location"), err)
	}
	return loc
}

func newStateFixture(t *testing.T, requireState bool) (*nonceFixture, *OAuthAuthorizeHandler) {
	t.Helper()
	f := newNonceFixture(t)
	h := NewOAuthAuthorizeHandler(
		auth.NewAuthorizationServer(f.pool, testhelper.TestLogger()),
		f.sessions, nil, nil, testhelper.TestLogger(), false, requireState)
	return f, h
}

func TestAuthorize_MissingStateIsRejectedByDefault(t *testing.T) {
	f, h := newStateFixture(t, true)
	loc := authorizeNoState(t, f, h)

	// The rejection must land on the registered redirect_uri as
	// invalid_request — the same phase-ordering contract as every other
	// post-validation error.
	if got, want := loc.Scheme+"://"+loc.Host+loc.Path, f.redirectURI; got != want {
		t.Fatalf("redirected to %q, want %q", got, want)
	}
	if got := loc.Query().Get("error"); got != "invalid_request" {
		t.Fatalf("error = %q, want invalid_request", got)
	}
	if got := loc.Query().Get("code"); got != "" {
		t.Fatalf("a code was issued (%q) despite the missing state", got)
	}
	if desc := loc.Query().Get("error_description"); !strings.Contains(desc, "state") {
		t.Fatalf("error_description = %q, want it to name state", desc)
	}
}

func TestAuthorize_MissingStateAllowedDuringMigrationWindow(t *testing.T) {
	f, h := newStateFixture(t, false)
	loc := authorizeNoState(t, f, h)

	// OAUTH_REQUIRE_STATE=false keeps the RFC-default behaviour: the request
	// proceeds and a code is issued (SSO short-circuit — the session cookie
	// already authenticated the user).
	if got := loc.Query().Get("code"); got == "" {
		t.Fatalf("no code issued under the migration window (%s)", loc)
	}
}
