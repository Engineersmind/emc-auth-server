package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// ---------------------------------------------------------------------------
// Regression tests for the captcha gate's CALLING CONTRACT (issue #145).
//
// These exist because of a bug that shipped past a green build, a green vet,
// a clean gosec run and a full unit-test suite, and was found only by running
// the server and reading the response body.
//
// captchaCheck used to return a bare error. Its refusal path ended in
//
//	return c.JSON(http.StatusUnauthorized, ...)
//
// and echo's c.JSON returns nil when the write SUCCEEDS. So the helper reported
// "no error" for a request it had just refused, every call site's
// `if resp != nil` was false, and each handler carried on and wrote a SECOND
// body into the same response. The observable result on /auth/login was:
//
//	HTTP 401
//	{"error":"captcha_required"}
//	{"access_token":"eyJ...","refresh_token":"..."}
//
// — a refused caller handed a valid token pair. The two-value signature is what
// prevents it, and these tests are what stop it coming back.
// ---------------------------------------------------------------------------

// newGateTestHandler builds an AuthHandler wired only with a captcha service.
// Nothing else is needed: every assertion here is about what the gate returns
// before any authentication would run.
func newGateTestHandler(t *testing.T, policy auth.CaptchaPolicy) *AuthHandler {
	t.Helper()
	rdb := testhelper.NewTestRedis(t)

	svc, err := auth.NewCaptchaService(rdb,
		auth.NewStaticCaptchaPolicyService(policy),
		"0123456789abcdef0123456789abcdef0123456789abcdef",
		2*time.Minute, true, testhelper.TestLogger())
	if err != nil {
		t.Fatalf("captcha service: %v", err)
	}
	return NewAuthHandler(nil, nil, nil, testhelper.TestLogger()).WithCaptcha(svc)
}

func alwaysOnPolicy() auth.CaptchaPolicy {
	p := auth.DefaultCaptchaPolicy
	p.Enabled = true
	p.Mode = auth.CaptchaModeAlways
	return p
}

func newGateContext(t *testing.T) (echo.Context, *httptest.ResponseRecorder) {
	t.Helper()
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader("{}"))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	return e.NewContext(req, rec), rec
}

// TestCaptchaCheck_ReportsHandledWhenItRefuses is the direct regression. If
// handled comes back false on a refusal, the caller proceeds and writes a second
// body — which is exactly the token leak described above.
func TestCaptchaCheck_ReportsHandledWhenItRefuses(t *testing.T) {
	h := newGateTestHandler(t, alwaysOnPolicy())
	c, rec := newGateContext(t)

	handled, err := h.captchaCheck(c, firstPartyCaptchaScope(), auth.CaptchaFlowLogin, "", "")

	if !handled {
		t.Fatal("handled = false on a refusal; the caller would continue and write a second body")
	}
	if err != nil {
		t.Fatalf("writing the refusal failed: %v", err)
	}
	// 428, not 401 — see captcha_gate.go's "WHY 428 AND NOT 401". Pinned because
	// the whole point of the status is that an integrator's generic 401 branch
	// cannot swallow it; reverting this to 401 silently recreates the failure
	// where captcha_required reaches a user as "invalid email or password".
	if rec.Code != http.StatusPreconditionRequired {
		t.Errorf("status = %d, want 428", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "captcha_required") {
		t.Errorf("body does not carry captcha_required: %s", rec.Body.String())
	}
	// The err being nil is the whole trap: a caller testing `err != nil` would
	// read this refusal as a success. Pinned so nobody "simplifies" the
	// signature back to one return value.
	if handled && err != nil {
		t.Error("unexpected: echo reported a write error")
	}
}

// TestCaptchaCheck_RefusalBodyIsOnlyTheError pins that exactly one JSON document
// is written. The original bug produced two, the second containing real
// credentials.
func TestCaptchaCheck_RefusalBodyIsOnlyTheError(t *testing.T) {
	h := newGateTestHandler(t, alwaysOnPolicy())
	c, rec := newGateContext(t)

	if handled, _ := h.captchaCheck(c, firstPartyCaptchaScope(), auth.CaptchaFlowLogin, "", ""); !handled {
		t.Fatal("expected the gate to refuse")
	}

	body := rec.Body.String()
	if strings.Count(body, "{") != 1 {
		t.Errorf("expected exactly one JSON object, got: %s", body)
	}
	for _, leak := range []string{"access_token", "refresh_token", "Bearer"} {
		if strings.Contains(body, leak) {
			t.Errorf("refusal body leaked %q: %s", leak, body)
		}
	}
}

// TestCaptchaCheck_WrongAnswerIsHandled covers the other refusal branch.
func TestCaptchaCheck_WrongAnswerIsHandled(t *testing.T) {
	h := newGateTestHandler(t, alwaysOnPolicy())
	c, rec := newGateContext(t)

	handled, err := h.captchaCheck(c, firstPartyCaptchaScope(), auth.CaptchaFlowLogin,
		"a-challenge-id-that-does-not-exist", "ABCDEF")
	if !handled {
		t.Fatal("a wrong/unknown challenge must be handled, not passed through")
	}
	if err != nil {
		t.Fatalf("writing the refusal failed: %v", err)
	}
	if rec.Code != http.StatusPreconditionRequired {
		t.Errorf("status = %d, want 428", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "captcha_invalid") {
		t.Errorf("expected captcha_invalid, got: %s", rec.Body.String())
	}
}

// TestAppCaptchaScopeFor_CarriesNoApplicationWithoutTheService pins the guard
// that keeps the client lookup off the login path when the feature is off.
//
// The lookup added by the scope fix sits AHEAD of authentication, on the path an
// attacker drives hardest. Unconditional, it would make a brute-force attempt
// double as a query amplifier against oauth_clients. With no captcha service the
// helper must not touch the database at all — which is also why this test can
// assert it with a handler that has no pool wired.
func TestAppCaptchaScopeFor_CarriesNoApplicationWithoutTheService(t *testing.T) {
	h := NewAuthHandler(nil, nil, nil, testhelper.TestLogger())
	c, _ := newGateContext(t)

	scope := h.appCaptchaScopeFor(c, "some-client-id")

	if scope.ClientID != "some-client-id" {
		t.Errorf("client binding lost: %q", scope.ClientID)
	}
	if scope.ApplicationID != nil || scope.TenantID != 0 {
		t.Errorf("resolved an application with no captcha service: tenant=%d app=%v",
			scope.TenantID, scope.ApplicationID)
	}
}

// TestCaptchaCheck_PassesThroughWhenDisabled is the property every existing
// deployment depends on: with no captcha service the gate must be invisible.
func TestCaptchaCheck_PassesThroughWhenDisabled(t *testing.T) {
	h := NewAuthHandler(nil, nil, nil, testhelper.TestLogger())
	c, rec := newGateContext(t)

	handled, err := h.captchaCheck(c, firstPartyCaptchaScope(), auth.CaptchaFlowLogin, "", "")
	if handled {
		t.Fatal("a nil captcha service must never handle the request")
	}
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("nothing should have been written, got: %s", rec.Body.String())
	}
}

// TestCaptchaCheck_PassesThroughWhenPolicyOff covers the same property one layer
// down: the service exists, but the policy does not protect this flow.
func TestCaptchaCheck_PassesThroughWhenPolicyOff(t *testing.T) {
	h := newGateTestHandler(t, auth.DefaultCaptchaPolicy) // Enabled: false
	c, rec := newGateContext(t)

	handled, err := h.captchaCheck(c, firstPartyCaptchaScope(), auth.CaptchaFlowLogin, "", "")
	if handled {
		t.Fatal("a disabled policy must never refuse")
	}
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("nothing should have been written, got: %s", rec.Body.String())
	}
}
