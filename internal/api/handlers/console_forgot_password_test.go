package handlers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// ---------------------------------------------------------------------------
// The captcha gate on POST /auth/console/forgot-password (issue #179).
//
// The handler under test has no reset service wired, so any request that got
// past the gate to the lookup would panic. Every assertion here is about what
// happens before that.
// ---------------------------------------------------------------------------

// consoleForgotRequest posts body from an address no other test uses, so a
// failure counter left in Redis by an earlier run cannot arm the gate early.
func consoleForgotRequest(h *AuthHandler, ip, body string) *httptest.ResponseRecorder {
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/console/forgot-password", strings.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	// Brackets are required: an unbracketed IPv6 host:port does not split, the
	// origin comes back empty, and the adaptive counter is silently skipped.
	req.RemoteAddr = "[" + ip + "]:40000"
	rec := httptest.NewRecorder()
	_ = h.ConsoleForgotPassword(e.NewContext(req, rec))
	return rec
}

func uniqueTestIP() string {
	n := time.Now().UnixNano()
	return fmt.Sprintf("2001:db8:179::%x:%x", (n>>16)&0xffff, n&0xffff)
}

func TestConsoleForgotPassword_CaptchaRefusesBeforeTheLookup(t *testing.T) {
	h := newGateTestHandler(t, alwaysOnPolicy())

	rec := consoleForgotRequest(h, uniqueTestIP(), `{"email":"admin@example.test"}`)

	if rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("status = %d, want 428 (body %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "captcha_required") {
		t.Errorf("body = %s, want captcha_required", rec.Body.String())
	}
}

// TestConsoleForgotPassword_EveryRequestArmsTheAdaptiveGate pins that a failure
// is recorded on each request. The route answers the same 200 whatever the
// outcome, so if it recorded nothing the adaptive gate could never arm on an
// unauthenticated route that sends email.
func TestConsoleForgotPassword_EveryRequestArmsTheAdaptiveGate(t *testing.T) {
	policy := auth.DefaultCaptchaPolicy
	policy.Enabled = true
	policy.Mode = auth.CaptchaModeAdaptive
	policy.TriggerAfterFailures = 2
	h := newGateTestHandler(t, policy)
	ip := uniqueTestIP()

	// An empty email stops after the gate, so the nil reset service is never
	// reached while the counter fills.
	for i := 0; i < policy.TriggerAfterFailures; i++ {
		if rec := consoleForgotRequest(h, ip, `{"email":""}`); rec.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200 before the gate arms", i+1, rec.Code)
		}
	}
	rec := consoleForgotRequest(h, ip, `{"email":""}`)
	if rec.Code != http.StatusPreconditionRequired {
		t.Errorf("after %d requests: status = %d, want 428 — the gate did not arm", policy.TriggerAfterFailures, rec.Code)
	}
}
