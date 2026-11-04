package handlers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"

	mw "github.com/engineersmind/emc-auth-server/internal/api/middleware"
	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
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

// TestConsoleForgotPassword_RefusesBodiesTheLimiterCannotRead pins that the
// handler reads the body with the limiter's reader. Each body here is one the
// per-email limiter reads as no email at all; if the handler still acted on it
// (c.Bind accepts a form body), one recipient could be mailed past the limit.
//
// The handler has no reset service wired, so a body it accepted would reach
// the fan-out and panic instead of answering the generic 200.
func TestConsoleForgotPassword_RefusesBodiesTheLimiterCannotRead(t *testing.T) {
	h := NewAuthHandler(nil, nil, nil, testhelper.TestLogger())

	for name, body := range map[string]string{
		"form encoded":     `email=victim@example.test`,
		"leading garbage":  `x{"email":"victim@example.test"}`,
		"truncated object": `{"email":"victim@example.test"`,
	} {
		t.Run(name, func(t *testing.T) {
			probe := echo.New().NewContext(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)), httptest.NewRecorder())
			if sub, _ := mw.SubjectEmail(probe, nil); sub != "" {
				t.Fatalf("limiter reads %q from this body; the case no longer tests a body it cannot read", sub)
			}

			rec := consoleForgotRequest(h, uniqueTestIP(), body)
			if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "if that email address is registered") {
				t.Fatalf("status = %d body = %s, want the generic 200", rec.Code, rec.Body.String())
			}
		})
	}
}

// gateContextFrom is a first-party request from ip, for driving the captcha
// helpers directly.
func gateContextFrom(ip string) echo.Context {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader("{}"))
	req.RemoteAddr = "[" + ip + "]:40000"
	return echo.New().NewContext(req, httptest.NewRecorder())
}

// TestConsoleForgotPassword_HasItsOwnCaptchaCounter pins that reset requests
// and console sign-in do not share an adaptive failure counter. Shared, a few
// reset requests behind one office NAT would put a captcha on every console
// login from it, and any successful sign-in from that address would disarm the
// reset route's gate.
func TestConsoleForgotPassword_HasItsOwnCaptchaCounter(t *testing.T) {
	policy := auth.DefaultCaptchaPolicy
	policy.Enabled = true
	policy.Mode = auth.CaptchaModeAdaptive
	policy.TriggerAfterFailures = 2

	t.Run("reset requests do not arm console login", func(t *testing.T) {
		h := newGateTestHandler(t, policy)
		ip := uniqueTestIP()
		for i := 0; i < policy.TriggerAfterFailures+1; i++ {
			consoleForgotRequest(h, ip, `{"email":""}`)
		}
		if handled, _ := h.captchaCheck(gateContextFrom(ip), firstPartyCaptchaScope(), auth.CaptchaFlowLogin, "", ""); handled {
			t.Fatal("console login asked for a captcha after reset requests from the same address")
		}
	})

	t.Run("a successful sign-in does not disarm the reset route", func(t *testing.T) {
		h := newGateTestHandler(t, policy)
		ip := uniqueTestIP()
		for i := 0; i < policy.TriggerAfterFailures; i++ {
			consoleForgotRequest(h, ip, `{"email":""}`)
		}
		h.captchaClearFailures(gateContextFrom(ip), firstPartyCaptchaScope())
		if rec := consoleForgotRequest(h, ip, `{"email":""}`); rec.Code != http.StatusPreconditionRequired {
			t.Fatalf("status = %d after a console sign-in cleared its counter, want 428 — the reset gate was disarmed", rec.Code)
		}
	})
}
