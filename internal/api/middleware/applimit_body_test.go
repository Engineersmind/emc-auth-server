package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
)

// The bug this pins (PR #147): AppClientRateLimiter keys on tokenClientID(c),
// which reads only the Authorization / X-Client-Authorization headers. Mounted
// on POST /captcha/challenge — which carries client_id in the JSON body and no
// auth headers at all — it read "" every time and passed every request through.
// The route was documented as carrying a per-application bucket that did not
// exist.
//
// These assert the body-aware replacement reads the field, and that the handler
// still gets an intact body afterwards.

func TestClientIDFromBody_ReadsTheField(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/",
		strings.NewReader(`{"purpose":"login","client_id":"app_abc123"}`))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	c := e.NewContext(req, httptest.NewRecorder())

	if got := clientIDFromBody(c); got != "app_abc123" {
		t.Errorf("clientIDFromBody = %q, want app_abc123", got)
	}
}

// The reason a body-peeking middleware is normally a bad idea: consume the body
// and the handler binds an empty struct. If this ever regresses, every captcha
// challenge request 400s.
func TestClientIDFromBody_RestoresTheBodyForTheHandler(t *testing.T) {
	e := echo.New()
	const payload = `{"purpose":"login","client_id":"app_abc123"}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(payload))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	c := e.NewContext(req, httptest.NewRecorder())

	_ = clientIDFromBody(c)

	var bound struct {
		Purpose  string `json:"purpose"`
		ClientID string `json:"client_id"`
	}
	if err := c.Bind(&bound); err != nil {
		t.Fatalf("handler could not bind after the peek: %v", err)
	}
	if bound.Purpose != "login" || bound.ClientID != "app_abc123" {
		t.Errorf("body did not survive the peek: %+v", bound)
	}
}

// Every unreadable shape means "no per-client bucket applies", never "reject" —
// the handler owns refusing a malformed request, and a limiter that 400s first
// would change the response an integrator sees for a bad payload.
func TestClientIDFromBody_FailsOpen(t *testing.T) {
	cases := []struct{ name, body string }{
		{"empty body", ""},
		{"truncated json", `{"client_id":"app_abc"`},
		{"no client_id", `{"purpose":"login"}`},
		{"wrong type", `{"client_id":12345}`},
		{"json array", `["client_id"]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := echo.New()
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tc.body))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			c := e.NewContext(req, httptest.NewRecorder())

			if got := clientIDFromBody(c); got != "" {
				t.Errorf("clientIDFromBody = %q, want \"\" (fail open)", got)
			}
		})
	}
}
