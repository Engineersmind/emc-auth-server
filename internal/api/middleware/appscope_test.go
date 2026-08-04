package middleware_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"

	"github.com/engineersmind/emc-auth-server/internal/api/middleware"
)

// runNormalized sends one request through NormalizeAppScopeUnauthorized wrapping
// the given handler, on a real Echo router so the framework's own error handler
// and Response bookkeeping are in play — the parts a bare echo.NewContext skips
// and where this middleware's failure modes live.
func runNormalized(handler echo.HandlerFunc) *httptest.ResponseRecorder {
	e := echo.New()
	e.GET("/api/v1/auth/apps/me", handler, middleware.NormalizeAppScopeUnauthorized)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/apps/me", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}

// TestNormalizeAppScopeUnauthorized_RewritesEvery401 is the no-oracle contract:
// whatever code a downstream middleware or handler chose, a 401 leaving this
// route says token_invalid and nothing more specific. jwtRenew's token_expired
// is the case that matters — it is produced before AppMe runs at all, so without
// this the endpoint would distinguish "expired" from "wrong application".
func TestNormalizeAppScopeUnauthorized_RewritesEvery401(t *testing.T) {
	downstreamCodes := []string{"token_expired", "token_missing", "unauthenticated", "service_unavailable"}

	for _, code := range downstreamCodes {
		t.Run(code, func(t *testing.T) {
			rec := runNormalized(func(c echo.Context) error {
				return c.JSON(http.StatusUnauthorized, map[string]string{
					"error": "some specific reason",
					"code":  code,
				})
			})

			if rec.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", rec.Code)
			}
			var body map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("unmarshal body %q: %v", rec.Body.String(), err)
			}
			if body["code"] != "token_invalid" {
				t.Errorf("code = %q, want token_invalid — the downstream reason leaked", body["code"])
			}
			if strings.Contains(rec.Body.String(), code) {
				t.Errorf("body %q still names the downstream reason %q", rec.Body.String(), code)
			}
		})
	}
}

// TestNormalizeAppScopeUnauthorized_PassesSuccessThrough pins that buffering does
// not disturb the ordinary path: status, body, and headers set by the handler
// must arrive unchanged.
func TestNormalizeAppScopeUnauthorized_PassesSuccessThrough(t *testing.T) {
	rec := runNormalized(func(c echo.Context) error {
		c.Response().Header().Set("X-Probe", "kept")
		return c.JSON(http.StatusOK, map[string]string{"email": "user@emc.local"})
	})

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("X-Probe"); got != "kept" {
		t.Errorf("X-Probe = %q, want %q — headers were dropped by the buffer", got, "kept")
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal body %q: %v", rec.Body.String(), err)
	}
	if body["email"] != "user@emc.local" {
		t.Errorf("email = %q, want user@emc.local", body["email"])
	}
}

// TestNormalizeAppScopeUnauthorized_ErrorReturnIsNotDoubleWritten covers the
// case a buffering middleware gets wrong: a handler that returns an error
// instead of writing a response.
//
// The buffer holds nothing, so replaying it commits a header — 0 defaults to 200
// — and then returning the error hands Echo's error handler an already-committed
// writer. The client gets a 200 carrying an error payload, and the real status is
// lost. The response must be a single clean 500.
func TestNormalizeAppScopeUnauthorized_ErrorReturnIsNotDoubleWritten(t *testing.T) {
	rec := runNormalized(func(c echo.Context) error {
		return errors.New("downstream exploded")
	})

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 — a returned error must not be reported as success", rec.Code)
	}
	if strings.Count(rec.Body.String(), "{") > 1 {
		t.Errorf("body %q looks like two responses concatenated", rec.Body.String())
	}
}

// TestNormalizeAppScopeUnauthorized_HTTPErrorKeepsItsStatus is the same hazard
// via echo.HTTPError, which is how Echo middleware most often reports failure.
// A 503 must stay a 503 rather than being flattened into the buffered default.
func TestNormalizeAppScopeUnauthorized_HTTPErrorKeepsItsStatus(t *testing.T) {
	rec := runNormalized(func(c echo.Context) error {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "upstream down")
	})

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rec.Code)
	}
}

// TestNormalizeAppScopeUnauthorized_401ErrorIsStillNormalized guards the
// interaction between the two fixes: an early `return err` must not become an
// escape hatch that lets a 401 out unnormalized. echo.NewHTTPError(401) is
// exactly how a middleware can report unauthorized as an error rather than by
// writing the body itself.
func TestNormalizeAppScopeUnauthorized_401ErrorIsStillNormalized(t *testing.T) {
	rec := runNormalized(func(c echo.Context) error {
		return echo.NewHTTPError(http.StatusUnauthorized, "token is expired")
	})

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "expired") {
		t.Errorf("body %q leaks the rejection reason", rec.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal body %q: %v", rec.Body.String(), err)
	}
	if body["code"] != "token_invalid" {
		t.Errorf("code = %q, want token_invalid", body["code"])
	}
}
