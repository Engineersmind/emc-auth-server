package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog"

	mw "github.com/engineersmind/emc-auth-server/internal/api/middleware"
	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// The three organisation outcomes of a sign-in must look identical whichever
// method the user signed in with, and none of them may read as a credential
// failure: they are reached only after the password (and any second factor)
// succeeded.
func TestOrganizationSignInError(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		status   int
		code     string
		handled  bool
		hasToken bool
	}{
		{"selection", &auth.OrganizationSelectionRequiredError{
			SelectionToken: "tok", ExpiresIn: 300,
			Organizations: []auth.OrganizationRef{{ID: "org_x", Slug: "acme", DisplayName: "Acme"}},
		}, http.StatusConflict, "organization_selection_required", true, true},
		{"denied", auth.ErrOrganizationAccessDenied, http.StatusForbidden, "organization_access_denied", true, false},
		{"wrapped denied", fmt.Errorf("mint: %w", auth.ErrOrganizationAccessDenied), http.StatusForbidden, "organization_access_denied", true, false},
		{"unavailable", auth.ErrOrganizationUnavailable, http.StatusServiceUnavailable, "organization_unavailable", true, false},
		{"unrelated", errors.New("invalid credentials"), 0, "", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			c := echo.New().NewContext(httptest.NewRequest(http.MethodPost, "/", nil), rec)
			handled, err := organizationSignInError(c, tc.err)
			if err != nil {
				t.Fatalf("write error = %v", err)
			}
			if handled != tc.handled {
				t.Fatalf("handled = %v, want %v", handled, tc.handled)
			}
			if !handled {
				return
			}
			if rec.Code != tc.status {
				t.Errorf("status = %d, want %d", rec.Code, tc.status)
			}
			var body map[string]any
			_ = json.Unmarshal(rec.Body.Bytes(), &body)
			if body["error"] != tc.code {
				t.Errorf("error = %v, want %s", body["error"], tc.code)
			}
			if _, ok := body["selection_token"]; ok != tc.hasToken {
				t.Errorf("selection_token present = %v, want %v", ok, tc.hasToken)
			}
		})
	}
}

// With ORGANIZATIONS_ENABLED=false every organisation endpoint must answer
// exactly like a route that does not exist, before reading credentials or
// the body.
func TestOrganizationRoutesAre404WhenDisabled(t *testing.T) {
	h := NewOrganizationHandler(auth.NewOrganizationService(nil, nil, false, zerolog.Nop()),
		nil, nil, nil, nil, mw.BuildCookieConfig("development", ""), zerolog.Nop())
	e := echo.New()
	handlers := map[string]echo.HandlerFunc{
		"select":       h.SelectOrganization,
		"switch":       h.SwitchOrganization,
		"me":           h.MyOrganizations,
		"preview":      h.PreviewInvitation,
		"accept":       h.AcceptInvitation,
		"app create":   h.CreateOrganization(h.AppScope),
		"admin create": h.CreateOrganization(h.AdminScope),
	}
	for name, fn := range handlers {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		if err := fn(e.NewContext(req, rec)); err != nil {
			t.Fatalf("%s: error = %v", name, err)
		}
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: status = %d, want 404 while organizations are disabled", name, rec.Code)
		}
	}
}

// The settings read is the exception: it answers 200 with the switch reported
// off, so the console can explain why the section is inert instead of showing
// an error.
func TestOrganizationSettingsReportDisabled(t *testing.T) {
	h := NewOrganizationHandler(auth.NewOrganizationService(nil, nil, false, zerolog.Nop()),
		nil, nil, nil, nil, mw.BuildCookieConfig("development", ""), zerolog.Nop())
	rec := httptest.NewRecorder()
	if err := h.GetSettings(echo.New().NewContext(httptest.NewRequest(http.MethodGet, "/", nil), rec)); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"organizations_enabled":false`) {
		t.Errorf("GetSettings = %d %s, want 200 with organizations_enabled false", rec.Code, rec.Body.String())
	}
}
