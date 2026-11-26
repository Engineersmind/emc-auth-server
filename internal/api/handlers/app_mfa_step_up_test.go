package handlers

import (
	"net/http"
	"testing"

	"github.com/engineersmind/emc-auth-server/internal/audit"
)

// PUT .../mfa with refresh_step_up (#197).
func TestUpdateApplicationMFA_RefreshStepUp(t *testing.T) {
	e := newAppMFAHandlerEnv(t, "stepup-h")

	code, out := e.call(t, e.h.GetApplicationMFA, http.MethodGet, "")
	if code != http.StatusOK || out["refresh_step_up"] != false {
		t.Fatalf("GET default: %d %v, want refresh_step_up=false", code, out)
	}

	// refresh_step_up alone is a valid body.
	code, out = e.call(t, e.h.UpdateApplicationMFA, http.MethodPut, `{"refresh_step_up":true}`)
	if code != http.StatusOK || out["refresh_step_up"] != true {
		t.Fatalf("PUT true: %d %v, want 200 refresh_step_up=true", code, out)
	}
	// Re-sending the same value is not a change.
	if code, out = e.call(t, e.h.UpdateApplicationMFA, http.MethodPut, `{"refresh_step_up":true}`); code != http.StatusOK {
		t.Fatalf("PUT true again: %d %v", code, out)
	}
	// Other fields leave it alone.
	if code, out = e.call(t, e.h.UpdateApplicationMFA, http.MethodPut, `{"mode":"required"}`); code != http.StatusOK || out["refresh_step_up"] != true {
		t.Fatalf("PUT mode only: %d %v, want refresh_step_up kept true", code, out)
	}

	n, meta := e.audits(t, audit.ActionAdminMFARefreshStepUpChanged)
	if n != 1 {
		t.Fatalf("refresh_step_up audits = %d, want 1", n)
	}
	if meta["old_refresh_step_up"] != false || meta["new_refresh_step_up"] != true {
		t.Errorf("audit metadata = %v, want false → true", meta)
	}
}
