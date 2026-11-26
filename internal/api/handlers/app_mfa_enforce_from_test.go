package handlers

import (
	"net/http"
	"testing"

	"github.com/engineersmind/emc-auth-server/internal/audit"
)

// PUT .../mfa with enforce_from (#198): value, explicit null, invalid.
func TestUpdateApplicationMFA_EnforceFrom(t *testing.T) {
	e := newAppMFAHandlerEnv(t, "ef-h")

	code, out := e.call(t, e.h.GetApplicationMFA, http.MethodGet, "")
	if code != http.StatusOK || out["enforce_from"] != nil {
		t.Fatalf("GET default: %d %v, want enforce_from null", code, out)
	}
	if _, ok := out["enforce_from"]; !ok {
		t.Error("GET omits enforce_from; want an explicit null")
	}

	code, out = e.call(t, e.h.UpdateApplicationMFA, http.MethodPut, `{"enforce_from":"2031-01-02T03:04:05Z"}`)
	if code != http.StatusOK || out["enforce_from"] != "2031-01-02T03:04:05Z" {
		t.Fatalf("PUT date: %d %v, want 200 with the date", code, out)
	}
	// Omitted keeps it.
	if code, out = e.call(t, e.h.UpdateApplicationMFA, http.MethodPut, `{"mode":"required"}`); code != http.StatusOK || out["enforce_from"] != "2031-01-02T03:04:05Z" {
		t.Fatalf("PUT without enforce_from: %d %v, want the date kept", code, out)
	}
	// Explicit null clears it.
	if code, out = e.call(t, e.h.UpdateApplicationMFA, http.MethodPut, `{"enforce_from":null}`); code != http.StatusOK || out["enforce_from"] != nil {
		t.Fatalf("PUT null: %d %v, want cleared", code, out)
	}
	if code, out = e.call(t, e.h.UpdateApplicationMFA, http.MethodPut, `{"enforce_from":"next tuesday"}`); code != http.StatusBadRequest {
		t.Fatalf("PUT invalid: %d %v, want 400", code, out)
	}

	n, meta := e.audits(t, audit.ActionAdminMFAEnforceFromChanged)
	if n != 2 {
		t.Fatalf("enforce_from audits = %d, want 2 (set, clear)", n)
	}
	if meta["old_enforce_from"] != "2031-01-02T03:04:05Z" || meta["new_enforce_from"] != nil {
		t.Errorf("last audit = %v, want date → null", meta)
	}
}
