package handlers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/engineersmind/emc-auth-server/internal/audit"
	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// GET/PUT .../mfa/role-rules and the role-deletion guard (#195).
func TestApplicationMFARoleRules(t *testing.T) {
	e := newAppMFAHandlerEnv(t, "rr-h")
	newRole := func(appID *int64, name string) int64 {
		t.Helper()
		var id int64
		if err := e.pool.QueryRow(e.ctx, `
			INSERT INTO roles (tenant_id, application_id, name, is_system, created_at)
			VALUES ($1, $2, $3, false, NOW()) RETURNING id
		`, e.tenantID, appID, fmt.Sprintf("%s-%d", name, time.Now().UnixNano())).Scan(&id); err != nil {
			t.Fatalf("insert role: %v", err)
		}
		return id
	}
	role := newRole(&e.appID, "finance")
	tenantRole := newRole(nil, "tenant-level")
	body := func(ids ...int64) string {
		s := `{"role_ids":[`
		for i, id := range ids {
			if i > 0 {
				s += ","
			}
			s += strconv.Quote(strconv.FormatInt(id, 10))
		}
		return s + `]}`
	}

	code, out := e.call(t, e.h.GetApplicationMFARoleRules, http.MethodGet, "")
	if code != http.StatusOK || len(out["rules"].([]any)) != 0 {
		t.Fatalf("GET empty: %d %v", code, out)
	}
	if code, out := e.call(t, e.h.UpdateApplicationMFARoleRules, http.MethodPut, `{}`); code != http.StatusBadRequest {
		t.Fatalf("missing role_ids: %d %v, want 400", code, out)
	}
	if code, out := e.call(t, e.h.UpdateApplicationMFARoleRules, http.MethodPut, body(tenantRole)); code != http.StatusBadRequest || out["error"] != "mfa_role_rule_invalid_role" {
		t.Fatalf("tenant-level role: %d %v, want 400 mfa_role_rule_invalid_role", code, out)
	}

	code, out = e.call(t, e.h.UpdateApplicationMFARoleRules, http.MethodPut, body(role))
	if code != http.StatusOK || len(out["rules"].([]any)) != 1 {
		t.Fatalf("PUT [role]: %d %v, want 200 with one rule", code, out)
	}
	if code, out = e.call(t, e.h.GetApplicationMFARoleRules, http.MethodGet, ""); code != http.StatusOK || len(out["rules"].([]any)) != 1 {
		t.Fatalf("GET after PUT: %d %v", code, out)
	}

	// The role cannot be deleted while a rule lists it.
	del := func() int {
		t.Helper()
		rec := httptest.NewRecorder()
		c := echo.New().NewContext(httptest.NewRequest(http.MethodDelete, "/", nil), rec)
		c.Set("user", e.claims)
		c.SetParamNames("tid", "rid")
		c.SetParamValues(strconv.FormatInt(e.tenantID, 10), strconv.FormatInt(role, 10))
		if err := e.h.TenantDeleteRole(c); err != nil {
			t.Fatalf("TenantDeleteRole: %v", err)
		}
		return rec.Code
	}
	if code := del(); code != http.StatusConflict {
		t.Fatalf("delete role listed by a rule: %d, want 409", code)
	}

	// Inactive application: a non-empty write is 409, clearing is fine.
	off := false
	if _, err := e.totpSvc.UpdateAppMFASettings(e.ctx, e.tenantID, e.appID, auth.AppMFAUpdate{Enabled: &off}, nil); err != nil {
		t.Fatalf("UpdateAppMFASettings(off): %v", err)
	}
	if code, out := e.call(t, e.h.UpdateApplicationMFARoleRules, http.MethodPut, body(role)); code != http.StatusConflict || out["error"] != "mfa_role_rules_inactive" {
		t.Fatalf("switch off: %d %v, want 409 mfa_role_rules_inactive", code, out)
	}
	if code, out := e.call(t, e.h.UpdateApplicationMFARoleRules, http.MethodPut, `{"role_ids":[]}`); code != http.StatusOK {
		t.Fatalf("clear while off: %d %v, want 200", code, out)
	}
	if code := del(); code != http.StatusOK {
		t.Fatalf("delete role after clearing the rule: %d, want 200", code)
	}

	// Two real changes (set, clear); the refused writes are not audited.
	n, meta := e.audits(t, audit.ActionAdminMFARoleRulesSet)
	if n != 2 {
		t.Fatalf("role-rule audits = %d, want 2", n)
	}
	if old, _ := meta["old_role_ids"].([]any); len(old) != 1 || old[0] != strconv.FormatInt(role, 10) {
		t.Errorf("last audit old_role_ids = %v, want [%d]", meta["old_role_ids"], role)
	}
	if nw, _ := meta["new_role_ids"].([]any); len(nw) != 0 {
		t.Errorf("last audit new_role_ids = %v, want []", meta["new_role_ids"])
	}
}
