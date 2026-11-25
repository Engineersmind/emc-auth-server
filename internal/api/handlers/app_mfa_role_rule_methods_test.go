package handlers

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/engineersmind/emc-auth-server/internal/audit"
	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// PUT .../mfa/role-rules with per-rule methods (#199).
func TestApplicationMFARoleRules_Methods(t *testing.T) {
	e := newAppMFAHandlerEnv(t, "rrm-h")
	if err := e.totpSvc.SetAppMFAPolicy(e.ctx, e.tenantID, e.appID, auth.MFAModeOptional, []string{auth.MFAMethodTOTP, auth.MFAMethodEmail}, nil); err != nil {
		t.Fatalf("SetAppMFAPolicy: %v", err)
	}
	var role int64
	if err := e.pool.QueryRow(e.ctx, `
		INSERT INTO roles (tenant_id, application_id, name, is_system, created_at)
		VALUES ($1, $2, $3, false, NOW()) RETURNING id
	`, e.tenantID, e.appID, fmt.Sprintf("rrm-%d", time.Now().UnixNano())).Scan(&role); err != nil {
		t.Fatalf("insert role: %v", err)
	}

	// Both shapes at once, or neither, is a 400.
	if code, out := e.call(t, e.h.UpdateApplicationMFARoleRules, http.MethodPut, `{"role_ids":[],"rules":[]}`); code != http.StatusBadRequest {
		t.Fatalf("both shapes: %d %v, want 400", code, out)
	}
	// Empty, unknown or foreign methods are 400 mfa_role_rule_invalid_methods.
	for _, methods := range []string{`[]`, `["sms"]`} {
		body := fmt.Sprintf(`{"rules":[{"role_id":"%d","allowed_methods":%s}]}`, role, methods)
		if code, out := e.call(t, e.h.UpdateApplicationMFARoleRules, http.MethodPut, body); code != http.StatusBadRequest || out["error"] != "mfa_role_rule_invalid_methods" {
			t.Fatalf("methods %s: %d %v, want 400 mfa_role_rule_invalid_methods", methods, code, out)
		}
	}

	body := fmt.Sprintf(`{"rules":[{"role_id":"%d","allowed_methods":["totp"]}]}`, role)
	code, out := e.call(t, e.h.UpdateApplicationMFARoleRules, http.MethodPut, body)
	if code != http.StatusOK {
		t.Fatalf("PUT rules: %d %v", code, out)
	}
	rules, _ := out["rules"].([]any)
	if len(rules) != 1 {
		t.Fatalf("rules = %v, want one", out["rules"])
	}
	if m, _ := rules[0].(map[string]any)["allowed_methods"].([]any); len(m) != 1 || m[0] != "totp" {
		t.Errorf("allowed_methods = %v, want [totp]", rules[0])
	}

	// role_ids still works and resets methods to the application's list.
	code, out = e.call(t, e.h.UpdateApplicationMFARoleRules, http.MethodPut, fmt.Sprintf(`{"role_ids":["%d"]}`, role))
	if code != http.StatusOK {
		t.Fatalf("PUT role_ids: %d %v", code, out)
	}
	if rules, _ = out["rules"].([]any); len(rules) != 1 || rules[0].(map[string]any)["allowed_methods"] != nil {
		t.Errorf("after role_ids: %v, want allowed_methods null", out["rules"])
	}

	n, meta := e.audits(t, audit.ActionAdminMFARoleRulesSet)
	if n != 2 {
		t.Fatalf("role-rule audits = %d, want 2 (methods set, methods reset)", n)
	}
	if _, ok := meta["new_rules"]; !ok {
		t.Errorf("audit metadata lacks new_rules: %v", meta)
	}
}
