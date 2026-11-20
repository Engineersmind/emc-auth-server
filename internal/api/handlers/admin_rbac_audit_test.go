package handlers

import (
	"testing"

	"github.com/engineersmind/emc-auth-server/internal/admin"
)

func TestRBACAuditChanges_ListsRolesAndBoundsTheDetail(t *testing.T) {
	rows := []admin.RBACImportRowResult{
		{Kind: admin.RBACKindPermission, Name: "p:one", Outcome: admin.RBACOutcomeCreate},
		{Kind: admin.RBACKindRole, Name: "viewer", Outcome: admin.RBACOutcomeUpdate,
			Added: []string{"a:read"}, Removed: []string{"b:read"}},
		{Kind: admin.RBACKindRole, Name: "same", Outcome: admin.RBACOutcomeSkip},
	}
	changes, truncated := rbacAuditChanges(rows)
	if truncated || len(changes) != 1 {
		t.Fatalf("changes = %+v truncated = %v", changes, truncated)
	}
	if changes[0]["role"] != "viewer" || changes[0]["removed_count"] != 1 {
		t.Errorf("change = %+v", changes[0])
	}

	// Many roles, and one role with many names, are cut and flagged.
	var many []admin.RBACImportRowResult
	for i := 0; i < maxAuditRoleChanges+10; i++ {
		many = append(many, admin.RBACImportRowResult{Kind: admin.RBACKindRole, Name: "r", Outcome: admin.RBACOutcomeCreate})
	}
	changes, truncated = rbacAuditChanges(many)
	if len(changes) != maxAuditRoleChanges || !truncated {
		t.Errorf("role cap: len = %d truncated = %v", len(changes), truncated)
	}
	names := make([]string, maxAuditNamesPerRole+5)
	_, truncated = rbacAuditChanges([]admin.RBACImportRowResult{
		{Kind: admin.RBACKindRole, Name: "big", Outcome: admin.RBACOutcomeUpdate, Added: names},
	})
	if !truncated {
		t.Error("a role with too many names was not flagged as truncated")
	}
}
