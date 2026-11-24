package auth

import (
	"strings"
	"testing"
)

// Database-free guard for the #220 lock-order fix: every statement that takes
// FOR SHARE on more than one roles row must order by id, with the ORDER BY
// written before the locking clause — the ordering is what keeps these paths
// from deadlocking against runRBACImport's and SetDefaultRole's id-ordered
// locks.
func TestRoleLockSQL_OrdersByIDBeforeLocking(t *testing.T) {
	for name, sql := range map[string]string{
		"resolveApplicationRolesSQL":   resolveApplicationRolesSQL,
		"lockInvitationRolesSQL":       lockInvitationRolesSQL,
		"assignAppUserRolesResolveSQL": assignAppUserRolesResolveSQL,
	} {
		order := strings.Index(sql, "ORDER BY id")
		lock := strings.Index(sql, "FOR SHARE")
		if order < 0 {
			t.Errorf("%s has no ORDER BY id", name)
			continue
		}
		if lock < 0 || order > lock {
			t.Errorf("%s: ORDER BY id at %d must come before FOR SHARE at %d", name, order, lock)
		}
	}
}
