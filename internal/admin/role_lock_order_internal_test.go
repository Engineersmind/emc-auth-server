package admin

import (
	"strings"
	"testing"
)

// Database-free guard for the #220 lock-order fix: SetDefaultRole must take
// its roles locks ordered by id, written before the locking clause, and the
// locking statement must not filter on deleted_at — it has to cover the same
// rows the clear-is_default UPDATE can write, which deliberately ignores
// tombstones.
func TestSetDefaultRoleLockSQL_OrdersByIDAndIgnoresDeletedAt(t *testing.T) {
	order := strings.Index(setDefaultRoleLockSQL, "ORDER BY id")
	lock := strings.Index(setDefaultRoleLockSQL, "FOR NO KEY UPDATE")
	if order < 0 {
		t.Fatal("setDefaultRoleLockSQL has no ORDER BY id")
	}
	if lock < 0 || order > lock {
		t.Errorf("ORDER BY id at %d must come before FOR NO KEY UPDATE at %d", order, lock)
	}
	if strings.Contains(setDefaultRoleLockSQL, "deleted_at") {
		t.Error("setDefaultRoleLockSQL filters on deleted_at; the lock must cover every row the clear-UPDATE can write")
	}
}
