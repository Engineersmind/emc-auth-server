package auth

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// Test seam for enforceSessionCap (#226) — same idea as export_mfa_gate_test.go.
//
// In an _test.go file, so nothing here is compiled into the binary.

// ExportedEnforceSessionCap calls the production enforceSessionCap, so a test
// can run the eviction inside a transaction it controls — including one it then
// rolls back — and assert nothing was counted before the commit.
func ExportedEnforceSessionCap(ctx context.Context, tx pgx.Tx, userID, tenantID int64, maxSessions int) ([]int64, error) {
	return enforceSessionCap(ctx, tx, userID, tenantID, maxSessions)
}
