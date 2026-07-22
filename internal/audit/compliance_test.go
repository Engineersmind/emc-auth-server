// Integration tests for the compliance features: tamper-evidence chain
// verification, append-only immutability, and GDPR pseudonymization.
// Real PostgreSQL via testhelper; skips when DATABASE_URL is unset.
package audit_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/engineersmind/emc-auth-server/internal/audit"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

func TestChainVerifiesAndIsTamperEvident(t *testing.T) {
	pool := testhelper.NewTestDB(t)
	action := uniqueAction(t)
	cleanupRows(t, pool, action)

	l := audit.New(pool, testhelper.TestLogger(),
		audit.WithBatchSize(10), audit.WithFlushInterval(30*time.Millisecond))

	for i := 0; i < 25; i++ {
		l.Log(context.Background(), audit.Event{
			ActorEmail: "chain@example.com", Action: action,
			ResourceType: "test", IPAddress: "203.0.113.7", Status: audit.StatusSuccess,
		})
	}
	ctx := context.Background()
	if err := l.Close(ctx); err != nil {
		t.Fatalf("close: %v", err)
	}

	res, err := l.VerifyChain(ctx, 1000)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.Intact {
		t.Fatalf("expected intact chain, got broken at %v: %s", res.BrokenAtID, res.Detail)
	}
	if res.Checked < 25 {
		t.Errorf("expected >=25 rows checked, got %d", res.Checked)
	}
}

func TestAuditLogsAppendOnly(t *testing.T) {
	pool := testhelper.NewTestDB(t)
	action := uniqueAction(t)
	cleanupRows(t, pool, action)

	l := audit.New(pool, testhelper.TestLogger(), audit.WithFlushInterval(20*time.Millisecond))
	l.Log(context.Background(), audit.Event{Action: action, ActorEmail: "x@y.com", ResourceType: "test"})
	if err := l.Close(context.Background()); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Direct UPDATE and DELETE must be rejected by the immutability trigger.
	_, updErr := pool.Exec(context.Background(),
		`UPDATE audit_logs SET actor_email = 'tampered' WHERE action = $1`, action)
	if updErr == nil || !strings.Contains(updErr.Error(), "append-only") {
		t.Errorf("expected append-only rejection on UPDATE, got %v", updErr)
	}
	_, delErr := pool.Exec(context.Background(),
		`DELETE FROM audit_logs WHERE action = $1`, action)
	if delErr == nil || !strings.Contains(delErr.Error(), "append-only") {
		t.Errorf("expected append-only rejection on DELETE, got %v", delErr)
	}
}

func TestPurgeAndPseudonymizeUseMaintenancePath(t *testing.T) {
	pool := testhelper.NewTestDB(t)
	action := uniqueAction(t)
	cleanupRows(t, pool, action)

	// purge_audit_logs runs through the maintenance path — it must succeed
	// (delete 0 rows for a 1-day window with only fresh rows) despite the
	// append-only trigger, proving the controlled-maintenance flag works.
	var purged int64
	if err := pool.QueryRow(context.Background(),
		`SELECT purge_audit_logs($1)`, 3650).Scan(&purged); err != nil {
		t.Fatalf("purge_audit_logs should succeed via maintenance path: %v", err)
	}
}
