// Integration tests for the async audit writer (writer.go).
// Follow the repo convention: real PostgreSQL via testhelper, skip when
// DATABASE_URL is not set.
package audit_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/engineersmind/emc-auth-server/internal/audit"
	"github.com/engineersmind/emc-auth-server/internal/metrics"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// uniqueAction returns a per-test action tag so concurrent test runs and
// leftover rows can never cross-contaminate assertions.
func uniqueAction(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("test.async_writer.%s.%d", t.Name(), time.Now().UnixNano())
}

func countRows(t *testing.T, pool *pgxpool.Pool, action string) int {
	t.Helper()
	var n int
	err := pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM audit_logs WHERE action = $1`, action).Scan(&n)
	if err != nil {
		t.Fatalf("count audit rows: %v", err)
	}
	return n
}

func cleanupRows(t *testing.T, pool *pgxpool.Pool, action string) {
	t.Helper()
	t.Cleanup(func() {
		// audit_logs is append-only (immutability trigger, migration 00056), so
		// the delete must go through the maintenance path: a transaction that
		// sets the maintenance flag the trigger checks.
		ctx := context.Background()
		tx, err := pool.Begin(ctx)
		if err != nil {
			return
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx, `SET LOCAL emc.audit_maintenance = 'on'`); err != nil {
			return
		}
		if _, err := tx.Exec(ctx, `DELETE FROM audit_logs WHERE action = $1`, action); err != nil {
			return
		}
		_ = tx.Commit(ctx)
	})
}

// TestAsyncWriterPersistsEvents verifies the whole pipeline: events enqueued
// via Log() are batch-inserted and all present after Close() drains.
func TestAsyncWriterPersistsEvents(t *testing.T) {
	pool := testhelper.NewTestDB(t)
	action := uniqueAction(t)
	cleanupRows(t, pool, action)

	l := audit.New(pool, testhelper.TestLogger(),
		audit.WithBatchSize(100),
		audit.WithFlushInterval(50*time.Millisecond),
	)

	const total = 1250 // several full batches plus a partial one
	for i := 0; i < total; i++ {
		l.Log(context.Background(), audit.Event{
			ActorEmail:   "writer-test@example.com",
			Action:       action,
			ResourceType: "test",
			ResourceID:   fmt.Sprintf("%d", i),
			IPAddress:    "203.0.113.7",
			UserAgent:    "writer-test",
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := l.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if got := countRows(t, pool, action); got != total {
		t.Fatalf("persisted rows = %d, want %d", got, total)
	}
}

// TestLogNeverBlocksWhenQueueFull verifies the core heavy-load guarantee:
// with a full buffer and no flushing, Log() drops immediately instead of
// blocking the caller.
func TestLogNeverBlocksWhenQueueFull(t *testing.T) {
	pool := testhelper.NewTestDB(t)
	action := uniqueAction(t)
	cleanupRows(t, pool, action)

	// Tiny queue, giant batch, hour-long interval: the worker never flushes
	// during the test, so everything past the buffer capacity must drop.
	l := audit.New(pool, testhelper.TestLogger(),
		audit.WithQueueSize(4),
		audit.WithBatchSize(100000),
		audit.WithFlushInterval(time.Hour),
	)

	droppedBefore := testutil.ToFloat64(metrics.AuditEventsDropped.WithLabelValues("queue_full"))

	const total = 200
	start := time.Now()
	for i := 0; i < total; i++ {
		l.Log(context.Background(), audit.Event{Action: action, UserAgent: "drop-test"})
	}
	elapsed := time.Since(start)

	// 200 non-blocking sends must complete near-instantly. The generous
	// bound only fails if Log() actually blocked on the DB or the channel.
	if elapsed > 2*time.Second {
		t.Fatalf("Log() blocked: %d calls took %v", total, elapsed)
	}

	droppedAfter := testutil.ToFloat64(metrics.AuditEventsDropped.WithLabelValues("queue_full"))
	if delta := droppedAfter - droppedBefore; delta < float64(total-4) {
		t.Fatalf("dropped counter delta = %v, want >= %d", delta, total-4)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := l.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestLogAfterCloseDropsSafely verifies shutdown behavior: Log() after
// Close() must neither panic nor write.
func TestLogAfterCloseDropsSafely(t *testing.T) {
	pool := testhelper.NewTestDB(t)
	action := uniqueAction(t)
	cleanupRows(t, pool, action)

	l := audit.New(pool, testhelper.TestLogger())
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := l.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Second Close must be safe too.
	if err := l.Close(ctx); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	l.Log(context.Background(), audit.Event{Action: action})

	if got := countRows(t, pool, action); got != 0 {
		t.Fatalf("event written after Close: %d rows", got)
	}
}

// TestApplicationIDRoundTrip verifies the new application_id column: an event
// stamped with an application is persisted with it and retrievable through
// the Query ApplicationID filter, and a filter for a different app excludes it.
func TestApplicationIDRoundTrip(t *testing.T) {
	pool := testhelper.NewTestDB(t)
	action := uniqueAction(t)
	cleanupRows(t, pool, action)

	ctx := context.Background()

	// Minimal tenant + application fixtures for the FK.
	slug := fmt.Sprintf("audit-writer-%d", time.Now().UnixNano())
	var tenantID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO tenants (name, slug, jwt_secret) VALUES ($1, $1, 'test-secret') RETURNING id`,
		slug).Scan(&tenantID); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	var appID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO oauth_clients (tenant_id, client_id, name) VALUES ($1, $2, $2) RETURNING id`,
		tenantID, "app_"+slug).Scan(&appID); err != nil {
		t.Fatalf("create application: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM audit_logs WHERE tenant_id = $1`, tenantID)
		_, _ = pool.Exec(ctx, `DELETE FROM oauth_clients WHERE id = $1`, appID)
		_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID)
	})

	l := audit.New(pool, testhelper.TestLogger(), audit.WithFlushInterval(50*time.Millisecond))
	l.Log(ctx, audit.Event{
		TenantID:      &tenantID,
		ApplicationID: &appID,
		ActorEmail:    "app-user@example.com",
		Action:        action,
		ResourceType:  "test",
		IPAddress:     "203.0.113.9",
		UserAgent:     "roundtrip-test",
	})
	// Second event with no application context — must not match the filter.
	l.Log(ctx, audit.Event{
		TenantID:   &tenantID,
		ActorEmail: "tenant-user@example.com",
		Action:     action,
	})

	closeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := l.Close(closeCtx); err != nil {
		t.Fatalf("Close: %v", err)
	}

	page, err := l.Query(ctx, audit.QueryParams{
		TenantID:      &tenantID,
		ApplicationID: fmt.Sprintf("%d", appID),
	})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if page.Total != 1 {
		t.Fatalf("app-filtered total = %d, want 1", page.Total)
	}
	got := page.Logs[0]
	if got.ApplicationID == nil || *got.ApplicationID != fmt.Sprintf("%d", appID) {
		t.Fatalf("ApplicationID = %v, want %d", got.ApplicationID, appID)
	}
	if got.IPAddress != "203.0.113.9" {
		t.Fatalf("IPAddress = %q, want 203.0.113.9", got.IPAddress)
	}

	// Unfiltered tenant query sees both events.
	all, err := l.Query(ctx, audit.QueryParams{TenantID: &tenantID})
	if err != nil {
		t.Fatalf("Query all: %v", err)
	}
	if all.Total != 2 {
		t.Fatalf("tenant total = %d, want 2", all.Total)
	}
}

// TestInvalidIPBecomesNull verifies one malformed IP cannot sink a batch:
// the event still persists, with ip_address NULL (returned as "").
func TestInvalidIPBecomesNull(t *testing.T) {
	pool := testhelper.NewTestDB(t)
	action := uniqueAction(t)
	cleanupRows(t, pool, action)

	l := audit.New(pool, testhelper.TestLogger(), audit.WithFlushInterval(50*time.Millisecond))
	l.Log(context.Background(), audit.Event{Action: action, IPAddress: "not-an-ip"})
	l.Log(context.Background(), audit.Event{Action: action, IPAddress: "198.51.100.20"})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := l.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if got := countRows(t, pool, action); got != 2 {
		t.Fatalf("persisted rows = %d, want 2 (bad IP must not sink the batch)", got)
	}
}

// TestStatusRequestIDMetadataRoundTrip verifies the rich-context columns
// persist and come back through Query intact, and that a secret threaded into
// metadata is redacted end-to-end.
func TestStatusRequestIDMetadataRoundTrip(t *testing.T) {
	pool := testhelper.NewTestDB(t)
	action := uniqueAction(t)
	cleanupRows(t, pool, action)

	l := audit.New(pool, testhelper.TestLogger(), audit.WithFlushInterval(50*time.Millisecond))
	l.Log(context.Background(), audit.Event{
		ActorEmail: "rich@example.com",
		Action:     action,
		Status:     audit.StatusFailure,
		RequestID:  "req_abc123",
		Metadata: map[string]any{
			"reason":        "invalid_credentials",
			"client_secret": "cs_should_be_hidden",
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := l.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}

	page, err := l.Query(ctx, audit.QueryParams{Action: action})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if page.Total != 1 {
		t.Fatalf("total = %d, want 1", page.Total)
	}
	got := page.Logs[0]
	if got.Status != audit.StatusFailure {
		t.Errorf("status = %q, want failure", got.Status)
	}
	if got.RequestID != "req_abc123" {
		t.Errorf("request_id = %q, want req_abc123", got.RequestID)
	}
	var md map[string]any
	if err := json.Unmarshal(got.Metadata, &md); err != nil {
		t.Fatalf("metadata not valid json: %v (%s)", err, got.Metadata)
	}
	if md["reason"] != "invalid_credentials" {
		t.Errorf("metadata.reason = %v, want invalid_credentials", md["reason"])
	}
	if md["client_secret"] != "[REDACTED]" {
		t.Errorf("metadata.client_secret = %v, want [REDACTED]", md["client_secret"])
	}
	if strings.Contains(string(got.Metadata), "cs_should_be_hidden") {
		t.Fatalf("secret leaked into persisted metadata: %s", got.Metadata)
	}
}

// TestStatusFilter verifies the Query status filter narrows to failures only.
func TestStatusFilter(t *testing.T) {
	pool := testhelper.NewTestDB(t)
	action := uniqueAction(t)
	cleanupRows(t, pool, action)

	l := audit.New(pool, testhelper.TestLogger(), audit.WithFlushInterval(50*time.Millisecond))
	l.Log(context.Background(), audit.Event{Action: action, Status: audit.StatusSuccess})
	l.Log(context.Background(), audit.Event{Action: action, Status: audit.StatusSuccess})
	l.Log(context.Background(), audit.Event{Action: action, Status: audit.StatusFailure})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := l.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}

	failures, err := l.Query(ctx, audit.QueryParams{Action: action, Status: audit.StatusFailure})
	if err != nil {
		t.Fatalf("Query failures: %v", err)
	}
	if failures.Total != 1 {
		t.Fatalf("failure count = %d, want 1", failures.Total)
	}

	all, err := l.Query(ctx, audit.QueryParams{Action: action})
	if err != nil {
		t.Fatalf("Query all: %v", err)
	}
	if all.Total != 3 {
		t.Fatalf("total count = %d, want 3", all.Total)
	}
}

// TestDefaultStatusIsSuccess verifies an event logged without an explicit
// status persists as success (never NULL / empty).
func TestDefaultStatusIsSuccess(t *testing.T) {
	pool := testhelper.NewTestDB(t)
	action := uniqueAction(t)
	cleanupRows(t, pool, action)

	l := audit.New(pool, testhelper.TestLogger(), audit.WithFlushInterval(50*time.Millisecond))
	l.Log(context.Background(), audit.Event{Action: action}) // no Status

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := l.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}

	page, err := l.Query(ctx, audit.QueryParams{Action: action})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if page.Total != 1 || page.Logs[0].Status != audit.StatusSuccess {
		t.Fatalf("expected 1 row with status=success, got total=%d status=%q", page.Total,
			func() string {
				if page.Total > 0 {
					return page.Logs[0].Status
				}
				return ""
			}())
	}
}
