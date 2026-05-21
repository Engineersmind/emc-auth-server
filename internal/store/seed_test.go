package store_test

import (
	"context"
	"testing"

	"github.com/engineersmind/emc-auth-server/internal/store"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

func TestRunSeed_Idempotent(t *testing.T) {
	pool := testhelper.NewTestDB(t)
	testhelper.CleanupTables(t, pool)

	ctx := context.Background()
	logger := testhelper.TestLogger()

	// First call.
	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("first RunSeed() error = %v", err)
	}

	// Second call — ON CONFLICT DO NOTHING must prevent duplicates.
	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("second RunSeed() error = %v", err)
	}

	// Verify exactly one tenant with slug 'emc' exists.
	var count int
	err := pool.QueryRow(ctx, `SELECT count(*) FROM tenants WHERE slug = 'emc'`).Scan(&count)
	if err != nil {
		t.Fatalf("count tenants: %v", err)
	}
	if count != 1 {
		t.Errorf("tenant count = %d, want 1 (RunSeed must be idempotent)", count)
	}
}

func TestSeed_TenantExists(t *testing.T) {
	pool := testhelper.NewTestDB(t)
	testhelper.CleanupTables(t, pool)

	ctx := context.Background()
	logger := testhelper.TestLogger()

	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed() error = %v", err)
	}

	var id string
	err := pool.QueryRow(ctx,
		`SELECT id::text FROM tenants WHERE id = $1`,
		store.SeedTenantID,
	).Scan(&id)
	if err != nil {
		t.Fatalf("query seed tenant: %v", err)
	}
	if id != store.SeedTenantID.String() {
		t.Errorf("seed tenant ID = %q, want %q", id, store.SeedTenantID.String())
	}
}

func TestSeed_AdminUserExists(t *testing.T) {
	pool := testhelper.NewTestDB(t)
	testhelper.CleanupTables(t, pool)

	ctx := context.Background()
	logger := testhelper.TestLogger()

	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed() error = %v", err)
	}

	var id string
	err := pool.QueryRow(ctx,
		`SELECT id::text FROM users WHERE id = $1`,
		store.SeedUserID,
	).Scan(&id)
	if err != nil {
		t.Fatalf("query seed user: %v", err)
	}
	if id != store.SeedUserID.String() {
		t.Errorf("seed user ID = %q, want %q", id, store.SeedUserID.String())
	}
}
