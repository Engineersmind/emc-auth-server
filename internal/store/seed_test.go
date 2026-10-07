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

	var id int64
	err := pool.QueryRow(ctx,
		`SELECT id FROM tenants WHERE slug = 'emc' AND deleted_at IS NULL`,
	).Scan(&id)
	if err != nil {
		t.Fatalf("query seed tenant: %v", err)
	}
	if id == 0 {
		t.Error("seed tenant ID should be non-zero")
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

	var id int64
	err := pool.QueryRow(ctx,
		`SELECT id FROM users WHERE email = 'admin@emc.local' AND deleted_at IS NULL`,
	).Scan(&id)
	if err != nil {
		t.Fatalf("query seed user: %v", err)
	}
	if id == 0 {
		t.Error("seed user ID should be non-zero")
	}
}

// GHSA-hv5j-m2r7-r4cr: a deployed environment must never seed a super-admin
// with the compiled-in default password.
func TestRunSeed_DeployedEnvRequiresSeedAdminPassword(t *testing.T) {
	pool := testhelper.NewTestDB(t)
	testhelper.CleanupTables(t, pool)
	t.Setenv("ENV", "production")
	t.Setenv("SEED_ADMIN_PASSWORD", "")

	ctx := context.Background()
	logger := testhelper.TestLogger()

	if err := store.RunSeed(ctx, pool, logger); err == nil {
		t.Fatal("RunSeed() without SEED_ADMIN_PASSWORD under ENV=production: expected error, got nil")
	}

	// With a real password the seed completes; a later boot without the
	// variable is the upgrade path — the credential row exists, so it must
	// not fail.
	t.Setenv("SEED_ADMIN_PASSWORD", "str0ng-first-boot-password")
	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed() with SEED_ADMIN_PASSWORD error = %v", err)
	}
	t.Setenv("SEED_ADMIN_PASSWORD", "")
	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("upgrade-boot RunSeed() without SEED_ADMIN_PASSWORD error = %v", err)
	}
}
