package auth_test

import (
	"context"
	"errors"
	"strconv"
	"testing"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/store"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// newAppLimitFixture returns an AppRateLimitService backed by real DB + Redis,
// a seeded tenant id, and a freshly created application's numeric id.
func newAppLimitFixture(t *testing.T) (*auth.AppRateLimitService, context.Context, int64, int64) {
	t.Helper()
	pool := testhelper.NewTestDB(t)
	rdb := testhelper.NewTestRedis(t)
	testhelper.CleanupTables(t, pool)
	logger := testhelper.TestLogger()

	ctx := context.Background()
	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}

	var tenantID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM tenants WHERE slug = 'emc' AND deleted_at IS NULL`).Scan(&tenantID); err != nil {
		t.Fatalf("fetch seed tenant id: %v", err)
	}

	appSvc := auth.NewApplicationService(pool, logger)
	app, err := appSvc.CreateApplication(ctx, tenantID, "rate-limit-test-app", "spa", nil)
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}
	appID, err := strconv.ParseInt(app.ID, 10, 64)
	if err != nil {
		t.Fatalf("parse app id %q: %v", app.ID, err)
	}

	svc := auth.NewAppRateLimitService(pool, rdb, logger)
	return svc, ctx, tenantID, appID
}

func TestAppLimit_SetGetListDelete(t *testing.T) {
	svc, ctx, tenantID, appID := newAppLimitFixture(t)

	// Create via upsert.
	created, err := svc.SetAppLimit(ctx, tenantID, appID, 2, 2, "test limit")
	if err != nil {
		t.Fatalf("SetAppLimit (create): %v", err)
	}
	if created.RequestsPerMinute != 2 || created.Burst != 2 {
		t.Errorf("created = rpm %d burst %d, want 2/2", created.RequestsPerMinute, created.Burst)
	}
	if created.ApplicationID != appID || created.TenantID != tenantID {
		t.Errorf("created ids = app %d tenant %d, want %d/%d", created.ApplicationID, created.TenantID, appID, tenantID)
	}

	// GetAppLimit returns it.
	got, err := svc.GetAppLimit(ctx, tenantID, appID)
	if err != nil {
		t.Fatalf("GetAppLimit: %v", err)
	}
	if got.RequestsPerMinute != 2 {
		t.Errorf("GetAppLimit rpm = %d, want 2", got.RequestsPerMinute)
	}

	// Update via the same upsert path — no duplicate row, values change.
	updated, err := svc.SetAppLimit(ctx, tenantID, appID, 5, 3, "raised")
	if err != nil {
		t.Fatalf("SetAppLimit (update): %v", err)
	}
	if updated.RequestsPerMinute != 5 || updated.Burst != 3 {
		t.Errorf("updated = rpm %d burst %d, want 5/3", updated.RequestsPerMinute, updated.Burst)
	}
	limits, err := svc.ListAppLimits(ctx, tenantID)
	if err != nil {
		t.Fatalf("ListAppLimits: %v", err)
	}
	if len(limits) != 1 {
		t.Fatalf("ListAppLimits len = %d, want 1 (upsert must not create a second row)", len(limits))
	}

	// Delete → GetAppLimit reports not found.
	if err := svc.DeleteAppLimit(ctx, tenantID, appID); err != nil {
		t.Fatalf("DeleteAppLimit: %v", err)
	}
	if _, err := svc.GetAppLimit(ctx, tenantID, appID); !errors.Is(err, auth.ErrAppLimitNotFound) {
		t.Errorf("GetAppLimit after delete err = %v, want ErrAppLimitNotFound", err)
	}
}

func TestAppLimit_GetLimit_CacheInvalidatedOnWrite(t *testing.T) {
	svc, ctx, tenantID, appID := newAppLimitFixture(t)

	// Prime the cache at the default (no row yet).
	if rpm, _ := svc.GetLimit(ctx, tenantID, appID); rpm != auth.DefaultRequestsPerMinute {
		t.Fatalf("GetLimit before config = %d, want default %d", rpm, auth.DefaultRequestsPerMinute)
	}

	// Writing a limit must invalidate the cached default immediately (the old
	// bug left the tenant-scoped cache key stale for up to the TTL).
	if _, err := svc.SetAppLimit(ctx, tenantID, appID, 2, 2, ""); err != nil {
		t.Fatalf("SetAppLimit: %v", err)
	}
	if rpm, burst := svc.GetLimit(ctx, tenantID, appID); rpm != 2 || burst != 2 {
		t.Errorf("GetLimit after set = rpm %d burst %d, want 2/2 (stale cache?)", rpm, burst)
	}

	// Deleting must invalidate again → back to default.
	if err := svc.DeleteAppLimit(ctx, tenantID, appID); err != nil {
		t.Fatalf("DeleteAppLimit: %v", err)
	}
	if rpm, _ := svc.GetLimit(ctx, tenantID, appID); rpm != auth.DefaultRequestsPerMinute {
		t.Errorf("GetLimit after delete = %d, want default %d (stale cache?)", rpm, auth.DefaultRequestsPerMinute)
	}
}

func TestAppLimit_GetLimitForClientID(t *testing.T) {
	pool := testhelper.NewTestDB(t)
	rdb := testhelper.NewTestRedis(t)
	testhelper.CleanupTables(t, pool)
	logger := testhelper.TestLogger()

	ctx := context.Background()
	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}
	var tenantID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM tenants WHERE slug = 'emc' AND deleted_at IS NULL`).Scan(&tenantID); err != nil {
		t.Fatalf("fetch seed tenant: %v", err)
	}
	app, err := auth.NewApplicationService(pool, logger).CreateApplication(ctx, tenantID, "cc-app", "m2m", nil)
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}
	appID, _ := strconv.ParseInt(app.ID, 10, 64)

	svc := auth.NewAppRateLimitService(pool, rdb, logger)
	if _, err := svc.SetAppLimit(ctx, tenantID, appID, 3, 3, ""); err != nil {
		t.Fatalf("SetAppLimit: %v", err)
	}

	// A live client_id resolves to its application + configured limit.
	gotTenant, gotApp, rpm, burst, ok := svc.GetLimitForClientID(ctx, app.ClientID)
	if !ok {
		t.Fatal("GetLimitForClientID ok = false, want true for a live client_id")
	}
	if gotTenant != tenantID || gotApp != appID {
		t.Errorf("resolved ids = tenant %d app %d, want %d/%d", gotTenant, gotApp, tenantID, appID)
	}
	if rpm != 3 || burst != 3 {
		t.Errorf("resolved limit = rpm %d burst %d, want 3/3", rpm, burst)
	}

	// An unknown client_id yields ok=false (caller skips per-app limiting).
	if _, _, _, _, ok := svc.GetLimitForClientID(ctx, "emcc_does_not_exist"); ok {
		t.Error("GetLimitForClientID ok = true for unknown client_id, want false")
	}
}

func TestAppLimit_GetLimit_TenantScoped(t *testing.T) {
	svc, ctx, tenantID, appID := newAppLimitFixture(t)

	if _, err := svc.SetAppLimit(ctx, tenantID, appID, 2, 2, ""); err != nil {
		t.Fatalf("SetAppLimit: %v", err)
	}

	// A different tenant asking for the same numeric app id must NOT see this
	// tenant's limit — it falls back to the default.
	otherTenant := tenantID + 99999
	if rpm, _ := svc.GetLimit(ctx, otherTenant, appID); rpm != auth.DefaultRequestsPerMinute {
		t.Errorf("cross-tenant GetLimit = %d, want default %d", rpm, auth.DefaultRequestsPerMinute)
	}
}
