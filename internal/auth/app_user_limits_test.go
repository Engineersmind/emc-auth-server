package auth_test

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/store"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

func TestUserLimitDefs_KeysUniqueAndCeilingsSane(t *testing.T) {
	seen := map[string]bool{}
	for _, d := range auth.UserLimitDefs {
		if seen[d.Key] {
			t.Fatalf("duplicate key %q", d.Key)
		}
		seen[d.Key] = true
		if d.Max < 1 || d.Name == "" || d.KeyedBy == "" || len(d.Endpoints) == 0 {
			t.Fatalf("incomplete definition: %+v", d)
		}
	}
	if len(seen) != 12 {
		t.Fatalf("%d limits defined, want 12 (one per middleware.AppUserLimits field)", len(seen))
	}
}

func TestAppUserLimitService_SetGetLookup(t *testing.T) {
	pool := testhelper.NewTestDB(t)
	logger := testhelper.TestLogger()
	ctx := context.Background()
	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}
	var tenantID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM tenants WHERE slug = 'emc' AND deleted_at IS NULL`).Scan(&tenantID); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	app, err := auth.NewApplicationService(pool, logger).CreateApplication(ctx, tenantID,
		fmt.Sprintf("user-limits-%d", time.Now().UnixNano()), "web", nil)
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}
	appID, _ := strconv.ParseInt(app.ID, 10, 64)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM oauth_clients WHERE id = $1`, appID)
	})

	svc := auth.NewAppUserLimitService(pool, logger)

	// Defaults: no overrides, nothing in the snapshot.
	got, err := svc.GetUserLimits(ctx, tenantID, appID)
	if err != nil || len(got) != 0 {
		t.Fatalf("new application: got %v, %v; want no overrides", got, err)
	}
	if err := svc.Reload(ctx); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if _, ok := svc.UserLimitOverride(appID, auth.UserLimitLogin); ok {
		t.Fatal("an application without overrides must not be in the snapshot")
	}

	// Set: applied to the snapshot on this instance immediately.
	got, err = svc.SetUserLimits(ctx, tenantID, appID, map[string]int{
		auth.UserLimitLogin:          12,
		auth.UserLimitForgotPassword: 2,
	})
	if err != nil {
		t.Fatalf("SetUserLimits: %v", err)
	}
	if got[auth.UserLimitLogin] != 12 || got[auth.UserLimitForgotPassword] != 2 || len(got) != 2 {
		t.Fatalf("after set: %v", got)
	}
	if v, ok := svc.UserLimitOverride(appID, auth.UserLimitLogin); !ok || v != 12 {
		t.Fatalf("snapshot after set: %d ok=%v", v, ok)
	}
	if _, ok := svc.UserLimitOverride(appID, auth.UserLimitRegister); ok {
		t.Fatal("a limit that was not overridden must use the default")
	}

	// Set replaces: a key left out returns to the default.
	if _, err := svc.SetUserLimits(ctx, tenantID, appID, map[string]int{auth.UserLimitLogin: 8}); err != nil {
		t.Fatalf("replace: %v", err)
	}
	if _, ok := svc.UserLimitOverride(appID, auth.UserLimitForgotPassword); ok {
		t.Fatal("a key left out of a replacement must return to the default")
	}

	// Invalid input changes nothing: unknown key, zero, above the ceiling.
	login, _ := auth.UserLimitDefByKey(auth.UserLimitLogin)
	for _, bad := range []map[string]int{
		{"made_up": 5},
		{auth.UserLimitLogin: 0},
		{auth.UserLimitLogin: login.Max + 1},
	} {
		if _, err := svc.SetUserLimits(ctx, tenantID, appID, bad); !errors.Is(err, auth.ErrInvalidUserLimit) {
			t.Fatalf("%v: want ErrInvalidUserLimit, got %v", bad, err)
		}
	}
	if v, _ := svc.UserLimitOverride(appID, auth.UserLimitLogin); v != 8 {
		t.Fatalf("a rejected update must not change anything, login = %d", v)
	}

	// Another tenant cannot read or change it.
	if _, err := svc.GetUserLimits(ctx, tenantID+100000, appID); !errors.Is(err, auth.ErrAppNotFound) {
		t.Fatalf("cross-tenant get: want ErrAppNotFound, got %v", err)
	}
	if _, err := svc.SetUserLimits(ctx, tenantID+100000, appID, map[string]int{auth.UserLimitLogin: 3}); !errors.Is(err, auth.ErrAppNotFound) {
		t.Fatalf("cross-tenant set: want ErrAppNotFound, got %v", err)
	}

	// A hand-edited row past a ceiling is ignored, not enforced.
	if _, err := pool.Exec(ctx, `UPDATE app_user_rate_limits SET limits = '{"login": 100000, "register": 7}' WHERE application_id = $1`, appID); err != nil {
		t.Fatalf("hand edit: %v", err)
	}
	if err := svc.Reload(ctx); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if _, ok := svc.UserLimitOverride(appID, auth.UserLimitLogin); ok {
		t.Fatal("a stored value above the ceiling must be ignored")
	}
	if v, ok := svc.UserLimitOverride(appID, auth.UserLimitRegister); !ok || v != 7 {
		t.Fatalf("valid values in the same row must still apply, register = %d ok=%v", v, ok)
	}

	// A suspended application falls back to the defaults.
	if _, err := pool.Exec(ctx, `UPDATE oauth_clients SET is_active = false WHERE id = $1`, appID); err != nil {
		t.Fatalf("suspend: %v", err)
	}
	if err := svc.Reload(ctx); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if _, ok := svc.UserLimitOverride(appID, auth.UserLimitRegister); ok {
		t.Fatal("a suspended application must leave the snapshot")
	}
	if _, err := pool.Exec(ctx, `UPDATE oauth_clients SET is_active = true WHERE id = $1`, appID); err != nil {
		t.Fatalf("reactivate: %v", err)
	}

	// {} clears everything.
	if got, err := svc.SetUserLimits(ctx, tenantID, appID, map[string]int{}); err != nil || len(got) != 0 {
		t.Fatalf("clear: %v, %v", got, err)
	}
	if _, ok := svc.UserLimitOverride(appID, auth.UserLimitRegister); ok {
		t.Fatal("a cleared application must leave the snapshot")
	}
}
