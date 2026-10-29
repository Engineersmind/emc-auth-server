package middleware_test

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/engineersmind/emc-auth-server/internal/api/middleware"
	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/store"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// Integration (DB + Redis): the application quota behind AppS2S.Resolve.
//
// What it pins: the quota an administrator sets is the product's limit, and a
// stranger who knows the public client_id but not the secret cannot spend it.
func TestAppClientRateLimiter_QuotaBehindResolve(t *testing.T) {
	pool := testhelper.NewTestDB(t)
	rdb := testhelper.NewTestRedis(t)
	logger := testhelper.TestLogger()
	ctx := context.Background()
	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}
	var tenantID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM tenants WHERE slug = 'emc' AND deleted_at IS NULL`).Scan(&tenantID); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	appSvc := auth.NewApplicationService(pool, logger)
	app, err := appSvc.CreateApplication(ctx, tenantID, fmt.Sprintf("s2s-quota-%d", time.Now().UnixNano()), "web", nil)
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}
	appID, _ := strconv.ParseInt(app.ID, 10, 64)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM oauth_clients WHERE id = $1`, appID)
	})

	limitSvc := auth.NewAppRateLimitService(pool, rdb, logger)
	if _, err := limitSvc.SetAppLimit(ctx, tenantID, appID, 3, 3, "test"); err != nil {
		t.Fatalf("SetAppLimit: %v", err)
	}
	// Fresh Redis buckets for this application.
	for _, prefix := range []string{"appauth:", "appauth-unverified:"} {
		rdb.Del(ctx, "rate:"+prefix+strconv.FormatInt(tenantID, 10)+":"+app.ID)
	}

	trust := auth.NewAppTrustService(pool, logger)
	middleware.ResetStoresForTest()
	s := middleware.NewAppS2S(middleware.AppS2SConfig{}, trust, appSvc, logger)
	chain := []echo.MiddlewareFunc{s.Resolve(middleware.SurfaceApp), middleware.AppClientRateLimiter(limitSvc, rdb, logger)}

	// A stranger who knows the public client_id but never authenticates —
	// wrong secrets, and empty-secret "Basic client_id:" requests (Copilot
	// review) — from many IPs so the per-IP limits do not stop them first.
	// Wrong secrets are not charged to any quota (the admission budgets bound
	// them, and a post-check refusal would reveal the outcome); empty-secret
	// requests spend only the separate unverified bucket.
	for i := 0; i < 4; i++ {
		runS2S(t, chain, s2sReq{remote: fmt.Sprintf("198.51.100.%d", 10+i), clientID: app.ClientID, secret: "wrong"})
	}
	for i := 0; i < 3; i++ {
		runS2S(t, chain, s2sReq{remote: fmt.Sprintf("198.51.100.%d", 30+i), clientID: app.ClientID, secret: ""})
	}
	res := runS2S(t, chain, s2sReq{remote: "198.51.100.50", clientID: app.ClientID, secret: ""})
	if res.code != http.StatusTooManyRequests {
		t.Fatalf("empty-secret requests past the unverified quota: got %d, want 429", res.code)
	}
	res = runS2S(t, chain, s2sReq{remote: "198.51.100.51", clientID: app.ClientID, secret: "wrong"})
	if res.code == http.StatusTooManyRequests && res.body["limiter"] == "app" {
		t.Fatal("a wrong secret must never be refused by the application quota after its check")
	}

	// The product itself still has its full quota.
	for i := 0; i < 3; i++ {
		res := runS2S(t, chain, s2sReq{remote: "203.0.113.10", clientID: app.ClientID, secret: app.ClientSecret})
		if res.code != http.StatusOK {
			t.Fatalf("verified request %d after the stranger's flood: got %d %v, want 200", i+1, res.code, res.body)
		}
	}
	res = runS2S(t, chain, s2sReq{remote: "203.0.113.10", clientID: app.ClientID, secret: app.ClientSecret})
	if res.code != http.StatusTooManyRequests || res.body["limiter"] != "app" {
		t.Fatalf("verified request past the quota: got %d %v, want 429 limiter=app", res.code, res.body)
	}
}
