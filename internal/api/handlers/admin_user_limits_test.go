package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/engineersmind/emc-auth-server/internal/admin"
	"github.com/engineersmind/emc-auth-server/internal/audit"
	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/store"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

func TestAdminUserLimits_GetSetClear(t *testing.T) {
	pool := testhelper.NewTestDB(t)
	logger := testhelper.TestLogger()
	ctx := context.Background()
	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}
	var tenantID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM tenants WHERE slug = 'emc' AND deleted_at IS NULL`).Scan(&tenantID); err != nil {
		t.Fatalf("tenant id: %v", err)
	}
	appSvc := auth.NewApplicationService(pool, logger)
	app, err := appSvc.CreateApplication(ctx, tenantID, fmt.Sprintf("user-limits-h-%d", time.Now().UnixNano()), "web", nil)
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}
	appID, _ := strconv.ParseInt(app.ID, 10, 64)
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM oauth_clients WHERE id = $1`, appID) })

	auditLog := audit.New(pool, logger, audit.WithFlushInterval(20*time.Millisecond))
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer ccancel()
		_ = auditLog.Close(cctx)
	})
	defaults := map[string]int{}
	for _, d := range auth.UserLimitDefs {
		defaults[d.Key] = 5
	}
	h := NewAdminHandler(admin.New(pool, nil, logger), auditLog, logger).
		WithApplications(appSvc).
		WithUserLimits(auth.NewAppUserLimitService(pool, logger), defaults, 600)
	claims := &auth.Claims{UserID: "1", TenantID: strconv.FormatInt(tenantID, 10), Email: "owner@emc.local"}

	call := func(method string, fn echo.HandlerFunc, appParam, body string) (int, AppUserLimits, string) {
		t.Helper()
		req := httptest.NewRequest(method, "/", strings.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := echo.New().NewContext(req, rec)
		c.Set("user", claims)
		c.SetParamNames("appID")
		c.SetParamValues(appParam)
		if err := fn(c); err != nil {
			t.Fatalf("handler error: %v", err)
		}
		var out AppUserLimits
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out, rec.Body.String()
	}
	find := func(v AppUserLimits, key string) UserLimitView {
		for _, l := range v.Limits {
			if l.Key == key {
				return l
			}
		}
		t.Fatalf("limit %q missing from %+v", key, v)
		return UserLimitView{}
	}

	// GET: every limit, all at the default, no overrides.
	code, got, raw := call(http.MethodGet, h.GetUserLimits, app.ID, "")
	if code != http.StatusOK || len(got.Limits) != len(auth.UserLimitDefs) {
		t.Fatalf("GET: %d %s", code, raw)
	}
	if l := find(got, auth.UserLimitLogin); l.Override != nil || l.Effective != 5 || l.Default != 5 || l.Max < 5 {
		t.Fatalf("login before override: %+v", l)
	}

	// PUT: override shows as effective.
	code, got, raw = call(http.MethodPut, h.SetUserLimits, app.ID, `{"overrides":{"login":12}}`)
	if code != http.StatusOK {
		t.Fatalf("PUT: %d %s", code, raw)
	}
	if l := find(got, auth.UserLimitLogin); l.Override == nil || *l.Override != 12 || l.Effective != 12 || l.Default != 5 {
		t.Fatalf("login after override: %+v", l)
	}

	// Validation: out of range, unknown key, missing overrides.
	for _, body := range []string{`{"overrides":{"login":1000}}`, `{"overrides":{"nope":3}}`, `{}`} {
		if code, _, raw := call(http.MethodPut, h.SetUserLimits, app.ID, body); code != http.StatusBadRequest {
			t.Fatalf("PUT %s: %d %s, want 400", body, code, raw)
		}
	}

	// Another tenant's application: 404, nothing revealed.
	if code, _, _ := call(http.MethodGet, h.GetUserLimits, "999999999", ""); code != http.StatusNotFound {
		t.Fatalf("unknown application: %d, want 404", code)
	}

	// {} returns everything to the defaults.
	code, got, raw = call(http.MethodPut, h.SetUserLimits, app.ID, `{"overrides":{}}`)
	if code != http.StatusOK {
		t.Fatalf("clear: %d %s", code, raw)
	}
	if l := find(got, auth.UserLimitLogin); l.Override != nil || l.Effective != 5 {
		t.Fatalf("login after clear: %+v", l)
	}
}
