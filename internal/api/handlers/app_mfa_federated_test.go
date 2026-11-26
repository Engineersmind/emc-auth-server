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

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"

	"github.com/engineersmind/emc-auth-server/internal/admin"
	"github.com/engineersmind/emc-auth-server/internal/audit"
	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/store"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// appMFAHandlerEnv is one application plus an AdminHandler wired for its MFA
// routes, called as a management (API-key) token.
type appMFAHandlerEnv struct {
	ctx      context.Context
	pool     *pgxpool.Pool
	tenantID int64
	app      *auth.AppResult
	appID    int64
	appSvc   *auth.ApplicationService
	totpSvc  *auth.TOTPService
	h        *AdminHandler
	claims   *auth.Claims
}

func newAppMFAHandlerEnv(t *testing.T, prefix string) *appMFAHandlerEnv {
	t.Helper()
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
	app, err := appSvc.CreateApplication(ctx, tenantID, fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano()), "web", nil)
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}
	appID, _ := strconv.ParseInt(app.ID, 10, 64)
	totpSvc, err := auth.NewTOTPService(pool, strings.Repeat("0", 64), "development", logger)
	if err != nil {
		t.Fatalf("NewTOTPService: %v", err)
	}
	auditLog := audit.New(pool, logger, audit.WithFlushInterval(20*time.Millisecond))
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer ccancel()
		_ = auditLog.Close(cctx)
	})
	h := NewAdminHandler(admin.New(pool, nil, logger), auditLog, logger).
		WithApplications(appSvc).
		WithTOTP(totpSvc)
	return &appMFAHandlerEnv{
		ctx: ctx, pool: pool, tenantID: tenantID, app: app, appID: appID, appSvc: appSvc,
		totpSvc: totpSvc, h: h,
		claims: &auth.Claims{UserID: "apikey-client", TenantID: strconv.FormatInt(tenantID, 10), Gty: auth.GrantAPIKey},
	}
}

// call runs handler with the env's claims, :appID set, and an optional JSON body.
func (e *appMFAHandlerEnv) call(t *testing.T, handler echo.HandlerFunc, method, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, "/", strings.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := echo.New().NewContext(req, rec)
	c.Set("user", e.claims)
	c.SetParamNames("appID")
	c.SetParamValues(e.app.ID)
	if err := handler(c); err != nil {
		t.Fatalf("handler error: %v", err)
	}
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

// audits waits for the asynchronous audit writer and counts rows of action
// for this application, returning the newest row's metadata.
func (e *appMFAHandlerEnv) audits(t *testing.T, action string) (int, map[string]any) {
	t.Helper()
	time.Sleep(500 * time.Millisecond)
	var n int
	if err := e.pool.QueryRow(e.ctx,
		`SELECT COUNT(*) FROM audit_logs WHERE action = $1 AND resource_id = $2`, action, e.app.ID).Scan(&n); err != nil {
		t.Fatalf("count audits: %v", err)
	}
	if n == 0 {
		return 0, nil
	}
	var raw []byte
	if err := e.pool.QueryRow(e.ctx,
		`SELECT metadata FROM audit_logs WHERE action = $1 AND resource_id = $2 ORDER BY id DESC LIMIT 1`,
		action, e.app.ID).Scan(&raw); err != nil {
		t.Fatalf("read audit metadata: %v", err)
	}
	var meta map[string]any
	_ = json.Unmarshal(raw, &meta)
	return n, meta
}

// PUT .../mfa with federated_mfa (#194).
func TestUpdateApplicationMFA_FederatedMFA(t *testing.T) {
	e := newAppMFAHandlerEnv(t, "fed-h")

	code, out := e.call(t, e.h.GetApplicationMFA, http.MethodGet, "")
	if code != http.StatusOK || out["federated_mfa"] != auth.FederatedMFATrust {
		t.Fatalf("GET default: %d %v, want 200 federated_mfa=trust", code, out)
	}

	if code, out := e.call(t, e.h.UpdateApplicationMFA, http.MethodPut, `{"federated_mfa":"sometimes"}`); code != http.StatusBadRequest {
		t.Fatalf("invalid value: %d %v, want 400", code, out)
	}

	// federated_mfa alone is a valid body (mode may be omitted).
	code, out = e.call(t, e.h.UpdateApplicationMFA, http.MethodPut, `{"federated_mfa":"enforce"}`)
	if code != http.StatusOK || out["federated_mfa"] != auth.FederatedMFAEnforce || out["mode"] != auth.MFAModeOptional {
		t.Fatalf("set enforce: %d %v, want 200 enforce with mode kept", code, out)
	}
	// Redundant: no second audit.
	if code, out := e.call(t, e.h.UpdateApplicationMFA, http.MethodPut, `{"federated_mfa":"enforce"}`); code != http.StatusOK {
		t.Fatalf("redundant enforce: %d %v", code, out)
	}

	n, meta := e.audits(t, audit.ActionAdminMFAFederatedChanged)
	if n != 1 {
		t.Fatalf("federated audits = %d, want 1 (redundant write not audited)", n)
	}
	if meta["old_federated_mfa"] != auth.FederatedMFATrust || meta["new_federated_mfa"] != auth.FederatedMFAEnforce {
		t.Errorf("audit metadata = %v, want trust → enforce", meta)
	}
}
