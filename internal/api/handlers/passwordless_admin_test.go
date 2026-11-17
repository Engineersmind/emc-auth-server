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

type pwAdminEnv struct {
	t        *testing.T
	h        *AdminHandler
	tenantID int64
	userID   string
	appID    int64
	appIDStr string
	policy   *auth.PasswordlessPolicyService
}

func newPWAdminEnv(t *testing.T) *pwAdminEnv {
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
	// Policy rows outlive a test run (they are not tied to the application the test
	// creates), so start from none.
	if _, err := pool.Exec(ctx, `TRUNCATE passwordless_policies, passwordless_policy_history`); err != nil {
		t.Fatalf("clear policies: %v", err)
	}
	var seededUser int64
	if err := pool.QueryRow(ctx, `SELECT id FROM users WHERE tenant_id = $1 AND deleted_at IS NULL ORDER BY id LIMIT 1`, tenantID).Scan(&seededUser); err != nil {
		t.Fatalf("seeded user: %v", err)
	}
	appSvc := auth.NewApplicationService(pool, logger)
	app, err := appSvc.CreateApplication(ctx, tenantID, fmt.Sprintf("pw-admin-%d", time.Now().UnixNano()), "web", nil)
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}
	appID, _ := strconv.ParseInt(app.ID, 10, 64)
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM oauth_clients WHERE id = $1`, appID) })

	policy := auth.NewPasswordlessPolicyService(pool, logger)
	auditLog := audit.New(pool, logger, audit.WithFlushInterval(20*time.Millisecond))
	t.Cleanup(func() {
		cctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = auditLog.Close(cctx)
	})
	h := NewAdminHandler(admin.New(pool, nil, logger), auditLog, logger).
		WithApplications(appSvc).
		WithPasswordlessAdmin(PasswordlessAdminDeps{
			Policy: policy, Admin: auth.NewPasswordlessAdminService(pool, policy), ServerEnabled: true,
		})
	return &pwAdminEnv{t: t, h: h, tenantID: tenantID, userID: strconv.FormatInt(seededUser, 10), appID: appID, appIDStr: app.ID, policy: policy}
}

func (e *pwAdminEnv) owner() *auth.Claims {
	return &auth.Claims{UserID: e.userID, TenantID: strconv.FormatInt(e.tenantID, 10), AdminScope: auth.AdminScopeTenant}
}

// appAdmin is a co-owner: scoped to specific applications, not the whole tenant.
func (e *pwAdminEnv) appAdmin() *auth.Claims {
	return &auth.Claims{UserID: e.userID, TenantID: strconv.FormatInt(e.tenantID, 10), AdminScope: auth.AdminScopeApps}
}

func (e *pwAdminEnv) call(fn echo.HandlerFunc, claims *auth.Claims, method, body string, params map[string]string) (int, map[string]any) {
	e.t.Helper()
	req := httptest.NewRequest(method, "/", strings.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := echo.New().NewContext(req, rec)
	c.Set("user", claims)
	var names, values []string
	for k, v := range params {
		names, values = append(names, k), append(values, v)
	}
	c.SetParamNames(names...)
	c.SetParamValues(values...)
	if err := fn(c); err != nil {
		e.t.Fatalf("handler error: %v", err)
	}
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func (e *pwAdminEnv) appParams() map[string]string {
	return map[string]string{"tid": strconv.FormatInt(e.tenantID, 10), "appID": e.appIDStr}
}

func (e *pwAdminEnv) tenantParams() map[string]string {
	return map[string]string{"tid": strconv.FormatInt(e.tenantID, 10)}
}

func TestPasswordlessAdmin_GetShowsDefaultsAndServerSwitch(t *testing.T) {
	e := newPWAdminEnv(t)
	code, out := e.call(e.h.GetPasswordlessPolicy, e.owner(), http.MethodGet, "", e.appParams())
	if code != http.StatusOK || out["mode"] != "password_only" || out["server_enabled"] != true || out["row"] != nil {
		t.Fatalf("GET = %d %v; want the password-only default and server_enabled", code, out)
	}
}

// Application administrators change their own application, but the transitions
// that reshape who can get in need a tenant owner.
func TestPasswordlessAdmin_SensitiveChangesNeedATenantOwner(t *testing.T) {
	e := newPWAdminEnv(t)

	// An application administrator may turn email codes on...
	body := `{"policy":{"email_otp_enabled":true},"version":0}`
	if code, out := e.call(e.h.PutPasswordlessPolicy, e.appAdmin(), http.MethodPut, body, e.appParams()); code != http.StatusOK {
		t.Fatalf("app admin enabling codes = %d %v, want 200", code, out)
	}
	// ...but not open sign-up...
	code, out := e.call(e.h.PutPasswordlessPolicy, e.appAdmin(), http.MethodPut,
		`{"policy":{"email_otp_enabled":true,"signup_enabled":true},"version":1}`, e.appParams())
	if code != http.StatusForbidden || out["error"] != "tenant_owner_required" {
		t.Errorf("app admin opening sign-up = %d %v, want 403 tenant_owner_required", code, out)
	}
	// ...nor close the password flow...
	code, out = e.call(e.h.PutPasswordlessPolicy, e.appAdmin(), http.MethodPut,
		`{"policy":{"email_otp_enabled":true,"password_enabled":false},"version":1}`, e.appParams())
	if code != http.StatusForbidden || out["error"] != "tenant_owner_required" {
		t.Errorf("app admin closing the password flow = %d %v, want 403", code, out)
	}
	// ...nor edit the tenant defaults.
	if code, _ = e.call(e.h.PutPasswordlessPolicy, e.appAdmin(), http.MethodPut,
		`{"policy":{"email_otp_enabled":true},"version":0}`, e.tenantParams()); code != http.StatusForbidden {
		t.Errorf("app admin editing tenant defaults = %d, want 403", code)
	}
	// A tenant owner can do all of it.
	if code, out = e.call(e.h.PutPasswordlessPolicy, e.owner(), http.MethodPut,
		`{"policy":{"email_otp_enabled":true,"signup_enabled":true,"password_enabled":false},"version":1}`, e.appParams()); code != http.StatusOK {
		t.Errorf("owner closing the password flow = %d %v, want 200", code, out)
	} else if out["mode"] != "passwordless_only" {
		t.Errorf("mode = %v, want passwordless_only", out["mode"])
	}
	if code, _ = e.call(e.h.PutPasswordlessPolicy, e.owner(), http.MethodPut,
		`{"policy":{"blocked_email_domains":["mailinator.com"]},"version":0}`, e.tenantParams()); code != http.StatusOK {
		t.Errorf("owner editing tenant defaults = %d, want 200", code)
	}
}

func TestPasswordlessAdmin_ConcurrentEditsAndValidation(t *testing.T) {
	e := newPWAdminEnv(t)
	if code, _ := e.call(e.h.PutPasswordlessPolicy, e.owner(), http.MethodPut,
		`{"policy":{"email_otp_enabled":true,"code_ttl_seconds":600},"version":0}`, e.appParams()); code != http.StatusOK {
		t.Fatalf("first PUT = %d", code)
	}
	// A second administrator holding the old version gets a 409 showing the change.
	code, out := e.call(e.h.PutPasswordlessPolicy, e.owner(), http.MethodPut,
		`{"policy":{"email_otp_enabled":true,"code_ttl_seconds":300},"version":0}`, e.appParams())
	if code != http.StatusConflict || out["error"] != "version_conflict" || out["current"] == nil {
		t.Errorf("stale PUT = %d %v, want 409 version_conflict with the current policy", code, out)
	}
	// No first factor left.
	if code, out = e.call(e.h.PutPasswordlessPolicy, e.owner(), http.MethodPut,
		`{"policy":{"email_otp_enabled":false,"password_enabled":false},"version":1}`, e.appParams()); code != http.StatusUnprocessableEntity || out["error"] != "no_first_factor" {
		t.Errorf("no first factor = %d %v, want 422 no_first_factor", code, out)
	}
	// Out of range.
	if code, out = e.call(e.h.PutPasswordlessPolicy, e.owner(), http.MethodPut,
		`{"policy":{"email_otp_enabled":true,"max_attempts":50},"version":1}`, e.appParams()); code != http.StatusBadRequest || out["error"] != "invalid_policy" {
		t.Errorf("max_attempts 50 = %d %v, want 400 invalid_policy", code, out)
	}
}

func TestPasswordlessAdmin_HistoryRestoreAndDelete(t *testing.T) {
	e := newPWAdminEnv(t)
	put := func(body string) {
		t.Helper()
		if code, out := e.call(e.h.PutPasswordlessPolicy, e.owner(), http.MethodPut, body, e.appParams()); code != http.StatusOK {
			t.Fatalf("PUT %s = %d %v", body, code, out)
		}
	}
	put(`{"policy":{"email_otp_enabled":true,"code_ttl_seconds":400},"version":0}`)
	put(`{"policy":{"email_otp_enabled":true,"code_ttl_seconds":800},"version":1}`)

	code, _ := e.call(e.h.PasswordlessHistory, e.owner(), http.MethodGet, "", e.appParams())
	if code != http.StatusOK {
		t.Fatalf("history = %d", code)
	}
	entries, err := e.policy.History(context.Background(), auth.PasswordlessScope{TenantID: &e.tenantID, ApplicationID: &e.appID}, 10)
	if err != nil || len(entries) != 2 {
		t.Fatalf("history = %v, %v; want 2 entries", entries, err)
	}
	if ch, ok := entries[0].Change["code_ttl_seconds"]; !ok || fmt.Sprint(ch.After) != "800" {
		t.Errorf("newest entry change = %v, want code_ttl_seconds -> 800", entries[0].Change)
	}

	// Restore the first version: a NEW version, not a rewrite.
	params := e.appParams()
	params["hid"] = strconv.FormatInt(entries[1].ID, 10)
	code, out := e.call(e.h.PasswordlessRestore, e.owner(), http.MethodPost, `{"version":2}`, params)
	if code != http.StatusOK {
		t.Fatalf("restore = %d %v", code, out)
	}
	if after, _ := e.policy.History(context.Background(), auth.PasswordlessScope{TenantID: &e.tenantID, ApplicationID: &e.appID}, 10); len(after) != 3 {
		t.Errorf("history after restore has %d entries, want 3 (append-only)", len(after))
	}
	// An application administrator may not restore (it can reopen sign-up).
	if code, _ = e.call(e.h.PasswordlessRestore, e.appAdmin(), http.MethodPost, `{"version":3}`, params); code != http.StatusForbidden {
		t.Errorf("app admin restore = %d, want 403", code)
	}

	// Delete reverts to inheriting.
	if code, _ = e.call(e.h.DeletePasswordlessPolicy, e.owner(), http.MethodDelete, "", e.appParams()); code != http.StatusOK {
		t.Errorf("delete = %d", code)
	}
	if code, _ = e.call(e.h.DeletePasswordlessPolicy, e.owner(), http.MethodDelete, "", e.appParams()); code != http.StatusNotFound {
		t.Errorf("second delete = %d, want 404", code)
	}
}

func TestPasswordlessAdmin_ImpactEndpoint(t *testing.T) {
	e := newPWAdminEnv(t)
	code, out := e.call(e.h.PasswordlessImpact, e.owner(), http.MethodPost,
		`{"policy":{"email_otp_enabled":true,"password_enabled":false,"signup_enabled":true}}`, e.appParams())
	if code != http.StatusOK || out["mode_after"] != "passwordless_only" || out["risky"] != true {
		t.Errorf("impact = %d %v, want passwordless_only and risky", code, out)
	}
	// A tenant-level call has no application to measure.
	if code, _ = e.call(e.h.PasswordlessImpact, e.owner(), http.MethodPost, `{"policy":{}}`, e.tenantParams()); code != http.StatusBadRequest {
		t.Errorf("tenant-level impact = %d, want 400", code)
	}
}

func TestPasswordlessAdmin_UnconfiguredAnswers503(t *testing.T) {
	e := newPWAdminEnv(t)
	bare := NewAdminHandler(e.h.svc, nil, testhelper.TestLogger()).WithApplications(e.h.appSvc)
	if code, _ := e.call(bare.GetPasswordlessPolicy, e.owner(), http.MethodGet, "", e.appParams()); code != http.StatusServiceUnavailable {
		t.Errorf("unconfigured GET = %d, want 503", code)
	}
}

// Deleting an override is a write whose result the parent chooses: an application
// administrator must not reach, by deleting, a state PUT refuses.
func TestPasswordlessAdmin_DeleteNeedsTenantOwnerForSensitiveResult(t *testing.T) {
	e := newPWAdminEnv(t)
	// Tenant defaults: codes on, password off. The application keeps passwords with an override.
	if code, out := e.call(e.h.PutPasswordlessPolicy, e.owner(), http.MethodPut,
		`{"policy":{"email_otp_enabled":true,"password_enabled":false},"version":0}`, e.tenantParams()); code != http.StatusOK {
		t.Fatalf("tenant PUT = %d %v", code, out)
	}
	if code, out := e.call(e.h.PutPasswordlessPolicy, e.owner(), http.MethodPut,
		`{"policy":{"password_enabled":true},"version":0}`, e.appParams()); code != http.StatusOK {
		t.Fatalf("app PUT = %d %v", code, out)
	}
	if code, out := e.call(e.h.DeletePasswordlessPolicy, e.appAdmin(), http.MethodDelete, "", e.appParams()); code != http.StatusForbidden || out["error"] != "tenant_owner_required" {
		t.Errorf("app admin DELETE closing the password flow = %d %v, want 403 tenant_owner_required", code, out)
	}
	if code, _ := e.call(e.h.DeletePasswordlessPolicy, e.owner(), http.MethodDelete, "", e.appParams()); code != http.StatusOK {
		t.Errorf("owner DELETE = %d, want 200", code)
	}
}

// A parent write is validated against the overrides beneath it.
func TestPasswordlessAdmin_ParentWriteValidatedAgainstChildren(t *testing.T) {
	e := newPWAdminEnv(t)
	if code, out := e.call(e.h.PutPasswordlessPolicy, e.owner(), http.MethodPut,
		`{"policy":{"email_otp_enabled":false},"version":0}`, e.appParams()); code != http.StatusOK {
		t.Fatalf("app PUT = %d %v", code, out)
	}
	code, out := e.call(e.h.PutPasswordlessPolicy, e.owner(), http.MethodPut,
		`{"policy":{"email_otp_enabled":true,"password_enabled":false},"version":0}`, e.tenantParams())
	if code != http.StatusUnprocessableEntity || out["error"] != "no_first_factor" {
		t.Errorf("tenant PUT stranding a child = %d %v, want 422 no_first_factor", code, out)
	}
}
