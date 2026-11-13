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

// PUT .../applications/:appID/mfa with the master switch (#192).
func TestUpdateApplicationMFA_Switch(t *testing.T) {
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
	app, err := appSvc.CreateApplication(ctx, tenantID, fmt.Sprintf("mfa-switch-h-%d", time.Now().UnixNano()), "web", nil)
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}
	appID, _ := strconv.ParseInt(app.ID, 10, 64)
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM oauth_clients WHERE id = $1`, appID) })

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

	// A real console user with a session row we can age and strip of MFA.
	var userID int64
	email := fmt.Sprintf("mfa-switch-owner-%d@test.example.com", time.Now().UnixNano())
	if err := pool.QueryRow(ctx, `
		INSERT INTO users (tenant_id, email, is_active, email_verified)
		VALUES ($1, $2, true, true) RETURNING id
	`, tenantID, email).Scan(&userID); err != nil {
		t.Fatalf("create user: %v", err)
	}
	var sessionID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO user_sessions (user_id, tenant_id, amr, idle_expires_at, absolute_expires_at)
		VALUES ($1, $2, '{pwd,otp,mfa}', NOW() + INTERVAL '1 hour', NOW() + INTERVAL '1 day') RETURNING id
	`, userID, tenantID).Scan(&sessionID); err != nil {
		t.Fatalf("create session: %v", err)
	}

	human := &auth.Claims{
		UserID: strconv.FormatInt(userID, 10), TenantID: strconv.FormatInt(tenantID, 10),
		Email: email, Gty: auth.GrantPassword, SessionID: strconv.FormatInt(sessionID, 10),
	}
	management := &auth.Claims{
		UserID: "apikey-client", TenantID: strconv.FormatInt(tenantID, 10), Gty: auth.GrantAPIKey,
	}

	put := func(claims *auth.Claims, body string) (int, map[string]any) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPut, "/", strings.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := echo.New().NewContext(req, rec)
		c.Set("user", claims)
		c.SetParamNames("appID")
		c.SetParamValues(app.ID)
		if err := h.UpdateApplicationMFA(c); err != nil {
			t.Fatalf("handler error: %v", err)
		}
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	enabled := func() bool {
		t.Helper()
		cfg, err := totpSvc.GetAppMFAConfig(ctx, appID)
		if err != nil {
			t.Fatalf("GetAppMFAConfig: %v", err)
		}
		return cfg.Enabled
	}
	switchAudits := func() int {
		t.Helper()
		var n int
		deadline := time.Now().Add(2 * time.Second)
		for {
			if err := pool.QueryRow(ctx, `
				SELECT COUNT(*) FROM audit_logs WHERE action = $1 AND resource_id = $2
			`, audit.ActionAdminMFASwitchChanged, app.ID).Scan(&n); err != nil {
				t.Fatalf("count audits: %v", err)
			}
			if time.Now().After(deadline) {
				return n
			}
			time.Sleep(100 * time.Millisecond)
		}
	}

	// Empty body is still a 400.
	if code, out := put(human, `{}`); code != http.StatusBadRequest {
		t.Fatalf("empty body: %d %v, want 400", code, out)
	}

	// A management (API-key) token cannot turn MFA off...
	if code, out := put(management, `{"mfa_enabled":false}`); code != http.StatusForbidden || out["error"] != "mfa_switch_off_service_token" {
		t.Fatalf("management off: %d %v, want 403 mfa_switch_off_service_token", code, out)
	}
	if !enabled() {
		t.Fatal("refused switch-off still turned MFA off")
	}

	// ...a stale session cannot either...
	if _, err := pool.Exec(ctx, `UPDATE user_sessions SET auth_time = NOW() - INTERVAL '11 minutes' WHERE id = $1`, sessionID); err != nil {
		t.Fatalf("age session: %v", err)
	}
	if code, out := put(human, `{"mfa_enabled":false}`); code != http.StatusForbidden || out["error"] != "mfa_switch_off_stale_session" {
		t.Fatalf("stale off: %d %v, want 403 mfa_switch_off_stale_session", code, out)
	}

	// ...nor a fresh session that never did MFA...
	if _, err := pool.Exec(ctx, `UPDATE user_sessions SET auth_time = NOW(), amr = '{pwd}' WHERE id = $1`, sessionID); err != nil {
		t.Fatalf("strip mfa: %v", err)
	}
	if code, out := put(human, `{"mfa_enabled":false}`); code != http.StatusForbidden || out["error"] != "mfa_switch_off_stale_session" {
		t.Fatalf("no-mfa off: %d %v, want 403 mfa_switch_off_stale_session", code, out)
	}

	// ...but a fresh MFA session can, with mode omitted.
	if _, err := pool.Exec(ctx, `UPDATE user_sessions SET amr = '{pwd,otp,mfa}' WHERE id = $1`, sessionID); err != nil {
		t.Fatalf("restore mfa: %v", err)
	}
	code, out := put(human, `{"mfa_enabled":false}`)
	if code != http.StatusOK || out["mfa_enabled"] != false || out["mode"] != auth.MFAModeOptional {
		t.Fatalf("fresh off: %d %v, want 200 with mfa_enabled=false, mode kept", code, out)
	}
	if enabled() {
		t.Fatal("switch-off did not persist")
	}

	// Redundant off: no change, no extra audit.
	if code, out := put(human, `{"mfa_enabled":false}`); code != http.StatusOK {
		t.Fatalf("redundant off: %d %v", code, out)
	}

	// The management token CAN turn it back on.
	if code, out := put(management, `{"mfa_enabled":true}`); code != http.StatusOK || out["mfa_enabled"] != true {
		t.Fatalf("management on: %d %v, want 200 mfa_enabled=true", code, out)
	}

	// Exactly two real changes (off, on) were audited.
	if n := switchAudits(); n != 2 {
		t.Errorf("switch audits = %d, want 2 (off and on; redundant off not audited)", n)
	}

	// Atomic: switch-on + valid mode + bad magic-link URL changes nothing.
	if _, err := totpSvc.SetAppMFAEnabled(ctx, tenantID, appID, false, nil); err != nil {
		t.Fatalf("reset switch: %v", err)
	}
	code, out = put(management, `{"mfa_enabled":true,"mode":"required","magic_link_enabled":true,"magic_link_redirect_url":"http://public.example.com/cb"}`)
	if code != http.StatusBadRequest {
		t.Fatalf("bad magic link: %d %v, want 400", code, out)
	}
	cfg, err := totpSvc.GetAppMFAConfig(ctx, appID)
	if err != nil {
		t.Fatalf("GetAppMFAConfig: %v", err)
	}
	if cfg.Enabled || cfg.Mode != auth.MFAModeOptional {
		t.Errorf("after failed PUT: %+v, want untouched (switch off, optional)", cfg)
	}
}
