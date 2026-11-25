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

	"github.com/engineersmind/emc-auth-server/internal/audit"
	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/store"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// POST /auth/otp/activate and /auth/otp/email/activate re-read the MFA master
// switch (#192, PR #244 review): an enrolment begun before switch-off must not
// activate a factor after it. Both endpoints answer 403 mfa_switched_off.
func TestSelfServiceActivate_RefusedWhileSwitchedOff(t *testing.T) {
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
	app, err := appSvc.CreateApplication(ctx, tenantID, fmt.Sprintf("mfa-activate-h-%d", time.Now().UnixNano()), "web", nil)
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}
	appID, _ := strconv.ParseInt(app.ID, 10, 64)

	var userID int64
	email := fmt.Sprintf("mfa-activate-%d@test.example.com", time.Now().UnixNano())
	if err := pool.QueryRow(ctx, `
		INSERT INTO users (tenant_id, application_id, email, is_active, email_verified)
		VALUES ($1, $2, $3, true, true) RETURNING id
	`, tenantID, appID, email).Scan(&userID); err != nil {
		t.Fatalf("create user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, userID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM oauth_clients WHERE id = $1`, appID)
	})

	totpSvc, err := auth.NewTOTPService(pool, strings.Repeat("0", 64), "development", logger)
	if err != nil {
		t.Fatalf("NewTOTPService: %v", err)
	}
	// Redis and the mailer are never reached: the switch guard answers first.
	emailSvc := auth.NewEmailMFAService(pool, nil, nil, logger)
	auditLog := audit.New(pool, logger, audit.WithFlushInterval(20*time.Millisecond))
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer ccancel()
		_ = auditLog.Close(cctx)
	})
	h := NewAuthHandler(nil, nil, auditLog, logger).WithTOTP(totpSvc).WithEmailMFA(emailSvc)

	if _, err := totpSvc.SetAppMFAEnabled(ctx, tenantID, appID, false, nil); err != nil {
		t.Fatalf("SetAppMFAEnabled(false): %v", err)
	}

	claims := &auth.Claims{
		UserID: strconv.FormatInt(userID, 10), TenantID: strconv.FormatInt(tenantID, 10),
		Email: email, Gty: auth.GrantPassword,
	}
	post := func(name string, handler func(echo.Context) error) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"code":"123456"}`))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		c := echo.New().NewContext(req, rec)
		c.Set("user", claims)
		if err := handler(c); err != nil {
			t.Fatalf("%s handler error: %v", name, err)
		}
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if rec.Code != http.StatusForbidden || out["error"] != "mfa_switched_off" {
			t.Errorf("%s: %d %v, want 403 mfa_switched_off", name, rec.Code, out)
		}
	}
	post("TOTPActivate", h.TOTPActivate)
	post("EmailMFAActivate", h.EmailMFAActivate)
}
