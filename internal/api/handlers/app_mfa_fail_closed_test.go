package handlers

import (
	"context"
	"encoding/base64"
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

// The helper maps ErrAppMFAUnavailable — wrapped or not — to 503
// app_mfa_unavailable, and leaves every other error to the caller.
func TestAppMFAUnavailableResponse(t *testing.T) {
	call := func(err error) (bool, *httptest.ResponseRecorder) {
		rec := httptest.NewRecorder()
		c := echo.New().NewContext(httptest.NewRequest(http.MethodPost, "/", nil), rec)
		handled, resp := appMFAUnavailableResponse(c, err)
		if resp != nil {
			t.Fatalf("helper returned a transport error: %v", resp)
		}
		return handled, rec
	}

	handled, rec := call(fmt.Errorf("login: %w", auth.ErrAppMFAUnavailable))
	if !handled || rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("handled = %v, status = %d; want true, 503", handled, rec.Code)
	}
	var body APIError
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body.Error != "app_mfa_unavailable" || body.Message == "" {
		t.Errorf("body = %+v, want error app_mfa_unavailable with a message", body)
	}

	if handled, _ := call(auth.ErrAdminMFAUnavailable); handled {
		t.Error("an unrelated error was handled")
	}
}

// End to end through POST /auth/apps/login: an application in 'required' mode
// on a deployment with no TOTP service and no Redis answers 503
// app_mfa_unavailable and sets no token, cookie or challenge (#193).
func TestAppLogin_AppMFAUnavailableIs503(t *testing.T) {
	pool := testhelper.NewTestDB(t)
	testhelper.CleanupTables(t, pool)
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
	app, err := appSvc.CreateApplication(ctx, tenantID, fmt.Sprintf("fc-h-%d", time.Now().UnixNano()), "web", nil)
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}
	appID, _ := strconv.ParseInt(app.ID, 10, 64)
	totpSvc, err := auth.NewTOTPService(pool, strings.Repeat("0", 64), "development", logger)
	if err != nil {
		t.Fatalf("NewTOTPService: %v", err)
	}
	if err := totpSvc.SetAppMFAPolicy(ctx, tenantID, appID, auth.MFAModeRequired, nil, nil); err != nil {
		t.Fatalf("SetAppMFAPolicy(required): %v", err)
	}

	jwtSvc, err := auth.NewJWTService(pool, "https://auth.emc.local")
	if err != nil {
		t.Fatalf("NewJWTService: %v", err)
	}
	// No WithTOTP: this deployment cannot run a second factor.
	authSvc := auth.NewAuthService(pool, jwtSvc, logger).WithApplications(appSvc)
	email := fmt.Sprintf("fc-h-%d@test.example.com", time.Now().UnixNano())
	if _, err := authSvc.Register(ctx, auth.RegisterInput{
		ClientID: app.ClientID, ClientSecret: app.ClientSecret, Email: email, Password: "Password123!",
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	auditLog := audit.New(pool, logger, audit.WithFlushInterval(20*time.Millisecond))
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer ccancel()
		_ = auditLog.Close(cctx)
	})
	h := NewAuthHandler(authSvc, nil, auditLog, logger).WithApplications(appSvc).WithJWT(jwtSvc)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/apps/login",
		strings.NewReader(fmt.Sprintf(`{"email":%q,"password":"Password123!"}`, email)))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req.Header.Set(echo.HeaderAuthorization,
		"Basic "+base64.StdEncoding.EncodeToString([]byte(app.ClientID+":"+app.ClientSecret)))
	rec := httptest.NewRecorder()
	if err := h.AppLogin(echo.New().NewContext(req, rec)); err != nil {
		t.Fatalf("AppLogin transport error: %v", err)
	}

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503. body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body["error"] != "app_mfa_unavailable" {
		t.Errorf("error = %v, want app_mfa_unavailable", body["error"])
	}
	for _, k := range []string{"access_token", "refresh_token", "otp_session_token", "enrollment_token"} {
		if _, ok := body[k]; ok {
			t.Errorf("refusal body carries %q", k)
		}
	}
	if cookies := rec.Result().Cookies(); len(cookies) > 0 {
		t.Errorf("refusal set %d cookie(s)", len(cookies))
	}
}
