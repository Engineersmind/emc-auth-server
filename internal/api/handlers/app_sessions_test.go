package handlers

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/engineersmind/emc-auth-server/internal/admin"
	"github.com/engineersmind/emc-auth-server/internal/audit"
	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// POST .../sessions/revoke (#196).
func TestRevokeApplicationSessionsHandler(t *testing.T) {
	e := newAppMFAHandlerEnv(t, "revoke-h")

	// Without the auth service wired the action refuses rather than revoking
	// rows it cannot deny access tokens for.
	if code, out := e.call(t, e.h.RevokeApplicationSessions, http.MethodPost, ""); code != http.StatusServiceUnavailable || out["error"] != "service_unavailable" {
		t.Fatalf("no auth service: %d %v, want 503 service_unavailable", code, out)
	}

	logger := testhelper.TestLogger()
	jwtSvc, err := auth.NewJWTService(e.pool, "https://auth.emc.local")
	if err != nil {
		t.Fatalf("NewJWTService: %v", err)
	}
	authSvc := auth.NewAuthService(e.pool, jwtSvc, logger).WithApplications(e.appSvc)
	auditLog := audit.New(e.pool, logger, audit.WithFlushInterval(20*time.Millisecond))
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer ccancel()
		_ = auditLog.Close(cctx)
	})
	e.h = NewAdminHandler(admin.New(e.pool, nil, logger).WithAuthService(authSvc), auditLog, logger).
		WithApplications(e.appSvc).
		WithTOTP(e.totpSvc)

	refresh := make([]string, 0, 2)
	for i := 0; i < 2; i++ {
		email := fmt.Sprintf("revoke-h-%d-%d@test.example.com", i, time.Now().UnixNano())
		if _, err := authSvc.Register(e.ctx, auth.RegisterInput{
			ClientID: e.app.ClientID, ClientSecret: e.app.ClientSecret, Email: email, Password: "Password123!",
		}); err != nil {
			t.Fatalf("Register: %v", err)
		}
		res, err := authSvc.Login(e.ctx, auth.LoginInput{
			ClientID: e.app.ClientID, ClientSecret: e.app.ClientSecret, Email: email, Password: "Password123!",
		})
		if err != nil || res.Token == nil {
			t.Fatalf("Login: %+v, %v", res, err)
		}
		refresh = append(refresh, res.Token.RefreshToken)
	}

	code, out := e.call(t, e.h.RevokeApplicationSessions, http.MethodPost, "")
	if code != http.StatusOK || out["revoked"] != float64(2) || out["application_id"] != e.app.ID {
		t.Fatalf("revoke: %d %v, want 200 revoked=2", code, out)
	}
	for _, rt := range refresh {
		if _, err := authSvc.Refresh(e.ctx, rt); err == nil {
			t.Error("refresh succeeded after the application's sessions were revoked")
		}
	}

	// Idempotent, and each call is audited with its count.
	if code, out = e.call(t, e.h.RevokeApplicationSessions, http.MethodPost, ""); code != http.StatusOK || out["revoked"] != float64(0) {
		t.Fatalf("second revoke: %d %v, want 200 revoked=0", code, out)
	}
	n, meta := e.audits(t, audit.ActionAdminAppSessionsRevoked)
	if n != 2 {
		t.Fatalf("revoke audits = %d, want 2", n)
	}
	if meta["revoked"] != float64(0) {
		t.Errorf("last audit revoked = %v, want 0", meta["revoked"])
	}
}
