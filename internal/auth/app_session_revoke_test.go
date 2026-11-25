package auth_test

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// ---------------------------------------------------------------------------
// Admin action: revoke every session of one application (#196)
// ---------------------------------------------------------------------------

// appSessionToken signs an application user in (no MFA due) and returns the
// refresh token of the new session.
func (f *mfaFixture) appSessionToken(t *testing.T, app *auth.AppResult, email string) string {
	t.Helper()
	res, err := f.appLogin(t, app, email, "Password123!")
	if err != nil {
		t.Fatalf("appLogin(%q): %v", email, err)
	}
	if res.Token == nil {
		t.Fatalf("appLogin(%q) returned a challenge, want tokens", email)
	}
	return res.Token.RefreshToken
}

func TestRevokeApplicationSessions_EndsOnlyThatApplication(t *testing.T) {
	f := newMFAFixture(t)
	app, appID := f.createApp(t, "revoke-all-app")
	other, _ := f.createApp(t, "revoke-all-other")

	emailA := uniqueEmail("revoke-a")
	emailB := uniqueEmail("revoke-b")
	emailOther := uniqueEmail("revoke-other")
	f.registerAppUser(t, app, emailA, "Password123!")
	f.registerAppUser(t, app, emailB, "Password123!")
	f.registerAppUser(t, other, emailOther, "Password123!")

	rtA1 := f.appSessionToken(t, app, emailA)
	rtA2 := f.appSessionToken(t, app, emailA)
	rtB := f.appSessionToken(t, app, emailB)
	rtOther := f.appSessionToken(t, other, emailOther)

	res, err := f.authSvc.RevokeApplicationSessions(f.ctx, f.tenantID, appID)
	if err != nil {
		t.Fatalf("RevokeApplicationSessions: %v", err)
	}
	if res.Revoked != 3 || res.Failed != 0 {
		t.Fatalf("result = %+v, want 3 revoked, 0 failed", res)
	}

	for name, rt := range map[string]string{"A session 1": rtA1, "A session 2": rtA2, "B": rtB} {
		if _, err := f.authSvc.Refresh(f.ctx, rt); !errors.Is(err, auth.ErrInvalidRefreshToken) {
			t.Errorf("%s: refresh after revoke error = %v, want ErrInvalidRefreshToken", name, err)
		}
	}
	if _, err := f.authSvc.Refresh(f.ctx, rtOther); err != nil {
		t.Errorf("other application's session was touched: refresh error = %v", err)
	}

	var reasons int
	if err := f.pool.QueryRow(f.ctx, `
		SELECT COUNT(*) FROM user_sessions WHERE application_id = $1 AND revoked_reason = $2
	`, appID, auth.RevokeReasonAdminAppRevokeAll).Scan(&reasons); err != nil {
		t.Fatalf("count revoke reasons: %v", err)
	}
	if reasons != 3 {
		t.Errorf("sessions with reason %q = %d, want 3", auth.RevokeReasonAdminAppRevokeAll, reasons)
	}

	// Idempotent: nothing left to revoke.
	res, err = f.authSvc.RevokeApplicationSessions(f.ctx, f.tenantID, appID)
	if err != nil || res.Revoked != 0 {
		t.Errorf("second call = %+v, %v; want 0 revoked", res, err)
	}
}

// The tenant is pinned: a caller in another tenant revokes nothing even when
// it names this application's id.
func TestRevokeApplicationSessions_TenantPinned(t *testing.T) {
	f := newMFAFixture(t)
	app, appID := f.createApp(t, "revoke-pinned")
	email := uniqueEmail("revoke-pinned")
	f.registerAppUser(t, app, email, "Password123!")
	rt := f.appSessionToken(t, app, email)

	var otherTenant int64
	if err := f.pool.QueryRow(f.ctx,
		`INSERT INTO tenants (name, slug, jwt_secret) VALUES ($1, $1, 'secret') RETURNING id`,
		fmt.Sprintf("revoke-tenant-%d", time.Now().UnixNano())).Scan(&otherTenant); err != nil {
		t.Fatalf("create other tenant: %v", err)
	}
	res, err := f.authSvc.RevokeApplicationSessions(f.ctx, otherTenant, appID)
	if err != nil || res.Revoked != 0 {
		t.Fatalf("cross-tenant revoke = %+v, %v; want 0 revoked", res, err)
	}
	if _, err := f.authSvc.Refresh(f.ctx, rt); err != nil {
		t.Errorf("session survived? refresh error = %v, want nil", err)
	}
}
