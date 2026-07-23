package admin_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"


	"github.com/engineersmind/emc-auth-server/internal/admin"
)

// createTestUser creates a user in the fixture tenant (tenant-level scope) and
// returns its numeric id.
func createTestUser(t *testing.T, f adminFixture, email string) int64 {
	t.Helper()
	u, err := f.svc.CreateUser(context.Background(), f.tenantID, nil, email, "Str0ngPass!", "Test", "User", nil)
	if err != nil {
		t.Fatalf("CreateUser(%s) error = %v", email, err)
	}
	return parseID(t, u.ID)
}

// seedRefreshToken inserts one refresh token row for the user and returns its
// session family id (family id = row id, mirroring migration 00026's seeding).
func seedRefreshToken(t *testing.T, f adminFixture, userID int64, ua string, expires time.Duration) int64 {
	t.Helper()
	var id int64
	err := f.pool.QueryRow(context.Background(), `
		INSERT INTO refresh_tokens (user_id, tenant_id, token_hash, expires_at, user_agent, session_family_id)
		VALUES ($1, $2, $3, NOW() + $4::interval, $5, 0)
		RETURNING id
	`, userID, f.tenantID, fmt.Sprintf("hash-%d-%s-%d", userID, ua, time.Now().UnixNano()), fmt.Sprintf("%f seconds", expires.Seconds()), ua).Scan(&id)
	if err != nil {
		t.Fatalf("seed refresh token: %v", err)
	}
	if _, err := f.pool.Exec(context.Background(),
		`UPDATE refresh_tokens SET session_family_id = id WHERE id = $1`, id); err != nil {
		t.Fatalf("set session family: %v", err)
	}
	return id
}

func TestGetUserDetail_Enrichment(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()
	userID := createTestUser(t, f, "detail@example.com")

	// Enroll TOTP with 2 backup codes and active email MFA.
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO totp_secrets (user_id, tenant_id, secret_enc, is_active, backup_codes)
		VALUES ($1, $2, 'enc', true, ARRAY['a','b'])
	`, userID, f.tenantID); err != nil {
		t.Fatalf("seed totp: %v", err)
	}
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO email_mfa_settings (user_id, tenant_id, is_active) VALUES ($1, $2, true)
	`, userID, f.tenantID); err != nil {
		t.Fatalf("seed email mfa: %v", err)
	}
	seedRefreshToken(t, f, userID, "Firefox", time.Hour)

	d, err := f.svc.GetUserDetail(ctx, f.tenantID, nil, userID)
	if err != nil {
		t.Fatalf("GetUserDetail() error = %v", err)
	}
	if !d.MFA.TOTPEnabled || !d.MFA.EmailEnabled {
		t.Errorf("MFA status = %+v, want both enabled", d.MFA)
	}
	if d.MFA.BackupCodesRemaining != 2 {
		t.Errorf("BackupCodesRemaining = %d, want 2", d.MFA.BackupCodesRemaining)
	}
	if d.ActiveSessions != 1 {
		t.Errorf("ActiveSessions = %d, want 1", d.ActiveSessions)
	}
	if d.LastLoginAt == nil {
		t.Error("LastLoginAt = nil, want the session timestamp")
	}
	if d.TokenVersion < 1 {
		t.Errorf("TokenVersion = %d, want >= 1", d.TokenVersion)
	}
	if d.Email != "detail@example.com" {
		t.Errorf("Email = %q", d.Email)
	}
}

func TestGetUserDetail_NotFound(t *testing.T) {
	f := newAdminFixture(t)
	if _, err := f.svc.GetUserDetail(context.Background(), f.tenantID, nil, 999999); !errors.Is(err, admin.ErrNotFound) {
		t.Fatalf("GetUserDetail(missing) error = %v, want ErrNotFound", err)
	}
}

func TestSetUserActive_BlockRevokesSessionsAndBumpsVersion(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()
	userID := createTestUser(t, f, "block@example.com")
	seedRefreshToken(t, f, userID, "Chrome", time.Hour)

	var versionBefore int
	if err := f.pool.QueryRow(ctx, `SELECT token_version FROM users WHERE id = $1`, userID).Scan(&versionBefore); err != nil {
		t.Fatalf("read token_version: %v", err)
	}

	u, err := f.svc.SetUserActive(ctx, f.tenantID, nil, userID, false)
	if err != nil {
		t.Fatalf("SetUserActive(block) error = %v", err)
	}
	if u.IsActive {
		t.Error("IsActive = true after block")
	}

	var versionAfter, liveTokens int
	if err := f.pool.QueryRow(ctx, `SELECT token_version FROM users WHERE id = $1`, userID).Scan(&versionAfter); err != nil {
		t.Fatalf("read token_version: %v", err)
	}
	if versionAfter != versionBefore+1 {
		t.Errorf("token_version = %d, want %d (bumped on block)", versionAfter, versionBefore+1)
	}
	if err := f.pool.QueryRow(ctx, `SELECT COUNT(*) FROM refresh_tokens WHERE user_id = $1 AND revoked_at IS NULL`, userID).Scan(&liveTokens); err != nil {
		t.Fatalf("count tokens: %v", err)
	}
	if liveTokens != 0 {
		t.Errorf("live refresh tokens after block = %d, want 0", liveTokens)
	}

	// Unblock restores is_active without bumping version again.
	u, err = f.svc.SetUserActive(ctx, f.tenantID, nil, userID, true)
	if err != nil {
		t.Fatalf("SetUserActive(unblock) error = %v", err)
	}
	if !u.IsActive {
		t.Error("IsActive = false after unblock")
	}
}

func TestSetUserActive_NotFound(t *testing.T) {
	f := newAdminFixture(t)
	if _, err := f.svc.SetUserActive(context.Background(), f.tenantID, nil, 999999, false); !errors.Is(err, admin.ErrNotFound) {
		t.Fatalf("SetUserActive(missing) error = %v, want ErrNotFound", err)
	}
}

func TestListUserSessions_ActiveOnly(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()
	userID := createTestUser(t, f, "sessions@example.com")

	famA := seedRefreshToken(t, f, userID, "Chrome", time.Hour)
	seedRefreshToken(t, f, userID, "Firefox", time.Hour)
	expired := seedRefreshToken(t, f, userID, "OldBrowser", -time.Hour) // already expired

	sessions, err := f.svc.ListUserSessions(ctx, f.tenantID, nil, userID)
	if err != nil {
		t.Fatalf("ListUserSessions() error = %v", err)
	}
	if len(sessions) != 2 {
		t.Fatalf("sessions = %d, want 2 (expired excluded)", len(sessions))
	}
	for _, s := range sessions {
		if s.SessionFamilyID == fmt.Sprint(expired) {
			t.Error("expired session returned in list")
		}
	}

	// Revoke one family; the list shrinks accordingly.
	if err := f.svc.RevokeUserSession(ctx, f.tenantID, nil, userID, famA); err != nil {
		t.Fatalf("RevokeUserSession() error = %v", err)
	}
	sessions, err = f.svc.ListUserSessions(ctx, f.tenantID, nil, userID)
	if err != nil {
		t.Fatalf("ListUserSessions() after revoke error = %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("sessions after revoke = %d, want 1", len(sessions))
	}
	if sessions[0].UserAgent != "Firefox" {
		t.Errorf("remaining session UA = %q, want Firefox", sessions[0].UserAgent)
	}
}

func TestRevokeUserSession_WrongUserRejected(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()
	userA := createTestUser(t, f, "owner@example.com")
	userB := createTestUser(t, f, "other@example.com")
	famA := seedRefreshToken(t, f, userA, "Chrome", time.Hour)

	// userB must not be able to have userA's session revoked through their id.
	if err := f.svc.RevokeUserSession(ctx, f.tenantID, nil, userB, famA); !errors.Is(err, admin.ErrNotFound) {
		t.Fatalf("RevokeUserSession(cross-user) error = %v, want ErrNotFound", err)
	}
}

func TestRevokeAllUserSessions(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()
	userID := createTestUser(t, f, "purge@example.com")
	seedRefreshToken(t, f, userID, "Chrome", time.Hour)
	seedRefreshToken(t, f, userID, "Firefox", time.Hour)

	var versionBefore int
	if err := f.pool.QueryRow(ctx, `SELECT token_version FROM users WHERE id = $1`, userID).Scan(&versionBefore); err != nil {
		t.Fatalf("read token_version: %v", err)
	}

	count, err := f.svc.RevokeAllUserSessions(ctx, f.tenantID, nil, userID)
	if err != nil {
		t.Fatalf("RevokeAllUserSessions() error = %v", err)
	}
	if count != 2 {
		t.Errorf("revoked = %d, want 2", count)
	}

	var versionAfter int
	if err := f.pool.QueryRow(ctx, `SELECT token_version FROM users WHERE id = $1`, userID).Scan(&versionAfter); err != nil {
		t.Fatalf("read token_version: %v", err)
	}
	if versionAfter != versionBefore+1 {
		t.Errorf("token_version = %d, want %d", versionAfter, versionBefore+1)
	}

	sessions, err := f.svc.ListUserSessions(ctx, f.tenantID, nil, userID)
	if err != nil {
		t.Fatalf("ListUserSessions() error = %v", err)
	}
	if len(sessions) != 0 {
		t.Errorf("sessions after purge = %d, want 0", len(sessions))
	}
}

func TestGetUserMFA_NotEnrolled(t *testing.T) {
	f := newAdminFixture(t)
	userID := createTestUser(t, f, "nomfa@example.com")

	status, err := f.svc.GetUserMFA(context.Background(), f.tenantID, nil, userID)
	if err != nil {
		t.Fatalf("GetUserMFA() error = %v", err)
	}
	if status.TOTPEnabled || status.EmailEnabled || status.BackupCodesRemaining != 0 {
		t.Errorf("MFA status = %+v, want all zero for unenrolled user", status)
	}
}

func TestUserManagement_AppScopeIsolation(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()
	// Tenant-level user; querying through the app scope must not find them.
	userID := createTestUser(t, f, "scoped@example.com")
	famID := seedRefreshToken(t, f, userID, "Chrome", time.Hour)

	if _, err := f.svc.GetUserDetail(ctx, f.tenantID, &f.appID, userID); !errors.Is(err, admin.ErrNotFound) {
		t.Errorf("GetUserDetail(wrong app scope) error = %v, want ErrNotFound", err)
	}
	if _, err := f.svc.SetUserActive(ctx, f.tenantID, &f.appID, userID, false); !errors.Is(err, admin.ErrNotFound) {
		t.Errorf("SetUserActive(wrong app scope) error = %v, want ErrNotFound", err)
	}
	if _, err := f.svc.ListUserSessions(ctx, f.tenantID, &f.appID, userID); !errors.Is(err, admin.ErrNotFound) {
		t.Errorf("ListUserSessions(wrong app scope) error = %v, want ErrNotFound", err)
	}
	if _, err := f.svc.GetUserMFA(ctx, f.tenantID, &f.appID, userID); !errors.Is(err, admin.ErrNotFound) {
		t.Errorf("GetUserMFA(wrong app scope) error = %v, want ErrNotFound", err)
	}
	if err := f.svc.RevokeUserSession(ctx, f.tenantID, &f.appID, userID, famID); !errors.Is(err, admin.ErrNotFound) {
		t.Errorf("RevokeUserSession(wrong app scope) error = %v, want ErrNotFound", err)
	}
	if _, err := f.svc.RevokeAllUserSessions(ctx, f.tenantID, &f.appID, userID); !errors.Is(err, admin.ErrNotFound) {
		t.Errorf("RevokeAllUserSessions(wrong app scope) error = %v, want ErrNotFound", err)
	}
}

// createSecondTenantUser provisions a distinct tenant B with one user and one
// live session, returning tenant B's id, the user's id, and the session family
// id. Used to prove that tenant A's service can never reach tenant B's rows.
func createSecondTenantUser(t *testing.T, f adminFixture, slug, email string) (tenantB, userB, famB int64) {
	t.Helper()
	ctx := context.Background()
	res, err := f.svc.CreateTenant(ctx, admin.CreateTenantInput{
		Name:       slug,
		Slug:       slug,
		OwnerEmail: "owner-" + slug + "@example.com",
	})
	if err != nil {
		t.Fatalf("CreateTenant(%s): %v", slug, err)
	}
	tenantB = parseID(t, res.Tenant.ID)

	u, err := f.svc.CreateUser(ctx, tenantB, nil, email, "Str0ngPass!", "Other", "Tenant", nil)
	if err != nil {
		t.Fatalf("CreateUser(tenant B): %v", err)
	}
	userB = parseID(t, u.ID)

	err = f.pool.QueryRow(ctx, `
		INSERT INTO refresh_tokens (user_id, tenant_id, token_hash, expires_at, user_agent, session_family_id)
		VALUES ($1, $2, $3, NOW() + interval '1 hour', 'Chrome', 0)
		RETURNING id
	`, userB, tenantB, fmt.Sprintf("hash-b-%d", time.Now().UnixNano())).Scan(&famB)
	if err != nil {
		t.Fatalf("seed tenant B refresh token: %v", err)
	}
	if _, err := f.pool.Exec(ctx,
		`UPDATE refresh_tokens SET session_family_id = id WHERE id = $1`, famB); err != nil {
		t.Fatalf("set tenant B session family: %v", err)
	}
	return tenantB, userB, famB
}

// TestUserManagement_CrossTenantIsolation proves every user-management method
// refuses to touch another tenant's user: called with tenant A's id but tenant
// B's user id, all seven return ErrNotFound and mutate nothing.
func TestUserManagement_CrossTenantIsolation(t *testing.T) {
	f := newAdminFixture(t) // f.tenantID is tenant A
	ctx := context.Background()
	_, userB, famB := createSecondTenantUser(t, f, "tenantb", "userb@example.com")

	// Enroll MFA for user B so a leak would actually surface data, not just a miss.
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO totp_secrets (user_id, tenant_id, secret_enc, is_active, backup_codes)
		SELECT $1, tenant_id, 'enc', true, ARRAY['a'] FROM users WHERE id = $1
	`, userB); err != nil {
		t.Fatalf("seed tenant B totp: %v", err)
	}

	if _, err := f.svc.GetUserDetail(ctx, f.tenantID, nil, userB); !errors.Is(err, admin.ErrNotFound) {
		t.Errorf("GetUserDetail(cross-tenant) error = %v, want ErrNotFound", err)
	}
	if _, err := f.svc.SetUserActive(ctx, f.tenantID, nil, userB, false); !errors.Is(err, admin.ErrNotFound) {
		t.Errorf("SetUserActive(cross-tenant) error = %v, want ErrNotFound", err)
	}
	if _, err := f.svc.ListUserSessions(ctx, f.tenantID, nil, userB); !errors.Is(err, admin.ErrNotFound) {
		t.Errorf("ListUserSessions(cross-tenant) error = %v, want ErrNotFound", err)
	}
	if _, err := f.svc.GetUserMFA(ctx, f.tenantID, nil, userB); !errors.Is(err, admin.ErrNotFound) {
		t.Errorf("GetUserMFA(cross-tenant) error = %v, want ErrNotFound", err)
	}
	if err := f.svc.RevokeUserSession(ctx, f.tenantID, nil, userB, famB); !errors.Is(err, admin.ErrNotFound) {
		t.Errorf("RevokeUserSession(cross-tenant) error = %v, want ErrNotFound", err)
	}
	if _, err := f.svc.RevokeAllUserSessions(ctx, f.tenantID, nil, userB); !errors.Is(err, admin.ErrNotFound) {
		t.Errorf("RevokeAllUserSessions(cross-tenant) error = %v, want ErrNotFound", err)
	}

	// Tenant B's session must still be live — nothing was revoked cross-tenant.
	var live int
	if err := f.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM refresh_tokens WHERE user_id = $1 AND revoked_at IS NULL`, userB).Scan(&live); err != nil {
		t.Fatalf("count tenant B tokens: %v", err)
	}
	if live != 1 {
		t.Errorf("tenant B live tokens = %d, want 1 (cross-tenant calls must not revoke)", live)
	}
}
