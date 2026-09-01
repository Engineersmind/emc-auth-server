package auth_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/mailer"
	"github.com/engineersmind/emc-auth-server/internal/security/breach"
	"github.com/engineersmind/emc-auth-server/internal/store"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// flowEnv is the shared fixture for the invitation / email-change / lockout /
// breach flows: a real DB with the "emc" tenant seeded and a capture mailer.
type flowEnv struct {
	pool     *pgxpool.Pool
	mail     *captureMailer
	tmplSvc  *auth.EmailTemplateService
	tenantID int64
	ctx      context.Context
}

func newFlowEnv(t *testing.T) flowEnv {
	t.Helper()
	pool := testhelper.NewTestDB(t)
	testhelper.CleanupTables(t, pool)
	logger := testhelper.TestLogger()
	ctx := context.Background()
	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}
	var tenantID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM tenants WHERE slug = 'emc'`).Scan(&tenantID); err != nil {
		t.Fatalf("tenant id: %v", err)
	}
	return flowEnv{
		pool:     pool,
		mail:     &captureMailer{},
		tmplSvc:  auth.NewEmailTemplateService(pool, logger),
		tenantID: tenantID,
		ctx:      ctx,
	}
}

// seedUser inserts an active tenant-level user with a known password and returns
// its id.
func (e flowEnv) seedUser(t *testing.T, email, passwordHash string) int64 {
	t.Helper()
	var id int64
	if err := e.pool.QueryRow(e.ctx, `
		INSERT INTO users (tenant_id, email, first_name, last_name, is_active)
		VALUES ($1, $2, 'Flow', 'User', true) RETURNING id
	`, e.tenantID, email).Scan(&id); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if passwordHash != "" {
		if _, err := e.pool.Exec(e.ctx, `
			INSERT INTO user_credentials (user_id, tenant_id, password_hash) VALUES ($1, $2, $3)
		`, id, e.tenantID, passwordHash); err != nil {
			t.Fatalf("seed credentials: %v", err)
		}
	}
	return id
}

// seedSession inserts one live refresh token for a user, so that revocation can
// be observed. session_family_id is NOT NULL and each new session seeds its own
// family from its primary key, matching migration 00026.
func (e flowEnv) seedSession(t *testing.T, userID int64, raw string) {
	t.Helper()
	var id int64
	if err := e.pool.QueryRow(e.ctx, `
		INSERT INTO refresh_tokens (user_id, tenant_id, token_hash, expires_at, session_family_id)
		VALUES ($1, $2, $3, NOW() + INTERVAL '30 days', 0)
		RETURNING id
	`, userID, e.tenantID, auth.HashToken(raw)).Scan(&id); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	if _, err := e.pool.Exec(e.ctx,
		`UPDATE refresh_tokens SET session_family_id = id WHERE id = $1`, id); err != nil {
		t.Fatalf("set session family: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Invitations
// ---------------------------------------------------------------------------

// testDashboardURL stands in for DASHBOARD_BASE_URL — the admin console origin,
// deliberately NOT the API origin. An invitation link must open a page that can
// collect a password; POST /api/v1/auth/accept-invitation answers a browser GET
// with "authorization required".
const testDashboardURL = "http://localhost:5173"

// TestInvitation_LinkTargetsTheConsolePage guards the shape of the emailed link.
// Pointing it at the API produced an invitation nobody could accept, which for a
// freshly seeded tenant owner meant a tenant nobody could enter at all.
func TestInvitation_LinkTargetsTheConsolePage(t *testing.T) {
	e := newFlowEnv(t)
	invSvc := auth.NewInvitationService(e.pool, e.mail, testDashboardURL, testhelper.TestLogger()).
		WithTemplates(e.tmplSvc)

	email := uniqueEmail("invite-link")
	userID := e.seedUser(t, email, "")
	if err := invSvc.Invite(e.ctx, e.tenantID, nil, userID, email, "", nil); err != nil {
		t.Fatalf("Invite: %v", err)
	}

	link := e.mail.invitations[0].Link
	if !strings.HasPrefix(link, testDashboardURL+"/accept-invitation?token=") {
		t.Errorf("invitation link = %q, want the console page on %s", link, testDashboardURL)
	}
	if strings.Contains(link, "/api/") {
		t.Errorf("invitation link = %q, must not point at an API endpoint", link)
	}
}

// TestInvitation_ConfirmsAdminGrantWithoutTouchingPassword covers the
// confirmation half of an administrative grant: the recipient already has a
// working account, so following the link must activate the grant and attach its
// role WITHOUT resetting their password or ending their sessions.
//
// Promoting someone already working in the tenant is the ordinary case; making
// it cost them a credential reset would be a real tax for no security gain,
// since the link only proves they control the inbox, which they had already
// proven.
func TestInvitation_ConfirmsAdminGrantWithoutTouchingPassword(t *testing.T) {
	e := newFlowEnv(t)
	invSvc := auth.NewInvitationService(e.pool, e.mail, testDashboardURL, testhelper.TestLogger()).
		WithTemplates(e.tmplSvc)

	// An existing, working account. MinCost keeps the test fast; the comparison
	// path is identical.
	const knownPassword = "ExistingPassw0rd!"
	hashed, err := bcrypt.GenerateFromPassword([]byte(knownPassword), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash existing password: %v", err)
	}
	knownHash := string(hashed)
	email := uniqueEmail("confirm-grant")
	userID := e.seedUser(t, email, knownHash)

	// A co_owner role plus a pending grant, as InviteTenantAdmin would leave it:
	// role unassigned, activated_at NULL.
	var roleID int64
	if err := e.pool.QueryRow(e.ctx, `
		INSERT INTO roles (tenant_id, name, is_system, created_at)
		VALUES ($1, 'co_owner', true, NOW()) RETURNING id
	`, e.tenantID).Scan(&roleID); err != nil {
		t.Fatalf("seed co_owner role: %v", err)
	}
	if _, err := e.pool.Exec(e.ctx, `
		INSERT INTO tenant_admins (tenant_id, user_id, admin_role) VALUES ($1, $2, 'co_owner')
	`, e.tenantID, userID); err != nil {
		t.Fatalf("seed pending grant: %v", err)
	}

	if err := invSvc.Invite(e.ctx, e.tenantID, nil, userID, email, "", nil); err != nil {
		t.Fatalf("Invite: %v", err)
	}
	raw := tokenFromLink(t, e.mail.invitations[0].Link)

	// The page learns from Preview that no password is needed here.
	preview, err := invSvc.Preview(e.ctx, raw)
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	if preview.RequiresPassword {
		t.Error("RequiresPassword = true for an account that already has a password")
	}
	if !preview.GrantsAdmin {
		t.Error("GrantsAdmin = false, want true so the page can say what is being confirmed")
	}
	if preview.Email != email {
		t.Errorf("Preview email = %q, want %q", preview.Email, email)
	}

	// The link alone is not enough: activating an administrative grant takes
	// proof that the recipient can operate the account, not only read the inbox.
	if _, err := invSvc.Accept(e.ctx, raw, auth.AcceptOptions{}); !errors.Is(err, auth.ErrCurrentPasswordMismatch) {
		t.Errorf("Accept with nothing supplied = %v, want ErrCurrentPasswordMismatch", err)
	}
	if _, err := invSvc.Accept(e.ctx, raw, auth.AcceptOptions{CurrentPassword: "wrong-password"}); !errors.Is(err, auth.ErrCurrentPasswordMismatch) {
		t.Errorf("Accept with the wrong password = %v, want ErrCurrentPasswordMismatch", err)
	}
	// A rejected attempt must not burn the token — otherwise one typo costs the
	// recipient their invitation and an operator has to reissue it.
	if _, err := invSvc.Accept(e.ctx, raw, auth.AcceptOptions{CurrentPassword: knownPassword}); err != nil {
		t.Fatalf("Accept keeping the current password: %v", err)
	}

	var hash string
	var activated *string
	var assignedRole *int64
	if err := e.pool.QueryRow(e.ctx, `
		SELECT c.password_hash, ta.activated_at::text, u.role_id
		FROM users u
		JOIN user_credentials c ON c.user_id = u.id
		JOIN tenant_admins ta ON ta.user_id = u.id
		WHERE u.id = $1
	`, userID).Scan(&hash, &activated, &assignedRole); err != nil {
		t.Fatalf("read state after confirm: %v", err)
	}
	if hash != knownHash {
		t.Error("password hash changed; confirming a grant must not reset a working password")
	}
	if activated == nil {
		t.Error("activated_at is still NULL, want the grant confirmed")
	}
	if assignedRole == nil || *assignedRole != roleID {
		t.Errorf("role_id = %v, want the co_owner role %d attached on confirmation", assignedRole, roleID)
	}

	// Preview must refuse a spent token rather than reporting it live.
	if _, err := invSvc.Preview(e.ctx, raw); !errors.Is(err, auth.ErrInvalidInvitation) {
		t.Errorf("Preview after accept = %v, want ErrInvalidInvitation", err)
	}
}

// Activating an administrative grant must end every session that predates it,
// even on the keep-my-password path — the path that does NOT otherwise revoke
// anything, and the one an existing tenant user actually takes.
//
// A refresh token captured before the grant existed would otherwise keep
// rotating, and each rotation re-reads the grant, so the stolen session
// silently acquires admin_scope it never had when it was taken. The
// token_version bump does not cover this: nothing verifies that counter.
func TestInvitation_ActivatingAGrantRevokesEarlierSessions(t *testing.T) {
	e := newFlowEnv(t)
	invSvc := auth.NewInvitationService(e.pool, e.mail, testDashboardURL, testhelper.TestLogger()).
		WithTemplates(e.tmplSvc)

	const knownPassword = "ExistingPassw0rd!"
	hashed, err := bcrypt.GenerateFromPassword([]byte(knownPassword), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash existing password: %v", err)
	}
	email := uniqueEmail("grant-revokes")
	userID := e.seedUser(t, email, string(hashed))

	if _, err := e.pool.Exec(e.ctx, `
		INSERT INTO roles (tenant_id, name, is_system, created_at)
		VALUES ($1, 'co_owner', true, NOW())
	`, e.tenantID); err != nil {
		t.Fatalf("seed co_owner role: %v", err)
	}
	if _, err := e.pool.Exec(e.ctx, `
		INSERT INTO tenant_admins (tenant_id, user_id, admin_role) VALUES ($1, $2, 'co_owner')
	`, e.tenantID, userID); err != nil {
		t.Fatalf("seed pending grant: %v", err)
	}

	// A session taken before the grant was accepted.
	e.seedSession(t, userID, "pre-grant-session")

	var beforeVersion int
	if err := e.pool.QueryRow(e.ctx, `SELECT token_version FROM users WHERE id = $1`, userID).Scan(&beforeVersion); err != nil {
		t.Fatalf("read token_version: %v", err)
	}

	if err := invSvc.Invite(e.ctx, e.tenantID, nil, userID, email, "", nil); err != nil {
		t.Fatalf("Invite: %v", err)
	}
	raw := tokenFromLink(t, e.mail.invitations[len(e.mail.invitations)-1].Link)

	// Keep the existing password: the branch that sets no credentials and so
	// revokes nothing of its own accord.
	if _, err := invSvc.Accept(e.ctx, raw, auth.AcceptOptions{CurrentPassword: knownPassword}); err != nil {
		t.Fatalf("Accept keeping the current password: %v", err)
	}

	var live, afterVersion int
	if err := e.pool.QueryRow(e.ctx, `
		SELECT (SELECT count(*) FROM refresh_tokens
		        WHERE user_id = $1 AND tenant_id = $2 AND revoked_at IS NULL),
		       (SELECT token_version FROM users WHERE id = $1)
	`, userID, e.tenantID).Scan(&live, &afterVersion); err != nil {
		t.Fatalf("read state after accept: %v", err)
	}
	if live != 0 {
		t.Errorf("live refresh tokens after activating a grant = %d, want 0", live)
	}
	if afterVersion <= beforeVersion {
		t.Errorf("token_version = %d, want greater than %d", afterVersion, beforeVersion)
	}
}

// GrantsAdmin answers "will accepting THIS invitation activate a grant?", so it
// must be scoped to the invitation's own tenant.
//
// Unscoped, a pending grant in any tenant made every ordinary invitation report
// grants_admin: true. Accept then resolves the grant by (user, invitation
// tenant), finds none, and no-ops — so the page told the recipient they were
// confirming administrative access and nothing of the kind happened.
func TestInvitationPreview_GrantsAdminIsScopedToTheInvitationTenant(t *testing.T) {
	e := newFlowEnv(t)
	invSvc := auth.NewInvitationService(e.pool, e.mail, testDashboardURL, testhelper.TestLogger()).
		WithTemplates(e.tmplSvc)

	// A second tenant, and the same person holding a pending grant there.
	var otherTenantID int64
	if err := e.pool.QueryRow(e.ctx, `
		INSERT INTO tenants (name, slug, jwt_secret, is_active)
		VALUES ('Other Co', 'other-co-preview', 'secret-for-other-co-tenant', true)
		RETURNING id
	`).Scan(&otherTenantID); err != nil {
		t.Fatalf("seed second tenant: %v", err)
	}

	email := uniqueEmail("cross-tenant-grant")
	// The invited identity, in the seed tenant, with no grant of its own.
	userID := e.seedUser(t, email, "")

	// The same address as a separate identity in the other tenant, holding a
	// pending administrative grant there. Distinct users row: identities do not
	// cross tenant boundaries.
	var otherUserID int64
	if err := e.pool.QueryRow(e.ctx, `
		INSERT INTO users (tenant_id, email, first_name, last_name, is_active)
		VALUES ($1, $2, 'Other', 'Identity', true) RETURNING id
	`, otherTenantID, email).Scan(&otherUserID); err != nil {
		t.Fatalf("seed other-tenant user: %v", err)
	}
	if _, err := e.pool.Exec(e.ctx, `
		INSERT INTO tenant_admins (tenant_id, user_id, admin_role) VALUES ($1, $2, 'co_owner')
	`, otherTenantID, otherUserID); err != nil {
		t.Fatalf("seed other-tenant grant: %v", err)
	}

	// An ordinary invitation into the seed tenant.
	if err := invSvc.Invite(e.ctx, e.tenantID, nil, userID, email, "", nil); err != nil {
		t.Fatalf("Invite: %v", err)
	}
	preview, err := invSvc.Preview(e.ctx, tokenFromLink(t, e.mail.invitations[len(e.mail.invitations)-1].Link))
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	if preview.GrantsAdmin {
		t.Error("GrantsAdmin = true for an ordinary invitation; a pending grant in another tenant leaked into this one")
	}

	// The same user WITH a pending grant in the invitation's own tenant must
	// still report true — the predicate has to narrow, not disable.
	if _, err := e.pool.Exec(e.ctx, `
		INSERT INTO tenant_admins (tenant_id, user_id, admin_role) VALUES ($1, $2, 'co_owner')
	`, e.tenantID, userID); err != nil {
		t.Fatalf("seed same-tenant grant: %v", err)
	}
	if err := invSvc.Invite(e.ctx, e.tenantID, nil, userID, email, "", nil); err != nil {
		t.Fatalf("re-Invite: %v", err)
	}
	preview, err = invSvc.Preview(e.ctx, tokenFromLink(t, e.mail.invitations[len(e.mail.invitations)-1].Link))
	if err != nil {
		t.Fatalf("Preview after same-tenant grant: %v", err)
	}
	if !preview.GrantsAdmin {
		t.Error("GrantsAdmin = false for a pending grant in the invitation's own tenant")
	}
}

// TestInvitation_OnboardingStillRequiresAPassword proves the other half: an
// account with no credentials cannot be activated by an empty password.
func TestInvitation_OnboardingStillRequiresAPassword(t *testing.T) {
	e := newFlowEnv(t)
	invSvc := auth.NewInvitationService(e.pool, e.mail, testDashboardURL, testhelper.TestLogger()).
		WithTemplates(e.tmplSvc)

	email := uniqueEmail("onboard-pw")
	userID := e.seedUser(t, email, "")
	if err := invSvc.Invite(e.ctx, e.tenantID, nil, userID, email, "", nil); err != nil {
		t.Fatalf("Invite: %v", err)
	}
	raw := tokenFromLink(t, e.mail.invitations[0].Link)

	preview, err := invSvc.Preview(e.ctx, raw)
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	if !preview.RequiresPassword {
		t.Error("RequiresPassword = false for an account with no credentials")
	}
	if _, err := invSvc.Accept(e.ctx, raw, auth.AcceptOptions{}); !errors.Is(err, auth.ErrWeakPassword) {
		t.Errorf("Accept with no password = %v, want ErrWeakPassword", err)
	}
	// CurrentPassword is meaningless for an account that has none, and must not
	// be accepted as a substitute for choosing one.
	if _, err := invSvc.Accept(e.ctx, raw, auth.AcceptOptions{CurrentPassword: "anything"}); !errors.Is(err, auth.ErrWeakPassword) {
		t.Errorf("Accept with only a current password = %v, want ErrWeakPassword", err)
	}
	// The token survives a rejected attempt, so the recipient can try again.
	if _, err := invSvc.Accept(e.ctx, raw, auth.AcceptOptions{NewPassword: "ChosenPassword123!"}); err != nil {
		t.Errorf("Accept after the rejected attempt: %v", err)
	}
}

// TestInvitation_FullFlow proves invite → emailed link → password set → verified,
// and that the token is single-use.
func TestInvitation_FullFlow(t *testing.T) {
	e := newFlowEnv(t)
	invSvc := auth.NewInvitationService(e.pool, e.mail, testDashboardURL, testhelper.TestLogger()).
		WithTemplates(e.tmplSvc)

	email := uniqueEmail("invite-full")
	userID := e.seedUser(t, email, "")

	if err := invSvc.Invite(e.ctx, e.tenantID, nil, userID, email, "admin@emc.local", nil); err != nil {
		t.Fatalf("Invite: %v", err)
	}
	if len(e.mail.invitations) != 1 || e.mail.invitations[0].To != email {
		t.Fatalf("invitations = %+v, want 1 to %s", e.mail.invitations, email)
	}
	if e.mail.invitations[0].InviterName != "admin@emc.local" {
		t.Errorf("InviterName = %q, want the inviting admin", e.mail.invitations[0].InviterName)
	}

	raw := tokenFromLink(t, e.mail.invitations[0].Link)
	target, err := invSvc.Accept(e.ctx, raw, auth.AcceptOptions{NewPassword: "ChosenPassword123!"})
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if target.UserID != userID || target.Email != email {
		t.Errorf("Accept target = %+v, want user %d / %s", target, userID, email)
	}

	// The password now exists and the address counts as verified.
	var verified bool
	var hash string
	if err := e.pool.QueryRow(e.ctx, `
		SELECT u.email_verified, c.password_hash
		FROM users u JOIN user_credentials c ON c.user_id = u.id WHERE u.id = $1
	`, userID).Scan(&verified, &hash); err != nil {
		t.Fatalf("read user after accept: %v", err)
	}
	if !verified {
		t.Error("email_verified = false, want true after accepting an invitation")
	}
	if hash == "" {
		t.Error("password_hash is empty, want the accepted password")
	}

	// Single use.
	if _, err := invSvc.Accept(e.ctx, raw, auth.AcceptOptions{NewPassword: "AnotherPassword123!"}); !errors.Is(err, auth.ErrInvalidInvitation) {
		t.Errorf("second Accept = %v, want ErrInvalidInvitation", err)
	}
}

// TestInvitation_ResendSupersedesPrevious proves a re-invite kills the old link,
// so a leaked earlier email cannot still claim the account.
func TestInvitation_ResendSupersedesPrevious(t *testing.T) {
	e := newFlowEnv(t)
	invSvc := auth.NewInvitationService(e.pool, e.mail, testDashboardURL, testhelper.TestLogger()).
		WithTemplates(e.tmplSvc)

	email := uniqueEmail("invite-resend")
	userID := e.seedUser(t, email, "")
	for i := 0; i < 2; i++ {
		if err := invSvc.Invite(e.ctx, e.tenantID, nil, userID, email, "", nil); err != nil {
			t.Fatalf("Invite #%d: %v", i, err)
		}
	}
	if len(e.mail.invitations) != 2 {
		t.Fatalf("invitations = %d, want 2", len(e.mail.invitations))
	}

	first := tokenFromLink(t, e.mail.invitations[0].Link)
	second := tokenFromLink(t, e.mail.invitations[1].Link)
	if _, err := invSvc.Accept(e.ctx, first, auth.AcceptOptions{NewPassword: "Password123!"}); !errors.Is(err, auth.ErrInvalidInvitation) {
		t.Errorf("superseded invitation = %v, want ErrInvalidInvitation", err)
	}
	if _, err := invSvc.Accept(e.ctx, second, auth.AcceptOptions{NewPassword: "Password123!"}); err != nil {
		t.Errorf("latest invitation Accept = %v, want success", err)
	}
}

// TestInvitation_AdminBlockCannotBeBypassed proves a still-live invitation link
// cannot undo an operator's block: an admin who invites a user and then blocks
// the account stays in control, and the account is not silently re-activated.
func TestInvitation_AdminBlockCannotBeBypassed(t *testing.T) {
	e := newFlowEnv(t)
	invSvc := auth.NewInvitationService(e.pool, e.mail, testDashboardURL, testhelper.TestLogger()).
		WithTemplates(e.tmplSvc)

	email := uniqueEmail("invite-blocked")
	userID := e.seedUser(t, email, "")
	if err := invSvc.Invite(e.ctx, e.tenantID, nil, userID, email, "", nil); err != nil {
		t.Fatalf("Invite: %v", err)
	}
	raw := tokenFromLink(t, e.mail.invitations[0].Link)

	if _, err := e.pool.Exec(e.ctx, `
		UPDATE users SET is_active = false, blocked_at = NOW(), block_reason = $2 WHERE id = $1
	`, userID, mailer.BlockReasonAdmin); err != nil {
		t.Fatalf("admin-block user: %v", err)
	}

	if _, err := invSvc.Accept(e.ctx, raw, auth.AcceptOptions{NewPassword: "Password123!"}); !errors.Is(err, auth.ErrInvitationBlocked) {
		t.Fatalf("Accept on an admin-blocked account = %v, want ErrInvitationBlocked", err)
	}
	var active bool
	var used *string
	if err := e.pool.QueryRow(e.ctx, `
		SELECT u.is_active, i.used_at::text
		FROM users u JOIN user_invitations i ON i.user_id = u.id
		WHERE u.id = $1
	`, userID).Scan(&active, &used); err != nil {
		t.Fatalf("read state after rejected accept: %v", err)
	}
	if active {
		t.Error("is_active = true after a rejected accept, want the admin block to stand")
	}
	if used != nil {
		t.Error("invitation was consumed by a rejected accept, want it untouched")
	}
}

// TestInvitation_SuppressedTemplateRetiresToken proves a disabled template sends
// nothing and leaves no usable link behind.
func TestInvitation_SuppressedTemplateRetiresToken(t *testing.T) {
	e := newFlowEnv(t)
	off := false
	if _, err := e.tmplSvc.Upsert(e.ctx, e.tenantID, nil, mailer.TemplateUserInvitation, auth.UpsertTemplateInput{
		Subject: "x", HTMLBody: "<p>x</p>", IsActive: &off,
	}, nil); err != nil {
		t.Fatalf("disable template: %v", err)
	}
	invSvc := auth.NewInvitationService(e.pool, e.mail, testDashboardURL, testhelper.TestLogger()).
		WithTemplates(e.tmplSvc)

	email := uniqueEmail("invite-suppressed")
	userID := e.seedUser(t, email, "")
	if err := invSvc.Invite(e.ctx, e.tenantID, nil, userID, email, "", nil); err != nil {
		t.Fatalf("Invite: %v", err)
	}
	if len(e.mail.invitations) != 0 {
		t.Errorf("invitations = %d, want 0 when the template is disabled", len(e.mail.invitations))
	}
	var live int
	if err := e.pool.QueryRow(e.ctx, `
		SELECT COUNT(*) FROM user_invitations WHERE user_id = $1 AND used_at IS NULL
	`, userID).Scan(&live); err != nil {
		t.Fatalf("count live invitations: %v", err)
	}
	if live != 0 {
		t.Errorf("live invitation tokens = %d, want 0 (nothing was emailed)", live)
	}
}

// ---------------------------------------------------------------------------
// Email change
// ---------------------------------------------------------------------------

// TestEmailChange_FullFlow proves the address moves only after the NEW inbox
// confirms, and that the token is single-use.
func TestEmailChange_FullFlow(t *testing.T) {
	e := newFlowEnv(t)
	chgSvc := auth.NewEmailChangeService(e.pool, e.mail, "http://localhost:9090", testhelper.TestLogger()).
		WithTemplates(e.tmplSvc)

	oldEmail := uniqueEmail("change-old")
	newEmail := uniqueEmail("change-new")
	userID := e.seedUser(t, oldEmail, "")

	if err := chgSvc.Request(e.ctx, e.tenantID, userID, newEmail); err != nil {
		t.Fatalf("Request: %v", err)
	}
	if len(e.mail.emailChanges) != 1 || e.mail.emailChanges[0].To != newEmail {
		t.Fatalf("change-email sends = %+v, want 1 to the NEW address %s", e.mail.emailChanges, newEmail)
	}

	// Until confirmation the account keeps the old address.
	var current string
	if err := e.pool.QueryRow(e.ctx, `SELECT email FROM users WHERE id = $1`, userID).Scan(&current); err != nil {
		t.Fatalf("read email: %v", err)
	}
	if current != oldEmail {
		t.Errorf("email = %s before confirmation, want the old address %s", current, oldEmail)
	}

	raw := tokenFromLink(t, e.mail.emailChanges[0].Link)
	got, err := chgSvc.Confirm(e.ctx, raw)
	if err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	if got.NewEmail != newEmail || got.OldEmail != oldEmail || got.UserID != userID || got.TenantID != e.tenantID {
		t.Errorf("Confirm returned %+v, want new=%s old=%s user=%d tenant=%d", got, newEmail, oldEmail, userID, e.tenantID)
	}

	// The previous address is told after the fact, so a takeover is never silent.
	if len(e.mail.emailChanges) != 2 || e.mail.emailChanges[1].To != oldEmail ||
		e.mail.emailChanges[1].Reason != mailer.EmailChangeApplied ||
		e.mail.emailChanges[1].NewEmail != newEmail {
		t.Errorf("second change-email send = %+v, want the %q notice to %s", e.mail.emailChanges, mailer.EmailChangeApplied, oldEmail)
	}

	// An email change is a credential change: prior sessions must not survive it.
	var tokenVersion int
	var liveTokens int
	if err := e.pool.QueryRow(e.ctx, `
		SELECT u.token_version,
		       (SELECT COUNT(*) FROM refresh_tokens WHERE user_id = u.id AND revoked_at IS NULL)
		FROM users u WHERE u.id = $1
	`, userID).Scan(&tokenVersion, &liveTokens); err != nil {
		t.Fatalf("read token state: %v", err)
	}
	if tokenVersion == 0 || liveTokens != 0 {
		t.Errorf("after confirm token_version=%d live refresh tokens=%d, want a bump and 0", tokenVersion, liveTokens)
	}

	var verified bool
	if err := e.pool.QueryRow(e.ctx, `SELECT email, email_verified FROM users WHERE id = $1`, userID).Scan(&current, &verified); err != nil {
		t.Fatalf("read email after confirm: %v", err)
	}
	if current != newEmail || !verified {
		t.Errorf("after confirm email=%s verified=%v, want %s / true", current, verified, newEmail)
	}

	if _, err := chgSvc.Confirm(e.ctx, raw); !errors.Is(err, auth.ErrInvalidEmailChange) {
		t.Errorf("second Confirm = %v, want ErrInvalidEmailChange", err)
	}
}

// TestEmailChange_RejectsTakenAndSame covers the two request-time guards.
func TestEmailChange_RejectsTakenAndSame(t *testing.T) {
	e := newFlowEnv(t)
	chgSvc := auth.NewEmailChangeService(e.pool, e.mail, "http://localhost:9090", testhelper.TestLogger()).
		WithTemplates(e.tmplSvc)

	mine := uniqueEmail("change-mine")
	theirs := uniqueEmail("change-theirs")
	userID := e.seedUser(t, mine, "")
	e.seedUser(t, theirs, "")

	if err := chgSvc.Request(e.ctx, e.tenantID, userID, theirs); !errors.Is(err, auth.ErrEmailTaken) {
		t.Errorf("Request(taken) = %v, want ErrEmailTaken", err)
	}
	if err := chgSvc.Request(e.ctx, e.tenantID, userID, strings.ToUpper(mine)); !errors.Is(err, auth.ErrSameEmail) {
		t.Errorf("Request(own address) = %v, want ErrSameEmail", err)
	}
	if len(e.mail.emailChanges) != 0 {
		t.Errorf("change-email sends = %d, want 0 for rejected requests", len(e.mail.emailChanges))
	}
}

// ---------------------------------------------------------------------------
// Account lockout
// ---------------------------------------------------------------------------

// TestLockout_BlocksAfterThresholdAndUnblocks walks the automatic path end to
// end: repeated failures block the account and email an unblock link, and the
// link restores access exactly once.
func TestLockout_BlocksAfterThresholdAndUnblocks(t *testing.T) {
	e := newFlowEnv(t)
	blockSvc := auth.NewAccountBlockService(e.pool, e.mail, "http://localhost:9090", testhelper.TestLogger()).
		WithTemplates(e.tmplSvc)

	email := uniqueEmail("lockout")
	userID := e.seedUser(t, email, "")

	// One short of the threshold: still active, nothing emailed.
	for i := 0; i < auth.MaxFailedLogins-1; i++ {
		if blocked := blockSvc.RecordFailedLogin(e.ctx, e.tenantID, userID); blocked {
			t.Fatalf("blocked after %d attempts, want only at %d", i+1, auth.MaxFailedLogins)
		}
	}
	if got := e.mail.Blocks(); len(got) != 0 {
		t.Fatalf("blocked-account emails = %d before the threshold, want 0", len(got))
	}

	if blocked := blockSvc.RecordFailedLogin(e.ctx, e.tenantID, userID); !blocked {
		t.Fatalf("attempt %d did not block, want blocked", auth.MaxFailedLogins)
	}

	var active bool
	var reason *string
	if err := e.pool.QueryRow(e.ctx, `SELECT is_active, block_reason FROM users WHERE id = $1`, userID).Scan(&active, &reason); err != nil {
		t.Fatalf("read user after block: %v", err)
	}
	if active {
		t.Error("is_active = true after lockout, want false")
	}
	if reason == nil || *reason != mailer.BlockReasonFailedAttempts {
		t.Errorf("block_reason = %v, want %q", reason, mailer.BlockReasonFailedAttempts)
	}
	blocks := e.mail.awaitBlocks(t, 1)
	if len(blocks) != 1 || blocks[0].Reason != mailer.BlockReasonFailedAttempts {
		t.Fatalf("blocked-account emails = %+v, want 1 with the failed-attempts reason", blocks)
	}

	raw := tokenFromLink(t, blocks[0].Link)
	if err := blockSvc.Unblock(e.ctx, raw); err != nil {
		t.Fatalf("Unblock: %v", err)
	}
	var attempts int
	if err := e.pool.QueryRow(e.ctx, `
		SELECT is_active, failed_login_attempts FROM users WHERE id = $1
	`, userID).Scan(&active, &attempts); err != nil {
		t.Fatalf("read user after unblock: %v", err)
	}
	if !active || attempts != 0 {
		t.Errorf("after unblock active=%v attempts=%d, want true / 0", active, attempts)
	}
	if err := blockSvc.Unblock(e.ctx, raw); !errors.Is(err, auth.ErrInvalidUnblockToken) {
		t.Errorf("second Unblock = %v, want ErrInvalidUnblockToken", err)
	}
}

// TestLockout_ResetClearsCounter proves a successful sign-in wipes accumulated
// failures, so ordinary typos never add up to a lockout.
func TestLockout_ResetClearsCounter(t *testing.T) {
	e := newFlowEnv(t)
	blockSvc := auth.NewAccountBlockService(e.pool, e.mail, "http://localhost:9090", testhelper.TestLogger()).
		WithTemplates(e.tmplSvc)

	userID := e.seedUser(t, uniqueEmail("lockout-reset"), "")
	for i := 0; i < auth.MaxFailedLogins-1; i++ {
		blockSvc.RecordFailedLogin(e.ctx, e.tenantID, userID)
	}
	blockSvc.ResetFailedLogins(e.ctx, e.tenantID, userID)

	// A single further failure must not block: the counter restarted at 1.
	if blocked := blockSvc.RecordFailedLogin(e.ctx, e.tenantID, userID); blocked {
		t.Error("blocked immediately after a successful sign-in reset the counter")
	}
	if got := e.mail.Blocks(); len(got) != 0 {
		t.Errorf("blocked-account emails = %d, want 0", len(got))
	}
}

// TestLockout_AttemptsAgeOutOfWindow proves failures older than
// FailedLoginWindow restart the counter, so occasional typos spread over days
// never accumulate into a lockout.
func TestLockout_AttemptsAgeOutOfWindow(t *testing.T) {
	e := newFlowEnv(t)
	blockSvc := auth.NewAccountBlockService(e.pool, e.mail, "http://localhost:9090", testhelper.TestLogger()).
		WithTemplates(e.tmplSvc)

	userID := e.seedUser(t, uniqueEmail("lockout-window"), "")
	for i := 0; i < auth.MaxFailedLogins-1; i++ {
		blockSvc.RecordFailedLogin(e.ctx, e.tenantID, userID)
	}

	// Age the last failure well past the window.
	if _, err := e.pool.Exec(e.ctx, `
		UPDATE users SET last_failed_login_at = NOW() - INTERVAL '1 day' WHERE id = $1
	`, userID); err != nil {
		t.Fatalf("backdate last failure: %v", err)
	}

	if blocked := blockSvc.RecordFailedLogin(e.ctx, e.tenantID, userID); blocked {
		t.Error("blocked on a failure that follows only aged-out attempts")
	}
	var attempts int
	if err := e.pool.QueryRow(e.ctx, `SELECT failed_login_attempts FROM users WHERE id = $1`, userID).Scan(&attempts); err != nil {
		t.Fatalf("read attempts: %v", err)
	}
	if attempts != 1 {
		t.Errorf("failed_login_attempts = %d after the window lapsed, want the counter restarted at 1", attempts)
	}
	if got := e.mail.Blocks(); len(got) != 0 {
		t.Errorf("blocked-account emails = %d, want 0", len(got))
	}
}

// TestUnblock_RejectsAdminBlockedAccount proves an admin block cannot be lifted
// with a self-service link, even one minted earlier by an automatic lockout.
func TestUnblock_RejectsAdminBlockedAccount(t *testing.T) {
	e := newFlowEnv(t)
	blockSvc := auth.NewAccountBlockService(e.pool, e.mail, "http://localhost:9090", testhelper.TestLogger()).
		WithTemplates(e.tmplSvc)

	email := uniqueEmail("lockout-admin")
	userID := e.seedUser(t, email, "")
	for i := 0; i < auth.MaxFailedLogins; i++ {
		blockSvc.RecordFailedLogin(e.ctx, e.tenantID, userID)
	}
	raw := tokenFromLink(t, e.mail.awaitBlocks(t, 1)[0].Link)

	// An admin now blocks the same account, overriding the automatic reason.
	blockSvc.NotifyAdminBlock(e.ctx, e.tenantID, nil, userID, email)

	if err := blockSvc.Unblock(e.ctx, raw); !errors.Is(err, auth.ErrInvalidUnblockToken) {
		t.Errorf("Unblock on an admin-blocked account = %v, want ErrInvalidUnblockToken", err)
	}
	var active bool
	if err := e.pool.QueryRow(e.ctx, `SELECT is_active FROM users WHERE id = $1`, userID).Scan(&active); err != nil {
		t.Fatalf("read user: %v", err)
	}
	if active {
		t.Error("is_active = true, want the admin block to stand")
	}
	blocks := e.mail.awaitBlocks(t, 2)
	if len(blocks) != 2 || blocks[1].Reason != mailer.BlockReasonAdmin {
		t.Errorf("second email = %+v, want the admin-block variant", blocks)
	}
}

// ---------------------------------------------------------------------------
// Breached passwords
// ---------------------------------------------------------------------------

// hibpStub serves a Pwned Passwords range response containing the suffix of the
// given password's SHA-1 hash, so a test can force a hit without network access.
func hibpStub(t *testing.T, suffix string, count int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Include decoys so the test also covers picking the right line.
		_, _ = w.Write([]byte("0000000000000000000000000000000000A:3\r\n" +
			suffix + ":" + itoa(count) + "\r\n" +
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFB:9\r\n"))
	}))
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// TestBreach_WarnsOnceForBreachedPassword proves a hit warns the user exactly
// once per password, and that a clean password warns nobody.
func TestBreach_WarnsOnceForBreachedPassword(t *testing.T) {
	e := newFlowEnv(t)
	const password = "Password123!"
	suffix := breach.HashSuffixForTest(password)

	srv := hibpStub(t, suffix, 4242)
	defer srv.Close()

	checker := breach.NewForTest(srv.URL+"/", testhelper.TestLogger())
	brchSvc := auth.NewBreachService(e.pool, checker, e.mail, "http://localhost:9090", testhelper.TestLogger()).
		WithTemplates(e.tmplSvc)

	email := uniqueEmail("breach")
	userID := e.seedUser(t, email, "")

	if err := brchSvc.CheckNow(e.ctx, e.tenantID, nil, userID, email, password); err != nil {
		t.Fatalf("CheckNow: %v", err)
	}
	if len(e.mail.breaches) != 1 || e.mail.breaches[0].To != email {
		t.Fatalf("breach warnings = %+v, want 1 to %s", e.mail.breaches, email)
	}

	// Same password again: already warned, so no second email.
	if err := brchSvc.CheckNow(e.ctx, e.tenantID, nil, userID, email, password); err != nil {
		t.Fatalf("second CheckNow: %v", err)
	}
	if len(e.mail.breaches) != 1 {
		t.Errorf("breach warnings = %d after a repeat sign-in, want 1", len(e.mail.breaches))
	}

	// After a password change the marker is cleared and a new hit warns again.
	brchSvc.ClearNotified(e.ctx, e.tenantID, userID)
	if err := brchSvc.CheckNow(e.ctx, e.tenantID, nil, userID, email, password); err != nil {
		t.Fatalf("CheckNow after clear: %v", err)
	}
	if len(e.mail.breaches) != 2 {
		t.Errorf("breach warnings = %d after clearing the marker, want 2", len(e.mail.breaches))
	}
}

// TestBreach_CleanPasswordSendsNothing proves a miss is silent.
func TestBreach_CleanPasswordSendsNothing(t *testing.T) {
	e := newFlowEnv(t)
	// The stub only knows one unrelated suffix, so any password is a miss.
	srv := hibpStub(t, "0123456789012345678901234567890ABCD", 1)
	defer srv.Close()

	brchSvc := auth.NewBreachService(e.pool, breach.NewForTest(srv.URL+"/", testhelper.TestLogger()),
		e.mail, "http://localhost:9090", testhelper.TestLogger()).WithTemplates(e.tmplSvc)

	email := uniqueEmail("breach-clean")
	userID := e.seedUser(t, email, "")
	if err := brchSvc.CheckNow(e.ctx, e.tenantID, nil, userID, email, "AnUncommonPassphrase!42"); err != nil {
		t.Fatalf("CheckNow: %v", err)
	}
	if len(e.mail.breaches) != 0 {
		t.Errorf("breach warnings = %d for a clean password, want 0", len(e.mail.breaches))
	}
}

// TestBreach_DisabledIsNoop proves the feature stays off without the env flag.
func TestBreach_DisabledIsNoop(t *testing.T) {
	e := newFlowEnv(t)
	brchSvc := auth.NewBreachService(e.pool, breach.New(false, testhelper.TestLogger()),
		e.mail, "http://localhost:9090", testhelper.TestLogger()).WithTemplates(e.tmplSvc)

	if brchSvc.Enabled() {
		t.Error("Enabled() = true with a disabled checker")
	}
	email := uniqueEmail("breach-off")
	userID := e.seedUser(t, email, "")
	if err := brchSvc.CheckNow(e.ctx, e.tenantID, nil, userID, email, "Password123!"); err != nil {
		t.Fatalf("CheckNow: %v", err)
	}
	if len(e.mail.breaches) != 0 {
		t.Errorf("breach warnings = %d with detection disabled, want 0", len(e.mail.breaches))
	}
}

// TestInvitationPreview_NamesTenantRoleAndExistingReach covers the context the
// acceptance page needs to be honest about what it is asking.
//
// Without it a cross-tenant invitation is indistinguishable from a first-time one:
// the page tells someone who has used the account for months to "set a password",
// which reads as an error, or worse as a phishing attempt. Naming the tenant, the
// tier, and what they already administer is what makes the request legible.
func TestInvitationPreview_NamesTenantRoleAndExistingReach(t *testing.T) {
	e := newFlowEnv(t)
	invSvc := auth.NewInvitationService(e.pool, e.mail, testDashboardURL, testhelper.TestLogger()).
		WithTemplates(e.tmplSvc)

	// One identity that ALREADY administers the seed tenant, activated.
	email := uniqueEmail("preview-reach")
	userID := e.seedUser(t, email, "$2a$10$abcdefghijklmnopqrstuvwxyz012345678901234567890123456")
	if _, err := e.pool.Exec(e.ctx, `
		INSERT INTO tenant_admins (tenant_id, user_id, admin_role, activated_at)
		VALUES ($1, $2, 'owner', NOW())
	`, e.tenantID, userID); err != nil {
		t.Fatalf("seed activated administration: %v", err)
	}

	// A second tenant, with a PENDING co-owner grant for the same identity — the
	// cross-tenant case that migration 00072 made representable.
	var secondTenantID int64
	if err := e.pool.QueryRow(e.ctx, `
		INSERT INTO tenants (name, slug, jwt_secret, is_active)
		VALUES ('Bolt Industries', $1, 'secret-for-bolt-tenant-preview', true)
		RETURNING id
	`, fmt.Sprintf("bolt-preview-%d", time.Now().UnixNano())).Scan(&secondTenantID); err != nil {
		t.Fatalf("seed second tenant: %v", err)
	}
	if _, err := e.pool.Exec(e.ctx, `
		INSERT INTO tenant_admins (tenant_id, user_id, admin_role) VALUES ($1, $2, 'co_owner')
	`, secondTenantID, userID); err != nil {
		t.Fatalf("seed pending cross-tenant grant: %v", err)
	}

	if err := invSvc.Invite(e.ctx, secondTenantID, nil, userID, email, "", nil); err != nil {
		t.Fatalf("Invite: %v", err)
	}
	raw := tokenFromLink(t, e.mail.invitations[0].Link)

	preview, err := invSvc.Preview(e.ctx, raw)
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}

	// The tenant being offered, so the recipient knows which one they are joining.
	if preview.TenantName != "Bolt Industries" {
		t.Errorf("tenant_name = %q, want %q", preview.TenantName, "Bolt Industries")
	}
	// The tier, because owner and co_owner confer very different reach.
	if preview.AdminRole != auth.AdminRoleCoOwner {
		t.Errorf("admin_role = %q, want %q", preview.AdminRole, auth.AdminRoleCoOwner)
	}
	// The account already has a password, so the page must ask them to confirm it
	// rather than offering to set one.
	if preview.RequiresPassword {
		t.Error("requires_password = true for an account that already has credentials")
	}
	// And it must name what they already administer, so "you already have an
	// account" is a statement the page can actually back up.
	if len(preview.ExistingTenants) != 1 {
		t.Fatalf("existing_tenants = %v, want exactly the seed tenant", preview.ExistingTenants)
	}
	// The tenant being INVITED to must not appear in the existing list: it would
	// tell the recipient they already hold access they are being asked to accept.
	for _, name := range preview.ExistingTenants {
		if name == "Bolt Industries" {
			t.Errorf("existing_tenants %v contains the invitation's own tenant", preview.ExistingTenants)
		}
	}
}

// TestInvitationPreview_NewAccountReportsNoExistingReach: the onboarding case must
// stay distinguishable, since it is what selects the "set your password" wording.
func TestInvitationPreview_NewAccountReportsNoExistingReach(t *testing.T) {
	e := newFlowEnv(t)
	invSvc := auth.NewInvitationService(e.pool, e.mail, testDashboardURL, testhelper.TestLogger()).
		WithTemplates(e.tmplSvc)

	email := uniqueEmail("preview-fresh")
	userID := e.seedUser(t, email, "") // no credentials
	if _, err := e.pool.Exec(e.ctx, `
		INSERT INTO tenant_admins (tenant_id, user_id, admin_role) VALUES ($1, $2, 'owner')
	`, e.tenantID, userID); err != nil {
		t.Fatalf("seed pending grant: %v", err)
	}
	if err := invSvc.Invite(e.ctx, e.tenantID, nil, userID, email, "", nil); err != nil {
		t.Fatalf("Invite: %v", err)
	}

	preview, err := invSvc.Preview(e.ctx, tokenFromLink(t, e.mail.invitations[0].Link))
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	if !preview.RequiresPassword {
		t.Error("requires_password = false for an account with no credentials")
	}
	if len(preview.ExistingTenants) != 0 {
		t.Errorf("existing_tenants = %v, want empty for a brand-new administrator", preview.ExistingTenants)
	}
	if preview.AdminRole != auth.AdminRoleOwner {
		t.Errorf("admin_role = %q, want %q", preview.AdminRole, auth.AdminRoleOwner)
	}
}

// TestInvitation_CrossTenantAcceptVerifiesEmail pins the fix for a silent
// verification failure.
//
// Accept updated the recipient with "WHERE id = $1 AND tenant_id = $2", where $2
// is the tenant the invitation grants administration of. But users.tenant_id is
// the account's HOME tenant — where its credentials live — and migration 00071
// established the two as separate axes. For a cross-tenant invitation they
// differ, so the predicate matched zero rows: the link was consumed, the grant
// activated, and email_verified stayed false.
//
// countUsableAdmins requires email_verified, so such an owner never counted as
// usable. A tenant with two accepted owners reported one, and removing either was
// refused with last_owner ("appoint another owner first") when another owner had
// in fact accepted — leaving the tenant stuck.
func TestInvitation_CrossTenantAcceptVerifiesEmail(t *testing.T) {
	e := newFlowEnv(t)
	invSvc := auth.NewInvitationService(e.pool, e.mail, testDashboardURL, testhelper.TestLogger()).
		WithTemplates(e.tmplSvc)

	// A second tenant, so the invitation crosses a tenant boundary.
	var otherTenantID int64
	if err := e.pool.QueryRow(e.ctx, `
		INSERT INTO tenants (name, slug, jwt_secret, is_active)
		VALUES ($1, $1, 'xtenant-verify-secret', true)
		RETURNING id
	`, "xtenant-verify-"+strconv.FormatInt(time.Now().UnixNano(), 10)).Scan(&otherTenantID); err != nil {
		t.Fatalf("create second tenant: %v", err)
	}

	// The account's HOME tenant is e.tenantID; the invitation is for otherTenantID.
	email := uniqueEmail("xtenant-verify")
	userID := e.seedUser(t, email, "")
	if _, err := e.pool.Exec(e.ctx,
		`UPDATE users SET email_verified = false WHERE id = $1`, userID); err != nil {
		t.Fatalf("reset email_verified: %v", err)
	}

	if err := invSvc.Invite(e.ctx, otherTenantID, nil, userID, email, "", nil); err != nil {
		t.Fatalf("Invite: %v", err)
	}
	link := e.mail.invitations[len(e.mail.invitations)-1].Link
	token := link[strings.Index(link, "token=")+len("token="):]

	if _, err := invSvc.Accept(e.ctx, token, auth.AcceptOptions{NewPassword: "NewPassw0rd!"}); err != nil {
		t.Fatalf("Accept: %v", err)
	}

	// The whole point: verification is a property of the ACCOUNT, so accepting an
	// invitation for a tenant that is not the account's home tenant must still
	// verify it.
	var verified bool
	var homeTenant int64
	if err := e.pool.QueryRow(e.ctx,
		`SELECT email_verified, tenant_id FROM users WHERE id = $1`, userID,
	).Scan(&verified, &homeTenant); err != nil {
		t.Fatalf("load user: %v", err)
	}
	if !verified {
		t.Errorf("email_verified = false after accepting a cross-tenant invitation, want true")
	}
	if homeTenant == otherTenantID {
		t.Fatalf("home tenant = %d, which equals the invited tenant — the test no longer crosses a boundary",
			homeTenant)
	}
}
