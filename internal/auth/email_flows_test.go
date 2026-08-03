package auth_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
	if len(e.mail.blocks) != 0 {
		t.Fatalf("blocked-account emails = %d before the threshold, want 0", len(e.mail.blocks))
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
	if len(e.mail.blocks) != 1 || e.mail.blocks[0].Reason != mailer.BlockReasonFailedAttempts {
		t.Fatalf("blocked-account emails = %+v, want 1 with the failed-attempts reason", e.mail.blocks)
	}

	raw := tokenFromLink(t, e.mail.blocks[0].Link)
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
	if len(e.mail.blocks) != 0 {
		t.Errorf("blocked-account emails = %d, want 0", len(e.mail.blocks))
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
	if len(e.mail.blocks) != 0 {
		t.Errorf("blocked-account emails = %d, want 0", len(e.mail.blocks))
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
	raw := tokenFromLink(t, e.mail.blocks[0].Link)

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
	if len(e.mail.blocks) != 2 || e.mail.blocks[1].Reason != mailer.BlockReasonAdmin {
		t.Errorf("second email = %+v, want the admin-block variant", e.mail.blocks)
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
