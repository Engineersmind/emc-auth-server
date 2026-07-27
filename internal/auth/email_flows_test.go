package auth_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

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

// TestInvitation_FullFlow proves invite → emailed link → password set → verified,
// and that the token is single-use.
func TestInvitation_FullFlow(t *testing.T) {
	e := newFlowEnv(t)
	invSvc := auth.NewInvitationService(e.pool, e.mail, "http://localhost:9090", testhelper.TestLogger()).
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
	target, err := invSvc.Accept(e.ctx, raw, "ChosenPassword123!")
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
	if _, err := invSvc.Accept(e.ctx, raw, "AnotherPassword123!"); !errors.Is(err, auth.ErrInvalidInvitation) {
		t.Errorf("second Accept = %v, want ErrInvalidInvitation", err)
	}
}

// TestInvitation_ResendSupersedesPrevious proves a re-invite kills the old link,
// so a leaked earlier email cannot still claim the account.
func TestInvitation_ResendSupersedesPrevious(t *testing.T) {
	e := newFlowEnv(t)
	invSvc := auth.NewInvitationService(e.pool, e.mail, "http://localhost:9090", testhelper.TestLogger()).
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
	if _, err := invSvc.Accept(e.ctx, first, "Password123!"); !errors.Is(err, auth.ErrInvalidInvitation) {
		t.Errorf("superseded invitation = %v, want ErrInvalidInvitation", err)
	}
	if _, err := invSvc.Accept(e.ctx, second, "Password123!"); err != nil {
		t.Errorf("latest invitation Accept = %v, want success", err)
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
	invSvc := auth.NewInvitationService(e.pool, e.mail, "http://localhost:9090", testhelper.TestLogger()).
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
	if got != newEmail {
		t.Errorf("Confirm returned %s, want %s", got, newEmail)
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
	brchSvc.ClearNotified(e.ctx, userID)
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
