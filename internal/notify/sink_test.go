package notify

import (
	"context"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/engineersmind/emc-auth-server/internal/audit"
	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/mailer"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// captureMailer records admin-activity mail instead of sending it. Only the one
// method is exercised here; the rest satisfy the interface.
type captureMailer struct {
	mu     sync.Mutex
	sent   []mailer.AdminActivityEmail
	access []mailer.AccessChangedEmail
}

func (m *captureMailer) SendAccessChanged(_ context.Context, _ *mailer.SMTPConfig, _ *mailer.Template, e mailer.AccessChangedEmail) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.access = append(m.access, e)
	return nil
}

func (m *captureMailer) accessNotices() []mailer.AccessChangedEmail {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]mailer.AccessChangedEmail(nil), m.access...)
}

func (m *captureMailer) SendAdminActivity(_ context.Context, _ *mailer.SMTPConfig, _ *mailer.Template, e mailer.AdminActivityEmail) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, e)
	return nil
}

func (m *captureMailer) messages() []mailer.AdminActivityEmail {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]mailer.AdminActivityEmail(nil), m.sent...)
}

func (m *captureMailer) SendReset(context.Context, *mailer.SMTPConfig, *mailer.Template, mailer.ResetEmail) error {
	return nil
}
func (m *captureMailer) SendMFACode(context.Context, *mailer.SMTPConfig, *mailer.Template, mailer.MFACodeEmail) error {
	return nil
}
func (m *captureMailer) SendMagicLink(context.Context, *mailer.SMTPConfig, *mailer.Template, mailer.MagicLinkEmail) error {
	return nil
}
func (m *captureMailer) SendVerification(context.Context, *mailer.SMTPConfig, *mailer.Template, mailer.VerificationEmail) error {
	return nil
}
func (m *captureMailer) SendWelcome(context.Context, *mailer.SMTPConfig, *mailer.Template, mailer.WelcomeEmail) error {
	return nil
}
func (m *captureMailer) SendPasswordChanged(context.Context, *mailer.SMTPConfig, *mailer.Template, mailer.PasswordChangedEmail) error {
	return nil
}
func (m *captureMailer) SendInvitation(context.Context, *mailer.SMTPConfig, *mailer.Template, mailer.InvitationEmail) error {
	return nil
}
func (m *captureMailer) SendChangeEmail(context.Context, *mailer.SMTPConfig, *mailer.Template, mailer.ChangeEmailEmail) error {
	return nil
}
func (m *captureMailer) SendBlockedAccount(context.Context, *mailer.SMTPConfig, *mailer.Template, mailer.BlockedAccountEmail) error {
	return nil
}
func (m *captureMailer) SendPasswordBreach(context.Context, *mailer.SMTPConfig, *mailer.Template, mailer.PasswordBreachEmail) error {
	return nil
}
func (m *captureMailer) SendTenantLockoutAlert(context.Context, *mailer.SMTPConfig, *mailer.Template, mailer.TenantLockoutAlertEmail) error {
	return nil
}
func (m *captureMailer) SendTest(context.Context, *mailer.SMTPConfig, *mailer.Template, mailer.TemplateType, string) error {
	return nil
}
func (m *captureMailer) GlobalProvider() string { return "dev" }

// liveSink wires the fixture to a real worker with a short collapse window, so
// tests exercise Emit → worker → mailer rather than calling deliver directly.
func (f notifyFixture) liveSink(t *testing.T, m mailer.Mailer) *EmailSink {
	t.Helper()
	s := &EmailSink{
		pool:           f.pool,
		notifier:       auth.NewEmailNotifier(m, testhelper.TestLogger()),
		mailer:         m,
		consoleBaseURL: "https://console.test",
		platformEmails: []string{f.platform},
		logger:         testhelper.TestLogger(),
		collapseWindow: 40 * time.Millisecond,
		flushTick:      10 * time.Millisecond,
		ch:             make(chan []audit.Event, queueSize),
		done:           make(chan struct{}),
		closed:         make(chan struct{}),
	}
	go s.run()
	t.Cleanup(s.Close)
	return s
}

func event(tenantID int64, actor, action, resourceType, resourceID string) audit.Event {
	return audit.Event{
		TenantID:     &tenantID,
		ActorEmail:   actor,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		IPAddress:    "203.0.113.9",
	}
}

// The worked example end to end: an owner rotates a secret, and the platform
// tier is told which tenant and which application.
func TestEmit_OwnerSecretRotationReachesPlatform(t *testing.T) {
	f := newNotifyFixture(t)
	m := &captureMailer{}
	s := f.liveSink(t, m)

	s.Emit([]audit.Event{
		event(f.tenantID, f.owner, audit.ActionAdminApplicationSecretRotated, "application", itoa(f.appID)),
	})
	s.Close()

	msgs := m.messages()
	// Two: the platform tier, plus the actor — secret rotation is sensitive.
	if len(msgs) != 2 {
		t.Fatalf("sent %d messages, want 2 (platform + actor)", len(msgs))
	}
	got := map[string]mailer.AdminActivityEmail{}
	for _, msg := range msgs {
		got[msg.To] = msg
	}
	platform, ok := got[f.platform]
	if !ok {
		t.Fatalf("platform address was not notified; recipients were %v", keysOf(got))
	}
	if _, ok := got[f.owner]; !ok {
		t.Errorf("actor did not get their own copy of a sensitive action")
	}
	if platform.TenantName != "Notify Co" {
		t.Errorf("TenantName = %q, want the tenant display name", platform.TenantName)
	}
	if platform.ResourceName != "Web Dashboard" {
		t.Errorf("ResourceName = %q, want the application name", platform.ResourceName)
	}
	if platform.ActorRole != "owner" {
		t.Errorf("ActorRole = %q, want owner", platform.ActorRole)
	}
	if platform.ActionLabel != "rotated a client secret" {
		t.Errorf("ActionLabel = %q", platform.ActionLabel)
	}
}

// Four rapid identical actions are one decision. Sending four emails would mean
// three of them describe a state that no longer exists.
func TestEmit_CollapsesRepeatedActions(t *testing.T) {
	f := newNotifyFixture(t)
	m := &captureMailer{}
	s := f.liveSink(t, m)

	for i := 0; i < 4; i++ {
		s.Emit([]audit.Event{
			event(f.tenantID, f.coOwner, audit.ActionAdminApplicationDeleted, "application", itoa(f.appID)),
		})
	}
	s.Close()

	msgs := m.messages()
	if len(msgs) != 1 {
		t.Fatalf("sent %d messages, want 1 collapsed message", len(msgs))
	}
	if msgs[0].Count != 4 {
		t.Errorf("Count = %d, want 4 — a collapsed message must say how many", msgs[0].Count)
	}
	if msgs[0].To != f.owner {
		t.Errorf("recipient = %s, want the owner", msgs[0].To)
	}
}

// Different resources are different decisions, even from the same actor doing
// the same thing — rotating two applications' secrets warrants two emails.
func TestEmit_DoesNotCollapseAcrossResources(t *testing.T) {
	f := newNotifyFixture(t)
	m := &captureMailer{}
	s := f.liveSink(t, m)

	s.Emit([]audit.Event{
		event(f.tenantID, f.coOwner, audit.ActionAdminApplicationDeleted, "application", "101"),
		event(f.tenantID, f.coOwner, audit.ActionAdminApplicationDeleted, "application", "102"),
	})
	s.Close()

	if got := len(m.messages()); got != 2 {
		t.Errorf("sent %d messages, want 2 — separate resources are separate decisions", got)
	}
}

// Uncatalogued and failed events must not produce mail. Logins in particular
// flow through this sink constantly.
func TestEmit_IgnoresUninterestingEvents(t *testing.T) {
	f := newNotifyFixture(t)
	m := &captureMailer{}
	s := f.liveSink(t, m)

	failed := event(f.tenantID, f.coOwner, audit.ActionAdminApplicationDeleted, "application", itoa(f.appID))
	failed.Status = audit.StatusFailure

	s.Emit([]audit.Event{
		event(f.tenantID, f.coOwner, audit.ActionAuthLogin, "user", "1"),
		event(f.tenantID, f.coOwner, audit.ActionNotificationSent, "notification", "1"),
		failed,
	})
	s.Close()

	if got := m.messages(); len(got) != 0 {
		t.Errorf("sent %d messages, want none: %+v", len(got), got)
	}
}

// Emit runs on the audit writer's goroutine. If it ever blocks, the writer
// stalls and audit rows start dropping — losing a notification is much cheaper
// than losing the log entry it describes.
func TestEmit_DropsRatherThanBlockingWhenFull(t *testing.T) {
	f := newNotifyFixture(t)
	// No worker started, so nothing drains the channel.
	s := &EmailSink{
		pool:           f.pool,
		logger:         testhelper.TestLogger(),
		collapseWindow: time.Second,
		flushTick:      time.Second,
		ch:             make(chan []audit.Event, 1),
		done:           make(chan struct{}),
		closed:         make(chan struct{}),
	}

	ev := []audit.Event{event(f.tenantID, f.owner, audit.ActionAdminApplicationDeleted, "application", "1")}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 50; i++ { // far more than the buffer holds
			s.Emit(ev)
		}
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Emit blocked when the queue was full — this stalls the audit writer")
	}
}

// The gap this closes: an owner changes a co-owner's applications, the platform
// tier and the owner both hear about it, and the co-owner — the only person
// whose access actually changed — used to hear nothing. They would discover it
// by being refused something they could do yesterday.
func TestEmit_TellsTheSubjectTheirAccessChanged(t *testing.T) {
	f := newNotifyFixture(t)
	m := &captureMailer{}
	s := f.liveSink(t, m)

	// The tenant_admins row of the co-owner, which is what the handler logs as
	// the resource — the audit event carries the actor, never the subject.
	var adminID int64
	if err := f.pool.QueryRow(f.ctx,
		`SELECT ta.id FROM tenant_admins ta JOIN users u ON u.id = ta.user_id
		 WHERE ta.tenant_id = $1 AND u.email = $2`, f.tenantID, f.coOwner).Scan(&adminID); err != nil {
		t.Fatalf("find co-owner admin row: %v", err)
	}

	s.Emit([]audit.Event{
		event(f.tenantID, f.owner, audit.ActionAdminTenantAdminGrantsSet, "tenant_admin", itoa(adminID)),
	})
	s.Close()

	notices := m.accessNotices()
	if len(notices) != 1 {
		t.Fatalf("sent %d access notices, want 1 to the co-owner", len(notices))
	}
	if notices[0].To != f.coOwner {
		t.Errorf("notice went to %s, want the co-owner %s", notices[0].To, f.coOwner)
	}
	if notices[0].ActionLabel != "The applications you administer were changed" {
		t.Errorf("ActionLabel = %q, want second-person phrasing", notices[0].ActionLabel)
	}
	if notices[0].ActorEmail != f.owner {
		t.Errorf("ActorEmail = %q, want the acting owner", notices[0].ActorEmail)
	}

	// The tier-up copies still go out — this is in addition, not instead.
	if len(m.messages()) == 0 {
		t.Error("no admin-activity notification was sent alongside the access notice")
	}
}

// Somebody adjusting their own grants already knows. They still get the actor
// copy of the activity notice; a second "your access changed" would be noise.
func TestEmit_DoesNotTellTheSubjectAboutTheirOwnChange(t *testing.T) {
	f := newNotifyFixture(t)
	m := &captureMailer{}
	s := f.liveSink(t, m)

	var adminID int64
	if err := f.pool.QueryRow(f.ctx,
		`SELECT ta.id FROM tenant_admins ta JOIN users u ON u.id = ta.user_id
		 WHERE ta.tenant_id = $1 AND u.email = $2`, f.tenantID, f.owner).Scan(&adminID); err != nil {
		t.Fatalf("find owner admin row: %v", err)
	}

	s.Emit([]audit.Event{
		event(f.tenantID, f.owner, audit.ActionAdminTenantAdminGrantsSet, "tenant_admin", itoa(adminID)),
	})
	s.Close()

	if got := m.accessNotices(); len(got) != 0 {
		t.Errorf("sent %d access notices to the actor about their own change: %+v", len(got), got)
	}
}

// A refusal is the only trace a probe leaves — the handler never runs. It is
// therefore the one action reported on FAILURE rather than success.
func TestEmit_ReportsDeniedPrivilegedRequests(t *testing.T) {
	f := newNotifyFixture(t)
	m := &captureMailer{}
	s := f.liveSink(t, m)

	denied := event(f.tenantID, f.coOwner, audit.ActionAdminAccessDenied, "route", "GET /api/v1/tenants/:tid/admins")
	denied.Status = audit.StatusFailure

	s.Emit([]audit.Event{denied})
	s.Close()

	msgs := m.messages()
	if len(msgs) != 1 {
		t.Fatalf("sent %d messages, want 1 — a refusal must be reported", len(msgs))
	}
	if msgs[0].To != f.owner {
		t.Errorf("refusal reported to %s, want the owner", msgs[0].To)
	}
	if msgs[0].ActionLabel != "was refused access to a privileged route" {
		t.Errorf("ActionLabel = %q", msgs[0].ActionLabel)
	}
}

func itoa(v int64) string { return strconv.FormatInt(v, 10) }

func keysOf(m map[string]mailer.AdminActivityEmail) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// An invitation announces itself. A second "your access has changed" mail
// alongside it said nothing had changed yet was already true, and closed with
// "you will see the change the next time you sign in" — an instruction a
// brand-new invitee cannot follow, because they have no account until they
// accept. It also competed with the invitation, the one mail carrying the link
// they actually need.
func TestEmit_DoesNotTellAPendingInviteeTheirAccessChanged(t *testing.T) {
	f := newNotifyFixture(t)
	m := &captureMailer{}
	s := f.liveSink(t, m)

	// A tenant_admins row that has NOT been accepted, which is the state every
	// invitation starts in.
	var adminID int64
	if err := f.pool.QueryRow(f.ctx,
		`SELECT ta.id FROM tenant_admins ta JOIN users u ON u.id = ta.user_id
		 WHERE ta.tenant_id = $1 AND u.email = $2`, f.tenantID, f.coOwner).Scan(&adminID); err != nil {
		t.Fatalf("find co-owner admin row: %v", err)
	}
	if _, err := f.pool.Exec(f.ctx,
		`UPDATE tenant_admins SET activated_at = NULL WHERE id = $1`, adminID); err != nil {
		t.Fatalf("make the grant pending: %v", err)
	}

	s.Emit([]audit.Event{
		event(f.tenantID, f.owner, audit.ActionAdminTenantAdminInvited, "tenant_admin", itoa(adminID)),
	})
	s.Close()

	if got := m.accessNotices(); len(got) != 0 {
		t.Errorf("sent %d access notices to a pending invitee, want 0 — the invitation covers it", len(got))
	}
	// The tier-up copies still go out: the people who oversee the tenant do need
	// to know an invitation was issued.
	if len(m.messages()) == 0 {
		t.Error("no admin-activity notification was sent; the tier-up audience must still hear about it")
	}
}

// The inverse: once the grant is live, an invitation event that WIDENS it is a
// real change to something the recipient already holds, so it is announced.
func TestEmit_TellsAnActiveAdminWhenAnInvitationWidensTheirGrant(t *testing.T) {
	f := newNotifyFixture(t)
	m := &captureMailer{}
	s := f.liveSink(t, m)

	var adminID int64
	if err := f.pool.QueryRow(f.ctx,
		`SELECT ta.id FROM tenant_admins ta JOIN users u ON u.id = ta.user_id
		 WHERE ta.tenant_id = $1 AND u.email = $2`, f.tenantID, f.coOwner).Scan(&adminID); err != nil {
		t.Fatalf("find co-owner admin row: %v", err)
	}
	if _, err := f.pool.Exec(f.ctx,
		`UPDATE tenant_admins SET activated_at = NOW() WHERE id = $1`, adminID); err != nil {
		t.Fatalf("activate the grant: %v", err)
	}

	s.Emit([]audit.Event{
		event(f.tenantID, f.owner, audit.ActionAdminTenantAdminInvited, "tenant_admin", itoa(adminID)),
	})
	s.Close()

	notices := m.accessNotices()
	if len(notices) != 1 {
		t.Fatalf("sent %d access notices, want 1 to the already-active administrator", len(notices))
	}
	if notices[0].To != f.coOwner {
		t.Errorf("notice went to %s, want %s", notices[0].To, f.coOwner)
	}
}

// A withdrawal must reach a pending invitee too: it is the most consequential
// message this feature sends, and suppressing it would leave somebody believing
// an invitation is still open.
func TestEmit_TellsAPendingInviteeTheirAccessWasWithdrawn(t *testing.T) {
	f := newNotifyFixture(t)
	m := &captureMailer{}
	s := f.liveSink(t, m)

	var adminID int64
	if err := f.pool.QueryRow(f.ctx,
		`SELECT ta.id FROM tenant_admins ta JOIN users u ON u.id = ta.user_id
		 WHERE ta.tenant_id = $1 AND u.email = $2`, f.tenantID, f.coOwner).Scan(&adminID); err != nil {
		t.Fatalf("find co-owner admin row: %v", err)
	}
	if _, err := f.pool.Exec(f.ctx,
		`UPDATE tenant_admins SET activated_at = NULL WHERE id = $1`, adminID); err != nil {
		t.Fatalf("make the grant pending: %v", err)
	}

	s.Emit([]audit.Event{
		event(f.tenantID, f.owner, audit.ActionAdminTenantAdminRemoved, "tenant_admin", itoa(adminID)),
	})
	s.Close()

	notices := m.accessNotices()
	if len(notices) != 1 {
		t.Fatalf("sent %d access notices for a withdrawal, want 1 even though the grant was pending", len(notices))
	}
	if notices[0].ActionLabel != "Your administrator access was withdrawn" {
		t.Errorf("ActionLabel = %q, want the withdrawal phrasing", notices[0].ActionLabel)
	}
}
