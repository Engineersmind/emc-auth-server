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

// captureMailer records admin-activity and access-change mail instead of
// sending it; the rest satisfy the interface.
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

func (m *captureMailer) accessChanges() []mailer.AccessChangedEmail {
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

func byRecipient(msgs []mailer.AdminActivityEmail) map[string]mailer.AdminActivityEmail {
	out := map[string]mailer.AdminActivityEmail{}
	for _, msg := range msgs {
		out[msg.To] = msg
	}
	return out
}

func recipients(msgs []mailer.AdminActivityEmail) []string {
	out := make([]string, 0, len(msgs))
	for _, msg := range msgs {
		out = append(out, msg.To)
	}
	return out
}

// The worked example end to end: a secret is rotated, and every administrator
// of that application — the owner and its co-owner — is told which tenant and
// which application. A co-owner of a different application is not.
func TestEmit_SecretRotationReachesTheApplicationsAdministrators(t *testing.T) {
	f := newNotifyFixture(t)
	m := &captureMailer{}
	s := f.liveSink(t, m)

	s.Emit([]audit.Event{
		event(f.tenantID, f.owner, audit.ActionAdminApplicationSecretRotated, "application", itoa(f.appID)),
	})
	s.Close()

	msgs := m.messages()
	if want := []string{f.owner, f.coOwner}; !equal(recipients(msgs), want) {
		t.Fatalf("recipients = %v, want %v", sorted(recipients(msgs)), sorted(want))
	}
	msg := byRecipient(msgs)[f.coOwner]
	if msg.TenantName != "Notify Co" {
		t.Errorf("TenantName = %q, want the tenant display name", msg.TenantName)
	}
	if msg.ResourceName != "Web Dashboard" {
		t.Errorf("ResourceName = %q, want the application name", msg.ResourceName)
	}
	if msg.ActorRole != "owner" {
		t.Errorf("ActorRole = %q, want owner", msg.ActorRole)
	}
	if msg.ActionLabel != "rotated a client secret" {
		t.Errorf("ActionLabel = %q", msg.ActionLabel)
	}
}

// A deactivated tenant reaches its owners only — co-owners were never in this
// audience. (The platform oversight tier resolves empty here: no super_admin
// is seeded and no PLATFORM_NOTIFY_EMAIL is configured on the fixture.)
func TestEmit_TenantDeactivationReachesOwnersOnly(t *testing.T) {
	f := newNotifyFixture(t)
	m := &captureMailer{}
	s := f.liveSink(t, m)

	s.Emit([]audit.Event{
		event(f.tenantID, "superadmin@platform.test", audit.ActionAdminTenantDeactivated, "tenant", itoa(f.tenantID)),
	})
	s.Close()

	msgs := m.messages()
	if want := []string{f.owner}; !equal(recipients(msgs), want) {
		t.Fatalf("recipients = %v, want owners only %v", sorted(recipients(msgs)), sorted(want))
	}
	msg := byRecipient(msgs)[f.owner]
	if msg.ActionLabel != "deactivated the tenant" {
		t.Errorf("ActionLabel = %q", msg.ActionLabel)
	}
	if msg.ActorRole != "platform administrator" {
		t.Errorf("ActorRole = %q, want platform administrator", msg.ActorRole)
	}
	if msg.ResourceName != "" {
		t.Errorf("ResourceName = %q, want none for a tenant-level action", msg.ResourceName)
	}
}

// An access change mails the person it was made TO — through the subject
// channel, not the observer audience. The administrators get no copy.
func TestEmit_AccessChangeMailsTheSubject(t *testing.T) {
	f := newNotifyFixture(t)
	m := &captureMailer{}
	s := f.liveSink(t, m)

	var adminID int64
	if err := f.pool.QueryRow(f.ctx,
		`SELECT ta.id FROM tenant_admins ta JOIN users u ON u.id = ta.user_id WHERE u.email = $1`,
		f.coOwner).Scan(&adminID); err != nil {
		t.Fatalf("find co-owner admin row: %v", err)
	}

	s.Emit([]audit.Event{
		event(f.tenantID, f.owner, audit.ActionAdminTenantAdminGrantsSet, "tenant_admin", itoa(adminID)),
	})
	s.Close()

	if got := m.messages(); len(got) != 0 {
		t.Errorf("sent %d observer messages for an access change, want none: %+v", len(got), got)
	}
	changes := m.accessChanges()
	if len(changes) != 1 || changes[0].To != f.coOwner {
		t.Fatalf("access-change mail = %+v, want exactly one to %s", changes, f.coOwner)
	}
	if changes[0].ActionLabel != "The applications you administer were changed" {
		t.Errorf("ActionLabel = %q", changes[0].ActionLabel)
	}
}

// The actions withdrawn from the catalogue send nothing. Access-change actions
// are not withdrawn — they live on the subject channel — but a resource id
// that resolves to no administrator leaves nobody to tell, so they still send
// nothing here.
func TestEmit_WithdrawnActionsSendNothing(t *testing.T) {
	f := newNotifyFixture(t)
	m := &captureMailer{}
	s := f.liveSink(t, m)

	var events []audit.Event
	for _, action := range []string{
		audit.ActionAdminApplicationCreated,
		audit.ActionAdminApplicationDeleted,
		audit.ActionAdminMFAPolicyUpdated,
		audit.ActionAdminRolePermissionsUpdated,
		audit.ActionAdminRoleDeleted,
		audit.ActionAdminPermissionCreated,
		audit.ActionAdminPermissionUpdated,
		audit.ActionAdminPermissionDeleted,
	} {
		events = append(events, event(f.tenantID, f.coOwner, action, "application", itoa(f.appID)))
	}
	// tenant_admin id 1 belongs to a different fixture entirely (or nobody), so
	// accessChangeSubject resolves nothing and no subject mail goes out either.
	for _, action := range []string{
		audit.ActionAdminTenantAdminInvited,
		audit.ActionAdminTenantAdminGrantsSet,
		audit.ActionAdminTenantAdminRemoved,
	} {
		events = append(events, event(f.tenantID, f.owner, action, "tenant_admin", "1"))
	}
	s.Emit(events)
	s.Close()

	if got := m.messages(); len(got) != 0 {
		t.Errorf("sent %d messages for withdrawn actions, want none: %+v", len(got), got)
	}
	if got := m.accessChanges(); len(got) != 0 {
		t.Errorf("sent %d access-change messages to an unresolvable subject, want none: %+v", len(got), got)
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
			event(f.tenantID, f.coOwner, audit.ActionAdminApplicationSecretRotated, "application", itoa(f.appID)),
		})
	}
	s.Close()

	msgs := m.messages()
	if want := []string{f.owner, f.coOwner}; !equal(recipients(msgs), want) {
		t.Fatalf("recipients = %v, want one collapsed message each to %v", sorted(recipients(msgs)), sorted(want))
	}
	for _, msg := range msgs {
		if msg.Count != 4 {
			t.Errorf("Count to %s = %d, want 4 — a collapsed message must say how many", msg.To, msg.Count)
		}
	}
}

// Different resources are different decisions, even from the same actor doing
// the same thing — rotating two applications' secrets warrants two emails.
func TestEmit_DoesNotCollapseAcrossResources(t *testing.T) {
	f := newNotifyFixture(t)
	m := &captureMailer{}
	s := f.liveSink(t, m)

	s.Emit([]audit.Event{
		event(f.tenantID, f.owner, audit.ActionAdminApplicationSecretRotated, "application", itoa(f.appID)),
		event(f.tenantID, f.owner, audit.ActionAdminApplicationSecretRotated, "application", itoa(f.otherAppID)),
	})
	s.Close()

	var toOwner int
	for _, msg := range m.messages() {
		if msg.To == f.owner {
			toOwner++
		}
	}
	if toOwner != 2 {
		t.Errorf("owner received %d messages, want 2 — separate resources are separate decisions", toOwner)
	}
}

// Uncatalogued and failed events must not produce mail. Logins in particular
// flow through this sink constantly.
func TestEmit_IgnoresUninterestingEvents(t *testing.T) {
	f := newNotifyFixture(t)
	m := &captureMailer{}
	s := f.liveSink(t, m)

	failed := event(f.tenantID, f.coOwner, audit.ActionAdminApplicationSecretRotated, "application", itoa(f.appID))
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

	ev := []audit.Event{event(f.tenantID, f.owner, audit.ActionAdminApplicationSecretRotated, "application", "1")}
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

// Failures are not mailed at all, refusals included. A refused privileged
// request is still audited, but failure volume is chosen by whoever is probing,
// not by how much work an operator did.
func TestEmit_DoesNotMailDeniedPrivilegedRequests(t *testing.T) {
	f := newNotifyFixture(t)
	m := &captureMailer{}
	s := f.liveSink(t, m)

	denied := event(f.tenantID, f.coOwner, audit.ActionAdminAccessDenied, "route", "GET /api/v1/tenants/:tid/admins")
	denied.Status = audit.StatusFailure

	s.Emit([]audit.Event{denied})
	s.Close()

	if msgs := m.messages(); len(msgs) != 0 {
		t.Errorf("sent %d messages for a refusal, want 0 — failures are audited, not mailed: %+v", len(msgs), msgs)
	}
}

// A failed deactivation is not news either: nothing changed.
func TestEmit_DoesNotMailFailedNotableActions(t *testing.T) {
	f := newNotifyFixture(t)
	m := &captureMailer{}
	s := f.liveSink(t, m)

	failed := event(f.tenantID, f.owner, audit.ActionAdminTenantDeactivated, "tenant", itoa(f.tenantID))
	failed.Status = audit.StatusFailure

	s.Emit([]audit.Event{failed})
	s.Close()

	if msgs := m.messages(); len(msgs) != 0 {
		t.Errorf("sent %d messages for a failed deactivation, want 0: %+v", len(msgs), msgs)
	}
}

func itoa(v int64) string { return strconv.FormatInt(v, 10) }
