package notify

import (
	"context"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/engineersmind/emc-auth-server/internal/audit"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// notifyFixture is a tenant with an owner, a co-owner and a platform admin,
// which is the smallest world in which "one tier up" means anything.
type notifyFixture struct {
	pool     *pgxpool.Pool
	sink     *EmailSink
	tenantID int64
	owner    string
	coOwner  string
	platform string
	appID    int64
	ctx      context.Context
}

func newNotifyFixture(t *testing.T) notifyFixture {
	t.Helper()
	pool := testhelper.NewTestDB(t)
	ctx := context.Background()
	stamp := time.Now().UnixNano()

	var tenantID int64
	slug := fmt.Sprintf("notify-%d", stamp)
	if err := pool.QueryRow(ctx,
		`INSERT INTO tenants (name, slug, jwt_secret, display_name) VALUES ($1, $1, 'secret', 'Notify Co') RETURNING id`,
		slug).Scan(&tenantID); err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	var appID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO oauth_clients (tenant_id, client_id, client_secret_hash, name, redirect_uris)
		 VALUES ($1, $2, 'x', 'Web Dashboard', ARRAY['https://x.test/cb']) RETURNING id`,
		tenantID, "client-"+slug).Scan(&appID); err != nil {
		t.Fatalf("create application: %v", err)
	}

	// The owner/co_owner roles a real tenant gets from CreateTenant.
	roleID := map[string]int64{}
	for _, name := range []string{"owner", "co_owner"} {
		var id int64
		if err := pool.QueryRow(ctx,
			`INSERT INTO roles (tenant_id, name, is_system, created_at) VALUES ($1, $2, true, NOW()) RETURNING id`,
			tenantID, name).Scan(&id); err != nil {
			t.Fatalf("create %s role: %v", name, err)
		}
		roleID[name] = id
	}

	f := notifyFixture{
		pool:     pool,
		tenantID: tenantID,
		appID:    appID,
		owner:    fmt.Sprintf("owner-%d@notify.test", stamp),
		coOwner:  fmt.Sprintf("co-%d@notify.test", stamp),
		platform: fmt.Sprintf("platform-%d@notify.test", stamp),
		ctx:      ctx,
	}

	f.addAdmin(t, f.owner, "owner", roleID["owner"], true)
	f.addAdmin(t, f.coOwner, "co_owner", roleID["co_owner"], true)

	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM tenant_admins WHERE tenant_id = $1`, tenantID)
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE tenant_id = $1`, tenantID)
		_, _ = pool.Exec(ctx, `DELETE FROM roles WHERE tenant_id = $1`, tenantID)
		_, _ = pool.Exec(ctx, `DELETE FROM oauth_clients WHERE tenant_id = $1`, tenantID)
		_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID)
	})

	// A configured platform address, so these tests do not depend on whichever
	// super_admins happen to exist in the shared database.
	f.sink = &EmailSink{
		pool:           pool,
		platformEmails: []string{f.platform},
		logger:         testhelper.TestLogger(),
	}
	return f
}

// addAdmin creates a usable administrator: verified, active, and with an
// ACTIVATED grant. Anything less is not somebody who can act.
func (f *notifyFixture) addAdmin(t *testing.T, email, adminRole string, roleID int64, activated bool) int64 {
	t.Helper()
	var userID int64
	if err := f.pool.QueryRow(f.ctx, `
		INSERT INTO users (tenant_id, email, first_name, last_name, role_id, is_active, email_verified)
		VALUES ($1, $2, '', '', $3, true, true) RETURNING id
	`, f.tenantID, email, roleID).Scan(&userID); err != nil {
		t.Fatalf("create user %s: %v", email, err)
	}
	activatedAt := "NOW()"
	if !activated {
		activatedAt = "NULL"
	}
	if _, err := f.pool.Exec(f.ctx, fmt.Sprintf(`
		INSERT INTO tenant_admins (tenant_id, user_id, admin_role, activated_at)
		VALUES ($1, $2, $3, %s)
	`, activatedAt), f.tenantID, userID, adminRole); err != nil {
		t.Fatalf("create tenant_admin %s: %v", email, err)
	}
	return userID
}

func sorted(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func TestResolveAudience_CoOwnerActionGoesToOwners(t *testing.T) {
	f := newNotifyFixture(t)

	aud, err := f.sink.resolveAudience(f.ctx, f.tenantID, nil, f.coOwner, audit.ActionAdminApplicationDeleted)
	if err != nil {
		t.Fatalf("resolveAudience: %v", err)
	}
	if aud.actorRole != "co-owner" {
		t.Errorf("actorRole = %q, want co-owner", aud.actorRole)
	}
	if got := sorted(aud.to); len(got) != 1 || got[0] != f.owner {
		t.Errorf("recipients = %v, want just the owner %s", got, f.owner)
	}
}

func TestResolveAudience_OwnerActionGoesToPlatform(t *testing.T) {
	f := newNotifyFixture(t)

	aud, err := f.sink.resolveAudience(f.ctx, f.tenantID, nil, f.owner, audit.ActionAdminApplicationDeleted)
	if err != nil {
		t.Fatalf("resolveAudience: %v", err)
	}
	if aud.actorRole != "owner" {
		t.Errorf("actorRole = %q, want owner", aud.actorRole)
	}
	if got := sorted(aud.to); len(got) != 1 || got[0] != f.platform {
		t.Errorf("recipients = %v, want just the platform address %s", got, f.platform)
	}
	// The co-owner must not hear about their owner's actions — notification
	// flows up, never down.
	for _, addr := range aud.to {
		if addr == f.coOwner {
			t.Error("a co-owner was told about an owner's action")
		}
	}
}

// A platform admin's action used to notify nobody, on the grounds that there is
// no tier above them. That was the wrong reading: the people entitled to know
// are the owners of the tenant being reached into. See
// TestResolveAudience_PlatformAdminActionReachesTenantOwners, which replaces
// this, and TestResolveAudience_IgnoresMachineCredentials for the case that
// genuinely notifies nobody.

// The actor is added only for sensitive actions. A copy of everything you do is
// what trains people to ignore the channel.
func TestResolveAudience_ActorIncludedOnlyWhenSensitive(t *testing.T) {
	f := newNotifyFixture(t)

	routine, err := f.sink.resolveAudience(f.ctx, f.tenantID, nil, f.coOwner, audit.ActionAdminApplicationDeleted)
	if err != nil {
		t.Fatalf("resolveAudience(routine): %v", err)
	}
	for _, addr := range routine.to {
		if addr == f.coOwner {
			t.Error("actor received a copy of a routine action")
		}
	}

	sensitive, err := f.sink.resolveAudience(f.ctx, f.tenantID, nil, f.coOwner, audit.ActionAdminApplicationSecretRotated)
	if err != nil {
		t.Fatalf("resolveAudience(sensitive): %v", err)
	}
	var sawActor bool
	for _, addr := range sensitive.to {
		if addr == f.coOwner {
			sawActor = true
		}
	}
	if !sawActor {
		t.Error("actor did not receive a copy of a sensitive action — this is the compromise-detection case")
	}
}

// An owner who has not accepted their invitation cannot sign in, so telling them
// achieves nothing; and an unaccepted grant means the holder is not answerable
// for the tenant yet.
func TestResolveAudience_SkipsUnusableOwners(t *testing.T) {
	f := newNotifyFixture(t)

	// Deactivate the only owner's grant.
	if _, err := f.pool.Exec(f.ctx,
		`UPDATE tenant_admins SET activated_at = NULL WHERE tenant_id = $1 AND admin_role = 'owner'`,
		f.tenantID); err != nil {
		t.Fatalf("deactivate owner: %v", err)
	}

	aud, err := f.sink.resolveAudience(f.ctx, f.tenantID, nil, f.coOwner, audit.ActionAdminApplicationDeleted)
	if err != nil {
		t.Fatalf("resolveAudience: %v", err)
	}
	if len(aud.to) != 0 {
		t.Errorf("recipients = %v, want none — the only owner has not accepted", aud.to)
	}
}

// The actor is matched on user id when the event carries one, because the id is
// stable and the address is not. After an email change, historical events still
// hold the OLD address; matching on that would miss, and the default branch
// would then class one of the tenant's own administrators as an outsider and
// tell its owners a "platform administrator" had acted.
func TestResolveAudience_MatchesActorByIDAcrossAnEmailChange(t *testing.T) {
	f := newNotifyFixture(t)

	var coOwnerID int64
	if err := f.pool.QueryRow(f.ctx,
		`SELECT id FROM users WHERE tenant_id = $1 AND email = $2`, f.tenantID, f.coOwner).Scan(&coOwnerID); err != nil {
		t.Fatalf("find co-owner: %v", err)
	}
	// They change their address; the audit row keeps the old one.
	if _, err := f.pool.Exec(f.ctx,
		`UPDATE users SET email = $1 WHERE id = $2`, "renamed-"+f.coOwner, coOwnerID); err != nil {
		t.Fatalf("rename co-owner: %v", err)
	}

	aud, err := f.sink.resolveAudience(f.ctx, f.tenantID, &coOwnerID, f.coOwner, audit.ActionAdminApplicationDeleted)
	if err != nil {
		t.Fatalf("resolveAudience: %v", err)
	}
	if aud.actorRole != "co-owner" {
		t.Errorf("actorRole = %q, want co-owner — the id should still resolve them", aud.actorRole)
	}
	if got := sorted(aud.to); len(got) != 1 || got[0] != f.owner {
		t.Errorf("recipients = %v, want the owner; a missed match would have gone to the tenant's owners with the wrong role label", got)
	}

	// Without the id, the stale address misses and they look like an outsider —
	// the bug this guards against.
	stale, err := f.sink.resolveAudience(f.ctx, f.tenantID, nil, f.coOwner, audit.ActionAdminApplicationDeleted)
	if err != nil {
		t.Fatalf("resolveAudience(no id): %v", err)
	}
	if stale.actorRole == "co-owner" {
		t.Error("email-only lookup unexpectedly matched; this test no longer proves anything")
	}
}

// The worst failure mode: an owner of one tenant must never be told what
// happened in another.
func TestResolveAudience_NeverCrossesTenants(t *testing.T) {
	a := newNotifyFixture(t)
	b := newNotifyFixture(t)

	aud, err := a.sink.resolveAudience(a.ctx, a.tenantID, nil, a.coOwner, audit.ActionAdminApplicationDeleted)
	if err != nil {
		t.Fatalf("resolveAudience: %v", err)
	}
	for _, addr := range aud.to {
		if addr == b.owner || addr == b.coOwner {
			t.Fatalf("tenant B's administrator %s was told about tenant A's event", addr)
		}
	}
}

// The email has to name the application, and Event.ApplicationID is usually nil
// because most admin handlers log tenant-level events. The resource is the
// fallback that makes the worked example ("...in that tenant and application")
// actually work.
func TestApplicationName_FallsBackToTheResource(t *testing.T) {
	f := newNotifyFixture(t)

	byResource := f.sink.applicationName(f.ctx, nil, "application", fmt.Sprintf("%d", f.appID))
	if byResource != "Web Dashboard" {
		t.Errorf("name from resource = %q, want Web Dashboard", byResource)
	}

	byField := f.sink.applicationName(f.ctx, &f.appID, "", "")
	if byField != "Web Dashboard" {
		t.Errorf("name from ApplicationID = %q, want Web Dashboard", byField)
	}

	// A tenant-level action names no application, and the template omits the row
	// rather than showing a blank one.
	if got := f.sink.applicationName(f.ctx, nil, "tenant", "7"); got != "" {
		t.Errorf("name for a non-application resource = %q, want empty", got)
	}
}

// Owners are jointly accountable for a tenant, so an owner's action reaches the
// platform tier AND the tenant's other owners. Reporting only upward would leave
// a co-owner better informed about an owner than that owner's own peer is.
func TestResolveAudience_OwnerActionAlsoReachesPeerOwners(t *testing.T) {
	f := newNotifyFixture(t)

	var ownerRoleID int64
	if err := f.pool.QueryRow(f.ctx,
		`SELECT id FROM roles WHERE tenant_id = $1 AND name = 'owner'`, f.tenantID).Scan(&ownerRoleID); err != nil {
		t.Fatalf("find owner role: %v", err)
	}
	peer := fmt.Sprintf("peer-owner-%d@notify.test", time.Now().UnixNano())
	f.addAdmin(t, peer, "owner", ownerRoleID, true)

	aud, err := f.sink.resolveAudience(f.ctx, f.tenantID, nil, f.owner, audit.ActionAdminApplicationDeleted)
	if err != nil {
		t.Fatalf("resolveAudience: %v", err)
	}
	got := sorted(aud.to)
	if len(got) != 2 {
		t.Fatalf("recipients = %v, want the platform address and the peer owner", got)
	}
	var sawPeer, sawPlatform bool
	for _, addr := range got {
		switch addr {
		case peer:
			sawPeer = true
		case f.platform:
			sawPlatform = true
		case f.owner:
			t.Error("the acting owner was sent their own tier-up copy")
		}
	}
	if !sawPeer || !sawPlatform {
		t.Errorf("recipients = %v, want both the peer owner and the platform address", got)
	}
}

// A platform admin reaching into someone else's tenant is exactly what that
// tenant's owners are entitled to know about. Acting in a tenant without being
// one of its administrators requires tenant:manage — the routes admit nobody
// else — so the inference is sound.
func TestResolveAudience_PlatformAdminActionReachesTenantOwners(t *testing.T) {
	f := newNotifyFixture(t)

	aud, err := f.sink.resolveAudience(f.ctx, f.tenantID, nil, "superadmin@platform.test", audit.ActionAdminApplicationDeleted)
	if err != nil {
		t.Fatalf("resolveAudience: %v", err)
	}
	if aud.actorRole != "platform administrator" {
		t.Errorf("actorRole = %q, want platform administrator", aud.actorRole)
	}
	if got := sorted(aud.to); len(got) != 1 || got[0] != f.owner {
		t.Errorf("recipients = %v, want the tenant's owner %s", got, f.owner)
	}
}

// An API key doing the job it was provisioned for is automation, not oversight.
// The administrator who created the key was already told about that.
func TestResolveAudience_IgnoresMachineCredentials(t *testing.T) {
	f := newNotifyFixture(t)

	aud, err := f.sink.resolveAudience(f.ctx, f.tenantID, nil, "ci-deploy@apikey", audit.ActionAdminApplicationDeleted)
	if err != nil {
		t.Fatalf("resolveAudience: %v", err)
	}
	if len(aud.to) != 0 {
		t.Errorf("recipients = %v, want none for an API-key actor", aud.to)
	}
}

// Regression: the platform lookup used to require email_verified, and the
// seeded super_admin has it false. Every owner action in the system went
// unreported, with no error — "no recipients" is a legitimate outcome for a
// platform admin's own actions, so nothing distinguished it from working.
//
// Verification is a self-service concept; a super_admin is provisioned.
func TestPlatformRecipients_DoesNotRequireVerifiedEmail(t *testing.T) {
	f := newNotifyFixture(t)

	// A super_admin exactly as the seed leaves one: active, unverified.
	var roleID int64
	if err := f.pool.QueryRow(f.ctx,
		`INSERT INTO roles (tenant_id, name, is_system, created_at) VALUES ($1, 'super_admin', true, NOW()) RETURNING id`,
		f.tenantID).Scan(&roleID); err != nil {
		t.Fatalf("create super_admin role: %v", err)
	}
	unverified := fmt.Sprintf("platform-unverified-%d@notify.test", time.Now().UnixNano())
	if _, err := f.pool.Exec(f.ctx, `
		INSERT INTO users (tenant_id, email, first_name, last_name, role_id, is_active, email_verified)
		VALUES ($1, $2, '', '', $3, true, false)
	`, f.tenantID, unverified, roleID); err != nil {
		t.Fatalf("create super_admin user: %v", err)
	}

	// Fall back to the DB rather than the configured address.
	sink := &EmailSink{pool: f.pool, logger: testhelper.TestLogger()}
	got, err := sink.platformRecipients(f.ctx)
	if err != nil {
		t.Fatalf("platformRecipients: %v", err)
	}
	var found bool
	for _, addr := range got {
		if addr == unverified {
			found = true
		}
	}
	if !found {
		t.Errorf("unverified super_admin %s was excluded; owner activity would go unreported", unverified)
	}
}

// A configured address short-circuits the query entirely — a deployment that
// names a mailbox does not also want mail fanned out to individuals.
func TestPlatformRecipients_ConfiguredAddressWins(t *testing.T) {
	f := newNotifyFixture(t)
	got, err := f.sink.platformRecipients(f.ctx)
	if err != nil {
		t.Fatalf("platformRecipients: %v", err)
	}
	if len(got) != 1 || got[0] != f.platform {
		t.Errorf("recipients = %v, want only the configured %s", got, f.platform)
	}
}

func TestTenantName_PrefersDisplayName(t *testing.T) {
	f := newNotifyFixture(t)
	if got := f.sink.tenantName(f.ctx, f.tenantID); got != "Notify Co" {
		t.Errorf("tenantName = %q, want the display name", got)
	}
}
