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

// notifyFixture is a tenant with two applications, an owner, a co-owner granted
// the first application and a second co-owner granted only the other one —
// the smallest world in which "everyone who administers this application"
// differs from "everyone in the tenant".
type notifyFixture struct {
	pool       *pgxpool.Pool
	sink       *EmailSink
	tenantID   int64
	owner      string
	coOwner    string // administers appID
	otherCoOwn string // administers otherAppID only
	appID      int64
	otherAppID int64
	roleID     map[string]int64
	ctx        context.Context
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

	newApp := func(name string) int64 {
		var id int64
		if err := pool.QueryRow(ctx,
			`INSERT INTO oauth_clients (tenant_id, client_id, client_secret_hash, name, redirect_uris)
			 VALUES ($1, $2, 'x', $3, ARRAY['https://x.test/cb']) RETURNING id`,
			tenantID, fmt.Sprintf("client-%s-%s", name, slug), name).Scan(&id); err != nil {
			t.Fatalf("create application %s: %v", name, err)
		}
		return id
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
		pool:       pool,
		tenantID:   tenantID,
		appID:      newApp("Web Dashboard"),
		otherAppID: newApp("Billing"),
		owner:      fmt.Sprintf("owner-%d@notify.test", stamp),
		coOwner:    fmt.Sprintf("co-%d@notify.test", stamp),
		otherCoOwn: fmt.Sprintf("co-other-%d@notify.test", stamp),
		roleID:     roleID,
		ctx:        ctx,
	}

	f.addAdmin(t, f.owner, "owner", true)
	f.addAdmin(t, f.coOwner, "co_owner", true, f.appID)
	f.addAdmin(t, f.otherCoOwn, "co_owner", true, f.otherAppID)

	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM tenant_admins WHERE tenant_id = $1`, tenantID)
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE tenant_id = $1`, tenantID)
		_, _ = pool.Exec(ctx, `DELETE FROM roles WHERE tenant_id = $1`, tenantID)
		_, _ = pool.Exec(ctx, `DELETE FROM oauth_clients WHERE tenant_id = $1`, tenantID)
		_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID)
	})

	f.sink = &EmailSink{pool: pool, logger: testhelper.TestLogger()}
	return f
}

// addAdmin creates a usable administrator — verified, active, and with an
// ACTIVATED grant unless activated is false — granted the given applications.
func (f *notifyFixture) addAdmin(t *testing.T, email, adminRole string, activated bool, apps ...int64) int64 {
	t.Helper()
	var userID int64
	if err := f.pool.QueryRow(f.ctx, `
		INSERT INTO users (tenant_id, email, first_name, last_name, role_id, is_active, email_verified)
		VALUES ($1, $2, '', '', $3, true, true) RETURNING id
	`, f.tenantID, email, f.roleID[adminRole]).Scan(&userID); err != nil {
		t.Fatalf("create user %s: %v", email, err)
	}
	activatedAt := "NOW()"
	if !activated {
		activatedAt = "NULL"
	}
	var adminID int64
	if err := f.pool.QueryRow(f.ctx, fmt.Sprintf(`
		INSERT INTO tenant_admins (tenant_id, user_id, admin_role, activated_at)
		VALUES ($1, $2, $3, %s) RETURNING id
	`, activatedAt), f.tenantID, userID, adminRole).Scan(&adminID); err != nil {
		t.Fatalf("create tenant_admin %s: %v", email, err)
	}
	for _, app := range apps {
		if _, err := f.pool.Exec(f.ctx,
			`INSERT INTO tenant_admin_app_scopes (admin_id, application_id) VALUES ($1, $2)`, adminID, app,
		); err != nil {
			t.Fatalf("grant %s application %d: %v", email, app, err)
		}
	}
	return userID
}

func sorted(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func equal(got, want []string) bool {
	got, want = sorted(got), sorted(want)
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// A secret rotation reaches everyone who administers that application — the
// owner and the co-owner granted it — and not a co-owner of another one.
func TestResolveAudience_SecretRotationReachesTheApplicationsAdministrators(t *testing.T) {
	f := newNotifyFixture(t)

	aud, err := f.sink.resolveAudience(f.ctx, f.tenantID, &f.appID, nil, f.owner, audit.ActionAdminApplicationSecretRotated)
	if err != nil {
		t.Fatalf("resolveAudience: %v", err)
	}
	if want := []string{f.owner, f.coOwner}; !equal(aud.to, want) {
		t.Errorf("recipients = %v, want %v", sorted(aud.to), sorted(want))
	}
	if aud.actorRole != "owner" {
		t.Errorf("actorRole = %q, want owner", aud.actorRole)
	}
}

// The actor is not special-cased: a co-owner rotating their own application's
// secret is one of its administrators and gets the same email — the copy that
// exposes a stolen session.
func TestResolveAudience_ActorIsIncludedAsAnAdministrator(t *testing.T) {
	f := newNotifyFixture(t)

	aud, err := f.sink.resolveAudience(f.ctx, f.tenantID, &f.appID, nil, f.coOwner, audit.ActionAdminApplicationSecretRotated)
	if err != nil {
		t.Fatalf("resolveAudience: %v", err)
	}
	if want := []string{f.owner, f.coOwner}; !equal(aud.to, want) {
		t.Errorf("recipients = %v, want %v", sorted(aud.to), sorted(want))
	}
	if aud.actorRole != "co-owner" {
		t.Errorf("actorRole = %q, want co-owner", aud.actorRole)
	}
}

// A deactivated tenant reaches every administrator of it, whichever
// applications they were granted.
func TestResolveAudience_TenantDeactivationReachesEveryAdministrator(t *testing.T) {
	f := newNotifyFixture(t)

	aud, err := f.sink.resolveAudience(f.ctx, f.tenantID, nil, nil, "superadmin@platform.test", audit.ActionAdminTenantDeactivated)
	if err != nil {
		t.Fatalf("resolveAudience: %v", err)
	}
	if want := []string{f.owner, f.coOwner, f.otherCoOwn}; !equal(aud.to, want) {
		t.Errorf("recipients = %v, want %v", sorted(aud.to), sorted(want))
	}
	if aud.actorRole != "platform administrator" {
		t.Errorf("actorRole = %q, want platform administrator", aud.actorRole)
	}
}

// Everything outside the catalogue notifies nobody — including the actions that
// used to be in it.
func TestResolveAudience_UncataloguedActionsNotifyNobody(t *testing.T) {
	f := newNotifyFixture(t)

	for _, action := range []string{
		audit.ActionAdminApplicationCreated,
		audit.ActionAdminApplicationDeleted,
		audit.ActionAdminMFAPolicyUpdated,
		audit.ActionAdminRolePermissionsUpdated,
		audit.ActionAdminPermissionCreated,
		audit.ActionAdminTenantAdminInvited,
		audit.ActionAdminTenantAdminGrantsSet,
		audit.ActionAdminTenantAdminRemoved,
	} {
		aud, err := f.sink.resolveAudience(f.ctx, f.tenantID, &f.appID, nil, f.owner, action)
		if err != nil {
			t.Fatalf("resolveAudience(%s): %v", action, err)
		}
		if len(aud.to) != 0 {
			t.Errorf("%s notified %v, want nobody", action, aud.to)
		}
	}
}

// An application-scoped action with no application resolves to nobody rather
// than widening to the whole tenant.
func TestResolveAudience_SecretRotationWithoutAnApplicationNotifiesNobody(t *testing.T) {
	f := newNotifyFixture(t)

	aud, err := f.sink.resolveAudience(f.ctx, f.tenantID, nil, nil, f.owner, audit.ActionAdminApplicationSecretRotated)
	if err != nil {
		t.Fatalf("resolveAudience: %v", err)
	}
	if len(aud.to) != 0 {
		t.Errorf("recipients = %v, want none", aud.to)
	}
}

// An administrator who cannot sign in — grant not accepted, or account blocked
// — is not told; it achieves nothing.
func TestResolveAudience_SkipsUnusableAdministrators(t *testing.T) {
	f := newNotifyFixture(t)

	pending := fmt.Sprintf("pending-%d@notify.test", time.Now().UnixNano())
	f.addAdmin(t, pending, "co_owner", false, f.appID)
	if _, err := f.pool.Exec(f.ctx,
		`UPDATE users SET blocked_at = NOW() WHERE tenant_id = $1 AND email = $2`, f.tenantID, f.coOwner,
	); err != nil {
		t.Fatalf("block co-owner: %v", err)
	}

	aud, err := f.sink.resolveAudience(f.ctx, f.tenantID, &f.appID, nil, f.owner, audit.ActionAdminApplicationSecretRotated)
	if err != nil {
		t.Fatalf("resolveAudience: %v", err)
	}
	if want := []string{f.owner}; !equal(aud.to, want) {
		t.Errorf("recipients = %v, want only the usable owner %v", sorted(aud.to), want)
	}
}

// The worst failure mode: an administrator of one tenant must never be told
// what happened in another — not even when an event names an application that
// belongs to a different tenant.
func TestResolveAudience_NeverCrossesTenants(t *testing.T) {
	a := newNotifyFixture(t)
	b := newNotifyFixture(t)

	aud, err := a.sink.resolveAudience(a.ctx, a.tenantID, &b.appID, nil, a.owner, audit.ActionAdminApplicationSecretRotated)
	if err != nil {
		t.Fatalf("resolveAudience: %v", err)
	}
	if len(aud.to) != 0 {
		t.Errorf("recipients = %v for another tenant's application, want none", aud.to)
	}

	aud, err = a.sink.resolveAudience(a.ctx, a.tenantID, nil, nil, a.owner, audit.ActionAdminTenantDeactivated)
	if err != nil {
		t.Fatalf("resolveAudience: %v", err)
	}
	for _, addr := range aud.to {
		if addr == b.owner || addr == b.coOwner || addr == b.otherCoOwn {
			t.Fatalf("tenant B's administrator %s was told about tenant A's event", addr)
		}
	}
}

// The actor is matched on user id when the event carries one, because the id is
// stable and the address is not. After an email change, historical events still
// hold the OLD address; matching on that would describe the tenant's own
// co-owner as a platform administrator.
func TestResolveAudience_MatchesActorByIDAcrossAnEmailChange(t *testing.T) {
	f := newNotifyFixture(t)

	var coOwnerID int64
	if err := f.pool.QueryRow(f.ctx,
		`SELECT id FROM users WHERE tenant_id = $1 AND email = $2`, f.tenantID, f.coOwner).Scan(&coOwnerID); err != nil {
		t.Fatalf("find co-owner: %v", err)
	}
	if _, err := f.pool.Exec(f.ctx,
		`UPDATE users SET email = $1 WHERE id = $2`, "renamed-"+f.coOwner, coOwnerID); err != nil {
		t.Fatalf("rename co-owner: %v", err)
	}

	aud, err := f.sink.resolveAudience(f.ctx, f.tenantID, &f.appID, &coOwnerID, f.coOwner, audit.ActionAdminApplicationSecretRotated)
	if err != nil {
		t.Fatalf("resolveAudience: %v", err)
	}
	if aud.actorRole != "co-owner" {
		t.Errorf("actorRole = %q, want co-owner — the id should still resolve them", aud.actorRole)
	}

	stale, err := f.sink.resolveAudience(f.ctx, f.tenantID, &f.appID, nil, f.coOwner, audit.ActionAdminApplicationSecretRotated)
	if err != nil {
		t.Fatalf("resolveAudience(no id): %v", err)
	}
	if stale.actorRole == "co-owner" {
		t.Error("email-only lookup unexpectedly matched; this test no longer proves anything")
	}
}

// An API key rotating a secret is still a rotated secret: every administrator
// of the application needs to know the old one stopped working.
func TestResolveAudience_MachineActorStillNotifies(t *testing.T) {
	f := newNotifyFixture(t)

	aud, err := f.sink.resolveAudience(f.ctx, f.tenantID, &f.appID, nil, "ci-deploy@apikey", audit.ActionAdminApplicationSecretRotated)
	if err != nil {
		t.Fatalf("resolveAudience: %v", err)
	}
	if want := []string{f.owner, f.coOwner}; !equal(aud.to, want) {
		t.Errorf("recipients = %v, want %v", sorted(aud.to), sorted(want))
	}
	if aud.actorRole != "API key" {
		t.Errorf("actorRole = %q, want API key", aud.actorRole)
	}
}

// The email has to name the application, and Event.ApplicationID is often nil.
// The resource is the fallback.
func TestEventApplication_FallsBackToTheResource(t *testing.T) {
	f := newNotifyFixture(t)

	byResource := eventApplication(nil, "application", fmt.Sprintf("%d", f.appID))
	if byResource == nil || *byResource != f.appID {
		t.Fatalf("app from resource = %v, want %d", byResource, f.appID)
	}
	if got := f.sink.applicationName(f.ctx, byResource); got != "Web Dashboard" {
		t.Errorf("applicationName = %q, want Web Dashboard", got)
	}
	if got := eventApplication(&f.appID, "", ""); got == nil || *got != f.appID {
		t.Errorf("app from ApplicationID = %v, want %d", got, f.appID)
	}
	// A tenant-level action names no application, and the template omits the row.
	if got := eventApplication(nil, "tenant", "7"); got != nil {
		t.Errorf("app for a non-application resource = %v, want nil", *got)
	}
}

func TestTenantName_PrefersDisplayName(t *testing.T) {
	f := newNotifyFixture(t)
	if got := f.sink.tenantName(f.ctx, f.tenantID); got != "Notify Co" {
		t.Errorf("tenantName = %q, want the display name", got)
	}
}
