package admin_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/engineersmind/emc-auth-server/internal/admin"
	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// ---------------------------------------------------------------------------
// Privilege-escalation rules for grant writes (plan §12).
//
// An owner may invite co-owners to their own tenants. The rules here are what
// stops that from becoming "an owner may mint a peer owner, who may mint
// another" — ownership must not be able to propagate itself, or the owner
// population stops being auditable.
//
// These assert against the DATABASE, not against a mock: the actor's tier is read
// from admin_grants inside the same transaction as the write, so a stale view of
// the actor's own standing cannot authorise anything.
// ---------------------------------------------------------------------------

type escEnv struct {
	ctx    context.Context
	pool   *pgxpool.Pool
	tenant int64
	other  int64
	app    int64
}

func newEscEnv(t *testing.T) *escEnv {
	t.Helper()
	// Reuse the package fixture: it runs RunSeed and registers the ONE
	// CleanupTables for the file. Registering a second truncation here would
	// race sibling tests that depend on the seeded tenant — TRUNCATE users
	// CASCADE does not respect another test's fixture.
	f := newAdminFixture(t)
	pool := f.pool
	e := &escEnv{ctx: context.Background(), pool: pool}
	e.tenant = e.tenantRow(t, "esc-own")
	e.other = e.tenantRow(t, "esc-other")
	e.app = e.appRow(t, e.tenant, "esc-app")
	return e
}

func (e *escEnv) tenantRow(t *testing.T, slug string) int64 {
	t.Helper()
	var id int64
	u := fmt.Sprintf("%s-%d", slug, time.Now().UnixNano())
	if err := e.pool.QueryRow(e.ctx, `
		INSERT INTO tenants (name, slug, jwt_secret, is_active)
		VALUES ($1, $1, 'x', true) RETURNING id
	`, u).Scan(&id); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	return id
}

func (e *escEnv) appRow(t *testing.T, tenantID int64, name string) int64 {
	t.Helper()
	var id int64
	u := fmt.Sprintf("%s-%d", name, time.Now().UnixNano())
	if err := e.pool.QueryRow(e.ctx, `
		INSERT INTO oauth_clients
		    (tenant_id, client_id, name, redirect_uris, grant_types, scopes,
		     app_type, require_pkce, first_party)
		VALUES ($1, $2, $2, ARRAY['https://x/cb'], ARRAY['authorization_code'],
		        ARRAY['openid'], 'spa', true, true)
		RETURNING id
	`, tenantID, u).Scan(&id); err != nil {
		t.Fatalf("seed app: %v", err)
	}
	return id
}

func (e *escEnv) user(t *testing.T, homeTenant int64, label string) int64 {
	t.Helper()
	var id int64
	email := fmt.Sprintf("%s-%d@esc.test", label, time.Now().UnixNano())
	if err := e.pool.QueryRow(e.ctx, `
		INSERT INTO users (tenant_id, application_id, email, first_name, last_name,
		                   is_active, email_verified)
		VALUES ($1, NULL, $2, 'E', 'S', true, true) RETURNING id
	`, homeTenant, email).Scan(&id); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return id
}

func (e *escEnv) grant(t *testing.T, userID, tenantID int64, role string, appID *int64) {
	t.Helper()
	if _, err := e.pool.Exec(e.ctx, `
		INSERT INTO admin_grants (user_id, tenant_id, admin_role, application_id, activated_at)
		VALUES ($1, $2, $3, $4, NOW())
	`, userID, tenantID, role, appID); err != nil {
		t.Fatalf("seed grant: %v", err)
	}
}

// TestAssertMayGrant_OwnerMayCreateCoOwnerNotOwner is rule 1, the load-bearing
// one. An owner inviting a co-owner is the whole point of the feature; an owner
// minting a peer owner is unbounded self-propagation.
func TestAssertMayGrant_OwnerMayCreateCoOwnerNotOwner(t *testing.T) {
	e := newEscEnv(t)
	owner := e.user(t, e.tenant, "owner")
	e.grant(t, owner, e.tenant, auth.AdminRoleOwner, nil)
	actor := admin.GrantActor{UserID: owner}

	target := e.user(t, e.tenant, "target")

	if err := admin.AssertMayGrant(e.ctx, e.pool, actor, e.tenant, target, auth.AdminRoleCoOwner); err != nil {
		t.Errorf("owner creating a co_owner grant: %v, want nil", err)
	}

	err := admin.AssertMayGrant(e.ctx, e.pool, actor, e.tenant, target, auth.AdminRoleOwner)
	if !errors.Is(err, admin.ErrOwnerCannotGrantOwnership) {
		t.Errorf("owner creating an OWNER grant: %v, want ErrOwnerCannotGrantOwnership", err)
	}
}

// TestAssertMayGrant_PlatformAdminMayGrantOwnership: the tier that creates tenants
// and their first owner must not be restricted by rule 1.
func TestAssertMayGrant_PlatformAdminMayGrantOwnership(t *testing.T) {
	e := newEscEnv(t)
	// A platform admin holds NO grants at all — the tier is a permission, not a
	// membership, so the actor is identified only by IsPlatformAdmin.
	platform := e.user(t, e.tenant, "platform")
	actor := admin.GrantActor{UserID: platform, IsPlatformAdmin: true}
	target := e.user(t, e.tenant, "new-owner")

	if err := admin.AssertMayGrant(e.ctx, e.pool, actor, e.tenant, target, auth.AdminRoleOwner); err != nil {
		t.Errorf("platform admin creating an owner grant: %v, want nil", err)
	}
	// And in a tenant they hold nothing in, which is the cross-tenant case.
	if err := admin.AssertMayGrant(e.ctx, e.pool, actor, e.other, target, auth.AdminRoleOwner); err != nil {
		t.Errorf("platform admin granting in another tenant: %v, want nil", err)
	}
}

// TestAssertMayGrant_CoOwnerMayNotWriteGrants is rule 3. The middleware should
// already have refused them — they hold the same permission NAMES as an owner, so
// only the AdminScopeApps check stops them — but a service that relies on a
// middleware for a security decision breaks the first time it is called from
// somewhere else.
func TestAssertMayGrant_CoOwnerMayNotWriteGrants(t *testing.T) {
	e := newEscEnv(t)
	coOwner := e.user(t, e.tenant, "co-owner")
	e.grant(t, coOwner, e.tenant, auth.AdminRoleCoOwner, &e.app)
	actor := admin.GrantActor{UserID: coOwner}
	target := e.user(t, e.tenant, "target")

	err := admin.AssertMayGrant(e.ctx, e.pool, actor, e.tenant, target, auth.AdminRoleCoOwner)
	if !errors.Is(err, admin.ErrForbiddenGrantWrite) {
		t.Errorf("co-owner writing a grant: %v, want ErrForbiddenGrantWrite", err)
	}
}

// TestAssertMayGrant_OwnerOfAnotherTenantIsRefused: an owner's authority is
// per-tenant. Being an owner somewhere confers nothing here — this is the
// isolation property that makes multi-tenant administration safe.
func TestAssertMayGrant_OwnerOfAnotherTenantIsRefused(t *testing.T) {
	e := newEscEnv(t)
	owner := e.user(t, e.tenant, "elsewhere-owner")
	e.grant(t, owner, e.other, auth.AdminRoleOwner, nil) // owner of `other`, not `tenant`
	actor := admin.GrantActor{UserID: owner}
	target := e.user(t, e.tenant, "target")

	err := admin.AssertMayGrant(e.ctx, e.pool, actor, e.tenant, target, auth.AdminRoleCoOwner)
	if !errors.Is(err, admin.ErrForbiddenGrantWrite) {
		t.Errorf("owner of another tenant writing here: %v, want ErrForbiddenGrantWrite", err)
	}

	// The same actor in the tenant they DO own: permitted.
	if err = admin.AssertMayGrant(e.ctx, e.pool, actor, e.other, target, auth.AdminRoleCoOwner); err != nil {
		t.Errorf("owner acting in their own tenant: %v, want nil", err)
	}
}

// TestAssertMayGrant_NobodyModifiesTheirOwnGrant is rule 4, and it applies to
// every tier including the platform one: a self-write is indistinguishable in the
// audit log from a legitimate one.
func TestAssertMayGrant_NobodyModifiesTheirOwnGrant(t *testing.T) {
	e := newEscEnv(t)
	owner := e.user(t, e.tenant, "self")
	e.grant(t, owner, e.tenant, auth.AdminRoleOwner, nil)

	err := admin.AssertMayGrant(e.ctx, e.pool,
		admin.GrantActor{UserID: owner}, e.tenant, owner, auth.AdminRoleCoOwner)
	if !errors.Is(err, admin.ErrCannotModifyOwnGrant) {
		t.Errorf("owner modifying their own grant: %v, want ErrCannotModifyOwnGrant", err)
	}

	// Also refused for a platform administrator.
	err = admin.AssertMayGrant(e.ctx, e.pool,
		admin.GrantActor{UserID: owner, IsPlatformAdmin: true}, e.tenant, owner, auth.AdminRoleOwner)
	if !errors.Is(err, admin.ErrCannotModifyOwnGrant) {
		t.Errorf("platform admin modifying their own grant: %v, want ErrCannotModifyOwnGrant", err)
	}
}

// TestAssertMayGrant_NoGrantFailsClosed: an actor with no standing in the tenant
// is refused rather than admitted by the absence of a row. The route may have let
// them through on a :tid match, which a legacy tenant admin predating admin_grants
// can satisfy.
func TestAssertMayGrant_NoGrantFailsClosed(t *testing.T) {
	e := newEscEnv(t)
	nobody := e.user(t, e.tenant, "nobody")
	target := e.user(t, e.tenant, "target")

	err := admin.AssertMayGrant(e.ctx, e.pool,
		admin.GrantActor{UserID: nobody}, e.tenant, target, auth.AdminRoleCoOwner)
	if !errors.Is(err, admin.ErrForbiddenGrantWrite) {
		t.Errorf("actor with no grant: %v, want ErrForbiddenGrantWrite", err)
	}

	// The zero-value actor, which is what an unset Actor field produces, must also
	// fail closed rather than skip the checks.
	err = admin.AssertMayGrant(e.ctx, e.pool, admin.GrantActor{}, e.tenant, target, auth.AdminRoleCoOwner)
	if !errors.Is(err, admin.ErrForbiddenGrantWrite) {
		t.Errorf("zero-value actor: %v, want ErrForbiddenGrantWrite", err)
	}
}

// TestAssertMayGrant_PendingActorGrantConfersNothing: an owner who has not
// accepted their own invitation cannot yet act. Their grant carries no RBAC role,
// so it must carry no authority to write grants either.
func TestAssertMayGrant_PendingActorGrantConfersNothing(t *testing.T) {
	e := newEscEnv(t)
	pendingOwner := e.user(t, e.tenant, "pending-owner")
	if _, err := e.pool.Exec(e.ctx, `
		INSERT INTO admin_grants (user_id, tenant_id, admin_role, application_id, activated_at)
		VALUES ($1, $2, 'owner', NULL, NULL)
	`, pendingOwner, e.tenant); err != nil {
		t.Fatalf("seed pending owner grant: %v", err)
	}
	target := e.user(t, e.tenant, "target")

	err := admin.AssertMayGrant(e.ctx, e.pool,
		admin.GrantActor{UserID: pendingOwner}, e.tenant, target, auth.AdminRoleCoOwner)
	if !errors.Is(err, admin.ErrForbiddenGrantWrite) {
		t.Errorf("pending owner writing a grant: %v, want ErrForbiddenGrantWrite", err)
	}
}

// TestAssertMayRemove_OwnerMayRemoveCoOwnerNotPeerOwner is rule 5. Two owners able
// to remove each other means the tenant belongs to whoever committed first.
func TestAssertMayRemove_OwnerMayRemoveCoOwnerNotPeerOwner(t *testing.T) {
	e := newEscEnv(t)
	owner := e.user(t, e.tenant, "remover")
	peer := e.user(t, e.tenant, "peer-owner")
	co := e.user(t, e.tenant, "removable-co")

	e.grant(t, owner, e.tenant, auth.AdminRoleOwner, nil)
	e.grant(t, peer, e.tenant, auth.AdminRoleOwner, nil)
	e.grant(t, co, e.tenant, auth.AdminRoleCoOwner, &e.app)

	actor := admin.GrantActor{UserID: owner}

	if err := admin.AssertMayRemove(e.ctx, e.pool, actor, e.tenant, co); err != nil {
		t.Errorf("owner removing a co-owner: %v, want nil", err)
	}

	err := admin.AssertMayRemove(e.ctx, e.pool, actor, e.tenant, peer)
	if !errors.Is(err, admin.ErrOwnerCannotRemoveOwner) {
		t.Errorf("owner removing a PEER OWNER: %v, want ErrOwnerCannotRemoveOwner", err)
	}

	// Self-removal is refused: an owner must not be able to strand their own
	// tenant, and rule 4 applies to removal as much as to granting.
	if err = admin.AssertMayRemove(e.ctx, e.pool, actor, e.tenant, owner); !errors.Is(err, admin.ErrCannotModifyOwnGrant) {
		t.Errorf("owner removing themselves: %v, want ErrCannotModifyOwnGrant", err)
	}

	// A platform administrator may remove a peer owner — that is the point of
	// reserving it to them.
	platform := admin.GrantActor{UserID: e.user(t, e.tenant, "platform-rm"), IsPlatformAdmin: true}
	if err = admin.AssertMayRemove(e.ctx, e.pool, platform, e.tenant, peer); err != nil {
		t.Errorf("platform admin removing an owner: %v, want nil", err)
	}
}

// TestAssertMayRemove_CoOwnerMayNotRemoveAnyone: removal is an owner-or-above act.
func TestAssertMayRemove_CoOwnerMayNotRemoveAnyone(t *testing.T) {
	e := newEscEnv(t)
	co := e.user(t, e.tenant, "co-remover")
	victim := e.user(t, e.tenant, "victim")
	e.grant(t, co, e.tenant, auth.AdminRoleCoOwner, &e.app)
	e.grant(t, victim, e.tenant, auth.AdminRoleCoOwner, &e.app)

	err := admin.AssertMayRemove(e.ctx, e.pool, admin.GrantActor{UserID: co}, e.tenant, victim)
	if !errors.Is(err, admin.ErrForbiddenGrantWrite) {
		t.Errorf("co-owner removing another co-owner: %v, want ErrForbiddenGrantWrite", err)
	}
}
