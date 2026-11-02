package auth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// Regression tests for the PR #176 review (#175 Organizations).
//
// Each test pins one finding: the grant, revocation and locking gaps the
// review found in the first cut. The two race tests are deterministic rather
// than probabilistic — they hold the conflicting lock open in a transaction of
// their own and wait for the code under test to block on it — so they fail
// reliably against the old ordering instead of only sometimes.

// waitForLockWait blocks until some backend is waiting on a row lock while
// running a statement containing fragment, or fails the test after 10s.
func waitForLockWait(t *testing.T, pool *pgxpool.Pool, fragment string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var waiting bool
		if err := pool.QueryRow(context.Background(), `
			SELECT EXISTS (SELECT 1 FROM pg_stat_activity
			               WHERE wait_event_type = 'Lock' AND query LIKE '%' || $1 || '%')
		`, fragment).Scan(&waiting); err != nil {
			t.Fatalf("poll pg_stat_activity: %v", err)
		}
		if waiting {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no backend blocked on a lock running %q within 10s", fragment)
}

// --- Authorization-code bindings (review comments 4 and 5) ------------------

// A code issued with no organisation is an explicit "no organisation" grant.
// If the application moves to required before the exchange, the code must not
// be re-decided as a fresh login and auto-bound to the user's sole membership.
func TestOrganizations_CodeWithoutOrganizationIsRefusedOnceRequired(t *testing.T) {
	f := newOrgFixture(t, "org-code-nil", auth.OrganizationsModeOptional)
	email := uniqueEmail("code-nil")
	uid := f.registerUser(t, email)
	acme := f.createOrg(t, "acme")
	f.addMember(t, acme, uid)
	ctx := context.Background()

	if _, err := f.orgs.SetApplicationMode(ctx, f.scope, auth.OrganizationsModeRequired, true); err != nil {
		t.Fatalf("SetApplicationMode(required) error = %v", err)
	}

	_, err := f.svc.IssueTokensForAuthorizationCode(ctx, f.tenantID, uid, f.scope.AppRowID, []string{"openid"}, "", nil)
	if !errors.Is(err, auth.ErrOrganizationAccessDenied) {
		t.Fatalf("exchange of an organisation-less code in required mode error = %v, want ErrOrganizationAccessDenied", err)
	}
}

// The same code in optional mode is still an ordinary organisation-less grant.
func TestOrganizations_CodeWithoutOrganizationStillWorksInOptional(t *testing.T) {
	f := newOrgFixture(t, "org-code-nil-opt", auth.OrganizationsModeOptional)
	email := uniqueEmail("code-nil-opt")
	uid := f.registerUser(t, email)
	f.addMember(t, f.createOrg(t, "acme"), uid)

	issued, err := f.svc.IssueTokensForAuthorizationCode(context.Background(), f.tenantID, uid, f.scope.AppRowID, []string{"openid"}, "", nil)
	if err != nil {
		t.Fatalf("IssueTokensForAuthorizationCode() error = %v", err)
	}
	if c := f.claimsOf(t, issued.Tokens.AccessToken); c.OrgID != "" {
		t.Errorf("org_id = %q, want none for a code issued without one", c.OrgID)
	}
}

// A code bound to an organisation must be refused — not silently stripped of
// its organisation — once organisations stop applying.
func TestOrganizations_BoundCodeIsRefusedWhenOrganizationsAreOff(t *testing.T) {
	t.Run("application mode off", func(t *testing.T) {
		f := newOrgFixture(t, "org-code-off", auth.OrganizationsModeRequired)
		uid := f.registerUser(t, uniqueEmail("code-off"))
		acme := f.createOrg(t, "acme")
		f.addMember(t, acme, uid)
		ctx := context.Background()

		if _, err := f.orgs.SetApplicationMode(ctx, f.scope, auth.OrganizationsModeOff, true); err != nil {
			t.Fatalf("SetApplicationMode(off) error = %v", err)
		}
		orgRow := acme.RowID()
		if _, err := f.svc.IssueTokensForAuthorizationCode(ctx, f.tenantID, uid, f.scope.AppRowID, nil, "", &orgRow); !errors.Is(err, auth.ErrOrganizationAccessDenied) {
			t.Errorf("exchange error = %v, want ErrOrganizationAccessDenied", err)
		}
	})

	t.Run("deployment switch off", func(t *testing.T) {
		f := newOrgFixture(t, "org-code-deploy-off", auth.OrganizationsModeRequired)
		uid := f.registerUser(t, uniqueEmail("code-deploy-off"))
		acme := f.createOrg(t, "acme")
		f.addMember(t, acme, uid)

		f.svc.WithOrganizations(auth.NewOrganizationService(f.pool, nil, false, testhelper.TestLogger()))
		orgRow := acme.RowID()
		if _, err := f.svc.IssueTokensForAuthorizationCode(context.Background(), f.tenantID, uid, f.scope.AppRowID, nil, "", &orgRow); !errors.Is(err, auth.ErrOrganizationAccessDenied) {
			t.Errorf("exchange error = %v, want ErrOrganizationAccessDenied", err)
		}
	})
}

// --- Introspection (review comments 6 and 8) --------------------------------

// RFC 7662 §2.1: a hint that misses must not make a live token read inactive.
func TestOrganizations_IntrospectionHintFallsBack(t *testing.T) {
	f := newOrgFixture(t, "org-introspect-hint", auth.OrganizationsModeOptional)
	email := uniqueEmail("introspect-hint")
	f.registerUser(t, email)
	res, err := f.login(email, "")
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	client := auth.IntrospectionClient{ClientID: f.app.ClientID, TenantID: f.tenantID, AppRowID: f.scope.AppRowID}
	ctx := context.Background()

	if got := f.svc.Introspect(ctx, client, res.Token.AccessToken, "refresh_token"); !got.Active || got.TokenType != "access_token" {
		t.Errorf("Introspect(access, hint=refresh_token) = %+v, want active access_token", got)
	}
	if got := f.svc.Introspect(ctx, client, res.Token.RefreshToken, "access_token"); !got.Active || got.TokenType != "refresh_token" {
		t.Errorf("Introspect(refresh, hint=access_token) = %+v, want active refresh_token", got)
	}
}

// With no Redis denylist at all — the state a Redis outage leaves — a revoked
// session's access token must still read inactive, from PostgreSQL alone.
func TestOrganizations_IntrospectionSeesRevokedSessionWithoutRedis(t *testing.T) {
	f := newOrgFixture(t, "org-introspect-revoked", auth.OrganizationsModeOptional)
	email := uniqueEmail("introspect-revoked")
	f.registerUser(t, email)
	res, err := f.login(email, "")
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	client := auth.IntrospectionClient{ClientID: f.app.ClientID, TenantID: f.tenantID, AppRowID: f.scope.AppRowID}
	ctx := context.Background()

	if got := f.svc.Introspect(ctx, client, res.Token.AccessToken, ""); !got.Active {
		t.Fatalf("Introspect() before logout = %+v, want active", got)
	}
	if _, err := f.svc.LogoutSession(ctx, res.Token.RefreshToken); err != nil {
		t.Fatalf("LogoutSession() error = %v", err)
	}
	if got := f.svc.Introspect(ctx, client, res.Token.AccessToken, ""); got.Active {
		t.Errorf("Introspect() after logout = %+v, want inactive", got)
	}
}

// --- Switch deadline (review comment 10) ------------------------------------

// The switched session is clamped to the source session's STORED deadline,
// not one recomputed from auth_time under today's policy. Shortening the
// stored deadline stands in for "the policy was lengthened since sign-in":
// either way the recomputed value would land later than the stored one.
func TestOrganizations_SwitchCannotOutliveTheSourceDeadline(t *testing.T) {
	f := newOrgFixture(t, "org-switch-cap", auth.OrganizationsModeOptional)
	email := uniqueEmail("switch-cap")
	uid := f.registerUser(t, email)
	acme, globex := f.createOrg(t, "acme"), f.createOrg(t, "globex")
	f.addMember(t, acme, uid)
	f.addMember(t, globex, uid)
	ctx := context.Background()

	res, err := f.login(email, "acme")
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	var source time.Time
	if err := f.pool.QueryRow(ctx, `
		UPDATE user_sessions SET absolute_expires_at = absolute_expires_at - INTERVAL '1 hour'
		WHERE user_id = $1 RETURNING absolute_expires_at
	`, uid).Scan(&source); err != nil {
		t.Fatalf("shorten source deadline: %v", err)
	}

	if _, err := f.svc.SwitchOrganization(ctx, auth.SwitchOrganizationInput{
		RefreshToken: res.Token.RefreshToken, Organization: "globex",
	}); err != nil {
		t.Fatalf("SwitchOrganization() error = %v", err)
	}

	var sessionDeadline, tokenDeadline time.Time
	if err := f.pool.QueryRow(ctx, `
		SELECT s.absolute_expires_at, rt.expires_at
		FROM user_sessions s JOIN refresh_tokens rt ON rt.session_id = s.id
		WHERE s.user_id = $1
		  AND s.organization_id = (SELECT id FROM organizations WHERE public_id = $2)
	`, uid, globex.ID).Scan(&sessionDeadline, &tokenDeadline); err != nil {
		t.Fatalf("load switched session: %v", err)
	}
	if sessionDeadline.After(source) || tokenDeadline.After(source) {
		t.Errorf("switched session deadline %v / refresh token %v outlive the source deadline %v",
			sessionDeadline, tokenDeadline, source)
	}
}

// --- Selection completion (review comment 2) --------------------------------

// A selection token must not finish a sign-in for an account that was
// disabled, or signed out everywhere, while the list was on screen.
func TestOrganizations_SelectionRechecksTheAccount(t *testing.T) {
	setup := func(t *testing.T, name string) (orgFixture, int64, string) {
		t.Helper()
		f := newOrgFixture(t, name, auth.OrganizationsModeRequired)
		f.svc.WithTOTP(nil, testhelper.NewTestRedis(t)) // skips without REDIS_URL
		email := uniqueEmail(name)
		uid := f.registerUser(t, email)
		f.addMember(t, f.createOrg(t, "acme"), uid)
		f.addMember(t, f.createOrg(t, "globex"), uid)
		_, err := f.login(email, "")
		var sel *auth.OrganizationSelectionRequiredError
		if !errors.As(err, &sel) {
			t.Fatalf("Login() error = %v, want OrganizationSelectionRequiredError", err)
		}
		return f, uid, sel.SelectionToken
	}

	t.Run("user disabled", func(t *testing.T) {
		f, uid, token := setup(t, "sel-disabled")
		if _, err := f.pool.Exec(context.Background(),
			`UPDATE users SET is_active = false WHERE id = $1`, uid); err != nil {
			t.Fatalf("disable user: %v", err)
		}
		if _, err := f.svc.CompleteOrganizationSelection(context.Background(), token, "acme"); !errors.Is(err, auth.ErrOrganizationSelectionInvalid) {
			t.Errorf("CompleteOrganizationSelection() error = %v, want ErrOrganizationSelectionInvalid", err)
		}
	})

	t.Run("account-wide revocation", func(t *testing.T) {
		f, uid, token := setup(t, "sel-revoked")
		f.svc.DenyUserSessions(context.Background(), uid, f.tenantID)
		if _, err := f.svc.CompleteOrganizationSelection(context.Background(), token, "acme"); !errors.Is(err, auth.ErrOrganizationSelectionInvalid) {
			t.Errorf("CompleteOrganizationSelection() error = %v, want ErrOrganizationSelectionInvalid", err)
		}
	})
}

// --- Races (review comments 3 and 9) ----------------------------------------

// A removal that is in flight while a login mints must not leave a session the
// removal's revocation never saw. The DELETE is held uncommitted, the login is
// started, and once it is blocked on the membership lock the DELETE commits:
// the login must then fail rather than mint into the removed organisation.
func TestOrganizations_MintCannotEscapeAConcurrentRemoval(t *testing.T) {
	f := newOrgFixture(t, "org-mint-race", auth.OrganizationsModeOptional)
	email := uniqueEmail("mint-race")
	uid := f.registerUser(t, email)
	acme := f.createOrg(t, "acme")
	f.addMember(t, acme, uid)
	ctx := context.Background()

	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx,
		`DELETE FROM organization_members WHERE organization_id = $1 AND user_id = $2`,
		acme.RowID(), uid); err != nil {
		t.Fatalf("delete membership: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := f.login(email, "acme")
		done <- err
	}()
	waitForLockWait(t, f.pool, "FOR SHARE OF o, mem")
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit removal: %v", err)
	}

	select {
	case err := <-done:
		if !errors.Is(err, auth.ErrOrganizationAccessDenied) {
			t.Errorf("Login() racing a removal error = %v, want ErrOrganizationAccessDenied", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Login() did not return after the removal committed")
	}

	var n int
	if err := f.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM user_sessions
		WHERE user_id = $1 AND organization_id = $2 AND revoked_at IS NULL
	`, uid, acme.RowID()).Scan(&n); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if n != 0 {
		t.Errorf("%d live session(s) bound to the organisation after removal, want 0", n)
	}
}

// Acceptance must take the organisation lock before the invitation lock, the
// order CreateInvitation and DeleteOrganization use. The other side here holds
// the organisation lock and then writes the invitation, as DeleteOrganization
// does: in the old order that was a deadlock, now acceptance simply waits and
// then sees the invitation closed.
func TestOrganizations_AcceptInvitationLocksOrganizationFirst(t *testing.T) {
	f := newOrgFixture(t, "org-invite-lock", auth.OrganizationsModeOptional)
	acme := f.createOrg(t, "acme")
	ctx := context.Background()

	inv, err := f.orgs.CreateInvitation(ctx, f.scope, "acme", auth.CreateOrganizationInvitationInput{
		Email: uniqueEmail("invite-lock"),
	})
	if err != nil {
		t.Fatalf("CreateInvitation() error = %v", err)
	}

	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `SELECT 1 FROM organizations WHERE id = $1 FOR UPDATE`, acme.RowID()); err != nil {
		t.Fatalf("lock organization: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := f.orgs.AcceptInvitation(ctx, auth.AcceptOrganizationInvitationInput{
			Token: inv.Token, Password: "Password123!",
		})
		done <- err
	}()
	waitForLockWait(t, f.pool, "FROM organizations WHERE id = $1 FOR UPDATE")

	// With acceptance holding the invitation lock (the old order) this UPDATE
	// would wait on it while acceptance waits on us — a deadlock PostgreSQL
	// breaks by aborting one side.
	if _, err := tx.Exec(ctx, `
		UPDATE organization_invitations SET revoked_at = NOW()
		WHERE organization_id = $1 AND accepted_at IS NULL AND revoked_at IS NULL
	`, acme.RowID()); err != nil {
		t.Fatalf("close invitations while holding the organisation lock: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	select {
	case err := <-done:
		if !errors.Is(err, auth.ErrOrganizationInvitationInvalid) {
			t.Errorf("AcceptInvitation() error = %v, want ErrOrganizationInvitationInvalid", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("AcceptInvitation() did not return after the organisation lock was released")
	}
}
