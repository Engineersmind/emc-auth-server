package auth_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"testing"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/password"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// Organizations (migrations 00100–00104).
//
// The first tests are the no-regression contract: an application that has not
// opted in must mint exactly the token it minted before organisations existed.
// The rest walk the behaviour table in the implementation plan — every mode,
// every refusal, and the isolation that keeps one application's organisations
// out of another's reach. Assertions are made on real minted and verified
// tokens, because the claims are what relying parties enforce.

type orgFixture struct {
	appRoleFixture
	orgs  *auth.OrganizationService
	scope auth.OrganizationScope
}

func newOrgFixture(t *testing.T, name, mode string) orgFixture {
	t.Helper()
	f := newAppRoleFixture(t, name)
	ctx := context.Background()

	orgs := auth.NewOrganizationService(f.pool, nil, true, testhelper.TestLogger()).
		WithHasher(password.NewHasher(password.DefaultParams()))
	f.svc.WithOrganizations(orgs)

	var appRowID int64
	if err := f.pool.QueryRow(ctx, `SELECT id FROM oauth_clients WHERE client_id = $1`,
		f.app.ClientID).Scan(&appRowID); err != nil {
		t.Fatalf("fetch app row id: %v", err)
	}
	sc := auth.OrganizationScope{TenantID: f.tenantID, AppRowID: appRowID}
	if mode != auth.OrganizationsModeOff {
		if _, err := orgs.SetApplicationMode(ctx, sc, mode, true); err != nil {
			t.Fatalf("SetApplicationMode(%s) error = %v", mode, err)
		}
	}
	return orgFixture{appRoleFixture: f, orgs: orgs, scope: sc}
}

func (f orgFixture) createOrg(t *testing.T, slug string) *auth.Organization {
	t.Helper()
	org, err := f.orgs.CreateOrganization(context.Background(), f.scope, auth.CreateOrganizationInput{
		Slug: slug, DisplayName: strings.ToUpper(slug[:1]) + slug[1:],
	})
	if err != nil {
		t.Fatalf("CreateOrganization(%s) error = %v", slug, err)
	}
	return org
}

func (f orgFixture) addMember(t *testing.T, org *auth.Organization, userID int64, roles ...string) {
	t.Helper()
	if _, _, err := f.orgs.AddMember(context.Background(), f.scope, org.ID, userID, roles, nil); err != nil {
		t.Fatalf("AddMember(%s) error = %v", org.Slug, err)
	}
}

func (f orgFixture) login(email, org string) (*auth.LoginResult, error) {
	return f.svc.Login(context.Background(), auth.LoginInput{
		ClientID: f.app.ClientID, ClientSecret: f.app.ClientSecret,
		Email: email, Password: "Password123!", Organization: org,
	})
}

func (f orgFixture) claimsOf(t *testing.T, token string) *auth.Claims {
	t.Helper()
	c, err := f.jwtSvc.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	return c
}

// claimKeys decodes a JWT payload and returns its sorted top-level keys,
// excluding the per-mint values (exp, iat, nbf, jti, sid).
func claimKeys(t *testing.T, token string) []string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token is not a JWT")
	}
	raw, err := decodeSegment(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	var keys []string
	for k := range m {
		switch k {
		case "exp", "iat", "nbf", "jti", "sid":
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func decodeSegment(seg string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(seg)
}

// --- No regression ---------------------------------------------------------

// The contract every live application depends on: with the feature switched
// on for the deployment but the application left in mode "off", a login that
// even names an organisation mints the same claim set as one that does not,
// and no org_* claim appears.
func TestOrganizations_ModeOffMintsTheUnchangedToken(t *testing.T) {
	f := newOrgFixture(t, "org-off", auth.OrganizationsModeOff)
	email := uniqueEmail("org-off")
	uid := f.registerUser(t, email)
	org := f.createOrg(t, "acme")
	f.addMember(t, org, uid)

	plain, err := f.login(email, "")
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	named, err := f.login(email, org.ID)
	if err != nil {
		t.Fatalf("Login(organization) error = %v, want the parameter ignored", err)
	}

	a, b := claimKeys(t, plain.Token.AccessToken), claimKeys(t, named.Token.AccessToken)
	if strings.Join(a, ",") != strings.Join(b, ",") {
		t.Errorf("claim keys differ: without org %v, with org %v", a, b)
	}
	for _, k := range b {
		if strings.HasPrefix(k, "org_") {
			t.Errorf("mode off minted %s; no org_* claim may appear", k)
		}
	}
}

// The deployment switch off is the whole-feature rollback: even an application
// whose database row says "required" behaves as "off".
func TestOrganizations_DeploymentSwitchOffOverridesApplicationMode(t *testing.T) {
	f := newOrgFixture(t, "org-switch-off", auth.OrganizationsModeRequired)
	email := uniqueEmail("org-switch-off")
	f.registerUser(t, email)

	f.svc.WithOrganizations(auth.NewOrganizationService(f.pool, nil, false, testhelper.TestLogger()))

	res, err := f.login(email, "")
	if err != nil {
		t.Fatalf("Login() error = %v, want an ordinary login while the feature is off", err)
	}
	if c := f.claimsOf(t, res.Token.AccessToken); c.OrgID != "" {
		t.Errorf("org_id = %q with the feature off, want none", c.OrgID)
	}
}

// --- Optional mode ---------------------------------------------------------

func TestOrganizations_OptionalMode(t *testing.T) {
	f := newOrgFixture(t, "org-optional", auth.OrganizationsModeOptional)
	grantRole(t, f.roleFixture, "org-admin", "docs:approve")
	grantRole(t, f.roleFixture, "org-viewer", "docs:read")

	email := uniqueEmail("sarah")
	uid := f.registerUser(t, email)
	acme, globex, other := f.createOrg(t, "acme"), f.createOrg(t, "globex"), f.createOrg(t, "initech")
	f.addMember(t, acme, uid, "org-admin")
	f.addMember(t, globex, uid, "org-viewer")

	t.Run("no organisation requested is a personal session", func(t *testing.T) {
		res, err := f.login(email, "")
		if err != nil {
			t.Fatalf("Login() error = %v", err)
		}
		if c := f.claimsOf(t, res.Token.AccessToken); c.OrgID != "" {
			t.Errorf("org_id = %q, want none", c.OrgID)
		}
	})

	t.Run("Admin at Acme", func(t *testing.T) {
		res, err := f.login(email, "acme")
		if err != nil {
			t.Fatalf("Login(acme) error = %v", err)
		}
		c := f.claimsOf(t, res.Token.AccessToken)
		if c.OrgID != acme.ID || c.OrgName != "acme" {
			t.Errorf("org claims = %q/%q, want %q/acme", c.OrgID, c.OrgName, acme.ID)
		}
		if !hasPerm(c.OrgPermissions, "docs:approve") || hasPerm(c.OrgPermissions, "docs:read") {
			t.Errorf("org_permissions = %v, want exactly Acme's admin grant", c.OrgPermissions)
		}
		// Application-wide claims keep their meaning: the org role is not in them.
		if hasPerm(c.Permissions, "docs:approve") {
			t.Errorf("permissions = %v; an organisation grant leaked into the application-wide claim", c.Permissions)
		}
	})

	t.Run("Viewer at Globex — the Sarah problem", func(t *testing.T) {
		res, err := f.login(email, globex.ID)
		if err != nil {
			t.Fatalf("Login(globex) error = %v", err)
		}
		c := f.claimsOf(t, res.Token.AccessToken)
		if hasPerm(c.OrgPermissions, "docs:approve") {
			t.Errorf("org_permissions = %v; Acme's admin grant must not reach Globex", c.OrgPermissions)
		}
		if !hasPerm(c.OrgPermissions, "docs:read") {
			t.Errorf("org_permissions = %v, want docs:read", c.OrgPermissions)
		}
	})

	t.Run("non-member, unknown and suspended all refuse alike", func(t *testing.T) {
		for _, ref := range []string{other.ID, "no-such-org", "org_AAAAAAAAAAAAAAAAAAAA"} {
			if _, err := f.login(email, ref); !errors.Is(err, auth.ErrOrganizationAccessDenied) {
				t.Errorf("Login(%s) error = %v, want ErrOrganizationAccessDenied", ref, err)
			}
		}
		if _, err := f.orgs.SetMemberStatus(context.Background(), f.scope, "globex", uid, auth.OrganizationMemberSuspended); err != nil {
			t.Fatalf("SetMemberStatus() error = %v", err)
		}
		if _, err := f.login(email, "globex"); !errors.Is(err, auth.ErrOrganizationAccessDenied) {
			t.Errorf("Login(suspended) error = %v, want ErrOrganizationAccessDenied", err)
		}
	})
}

// --- Required mode ---------------------------------------------------------

func TestOrganizations_RequiredMode(t *testing.T) {
	f := newOrgFixture(t, "org-required", auth.OrganizationsModeRequired)
	acme, globex := f.createOrg(t, "acme"), f.createOrg(t, "globex")

	t.Run("single membership is selected automatically", func(t *testing.T) {
		email := uniqueEmail("single")
		uid := f.registerUser(t, email)
		f.addMember(t, acme, uid)
		res, err := f.login(email, "")
		if err != nil {
			t.Fatalf("Login() error = %v", err)
		}
		if c := f.claimsOf(t, res.Token.AccessToken); c.OrgID != acme.ID {
			t.Errorf("org_id = %q, want %q", c.OrgID, acme.ID)
		}
	})

	t.Run("no membership is refused and creates no session", func(t *testing.T) {
		email := uniqueEmail("none")
		uid := f.registerUser(t, email)
		if _, err := f.login(email, ""); !errors.Is(err, auth.ErrOrganizationAccessDenied) {
			t.Fatalf("Login() error = %v, want ErrOrganizationAccessDenied", err)
		}
		var n int
		if err := f.pool.QueryRow(context.Background(),
			`SELECT COUNT(*) FROM user_sessions WHERE user_id = $1`, uid).Scan(&n); err != nil {
			t.Fatalf("count sessions: %v", err)
		}
		if n != 0 {
			t.Errorf("sessions = %d after a refused login, want 0", n)
		}
	})

	t.Run("personal switch is refused", func(t *testing.T) {
		email := uniqueEmail("personal")
		uid := f.registerUser(t, email)
		f.addMember(t, acme, uid)
		res, err := f.login(email, "")
		if err != nil {
			t.Fatalf("Login() error = %v", err)
		}
		_, err = f.svc.SwitchOrganization(context.Background(), auth.SwitchOrganizationInput{
			RefreshToken: res.Token.RefreshToken, Personal: true,
		})
		if !errors.Is(err, auth.ErrOrganizationAccessDenied) {
			t.Errorf("SwitchOrganization(personal) error = %v, want ErrOrganizationAccessDenied", err)
		}
	})

	t.Run("several memberships ask for a choice", func(t *testing.T) {
		rdb := testhelper.NewTestRedis(t) // skips without REDIS_URL
		f.svc.WithTOTP(nil, rdb)
		email := uniqueEmail("several")
		uid := f.registerUser(t, email)
		f.addMember(t, acme, uid)
		f.addMember(t, globex, uid)

		_, err := f.login(email, "")
		var sel *auth.OrganizationSelectionRequiredError
		if !errors.As(err, &sel) {
			t.Fatalf("Login() error = %v, want OrganizationSelectionRequiredError", err)
		}
		if len(sel.Organizations) != 2 {
			t.Errorf("choices = %v, want both organisations", sel.Organizations)
		}
		tok, err := f.svc.CompleteOrganizationSelection(context.Background(), sel.SelectionToken, globex.ID)
		if err != nil {
			t.Fatalf("CompleteOrganizationSelection() error = %v", err)
		}
		if c := f.claimsOf(t, tok.AccessToken); c.OrgID != globex.ID {
			t.Errorf("org_id = %q, want %q", c.OrgID, globex.ID)
		}
		if _, err := f.svc.CompleteOrganizationSelection(context.Background(), sel.SelectionToken, globex.ID); !errors.Is(err, auth.ErrOrganizationSelectionInvalid) {
			t.Errorf("replayed selection error = %v, want ErrOrganizationSelectionInvalid", err)
		}
	})
}

// Moving to "required" while users would be locked out must be a deliberate act.
func TestOrganizations_RequiredModeRefusedWhileUsersHaveNoOrganization(t *testing.T) {
	f := newOrgFixture(t, "org-unmet", auth.OrganizationsModeOff)
	f.registerUser(t, uniqueEmail("orphan"))

	_, err := f.orgs.SetApplicationMode(context.Background(), f.scope, auth.OrganizationsModeRequired, false)
	var unmet *auth.OrganizationsModeUnmetError
	if !errors.As(err, &unmet) || unmet.UsersWithoutMembership != 1 {
		t.Fatalf("SetApplicationMode(required) error = %v, want OrganizationsModeUnmetError{1}", err)
	}
	if _, err := f.orgs.SetApplicationMode(context.Background(), f.scope, auth.OrganizationsModeRequired, true); err != nil {
		t.Errorf("SetApplicationMode(required, force) error = %v", err)
	}
}

// --- Refresh, switching and revocation -------------------------------------

func TestOrganizations_RefreshFollowsTheMembership(t *testing.T) {
	f := newOrgFixture(t, "org-refresh", auth.OrganizationsModeOptional)
	grantRole(t, f.roleFixture, "org-admin", "docs:approve")
	email := uniqueEmail("refresh")
	uid := f.registerUser(t, email)
	acme := f.createOrg(t, "acme")
	f.addMember(t, acme, uid)
	ctx := context.Background()

	res, err := f.login(email, "acme")
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	// A role granted mid-session arrives at the next refresh.
	if _, err := f.orgs.AssignMemberRoles(ctx, f.scope, "acme", uid, []string{"org-admin"}, false, nil); err != nil {
		t.Fatalf("AssignMemberRoles() error = %v", err)
	}
	rotated, err := f.svc.Refresh(ctx, res.Token.RefreshToken)
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	c := f.claimsOf(t, rotated.AccessToken)
	if c.OrgID != acme.ID || !hasPerm(c.OrgPermissions, "docs:approve") {
		t.Errorf("after refresh org_id=%q org_permissions=%v, want Acme with docs:approve", c.OrgID, c.OrgPermissions)
	}

	// Removal ends the session at the next refresh — never a quiet downgrade to
	// an organisation-less token.
	if err := f.orgs.RemoveMember(ctx, f.scope, "acme", uid); err != nil {
		t.Fatalf("RemoveMember() error = %v", err)
	}
	if _, err := f.svc.Refresh(ctx, rotated.RefreshToken); !errors.Is(err, auth.ErrInvalidRefreshToken) {
		t.Errorf("Refresh() after removal error = %v, want ErrInvalidRefreshToken", err)
	}
}

func TestOrganizations_ModeOffEndsOrganizationSessions(t *testing.T) {
	f := newOrgFixture(t, "org-mode-back", auth.OrganizationsModeOptional)
	email := uniqueEmail("mode-back")
	uid := f.registerUser(t, email)
	acme := f.createOrg(t, "acme")
	f.addMember(t, acme, uid)
	ctx := context.Background()

	res, err := f.login(email, "acme")
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	if _, err := f.orgs.SetApplicationMode(ctx, f.scope, auth.OrganizationsModeOff, false); err != nil {
		t.Fatalf("SetApplicationMode(off) error = %v", err)
	}
	if _, err := f.svc.Refresh(ctx, res.Token.RefreshToken); !errors.Is(err, auth.ErrInvalidRefreshToken) {
		t.Errorf("Refresh() after mode off error = %v, want ErrInvalidRefreshToken", err)
	}
	again, err := f.login(email, "")
	if err != nil {
		t.Fatalf("Login() after mode off error = %v", err)
	}
	if c := f.claimsOf(t, again.Token.AccessToken); c.OrgID != "" {
		t.Errorf("org_id = %q after mode off, want none", c.OrgID)
	}
}

func TestOrganizations_SwitchKeepsTheOriginalAuthentication(t *testing.T) {
	f := newOrgFixture(t, "org-switch", auth.OrganizationsModeOptional)
	email := uniqueEmail("switch")
	uid := f.registerUser(t, email)
	acme, globex, other := f.createOrg(t, "acme"), f.createOrg(t, "globex"), f.createOrg(t, "initech")
	f.addMember(t, acme, uid)
	f.addMember(t, globex, uid)
	ctx := context.Background()

	res, err := f.login(email, "acme")
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	switched, err := f.svc.SwitchOrganization(ctx, auth.SwitchOrganizationInput{
		RefreshToken: res.Token.RefreshToken, Organization: "globex",
	})
	if err != nil {
		t.Fatalf("SwitchOrganization() error = %v", err)
	}
	if c := f.claimsOf(t, switched.AccessToken); c.OrgID != globex.ID {
		t.Errorf("org_id = %q after switch, want %q", c.OrgID, globex.ID)
	}

	// The new session inherits the original sign-in: same auth_time and the
	// same absolute deadline, so switching cannot extend a session.
	var sameAuth, sameDeadline bool
	if err := f.pool.QueryRow(ctx, `
		SELECT a.auth_time = b.auth_time, a.absolute_expires_at = b.absolute_expires_at
		FROM user_sessions a, user_sessions b
		WHERE a.user_id = $1 AND b.user_id = $1
		  AND a.organization_id = (SELECT id FROM organizations WHERE public_id = $2)
		  AND b.organization_id = (SELECT id FROM organizations WHERE public_id = $3)
	`, uid, acme.ID, globex.ID).Scan(&sameAuth, &sameDeadline); err != nil {
		t.Fatalf("compare sessions: %v", err)
	}
	if !sameAuth || !sameDeadline {
		t.Errorf("switched session auth_time equal=%v, absolute deadline equal=%v; want both", sameAuth, sameDeadline)
	}

	if _, err := f.svc.SwitchOrganization(ctx, auth.SwitchOrganizationInput{
		RefreshToken: res.Token.RefreshToken, Organization: other.ID,
	}); !errors.Is(err, auth.ErrOrganizationAccessDenied) {
		t.Errorf("SwitchOrganization(non-member) error = %v, want ErrOrganizationAccessDenied", err)
	}
}

// --- Isolation -------------------------------------------------------------

func TestOrganizations_ApplicationIsolation(t *testing.T) {
	f := newOrgFixture(t, "org-isolation", auth.OrganizationsModeOptional)
	ctx := context.Background()
	acme := f.createOrg(t, "acme")

	// A user of the sibling application.
	if _, err := f.svc.Register(ctx, auth.RegisterInput{
		ClientID: f.otherApp.ClientID, ClientSecret: f.otherApp.ClientSecret,
		Email: uniqueEmail("sibling"), Password: "Password123!",
	}); err != nil {
		t.Fatalf("Register(sibling) error = %v", err)
	}
	var siblingUser, siblingApp int64
	if err := f.pool.QueryRow(ctx, `
		SELECT u.id, u.application_id FROM users u
		JOIN oauth_clients oc ON oc.id = u.application_id
		WHERE oc.client_id = $1`, f.otherApp.ClientID).Scan(&siblingUser, &siblingApp); err != nil {
		t.Fatalf("fetch sibling user: %v", err)
	}

	if _, _, err := f.orgs.AddMember(ctx, f.scope, acme.ID, siblingUser, nil, nil); !errors.Is(err, auth.ErrUserNotInApplication) {
		t.Errorf("AddMember(sibling user) error = %v, want ErrUserNotInApplication", err)
	}

	// The database refuses it too, whatever the service layer does.
	_, err := f.pool.Exec(ctx, `
		INSERT INTO organization_members (organization_id, application_id, user_id, tenant_id)
		VALUES ($1, $2, $3, $4)`, acme.RowID(), f.scope.AppRowID, siblingUser, f.tenantID)
	if err == nil {
		t.Error("direct insert of a cross-application member succeeded; the trigger must refuse it")
	}

	// The sibling application cannot see this application's organisation.
	siblingScope := auth.OrganizationScope{TenantID: f.tenantID, AppRowID: siblingApp}
	if _, err := f.orgs.GetOrganization(ctx, siblingScope, acme.ID); !errors.Is(err, auth.ErrOrganizationNotFound) {
		t.Errorf("GetOrganization from sibling error = %v, want ErrOrganizationNotFound", err)
	}

	// Nor grant its roles inside it.
	email := uniqueEmail("member")
	uid := f.registerUser(t, email)
	f.addMember(t, acme, uid)
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO roles (tenant_id, application_id, name, is_system, is_default, created_at)
		VALUES ($1, $2, 'sibling-admin', false, false, NOW())`, f.tenantID, siblingApp); err != nil {
		t.Fatalf("insert sibling role: %v", err)
	}
	if _, err := f.orgs.AssignMemberRoles(ctx, f.scope, acme.ID, uid, []string{"sibling-admin"}, false, nil); !errors.Is(err, auth.ErrRoleNotInApplication) {
		t.Errorf("AssignMemberRoles(sibling role) error = %v, want ErrRoleNotInApplication", err)
	}
}

func TestOrganizations_SlugRules(t *testing.T) {
	f := newOrgFixture(t, "org-slugs", auth.OrganizationsModeOff)
	ctx := context.Background()
	f.createOrg(t, "acme")
	for _, bad := range []string{"", "-acme", "acme-", "Acme Corp", strings.Repeat("a", 64)} {
		if _, err := f.orgs.CreateOrganization(ctx, f.scope, auth.CreateOrganizationInput{Slug: bad, DisplayName: "X"}); !errors.Is(err, auth.ErrInvalidOrganizationSlug) {
			t.Errorf("CreateOrganization(%q) error = %v, want ErrInvalidOrganizationSlug", bad, err)
		}
	}
	if _, err := f.orgs.CreateOrganization(ctx, f.scope, auth.CreateOrganizationInput{Slug: "ACME", DisplayName: "Dup"}); !errors.Is(err, auth.ErrOrganizationSlugTaken) {
		t.Errorf("duplicate slug error = %v, want ErrOrganizationSlugTaken", err)
	}
}

// --- Invitations -----------------------------------------------------------

func TestOrganizations_InvitationCreatesAccountMembershipAndRoles(t *testing.T) {
	f := newOrgFixture(t, "org-invite", auth.OrganizationsModeOptional)
	grantRole(t, f.roleFixture, "org-admin", "docs:approve")
	acme := f.createOrg(t, "acme")
	ctx := context.Background()

	email := uniqueEmail("invitee")
	inv, err := f.orgs.CreateInvitation(ctx, f.scope, "acme", auth.CreateOrganizationInvitationInput{
		Email: email, Roles: []string{"org-admin"},
	})
	if err != nil {
		t.Fatalf("CreateInvitation() error = %v", err)
	}
	preview, err := f.orgs.PreviewInvitation(ctx, inv.Token)
	if err != nil || preview.AccountExists || preview.Organization.ID != acme.ID {
		t.Fatalf("PreviewInvitation() = %+v, %v; want a new-account invitation to Acme", preview, err)
	}

	res, err := f.orgs.AcceptInvitation(ctx, auth.AcceptOrganizationInvitationInput{
		Token: inv.Token, Password: "Password123!", FirstName: "Ina",
	})
	if err != nil {
		t.Fatalf("AcceptInvitation() error = %v", err)
	}
	if !res.AccountCreated || len(res.Roles) != 1 || res.Roles[0] != "org-admin" {
		t.Errorf("accepted = %+v, want a new account holding org-admin", res)
	}

	login, err := f.login(email, "acme")
	if err != nil {
		t.Fatalf("Login(acme) after acceptance error = %v", err)
	}
	if c := f.claimsOf(t, login.Token.AccessToken); !hasPerm(c.OrgPermissions, "docs:approve") {
		t.Errorf("org_permissions = %v, want docs:approve from the invitation", c.OrgPermissions)
	}

	if _, err := f.orgs.AcceptInvitation(ctx, auth.AcceptOrganizationInvitationInput{
		Token: inv.Token, Password: "Password123!",
	}); !errors.Is(err, auth.ErrOrganizationInvitationInvalid) {
		t.Errorf("second acceptance error = %v, want ErrOrganizationInvitationInvalid", err)
	}
}

func TestOrganizations_InvitationRefusesTheWrongAccount(t *testing.T) {
	f := newOrgFixture(t, "org-invite-wrong", auth.OrganizationsModeOptional)
	f.createOrg(t, "acme")
	ctx := context.Background()

	inv, err := f.orgs.CreateInvitation(ctx, f.scope, "acme", auth.CreateOrganizationInvitationInput{
		Email: uniqueEmail("intended"),
	})
	if err != nil {
		t.Fatalf("CreateInvitation() error = %v", err)
	}
	someoneElse := f.registerUser(t, uniqueEmail("someone-else"))
	if _, err := f.orgs.AcceptInvitation(ctx, auth.AcceptOrganizationInvitationInput{
		Token: inv.Token, ExistingUserID: &someoneElse, AppRowID: f.scope.AppRowID,
	}); !errors.Is(err, auth.ErrOrganizationInvitationInvalid) {
		t.Errorf("AcceptInvitation(other account) error = %v, want ErrOrganizationInvitationInvalid", err)
	}
}

func TestOrganizations_InvitationURLMustBeARegisteredOrigin(t *testing.T) {
	f := newOrgFixture(t, "org-invite-url", auth.OrganizationsModeOptional)
	f.createOrg(t, "acme")
	_, err := f.orgs.CreateInvitation(context.Background(), f.scope, "acme", auth.CreateOrganizationInvitationInput{
		Email: uniqueEmail("phish"), InvitationURL: "https://attacker.example/accept",
	})
	if !errors.Is(err, auth.ErrInvalidInvitationURL) {
		t.Errorf("CreateInvitation(foreign URL) error = %v, want ErrInvalidInvitationURL", err)
	}
}

// --- Authorization code and introspection ----------------------------------

func TestOrganizations_AuthorizationCodeCarriesTheOrganization(t *testing.T) {
	f := newOrgFixture(t, "org-code", auth.OrganizationsModeRequired)
	email := uniqueEmail("code")
	uid := f.registerUser(t, email)
	acme := f.createOrg(t, "acme")
	f.addMember(t, acme, uid)
	ctx := context.Background()

	orgRow := acme.RowID()
	issued, err := f.svc.IssueTokensForAuthorizationCode(ctx, f.tenantID, uid, f.scope.AppRowID, []string{"openid"}, "", &orgRow)
	if err != nil {
		t.Fatalf("IssueTokensForAuthorizationCode() error = %v", err)
	}
	if c := f.claimsOf(t, issued.Tokens.AccessToken); c.OrgID != acme.ID {
		t.Errorf("org_id = %q, want %q", c.OrgID, acme.ID)
	}

	if err := f.orgs.RemoveMember(ctx, f.scope, acme.ID, uid); err != nil {
		t.Fatalf("RemoveMember() error = %v", err)
	}
	if _, err := f.svc.IssueTokensForAuthorizationCode(ctx, f.tenantID, uid, f.scope.AppRowID, nil, "", &orgRow); !errors.Is(err, auth.ErrOrganizationAccessDenied) {
		t.Errorf("exchange after removal error = %v, want ErrOrganizationAccessDenied", err)
	}
}

func TestOrganizations_IntrospectionIsLive(t *testing.T) {
	f := newOrgFixture(t, "org-introspect", auth.OrganizationsModeOptional)
	email := uniqueEmail("introspect")
	uid := f.registerUser(t, email)
	acme := f.createOrg(t, "acme")
	f.addMember(t, acme, uid)
	ctx := context.Background()

	res, err := f.login(email, "acme")
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	client := auth.IntrospectionClient{ClientID: f.app.ClientID, TenantID: f.tenantID, AppRowID: f.scope.AppRowID}

	got := f.svc.Introspect(ctx, client, res.Token.AccessToken, "")
	if !got.Active || got.OrgID != acme.ID || got.Sub == "" {
		t.Fatalf("Introspect() = %+v, want active with org_id %s", got, acme.ID)
	}
	if rt := f.svc.Introspect(ctx, client, res.Token.RefreshToken, "refresh_token"); !rt.Active || rt.OrgID != acme.ID {
		t.Errorf("Introspect(refresh) = %+v, want active in Acme", rt)
	}

	// Another application's credentials see nothing.
	sibling := auth.IntrospectionClient{ClientID: f.otherApp.ClientID, TenantID: f.tenantID, AppRowID: f.scope.AppRowID + 1_000_000}
	if f.svc.Introspect(ctx, sibling, res.Token.AccessToken, "").Active {
		t.Error("a different application's client saw the token as active")
	}

	// The live check sees a removal the JWT itself cannot.
	if err := f.orgs.RemoveMember(ctx, f.scope, acme.ID, uid); err != nil {
		t.Fatalf("RemoveMember() error = %v", err)
	}
	if after := f.svc.Introspect(ctx, client, res.Token.AccessToken, ""); after.Active {
		t.Errorf("Introspect() after removal = %+v, want inactive", after)
	}
	if after := f.svc.Introspect(ctx, client, "not-a-token", ""); after.Active {
		t.Error("garbage token introspected as active")
	}
}
