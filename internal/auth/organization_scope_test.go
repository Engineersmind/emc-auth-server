package auth_test

import (
	"context"
	"errors"
	"testing"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// The rate limiter trusts a backend only for its own application's tokens, so
// these lookups must name the owning tenant and application, must not consume
// the token, and must stop resolving once the token is spent.

func TestInvitationScope_NamesTheOwningApplicationAndStopsAfterAcceptance(t *testing.T) {
	f := newOrgFixture(t, "org-scope-invite", auth.OrganizationsModeOptional)
	f.createOrg(t, "acme")
	ctx := context.Background()

	inv, err := f.orgs.CreateInvitation(ctx, f.scope, "acme", auth.CreateOrganizationInvitationInput{Email: uniqueEmail("scope")})
	if err != nil {
		t.Fatalf("CreateInvitation() error = %v", err)
	}
	for i := 0; i < 2; i++ { // read only: asking twice changes nothing
		tenantID, appID, ok := f.orgs.InvitationScope(ctx, inv.Token)
		if !ok || tenantID != f.scope.TenantID || appID != f.scope.AppRowID {
			t.Fatalf("InvitationScope() = %d, %d, %v; want %d, %d, true", tenantID, appID, ok, f.scope.TenantID, f.scope.AppRowID)
		}
	}
	if _, _, ok := f.orgs.InvitationScope(ctx, "not-a-token"); ok {
		t.Error("an unknown token resolved")
	}
	if _, _, ok := f.orgs.InvitationScope(ctx, ""); ok {
		t.Error("an empty token resolved")
	}

	if _, err := f.orgs.AcceptInvitation(ctx, auth.AcceptOrganizationInvitationInput{
		Token: inv.Token, Password: "Password123!",
	}); err != nil {
		t.Fatalf("AcceptInvitation() error = %v", err)
	}
	if _, _, ok := f.orgs.InvitationScope(ctx, inv.Token); ok {
		t.Error("a used invitation still resolved")
	}
}

func TestOrganizationSelectionScope_NamesTheOwningApplicationAndDoesNotConsume(t *testing.T) {
	f := newOrgFixture(t, "org-scope-select", auth.OrganizationsModeOptional)
	rdb := testhelper.NewTestRedis(t) // skips without REDIS_URL
	f.svc.WithTOTP(nil, rdb)
	acme, globex := f.createOrg(t, "acme"), f.createOrg(t, "globex")
	email := uniqueEmail("scope-select")
	uid := f.registerUser(t, email)
	f.addMember(t, acme, uid)
	f.addMember(t, globex, uid)
	ctx := context.Background()

	_, err := f.login(email, "")
	var sel *auth.OrganizationSelectionRequiredError
	if !errors.As(err, &sel) {
		t.Fatalf("Login() error = %v, want OrganizationSelectionRequiredError", err)
	}
	for i := 0; i < 2; i++ {
		tenantID, appID, ok := f.svc.OrganizationSelectionScope(ctx, sel.SelectionToken)
		if !ok || tenantID != f.scope.TenantID || appID != f.scope.AppRowID {
			t.Fatalf("OrganizationSelectionScope() = %d, %d, %v; want %d, %d, true", tenantID, appID, ok, f.scope.TenantID, f.scope.AppRowID)
		}
	}
	if _, _, ok := f.svc.OrganizationSelectionScope(ctx, "not-a-token"); ok {
		t.Error("an unknown selection token resolved")
	}
	// Looking it up did not spend it.
	if _, err := f.svc.CompleteOrganizationSelection(ctx, sel.SelectionToken, globex.ID); err != nil {
		t.Fatalf("CompleteOrganizationSelection() after scope lookups error = %v", err)
	}
	if _, _, ok := f.svc.OrganizationSelectionScope(ctx, sel.SelectionToken); ok {
		t.Error("a completed selection still resolved")
	}
}
