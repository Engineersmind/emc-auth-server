package admin_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/engineersmind/emc-auth-server/internal/admin"
)

// A tenant with no row of its own inherits the platform policy, and MFA is
// reported as required whatever the methods.
func TestAdminMFAPolicy_InheritsPlatformUntilSet(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()
	tenantID, _ := newAdminTenant(t, f, "admin-mfa-inherit")

	view, err := f.svc.GetAdminMFAPolicy(ctx, tenantID)
	if err != nil {
		t.Fatalf("GetAdminMFAPolicy: %v", err)
	}
	if !view.Inherited || view.Scope != "platform" || !view.MFARequired {
		t.Errorf("view = %+v, want an inherited platform policy with MFA required", view)
	}
	if len(view.AllowedMethods) == 0 {
		t.Error("inherited policy allows no methods")
	}

	set, err := f.svc.SetAdminMFAPolicy(ctx, tenantID, nil, admin.AdminMFAPolicyInput{
		AllowedMethods: []string{"email", "totp"},
	})
	if err != nil {
		t.Fatalf("SetAdminMFAPolicy: %v", err)
	}
	if set.Inherited || set.Scope != "tenant" {
		t.Errorf("after set: %+v, want the tenant's own policy", set)
	}
	// Stored and returned in presentation order, whatever order was sent.
	if want := []string{"totp", "email"}; !slices.Equal(set.AllowedMethods, want) {
		t.Errorf("AllowedMethods = %v, want %v", set.AllowedMethods, want)
	}

	if err := f.svc.DeleteAdminMFAPolicy(ctx, tenantID); err != nil {
		t.Fatalf("DeleteAdminMFAPolicy: %v", err)
	}
	back, err := f.svc.GetAdminMFAPolicy(ctx, tenantID)
	if err != nil {
		t.Fatalf("GetAdminMFAPolicy after reset: %v", err)
	}
	if !back.Inherited {
		t.Errorf("after reset: %+v, want inherited again", back)
	}
	if err := f.svc.DeleteAdminMFAPolicy(ctx, tenantID); !errors.Is(err, admin.ErrNotFound) {
		t.Errorf("second reset: err = %v, want ErrNotFound", err)
	}
}

// At least one method must always remain: an empty set would lock every
// administrator of the tenant out.
func TestAdminMFAPolicy_RejectsInvalidSets(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()
	tenantID, _ := newAdminTenant(t, f, "admin-mfa-invalid")

	for _, methods := range [][]string{nil, {}, {"sms"}, {"totp", "totp"}} {
		_, err := f.svc.SetAdminMFAPolicy(ctx, tenantID, nil, admin.AdminMFAPolicyInput{AllowedMethods: methods})
		if !errors.Is(err, admin.ErrInvalidAdminMFAPolicy) {
			t.Errorf("SetAdminMFAPolicy(%v): err = %v, want ErrInvalidAdminMFAPolicy", methods, err)
		}
	}
	if err := f.svc.DeleteAdminMFAPolicy(ctx, 0); !errors.Is(err, admin.ErrInvalidAdminMFAPolicy) {
		t.Errorf("deleting the platform policy: err = %v, want ErrInvalidAdminMFAPolicy", err)
	}
}

// The platform policy is editable and governs tenants without their own row.
func TestAdminMFAPolicy_PlatformPolicyGovernsInheritingTenants(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()
	tenantID, _ := newAdminTenant(t, f, "admin-mfa-platform")

	original, err := f.svc.GetAdminMFAPolicy(ctx, 0)
	if err != nil {
		t.Fatalf("GetAdminMFAPolicy(platform): %v", err)
	}
	t.Cleanup(func() {
		_, _ = f.svc.SetAdminMFAPolicy(context.Background(), 0, nil,
			admin.AdminMFAPolicyInput{AllowedMethods: original.AllowedMethods})
	})

	if _, err := f.svc.SetAdminMFAPolicy(ctx, 0, nil, admin.AdminMFAPolicyInput{AllowedMethods: []string{"totp"}}); err != nil {
		t.Fatalf("SetAdminMFAPolicy(platform): %v", err)
	}
	view, err := f.svc.GetAdminMFAPolicy(ctx, tenantID)
	if err != nil {
		t.Fatalf("GetAdminMFAPolicy(tenant): %v", err)
	}
	if !slices.Equal(view.AllowedMethods, []string{"totp"}) || !view.Inherited {
		t.Errorf("tenant view = %+v, want the platform's [totp], inherited", view)
	}
}

// The reset path resolves an administrator record to the account behind it,
// and never reaches across tenants.
func TestAdministratorForReset_ScopedToTheTenant(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()
	tenantA, adminA := newAdminTenant(t, f, "admin-mfa-reset-a")
	tenantB, _ := newAdminTenant(t, f, "admin-mfa-reset-b")

	userID, home, err := f.svc.AdministratorForReset(ctx, tenantA, adminA)
	if err != nil {
		t.Fatalf("AdministratorForReset: %v", err)
	}
	if userID == 0 || home != tenantA {
		t.Errorf("resolved user=%d home=%d, want a user homed in tenant %d", userID, home, tenantA)
	}
	if _, _, err := f.svc.AdministratorForReset(ctx, tenantB, adminA); !errors.Is(err, admin.ErrNotFound) {
		t.Errorf("tenant B resolving tenant A's administrator: err = %v, want ErrNotFound", err)
	}
}
