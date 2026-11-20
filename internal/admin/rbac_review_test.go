package admin_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/engineersmind/emc-auth-server/internal/admin"
)

// A NUL in a name used to pass validation and then fail inside Postgres, so the
// commit answered 500 after validate had reported the row as "create".
func TestRBACImport_ControlCharactersAreRejectedNotA500(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()
	doc := admin.RBACImportDocument{
		Permissions: []admin.RBACImportPermission{
			{Name: "ok:perm", Description: "fine\nwith a newline"},
			{Name: "bad:desc", Description: "nul\x00desc"},
		},
		Roles: []admin.RBACImportRole{{Name: "nul\x00role", Permissions: []string{"ok:perm"}}},
	}

	val, err := f.svc.ValidateRBACImport(ctx, f.tenantID, f.appID, doc)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if val.Rejected != 2 {
		t.Fatalf("validate rejected %d rows, want 2 (description and role name): %+v", val.Rejected, val.Rows)
	}
	res, err := f.svc.CommitRBACImport(ctx, f.tenantID, f.appID, doc)
	if !errors.Is(err, admin.ErrRBACImportRejected) {
		t.Fatalf("commit err = %v, want ErrRBACImportRejected (never a 500)", err)
	}
	if res == nil || res.Rejected != 2 {
		t.Fatalf("commit report = %+v", res)
	}
}

// " admin" used to be created as a separate role that looks exactly like
// "admin" in the console.
func TestRBACImport_RoleNamesAreTrimmed(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()
	res, err := f.svc.CommitRBACImport(ctx, f.tenantID, f.appID, admin.RBACImportDocument{
		Permissions: []admin.RBACImportPermission{{Name: "a:read"}},
		Roles:       []admin.RBACImportRole{{Name: "  padded  ", Permissions: []string{"a:read"}}},
	})
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	if res.RolesCreated != 1 {
		t.Fatalf("result = %+v", res)
	}
	_, roles := rbacState(t, f)
	if _, ok := roles["padded"]; !ok {
		t.Errorf("role was not stored under its trimmed name: %v", roles)
	}
	if _, ok := roles["  padded  "]; ok {
		t.Errorf("role kept its surrounding whitespace: %v", roles)
	}

	// A padded duplicate of an unpadded name is a duplicate, not a second role.
	val, err := f.svc.ValidateRBACImport(ctx, f.tenantID, f.appID, admin.RBACImportDocument{
		Roles: []admin.RBACImportRole{{Name: "x"}, {Name: " x"}},
	})
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if val.Rejected != 1 {
		t.Errorf("padded duplicate was not caught: %+v", val.Rows)
	}
}

func TestRBACImport_InvalidModeIsAFileLevelError(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()
	doc := admin.RBACImportDocument{Mode: "overwrite", Permissions: []admin.RBACImportPermission{{Name: "a:b"}}}

	if _, err := f.svc.ValidateRBACImport(ctx, f.tenantID, f.appID, doc); !errors.Is(err, admin.ErrRBACImportInvalid) {
		t.Errorf("validate err = %v, want ErrRBACImportInvalid", err)
	}
	if _, err := f.svc.CommitRBACImport(ctx, f.tenantID, f.appID, doc); !errors.Is(err, admin.ErrRBACImportInvalid) {
		t.Errorf("commit err = %v, want ErrRBACImportInvalid", err)
	}
	perms, _ := rbacState(t, f)
	if len(perms) != 0 {
		t.Errorf("an invalid mode wrote %v", perms)
	}
}

// A validate call must not queue behind, or hold up, real writers. It used to
// take the same FOR UPDATE locks as the commit.
func TestRBACImport_ValidateDoesNotTakeRoleLocks(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()
	if _, err := f.svc.CommitRBACImport(ctx, f.tenantID, f.appID, rbacDoc()); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Hold the strongest row lock on the application's roles, as a competing
	// writer would.
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx,
		`SELECT 1 FROM roles WHERE tenant_id = $1 AND application_id = $2 FOR UPDATE`,
		f.tenantID, f.appID); err != nil {
		t.Fatalf("lock: %v", err)
	}

	vctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err := f.svc.ValidateRBACImport(vctx, f.tenantID, f.appID, rbacDoc()); err != nil {
		t.Fatalf("validate blocked or failed while another transaction held the role locks: %v", err)
	}
}

// Older roles can hold a tenant-level permission (no application). It is not in
// the application's permission list, so it must not appear in the export (the
// file would not re-import) and a replace import must not count it as removed
// (the DELETE could never remove it).
func TestRBACImport_TenantLevelPermissionOnARoleIsIgnored(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()
	if _, err := f.svc.CommitRBACImport(ctx, f.tenantID, f.appID, admin.RBACImportDocument{
		Permissions: []admin.RBACImportPermission{{Name: "a:read"}},
		Roles:       []admin.RBACImportRole{{Name: "legacy", Permissions: []string{"a:read"}}},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	var permID, roleID int64
	if err := f.pool.QueryRow(ctx, `
		INSERT INTO permissions (tenant_id, application_id, name, description)
		VALUES ($1, NULL, 'tenant:level', '') RETURNING id`, f.tenantID).Scan(&permID); err != nil {
		t.Fatalf("insert tenant-level permission: %v", err)
	}
	if err := f.pool.QueryRow(ctx, `
		SELECT id FROM roles WHERE tenant_id = $1 AND application_id = $2 AND name = 'legacy'`,
		f.tenantID, f.appID).Scan(&roleID); err != nil {
		t.Fatalf("find role: %v", err)
	}
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO role_permissions (role_id, permission_id, tenant_id) VALUES ($1, $2, $3)`,
		roleID, permID, f.tenantID); err != nil {
		t.Fatalf("grant tenant-level permission: %v", err)
	}

	doc, err := f.svc.ExportRBAC(ctx, f.tenantID, f.appID)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	for _, r := range doc.Roles {
		for _, p := range r.Permissions {
			if p == "tenant:level" {
				t.Fatalf("export lists a permission that is not in the application: %+v", r)
			}
		}
	}

	res, err := f.svc.ValidateRBACImport(ctx, f.tenantID, f.appID, admin.RBACImportDocument{
		Mode:  admin.RBACModeReplace,
		Roles: []admin.RBACImportRole{{Name: "legacy", Permissions: []string{"a:read"}}},
	})
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if res.RolesUpdated != 0 || res.RolesSkipped != 1 {
		t.Errorf("replace reported a removal it could not perform: %+v", res.Rows)
	}
}
