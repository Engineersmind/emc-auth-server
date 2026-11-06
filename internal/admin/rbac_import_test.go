package admin_test

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/engineersmind/emc-auth-server/internal/admin"
	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

func rbacDoc() admin.RBACImportDocument {
	return admin.RBACImportDocument{
		Permissions: []admin.RBACImportPermission{
			{Name: "claims:read", Description: "View claims"},
			{Name: "claims:write", Description: "Edit claims"},
			{Name: "reports:read", Description: "View reports"},
		},
		Roles: []admin.RBACImportRole{
			{Name: "viewer", Permissions: []string{"claims:read", "reports:read"}},
			{Name: "manager", Permissions: []string{"claims:read", "claims:write"}},
		},
	}
}

// rbacState reads the application's permission and role->permission names.
func rbacState(t *testing.T, f adminFixture) (perms []string, roles map[string][]string) {
	t.Helper()
	ctx := context.Background()
	pl, err := f.svc.ListPermissions(ctx, f.tenantID, &f.appID)
	if err != nil {
		t.Fatalf("ListPermissions: %v", err)
	}
	for _, p := range pl {
		perms = append(perms, p.Name)
	}
	sort.Strings(perms)
	rl, err := f.svc.ListRoles(ctx, f.tenantID, &f.appID)
	if err != nil {
		t.Fatalf("ListRoles: %v", err)
	}
	roles = map[string][]string{}
	for _, r := range rl {
		names := []string{}
		for _, p := range r.Permissions {
			names = append(names, p.Name)
		}
		sort.Strings(names)
		roles[r.Name] = names
	}
	return perms, roles
}

func eq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestRBACImport_CreatesAndMaps(t *testing.T) {
	f := newAdminFixture(t)
	res, err := f.svc.CommitRBACImport(context.Background(), f.tenantID, f.appID, rbacDoc())
	if err != nil {
		t.Fatalf("CommitRBACImport: %v", err)
	}
	if res.PermissionsCreated != 3 || res.RolesCreated != 2 || res.Rejected != 0 {
		t.Fatalf("result = %+v", res)
	}
	perms, roles := rbacState(t, f)
	if !eq(perms, []string{"claims:read", "claims:write", "reports:read"}) {
		t.Errorf("permissions = %v", perms)
	}
	if !eq(roles["viewer"], []string{"claims:read", "reports:read"}) ||
		!eq(roles["manager"], []string{"claims:read", "claims:write"}) {
		t.Errorf("roles = %v", roles)
	}
}

func TestRBACImport_RerunIsNoOp(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()
	if _, err := f.svc.CommitRBACImport(ctx, f.tenantID, f.appID, rbacDoc()); err != nil {
		t.Fatalf("first import: %v", err)
	}
	res, err := f.svc.CommitRBACImport(ctx, f.tenantID, f.appID, rbacDoc())
	if err != nil {
		t.Fatalf("second import: %v", err)
	}
	if res.PermissionsCreated != 0 || res.RolesCreated != 0 || res.RolesUpdated != 0 ||
		res.PermissionsSkipped != 3 || res.RolesSkipped != 2 {
		t.Errorf("re-run changed something: %+v", res)
	}
}

// Any rejected row means NOTHING is written — including the rows that were fine.
func TestRBACImport_RejectedRowWritesNothing(t *testing.T) {
	f := newAdminFixture(t)
	doc := rbacDoc()
	doc.Roles = append(doc.Roles, admin.RBACImportRole{Name: "broken", Permissions: []string{"does:not-exist"}})

	res, err := f.svc.CommitRBACImport(context.Background(), f.tenantID, f.appID, doc)
	if !errors.Is(err, admin.ErrRBACImportRejected) {
		t.Fatalf("err = %v, want ErrRBACImportRejected", err)
	}
	if res == nil || res.Rejected != 1 {
		t.Fatalf("result = %+v, want 1 rejected", res)
	}
	perms, roles := rbacState(t, f)
	if len(perms) != 0 || len(roles) != 0 {
		t.Errorf("rolled-back import left rows: perms=%v roles=%v", perms, roles)
	}
}

func TestRBACImport_ValidateWritesNothingAndReports(t *testing.T) {
	f := newAdminFixture(t)
	res, err := f.svc.ValidateRBACImport(context.Background(), f.tenantID, f.appID, rbacDoc())
	if err != nil {
		t.Fatalf("ValidateRBACImport: %v", err)
	}
	if !res.DryRun || res.PermissionsCreated != 3 || res.RolesCreated != 2 {
		t.Errorf("result = %+v", res)
	}
	perms, roles := rbacState(t, f)
	if len(perms) != 0 || len(roles) != 0 {
		t.Errorf("validate wrote rows: perms=%v roles=%v", perms, roles)
	}

	// A validate with a bad row returns the report, not an error.
	bad := rbacDoc()
	bad.Permissions[0].Name = "Bad Name!"
	res, err = f.svc.ValidateRBACImport(context.Background(), f.tenantID, f.appID, bad)
	if err != nil || res.Rejected == 0 {
		t.Errorf("validate of bad file: err=%v res=%+v", err, res)
	}
}

// A role may only reference permissions of ITS application. A name that exists
// only in another application is unknown here.
func TestRBACImport_PermissionFromAnotherApplicationIsUnknown(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	appSvc := auth.NewApplicationService(f.pool, testhelper.TestLogger())
	other, err := appSvc.CreateApplication(ctx, f.tenantID, "rbac-other-app-"+time.Now().Format("150405.000000000"), "web", nil)
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}
	var otherID int64
	if err := f.pool.QueryRow(ctx, `SELECT id FROM oauth_clients WHERE client_id = $1`, other.ClientID).Scan(&otherID); err != nil {
		t.Fatalf("other app id: %v", err)
	}
	if _, err := f.svc.CreatePermission(ctx, f.tenantID, &otherID, "elsewhere:read", ""); err != nil {
		t.Fatalf("CreatePermission: %v", err)
	}

	doc := admin.RBACImportDocument{
		Roles: []admin.RBACImportRole{{Name: "leaky", Permissions: []string{"elsewhere:read"}}},
	}
	_, err = f.svc.CommitRBACImport(ctx, f.tenantID, f.appID, doc)
	if !errors.Is(err, admin.ErrRBACImportRejected) {
		t.Fatalf("err = %v, want ErrRBACImportRejected", err)
	}
	_, roles := rbacState(t, f)
	if _, ok := roles["leaky"]; ok {
		t.Error("role was created despite referencing another application's permission")
	}
}

func TestRBACImport_MergeKeepsExistingReplaceRemoves(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()
	if _, err := f.svc.CommitRBACImport(ctx, f.tenantID, f.appID, rbacDoc()); err != nil {
		t.Fatalf("seed import: %v", err)
	}

	// viewer currently holds claims:read + reports:read. Import it with only
	// claims:write.
	narrow := admin.RBACImportDocument{
		Roles: []admin.RBACImportRole{{Name: "viewer", Permissions: []string{"claims:write"}}},
	}
	res, err := f.svc.CommitRBACImport(ctx, f.tenantID, f.appID, narrow) // default = merge
	if err != nil {
		t.Fatalf("merge import: %v", err)
	}
	if res.RolesUpdated != 1 {
		t.Errorf("merge result = %+v", res)
	}
	_, roles := rbacState(t, f)
	if !eq(roles["viewer"], []string{"claims:read", "claims:write", "reports:read"}) {
		t.Errorf("merge lost or missed permissions: %v", roles["viewer"])
	}

	// Replace reports what it removes on a dry run, then does it on commit.
	narrow.Mode = admin.RBACModeReplace
	dry, err := f.svc.ValidateRBACImport(ctx, f.tenantID, f.appID, narrow)
	if err != nil {
		t.Fatalf("validate replace: %v", err)
	}
	var removed []string
	for _, r := range dry.Rows {
		if r.Kind == admin.RBACKindRole && r.Name == "viewer" {
			removed = r.Removed
		}
	}
	if !eq(removed, []string{"claims:read", "reports:read"}) {
		t.Errorf("dry run removed = %v", removed)
	}
	if _, roles = rbacState(t, f); len(roles["viewer"]) != 3 {
		t.Errorf("dry run changed the role: %v", roles["viewer"])
	}

	if _, err := f.svc.CommitRBACImport(ctx, f.tenantID, f.appID, narrow); err != nil {
		t.Fatalf("replace import: %v", err)
	}
	if _, roles = rbacState(t, f); !eq(roles["viewer"], []string{"claims:write"}) {
		t.Errorf("replace result = %v, want [claims:write]", roles["viewer"])
	}
}

func TestRBACImport_FileLevelValidation(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	cases := map[string]admin.RBACImportDocument{
		"bad permission name": {Permissions: []admin.RBACImportPermission{{Name: "has space"}}},
		"empty permission":    {Permissions: []admin.RBACImportPermission{{Name: ""}}},
		"duplicate permission": {Permissions: []admin.RBACImportPermission{
			{Name: "a:b"}, {Name: "a:b"}}},
		"duplicate role": {Roles: []admin.RBACImportRole{{Name: "r"}, {Name: "r"}}},
		"empty role":     {Roles: []admin.RBACImportRole{{Name: ""}}},
		"bad mode":       {Mode: "overwrite", Roles: []admin.RBACImportRole{{Name: "r"}}},
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			res, err := f.svc.CommitRBACImport(ctx, f.tenantID, f.appID, doc)
			if !errors.Is(err, admin.ErrRBACImportRejected) || res.Rejected == 0 {
				t.Errorf("err=%v res=%+v, want rejection", err, res)
			}
		})
	}
}

func TestRBACImport_TooLarge(t *testing.T) {
	f := newAdminFixture(t)
	doc := admin.RBACImportDocument{}
	for i := 0; i < 2001; i++ {
		doc.Permissions = append(doc.Permissions, admin.RBACImportPermission{Name: "p:" + strconv.Itoa(i)})
	}
	if _, err := f.svc.CommitRBACImport(context.Background(), f.tenantID, f.appID, doc); !errors.Is(err, admin.ErrRBACImportTooLarge) {
		t.Errorf("err = %v, want ErrRBACImportTooLarge", err)
	}
}

// A role that already exists in another application of the same tenant must not
// be touched by an import into this one.
func TestRBACImport_DoesNotTouchOtherApplicationsRoles(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	appSvc := auth.NewApplicationService(f.pool, testhelper.TestLogger())
	other, err := appSvc.CreateApplication(ctx, f.tenantID, "rbac-other-app2-"+time.Now().Format("150405.000000000"), "web", nil)
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}
	var otherID int64
	if err := f.pool.QueryRow(ctx, `SELECT id FROM oauth_clients WHERE client_id = $1`, other.ClientID).Scan(&otherID); err != nil {
		t.Fatalf("other app id: %v", err)
	}
	if _, err := f.svc.CommitRBACImport(ctx, f.tenantID, otherID, rbacDoc()); err != nil {
		t.Fatalf("import into other app: %v", err)
	}

	narrow := admin.RBACImportDocument{
		Mode:  admin.RBACModeReplace,
		Roles: []admin.RBACImportRole{{Name: "viewer"}},
	}
	if _, err := f.svc.CommitRBACImport(ctx, f.tenantID, f.appID, narrow); err != nil {
		t.Fatalf("import into this app: %v", err)
	}
	otherRoles, err := f.svc.ListRoles(ctx, f.tenantID, &otherID)
	if err != nil {
		t.Fatalf("ListRoles: %v", err)
	}
	for _, r := range otherRoles {
		if r.Name == "viewer" && len(r.Permissions) != 2 {
			t.Errorf("other application's viewer role was modified: %d permissions", len(r.Permissions))
		}
	}
}

// Two replace imports that read the same role at the same time used to each
// delete a different mapping and commit an empty role. With the role rows
// locked before the grants are read they run one after the other, so the role
// ends with whichever list ran last, never with neither.
func TestRBACImport_ConcurrentReplaceNeverEmptiesARole(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()
	if _, err := f.svc.CommitRBACImport(ctx, f.tenantID, f.appID, admin.RBACImportDocument{
		Permissions: []admin.RBACImportPermission{{Name: "a:read"}, {Name: "b:read"}},
		Roles:       []admin.RBACImportRole{{Name: "shared", Permissions: []string{"a:read", "b:read"}}},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	for round := 0; round < 5; round++ {
		// Back to {a,b} each round so every round starts from the racy state.
		if _, err := f.svc.CommitRBACImport(ctx, f.tenantID, f.appID, admin.RBACImportDocument{
			Roles: []admin.RBACImportRole{{Name: "shared", Permissions: []string{"a:read", "b:read"}}},
		}); err != nil {
			t.Fatalf("reset: %v", err)
		}
		errs := make(chan error, 2)
		for _, only := range []string{"a:read", "b:read"} {
			go func() {
				_, err := f.svc.CommitRBACImport(ctx, f.tenantID, f.appID, admin.RBACImportDocument{
					Mode:  admin.RBACModeReplace,
					Roles: []admin.RBACImportRole{{Name: "shared", Permissions: []string{only}}},
				})
				errs <- err
			}()
		}
		for i := 0; i < 2; i++ {
			if err := <-errs; err != nil {
				t.Fatalf("round %d: concurrent replace: %v", round, err)
			}
		}
		_, roles := rbacState(t, f)
		if got := roles["shared"]; len(got) != 1 {
			t.Fatalf("round %d: role ended with %v, want exactly one permission (last writer wins, never empty)", round, got)
		}
	}
}
