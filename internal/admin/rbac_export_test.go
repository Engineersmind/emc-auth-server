package admin_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/engineersmind/emc-auth-server/internal/admin"
)

func TestRBACExport_RoundTripsThroughImport(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()
	if _, err := f.svc.CommitRBACImport(ctx, f.tenantID, f.appID, rbacDoc()); err != nil {
		t.Fatalf("seed import: %v", err)
	}

	doc, err := f.svc.ExportRBAC(ctx, f.tenantID, f.appID)
	if err != nil {
		t.Fatalf("ExportRBAC: %v", err)
	}
	if len(doc.Permissions) != 3 || doc.Permissions[0].Name != "claims:read" || doc.Permissions[0].Description != "View claims" {
		t.Errorf("permissions = %+v", doc.Permissions)
	}
	if len(doc.Roles) != 2 || doc.Roles[0].Name != "manager" || doc.Roles[1].Name != "viewer" {
		t.Fatalf("roles not sorted by name = %+v", doc.Roles)
	}
	if !eq(doc.Roles[1].Permissions, []string{"claims:read", "reports:read"}) {
		t.Errorf("viewer permissions = %v", doc.Roles[1].Permissions)
	}

	// The point of the shape: feeding the export back is a clean no-op.
	res, err := f.svc.CommitRBACImport(ctx, f.tenantID, f.appID, *doc)
	if err != nil {
		t.Fatalf("re-import of the export: %v", err)
	}
	if res.PermissionsCreated != 0 || res.RolesCreated != 0 || res.RolesUpdated != 0 || res.Rejected != 0 {
		t.Errorf("re-import changed something: %+v", res)
	}
}

func TestRBACExport_EmptyApplicationGivesEmptyArrays(t *testing.T) {
	f := newAdminFixture(t)
	doc, err := f.svc.ExportRBAC(context.Background(), f.tenantID, f.appID)
	if err != nil {
		t.Fatalf("ExportRBAC: %v", err)
	}
	if doc.Permissions == nil || doc.Roles == nil {
		t.Error("empty lists must be [] not null, so the file stays a valid import")
	}
}

func TestWriteRBACCSV(t *testing.T) {
	doc := &admin.RBACImportDocument{
		Permissions: []admin.RBACImportPermission{
			{Name: "claims:read", Description: "View, then \"read\""},
			{Name: "claims:write", Description: "=HYPERLINK(\"x\")"},
			{Name: "orphan:perm"},
			{Name: "-1-2"}, // a valid name that a spreadsheet would evaluate
		},
		Roles: []admin.RBACImportRole{
			{Name: "manager", Permissions: []string{"claims:read", "claims:write"}},
			{Name: "viewer", Permissions: []string{"claims:read"}},
		},
	}
	var buf bytes.Buffer
	if err := admin.WriteRBACCSV(doc, &buf); err != nil {
		t.Fatalf("WriteRBACCSV: %v", err)
	}
	got := buf.String()
	for _, want := range []string{
		"permission,description,roles\n",
		"claims:read,\"View, then \"\"read\"\"\",manager;viewer\n",
		"claims:write,\"'=HYPERLINK(\"\"x\"\")\",manager\n", // formula neutralised
		"orphan:perm,,\n", // permission nobody holds still listed
		"'-1-2,,\n",       // permission names are neutralised too
	} {
		if !strings.Contains(got, want) {
			t.Errorf("csv missing %q in:\n%s", want, got)
		}
	}
}

func TestWriteRBACCSV_RefusesRoleNameWithSemicolon(t *testing.T) {
	doc := &admin.RBACImportDocument{
		Roles: []admin.RBACImportRole{{Name: "a;b", Permissions: []string{"x:y"}}},
	}
	err := admin.WriteRBACCSV(doc, &bytes.Buffer{})
	if !errors.Is(err, admin.ErrRBACCSVUnsupported) {
		t.Fatalf("err = %v, want ErrRBACCSVUnsupported", err)
	}
}

func TestRBACExport_ExceedsImportLimit(t *testing.T) {
	doc := &admin.RBACImportDocument{}
	if doc.ExceedsImportLimit() {
		t.Fatal("an empty document is within the limit")
	}
	for i := 0; i < 1500; i++ {
		doc.Permissions = append(doc.Permissions, admin.RBACImportPermission{Name: "p"})
		doc.Roles = append(doc.Roles, admin.RBACImportRole{Name: "r"})
	}
	if !doc.ExceedsImportLimit() {
		t.Fatal("3000 rows is over the 2000-row import limit")
	}
}
