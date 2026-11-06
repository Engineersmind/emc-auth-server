package admin

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
)

// Bulk RBAC export (#187): an application's permissions and roles in the exact
// shape the import takes, so an export is a backup that can be restored and a
// template that can be copied to another application.
//
// System roles are left out. The importer refuses to change them, so a file that
// listed them would be rejected on the way back in; they are seeded by the
// platform, not configured by the operator.

// ExportRBAC returns the application's permissions and roles as an import
// document. Mode is left empty: it is a property of the import, not of the data.
func (s *Service) ExportRBAC(ctx context.Context, tenantID, applicationID int64) (*RBACImportDocument, error) {
	// One snapshot for both reads, so a role never lists a permission the
	// permission list does not contain.
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, fmt.Errorf("begin rbac export tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	doc := &RBACImportDocument{
		Permissions: []RBACImportPermission{},
		Roles:       []RBACImportRole{},
	}

	prows, err := tx.Query(ctx, `
		SELECT name, COALESCE(description, '') FROM permissions
		WHERE tenant_id = $1 AND application_id = $2 AND deleted_at IS NULL
		ORDER BY name`, tenantID, applicationID)
	if err != nil {
		return nil, fmt.Errorf("export permissions: %w", err)
	}
	defer prows.Close()
	for prows.Next() {
		var p RBACImportPermission
		if err := prows.Scan(&p.Name, &p.Description); err != nil {
			return nil, fmt.Errorf("scan permission: %w", err)
		}
		doc.Permissions = append(doc.Permissions, p)
	}
	if err := prows.Err(); err != nil {
		return nil, err
	}
	prows.Close()

	roles, err := loadAppRoles(ctx, tx, tenantID, applicationID)
	if err != nil {
		return nil, err
	}
	for name, r := range roles {
		if r.isSystem {
			continue
		}
		perms := make([]string, 0, len(r.perms))
		for pn := range r.perms {
			perms = append(perms, pn)
		}
		sort.Strings(perms)
		doc.Roles = append(doc.Roles, RBACImportRole{Name: name, Permissions: perms})
	}
	sort.Slice(doc.Roles, func(i, j int) bool { return doc.Roles[i].Name < doc.Roles[j].Name })
	return doc, nil
}

// ErrRBACCSVUnsupported means the data cannot survive the CSV form: the CSV puts
// a permission's roles in one cell separated by ";", so a role name containing
// one would split into two roles on the way back in.
var ErrRBACCSVUnsupported = fmt.Errorf("a role name contains ';', which the CSV form cannot represent; export as JSON")

// WriteRBACCSV writes doc as CSV with the header `permission,description,roles`,
// one row per permission, roles separated by ";". Roles that hold no permission
// have no row, so the CSV form is for the permission matrix; JSON is lossless.
//
// Every cell goes through csvSafe for the reason given there, permission names
// included: the import's name pattern allows a leading '-', so a valid name such
// as "-1-2" would otherwise be evaluated as arithmetic by a spreadsheet. A
// prefixed name is not a valid permission name, so a CSV holding one is rejected
// on re-import with a clear reason; JSON carries every value exactly.
func WriteRBACCSV(doc *RBACImportDocument, w io.Writer) error {
	byPerm := map[string][]string{}
	for _, r := range doc.Roles {
		if strings.Contains(r.Name, ";") {
			return ErrRBACCSVUnsupported
		}
		for _, p := range r.Permissions {
			byPerm[p] = append(byPerm[p], r.Name)
		}
	}
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{"permission", "description", "roles"}); err != nil {
		return err
	}
	for _, p := range doc.Permissions {
		roles := byPerm[p.Name]
		safe := make([]string, len(roles))
		for i, n := range roles {
			safe[i] = csvSafe(n)
		}
		if err := cw.Write([]string{csvSafe(p.Name), csvSafe(p.Description), strings.Join(safe, ";")}); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// ExceedsImportLimit reports whether the document has more rows than one import
// accepts. An export is complete rather than truncated, so a large application
// can produce a file that has to be split before it can be imported; callers
// surface this instead of presenting the file as restorable in one step.
func (d *RBACImportDocument) ExceedsImportLimit() bool {
	return len(d.Permissions)+len(d.Roles) > maxRBACImportRows
}
