package admin

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"

	"github.com/jackc/pgx/v5"
)

// Bulk RBAC import (#187): create an application's permissions and roles, and
// map them, in ONE all-or-nothing transaction.
//
// Why this is not the user-import shape. User import commits row by row because
// a 5,000-row file that rolls back for row 4,999 is unusable and each row costs
// a password hash. Neither holds here: nothing is hashed, the cap is small, and
// the failure this feature exists to prevent is the half-configured role — a
// permission created but never mapped, or a role that ended up with part of its
// intended list. A client script looping over the per-row endpoints cannot give
// that guarantee; the server can, so it does.
//
// A file with any rejected row therefore writes nothing, and the report names
// every offending row so the operator fixes the whole file in one pass.

// maxRBACImportRows bounds permissions + roles in one document. The work is a
// handful of set-based statements, so this is about keeping one transaction and
// one report small, not about per-row cost.
const maxRBACImportRows = 2000

// maxRBACRolePermissions bounds the permission list of a single role.
const maxRBACRolePermissions = 1000

// RBAC import modes — how a role's permission list is applied.
const (
	// RBACModeMerge (default) adds the listed permissions and keeps whatever the
	// role already has. Re-running a file is a no-op, and a file that lists only
	// part of a role cannot silently strip the rest.
	RBACModeMerge = "merge"
	// RBACModeReplace makes the listed permissions the role's complete list,
	// removing any it holds that the file does not name. Destructive, so it is
	// opt-in, and the validate report shows exactly what would be removed.
	RBACModeReplace = "replace"
)

// RBAC import row kinds and outcomes.
const (
	RBACKindPermission = "permission"
	RBACKindRole       = "role"

	RBACOutcomeCreate = "create"
	RBACOutcomeUpdate = "update" // role exists; its permission list changes
	RBACOutcomeSkip   = "skip"   // already present and already as requested
	RBACOutcomeReject = "reject"
)

var (
	// ErrRBACImportTooLarge is returned when a document exceeds maxRBACImportRows.
	ErrRBACImportTooLarge = fmt.Errorf("import exceeds %d rows (permissions + roles)", maxRBACImportRows)
	// ErrRBACImportRejected is returned by the commit when validation rejected
	// any row. The accompanying result lists them; nothing was written.
	ErrRBACImportRejected = errors.New("import has rejected rows; nothing was written")
)

// permissionNameRE mirrors the chk_permissions_name constraint so a bad name is
// reported against its row instead of aborting the transaction at the database.
var permissionNameRE = regexp.MustCompile(`^[A-Za-z0-9:_-]{1,100}$`)

// RBACImportPermission is one permission to create.
type RBACImportPermission struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// RBACImportRole is one role and the permissions it should carry. Permissions
// are referenced by NAME, so a caller never needs ids; each must be defined in
// the same document or already exist in the application.
type RBACImportRole struct {
	Name        string   `json:"name"`
	Permissions []string `json:"permissions"`
}

// RBACImportDocument is the uploaded payload.
type RBACImportDocument struct {
	Permissions []RBACImportPermission `json:"permissions"`
	Roles       []RBACImportRole       `json:"roles"`
	// Mode is "merge" (default) or "replace" — see RBACModeMerge.
	Mode string `json:"mode"`
}

// RBACImportRowResult is the verdict for one permission or role. Index is the
// row's position within its own array in the uploaded document.
type RBACImportRowResult struct {
	Kind    string `json:"kind"`
	Index   int    `json:"index"`
	Name    string `json:"name"`
	Outcome string `json:"outcome"`
	Reason  string `json:"reason,omitempty"`
	// Added and Removed list permission names a role gains or loses. Only set
	// for roles with a changing permission list.
	Added   []string `json:"added,omitempty"`
	Removed []string `json:"removed,omitempty"`
}

// RBACImportResult summarises a validate or commit run.
type RBACImportResult struct {
	DryRun             bool                  `json:"dry_run"`
	Mode               string                `json:"mode"`
	PermissionsCreated int                   `json:"permissions_created"`
	PermissionsSkipped int                   `json:"permissions_skipped"`
	RolesCreated       int                   `json:"roles_created"`
	RolesUpdated       int                   `json:"roles_updated"`
	RolesSkipped       int                   `json:"roles_skipped"`
	Rejected           int                   `json:"rejected"`
	Rows               []RBACImportRowResult `json:"rows"`
}

// ValidateRBACImport checks the whole document against the application's
// current state and writes nothing.
func (s *Service) ValidateRBACImport(ctx context.Context, tenantID, applicationID int64, doc RBACImportDocument) (*RBACImportResult, error) {
	return s.runRBACImport(ctx, tenantID, applicationID, doc, true)
}

// CommitRBACImport applies the document in one transaction. If any row is
// rejected it writes nothing and returns ErrRBACImportRejected together with
// the report.
func (s *Service) CommitRBACImport(ctx context.Context, tenantID, applicationID int64, doc RBACImportDocument) (*RBACImportResult, error) {
	return s.runRBACImport(ctx, tenantID, applicationID, doc, false)
}

// rbacRole is an existing role in the import's application.
type rbacRole struct {
	id       int64
	isSystem bool
	perms    map[string]int64 // permission name -> id currently granted
}

// rbacPlanned is a role whose permission list the commit has to write.
type rbacPlanned struct {
	name   string
	exists bool
	role   rbacRole
	grant  []string // permission names to add
	revoke []string // permission names to remove (replace mode only)
}

func (s *Service) runRBACImport(ctx context.Context, tenantID, applicationID int64, doc RBACImportDocument, dryRun bool) (*RBACImportResult, error) {
	if len(doc.Permissions)+len(doc.Roles) > maxRBACImportRows {
		return nil, ErrRBACImportTooLarge
	}

	mode := doc.Mode
	if mode == "" {
		mode = RBACModeMerge
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin rbac import tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// Lock the application's roles BEFORE reading their grants. A transaction on
	// its own does not serialise this read-plan-write: two replace imports that
	// both read a role holding {a,b}, one asking for {a} and one for {b}, would
	// each delete a different mapping and commit an empty role. Locking first,
	// in a statement of its own, means the grants read next are read after any
	// competing writer has committed (READ COMMITTED takes a fresh snapshot per
	// statement). Ordered by id so two imports cannot deadlock; the other
	// writer, UpdateRolePermissions, locks the one role row it changes.
	if _, err := tx.Exec(ctx, `
		SELECT 1 FROM (
			SELECT id FROM roles
			WHERE tenant_id = $1 AND application_id = $2 AND deleted_at IS NULL
			ORDER BY id
			FOR UPDATE
		) locked`, tenantID, applicationID); err != nil {
		return nil, fmt.Errorf("lock application roles: %w", err)
	}

	// Existing state is read inside the transaction the writes will use, so the
	// plan is computed against the same snapshot it is applied to. A concurrent
	// writer that sneaks a NEW name in between is caught by the unique index and
	// aborts the whole import (ErrAlreadyExists) rather than half-applying it.
	existingPerms, err := loadAppPermissions(ctx, tx, tenantID, applicationID)
	if err != nil {
		return nil, err
	}
	existingRoles, err := loadAppRoles(ctx, tx, tenantID, applicationID)
	if err != nil {
		return nil, err
	}

	res := &RBACImportResult{DryRun: dryRun, Mode: mode, Rows: []RBACImportRowResult{}}
	reject := func(kind string, idx int, name, reason string) {
		res.Rejected++
		res.Rows = append(res.Rows, RBACImportRowResult{
			Kind: kind, Index: idx, Name: name, Outcome: RBACOutcomeReject, Reason: reason})
	}

	if mode != RBACModeMerge && mode != RBACModeReplace {
		reject(RBACKindRole, 0, "", `mode must be "merge" or "replace"`)
	}

	// --- Permissions ---------------------------------------------------------
	// definedPerms is every permission name a role may reference: the ones that
	// already exist plus the ones this document creates.
	definedPerms := make(map[string]struct{}, len(existingPerms)+len(doc.Permissions))
	for n := range existingPerms {
		definedPerms[n] = struct{}{}
	}
	var newPermNames, newPermDescs []string
	seenPerm := make(map[string]int, len(doc.Permissions))
	for i, p := range doc.Permissions {
		switch {
		case !permissionNameRE.MatchString(p.Name):
			reject(RBACKindPermission, i, p.Name,
				"name must be 1-100 characters of letters, digits, ':', '_' or '-'")
			continue
		case seenPerm[p.Name] != 0:
			reject(RBACKindPermission, i, p.Name,
				fmt.Sprintf("duplicate of permission #%d in this file", seenPerm[p.Name]-1))
			continue
		}
		seenPerm[p.Name] = i + 1
		if _, ok := existingPerms[p.Name]; ok {
			res.PermissionsSkipped++
			res.Rows = append(res.Rows, RBACImportRowResult{
				Kind: RBACKindPermission, Index: i, Name: p.Name, Outcome: RBACOutcomeSkip,
				Reason: "already exists in this application"})
			continue
		}
		definedPerms[p.Name] = struct{}{}
		newPermNames = append(newPermNames, p.Name)
		newPermDescs = append(newPermDescs, p.Description)
		res.PermissionsCreated++
		res.Rows = append(res.Rows, RBACImportRowResult{
			Kind: RBACKindPermission, Index: i, Name: p.Name, Outcome: RBACOutcomeCreate})
	}

	// --- Roles ---------------------------------------------------------------
	var plan []rbacPlanned
	seenRole := make(map[string]int, len(doc.Roles))
	for i, r := range doc.Roles {
		if l := len([]rune(r.Name)); l < 1 || l > 100 {
			reject(RBACKindRole, i, r.Name, "name must be 1-100 characters")
			continue
		}
		if seenRole[r.Name] != 0 {
			reject(RBACKindRole, i, r.Name,
				fmt.Sprintf("duplicate of role #%d in this file", seenRole[r.Name]-1))
			continue
		}
		seenRole[r.Name] = i + 1
		if len(r.Permissions) > maxRBACRolePermissions {
			reject(RBACKindRole, i, r.Name,
				fmt.Sprintf("more than %d permissions", maxRBACRolePermissions))
			continue
		}

		// Every referenced permission must be defined; list ALL the unknown ones
		// so the operator fixes the row once.
		want := make(map[string]struct{}, len(r.Permissions))
		var unknown []string
		for _, pn := range r.Permissions {
			if _, ok := definedPerms[pn]; !ok {
				unknown = append(unknown, pn)
				continue
			}
			want[pn] = struct{}{}
		}
		if len(unknown) > 0 {
			sort.Strings(unknown)
			reject(RBACKindRole, i, r.Name, fmt.Sprintf(
				"unknown permission(s) %v: define them in this file or create them in the application first", dedupeStrings(unknown)))
			continue
		}

		ex, exists := existingRoles[r.Name]
		if exists && ex.isSystem {
			reject(RBACKindRole, i, r.Name, "system roles cannot be changed by import")
			continue
		}

		var grant, revoke []string
		for pn := range want {
			if _, have := ex.perms[pn]; !have {
				grant = append(grant, pn)
			}
		}
		if mode == RBACModeReplace {
			for pn := range ex.perms {
				if _, keep := want[pn]; !keep {
					revoke = append(revoke, pn)
				}
			}
		}
		sort.Strings(grant)
		sort.Strings(revoke)

		row := RBACImportRowResult{Kind: RBACKindRole, Index: i, Name: r.Name, Added: grant, Removed: revoke}
		switch {
		case !exists:
			row.Outcome = RBACOutcomeCreate
			res.RolesCreated++
		case len(grant) == 0 && len(revoke) == 0:
			row.Outcome = RBACOutcomeSkip
			row.Reason = "already exists with these permissions"
			res.RolesSkipped++
		default:
			row.Outcome = RBACOutcomeUpdate
			res.RolesUpdated++
		}
		res.Rows = append(res.Rows, row)
		if row.Outcome != RBACOutcomeSkip {
			plan = append(plan, rbacPlanned{
				name: r.Name, exists: exists, role: ex, grant: grant, revoke: revoke,
			})
		}
	}

	sort.SliceStable(res.Rows, func(a, b int) bool {
		if res.Rows[a].Kind != res.Rows[b].Kind {
			return res.Rows[a].Kind == RBACKindPermission
		}
		return res.Rows[a].Index < res.Rows[b].Index
	})

	if dryRun {
		return res, nil
	}
	if res.Rejected > 0 {
		return res, ErrRBACImportRejected
	}

	// --- Apply ---------------------------------------------------------------
	permIDs := make(map[string]int64, len(existingPerms)+len(newPermNames))
	for n, id := range existingPerms {
		permIDs[n] = id
	}
	if len(newPermNames) > 0 {
		rows, err := tx.Query(ctx, `
			INSERT INTO permissions (tenant_id, application_id, name, description)
			SELECT $1, $2, n, d FROM unnest($3::text[], $4::text[]) AS t(n, d)
			RETURNING id, name`,
			tenantID, applicationID, newPermNames, newPermDescs)
		if err != nil {
			return nil, rbacWriteErr("insert permissions", err)
		}
		for rows.Next() {
			var id int64
			var name string
			if err := rows.Scan(&id, &name); err != nil {
				rows.Close()
				return nil, fmt.Errorf("scan inserted permission: %w", err)
			}
			permIDs[name] = id
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, rbacWriteErr("insert permissions", err)
		}
	}

	var newRoleNames []string
	for _, p := range plan {
		if !p.exists {
			newRoleNames = append(newRoleNames, p.name)
		}
	}
	roleIDs := make(map[string]int64, len(plan))
	for _, p := range plan {
		if p.exists {
			roleIDs[p.name] = p.role.id
		}
	}
	if len(newRoleNames) > 0 {
		rows, err := tx.Query(ctx, `
			INSERT INTO roles (tenant_id, application_id, name, is_system, created_at)
			SELECT $1, $2, n, false, NOW() FROM unnest($3::text[]) AS t(n)
			RETURNING id, name`,
			tenantID, applicationID, newRoleNames)
		if err != nil {
			return nil, rbacWriteErr("insert roles", err)
		}
		for rows.Next() {
			var id int64
			var name string
			if err := rows.Scan(&id, &name); err != nil {
				rows.Close()
				return nil, fmt.Errorf("scan inserted role: %w", err)
			}
			roleIDs[name] = id
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, rbacWriteErr("insert roles", err)
		}
	}

	var delRole, delPerm, addRole, addPerm []int64
	for _, p := range plan {
		rid := roleIDs[p.name]
		for _, pn := range p.revoke {
			delRole = append(delRole, rid)
			delPerm = append(delPerm, permIDs[pn])
		}
		for _, pn := range p.grant {
			addRole = append(addRole, rid)
			addPerm = append(addPerm, permIDs[pn])
		}
	}
	if len(delRole) > 0 {
		if _, err := tx.Exec(ctx, `
			DELETE FROM role_permissions rp
			USING unnest($1::bigint[], $2::bigint[]) AS d(role_id, permission_id)
			WHERE rp.role_id = d.role_id AND rp.permission_id = d.permission_id`,
			delRole, delPerm); err != nil {
			return nil, fmt.Errorf("revoke role permissions: %w", err)
		}
	}
	if len(addRole) > 0 {
		if _, err := tx.Exec(ctx, `
			INSERT INTO role_permissions (role_id, permission_id, tenant_id)
			SELECT role_id, permission_id, $3
			FROM unnest($1::bigint[], $2::bigint[]) AS a(role_id, permission_id)
			ON CONFLICT DO NOTHING`,
			addRole, addPerm, tenantID); err != nil {
			return nil, fmt.Errorf("grant role permissions: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, rbacWriteErr("commit rbac import", err)
	}
	return res, nil
}

// rbacWriteErr maps a unique violation (a name created by a concurrent writer
// after the snapshot was read) to ErrAlreadyExists so the handler can answer
// 409, and wraps anything else.
func rbacWriteErr(op string, err error) error {
	if isDuplicateErr(err) {
		return ErrAlreadyExists
	}
	return fmt.Errorf("%s: %w", op, err)
}

func dedupeStrings(in []string) []string {
	out := in[:0:0]
	var prev string
	for i, s := range in { // callers pass a sorted slice
		if i == 0 || s != prev {
			out = append(out, s)
		}
		prev = s
	}
	return out
}

// loadAppPermissions returns name -> id for the application's live permissions.
func loadAppPermissions(ctx context.Context, tx pgx.Tx, tenantID, applicationID int64) (map[string]int64, error) {
	rows, err := tx.Query(ctx, `
		SELECT id, name FROM permissions
		WHERE tenant_id = $1 AND application_id = $2 AND deleted_at IS NULL`,
		tenantID, applicationID)
	if err != nil {
		return nil, fmt.Errorf("load application permissions: %w", err)
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var id int64
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil, fmt.Errorf("scan permission: %w", err)
		}
		out[name] = id
	}
	return out, rows.Err()
}

// loadAppRoles returns the application's live roles with their current grants.
func loadAppRoles(ctx context.Context, tx pgx.Tx, tenantID, applicationID int64) (map[string]rbacRole, error) {
	rows, err := tx.Query(ctx, `
		SELECT r.id, r.name, r.is_system, p.id, p.name
		FROM roles r
		LEFT JOIN role_permissions rp ON rp.role_id = r.id
		LEFT JOIN permissions p ON p.id = rp.permission_id AND p.deleted_at IS NULL
		WHERE r.tenant_id = $1 AND r.application_id = $2 AND r.deleted_at IS NULL`,
		tenantID, applicationID)
	if err != nil {
		return nil, fmt.Errorf("load application roles: %w", err)
	}
	defer rows.Close()
	out := map[string]rbacRole{}
	for rows.Next() {
		var (
			id       int64
			name     string
			isSystem bool
			pid      *int64
			pname    *string
		)
		if err := rows.Scan(&id, &name, &isSystem, &pid, &pname); err != nil {
			return nil, fmt.Errorf("scan role: %w", err)
		}
		r, ok := out[name]
		if !ok {
			r = rbacRole{id: id, isSystem: isSystem, perms: map[string]int64{}}
		}
		if pid != nil && pname != nil {
			r.perms[*pname] = *pid
		}
		out[name] = r
	}
	return out, rows.Err()
}
