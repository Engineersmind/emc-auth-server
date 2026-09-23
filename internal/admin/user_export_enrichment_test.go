package admin_test

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/engineersmind/emc-auth-server/internal/admin"
	"github.com/engineersmind/emc-auth-server/internal/audit"
)

// exportedJSON runs the JSON export and returns its rows.
func exportedJSON(t *testing.T, f adminFixture, p admin.UserExportParams) []admin.ExportedUser {
	t.Helper()
	var buf bytes.Buffer
	if err := f.svc.ExportUsersJSON(context.Background(), p, &buf); err != nil {
		t.Fatalf("ExportUsersJSON() error = %v", err)
	}
	var doc admin.ExportedDocument
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("parse export json: %v\n%s", err, buf.String())
	}
	return doc.Users
}

func exportedUserByEmail(rows []admin.ExportedUser, email string) *admin.ExportedUser {
	for i := range rows {
		if rows[i].Email == email {
			return &rows[i]
		}
	}
	return nil
}

// insertAuditEvent writes one audit row directly. The logger's own pipeline is
// asynchronous and enriched; these tests need a row with a known action, which
// is what the export query reads.
func insertAuditEvent(t *testing.T, f adminFixture, userID int64, action string) {
	t.Helper()
	if _, err := f.pool.Exec(context.Background(), `
		INSERT INTO audit_logs (tenant_id, user_id, action, status)
		VALUES ($1, $2, $3, 'success')
	`, f.tenantID, userID, action); err != nil {
		t.Fatalf("insert audit event %q: %v", action, err)
	}
}

// makeSystemRoleHolder creates a user and puts a system role on it directly.
//
// CreateUser refuses a system role (ErrSystemRole) and so does AssignUserRole:
// administrative tiers are granted by invitation, which is the same reason the
// importer cannot accept them. The row still EXISTS in production — a tenant
// owner is exactly this shape — so the export has to be tested against one, and
// SQL is the only way to reach that state from a test.
func makeSystemRoleHolder(t *testing.T, f adminFixture, email string) {
	t.Helper()
	ctx := context.Background()

	user, err := f.svc.CreateUser(ctx, f.tenantID, nil, email, "Sup3rSecret!pw", "Sys", "Holder", nil)
	if err != nil {
		t.Fatalf("CreateUser(%s) error = %v", email, err)
	}
	if _, err := f.pool.Exec(ctx,
		`UPDATE users SET role_id = $1 WHERE id = $2`,
		seedSystemRoleID(t, f), parseID(t, user.ID)); err != nil {
		t.Fatalf("assign system role to %s: %v", email, err)
	}
}

// Finding 7 — login_count must count real login events.
//
// The query filtered on al.action = 'login'. The constant is 'auth.login'
// (audit.ActionAuthLogin), so the predicate matched nothing and login_count read
// zero for every user in every export — silently, since zero is a plausible
// answer for a new account. An operator using the export to find dormant seats
// was reading a column that was always zero.
func TestExportUsers_LoginCountCountsAuthLoginEvents(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	user, err := f.svc.CreateUser(ctx, f.tenantID, &f.appID,
		"login-count@example.com", "Sup3rSecret!pw", "Login", "Count", nil)
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	userID := parseID(t, user.ID)

	// Three sign-ins, and one event that is not a sign-in — the count must
	// include the former and exclude the latter.
	for i := 0; i < 3; i++ {
		insertAuditEvent(t, f, userID, audit.ActionAuthLogin)
	}
	insertAuditEvent(t, f, userID, audit.ActionAuthLoginFailed)

	rows := exportedJSON(t, f, admin.UserExportParams{TenantID: f.tenantID, ApplicationID: &f.appID})
	got := exportedUserByEmail(rows, "login-count@example.com")
	if got == nil {
		t.Fatal("the exported document is missing the user")
	}
	if got.LoginCount != 3 {
		t.Errorf("login_count = %d, want 3", got.LoginCount)
	}
}

// Finding 7 — last_login_at must report when the user was last seen.
//
// MAX(refresh_tokens.created_at) is when a token was ISSUED, which is not a
// login event and goes stale the moment session rows are reaped. service.go's
// userEnrichmentColumns takes the greatest of the session's last use and the
// audited sign-in events for the same field, so the export and the console must
// agree — an export is largely read to judge dormancy, and two answers to that
// question is worse than one imperfect one.
func TestExportUsers_LastLoginFallsBackToTheAuditedLogin(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	user, err := f.svc.CreateUser(ctx, f.tenantID, &f.appID,
		"last-login@example.com", "Sup3rSecret!pw", "Last", "Login", nil)
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	userID := parseID(t, user.ID)

	// An audited login and no session at all — the state a user reaches once
	// their refresh tokens have been reaped. The old query reported NULL here.
	when := time.Now().UTC().Add(-72 * time.Hour).Truncate(time.Second)
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO audit_logs (tenant_id, user_id, action, status, created_at)
		VALUES ($1, $2, $3, 'success', $4)
	`, f.tenantID, userID, audit.ActionAuthLogin, when); err != nil {
		t.Fatal(err)
	}

	rows := exportedJSON(t, f, admin.UserExportParams{TenantID: f.tenantID, ApplicationID: &f.appID})
	got := exportedUserByEmail(rows, "last-login@example.com")
	if got == nil {
		t.Fatal("the exported document is missing the user")
	}
	if got.LastLoginAt == nil {
		t.Fatal("last_login_at is null although the user has an audited login")
	}
	if d := got.LastLoginAt.Sub(when); d > time.Second || d < -time.Second {
		t.Errorf("last_login_at = %v, want ~%v", got.LastLoginAt.UTC(), when)
	}
}

// Finding 12 — the export must not carry users it cannot re-import.
//
// ExportedUser exists so an export can be edited and fed back to the importer.
// importRoleMap deliberately loads is_system = false roles only, because
// administrative tiers are granted by invitation and never by assignment — so
// an owner or super_admin row comes straight back as
// `role "owner" is not available in this application`. Excluding them is what
// makes the advertised round trip true, and it keeps the export a directory of
// end users rather than a roster of who administers the tenant.
func TestExportUsers_ExcludesSystemRoleHolders(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	makeSystemRoleHolder(t, f, "tenant-admin@example.com")

	// An ordinary user with an assignable role, so the assertion proves the
	// exclusion is targeted rather than an empty export.
	role, err := f.svc.CreateRole(ctx, f.tenantID, nil, "reporting-viewer", nil)
	if err != nil {
		t.Fatalf("CreateRole() error = %v", err)
	}
	roleID := parseID(t, role.ID)
	if _, err := f.svc.CreateUser(ctx, f.tenantID, nil,
		"ordinary@example.com", "Sup3rSecret!pw", "Ordinary", "User", &roleID); err != nil {
		t.Fatalf("CreateUser(assignable role) error = %v", err)
	}

	rows := exportedJSON(t, f, admin.UserExportParams{TenantID: f.tenantID})

	if got := exportedUserByEmail(rows, "tenant-admin@example.com"); got != nil {
		t.Errorf("a system-role holder was exported (role %q) and cannot be re-imported", got.Role)
	}
	if got := exportedUserByEmail(rows, "ordinary@example.com"); got == nil {
		t.Error("the ordinary user is missing; the exclusion is too broad")
	}
}

// The exclusion has to hold for CSV too, or one format leaks what the other
// withholds — the reason both serialisers share one query.
func TestExportUsersCSV_ExcludesSystemRoleHolders(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	makeSystemRoleHolder(t, f, "csv-admin@example.com")
	if _, err := f.svc.CreateUser(ctx, f.tenantID, nil,
		"csv-ordinary@example.com", "Sup3rSecret!pw", "Csv", "Ordinary", nil); err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}

	_, rows := exportRows(t, f, admin.UserExportParams{TenantID: f.tenantID})
	if findRow(rows, "csv-admin@example.com") != nil {
		t.Error("a system-role holder appears in the CSV export")
	}
	if findRow(rows, "csv-ordinary@example.com") == nil {
		t.Error("the ordinary user is missing from the CSV export")
	}
}

// The round trip the exclusion exists to protect: every row an export emits
// must be one the importer will accept once credentials are added.
func TestExportUsers_EveryExportedRowIsAcceptedByTheImporter(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	makeSystemRoleHolder(t, f, "rt-admin@example.com")
	if _, err := f.svc.CreateUser(ctx, f.tenantID, nil,
		"rt-plain@example.com", "Sup3rSecret!pw", "Rt", "Plain", nil); err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}

	exported := exportedJSON(t, f, admin.UserExportParams{TenantID: f.tenantID})
	if len(exported) == 0 {
		t.Fatal("nothing was exported; the assertion would be vacuous")
	}

	// Validated against the SAME scope it was exported from, with a credential
	// added — the documented workflow. Same scope on purpose: roles are
	// per-(tenant, application), so validating elsewhere would fail on the role
	// names rather than on the thing under test. Existing rows come back as
	// `skip`; what must not appear is a REJECT, because a rejection is the
	// importer refusing a row this export chose to emit.
	doc := admin.ImportDocument{}
	for _, u := range exported {
		doc.Users = append(doc.Users, admin.ImportUser{
			Email:         u.Email,
			FirstName:     u.FirstName,
			LastName:      u.LastName,
			Role:          u.Role,
			EmailVerified: u.EmailVerified,
			IsActive:      u.IsActive,
			PasswordHash:  bcryptHash(t, "round-trip-pw"),
		})
	}

	res, err := f.svc.ValidateImport(ctx, f.tenantID, nil, doc)
	if err != nil {
		t.Fatalf("ValidateImport() error = %v", err)
	}
	for _, r := range res.Rows {
		if r.Outcome == admin.ImportOutcomeReject {
			t.Errorf("exported row %q cannot be re-imported: %s", r.Email, r.Reason)
		}
	}
	if res.Rejected != 0 {
		t.Errorf("%d of %d exported rows were rejected by the importer", res.Rejected, res.Total)
	}
}
