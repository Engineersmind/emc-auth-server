package admin_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/engineersmind/emc-auth-server/internal/admin"
	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/password"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// bcryptHash produces a real bcrypt digest at the cheapest cost — the test
// cares that the digest is well-formed and verifiable, not that it is slow.
func bcryptHash(t *testing.T, pw string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt.GenerateFromPassword: %v", err)
	}
	return string(h)
}

func rowByEmail(t *testing.T, res *admin.ImportResult, email string) admin.ImportRowResult {
	t.Helper()
	for _, r := range res.Rows {
		if r.Email == email {
			return r
		}
	}
	t.Fatalf("no result row for %q; rows=%+v", email, res.Rows)
	return admin.ImportRowResult{}
}

// A validate run must not create anything. This is the property the whole
// two-phase design rests on.
func TestValidateImport_WritesNothing(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	doc := admin.ImportDocument{Users: []admin.ImportUser{{
		Email:        "dryrun@example.com",
		FirstName:    "Dry",
		PasswordHash: bcryptHash(t, "whatever"),
	}}}

	res, err := f.svc.ValidateImport(ctx, f.tenantID, &f.appID, doc)
	if err != nil {
		t.Fatalf("ValidateImport() error = %v", err)
	}
	if !res.DryRun || res.Created != 1 {
		t.Fatalf("dry run = %v, created = %d, want true/1", res.DryRun, res.Created)
	}

	var n int
	if err := f.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM users WHERE email = 'dryrun@example.com'`).Scan(&n); err != nil {
		t.Fatalf("count users: %v", err)
	}
	if n != 0 {
		t.Errorf("dry run created %d user rows, want 0", n)
	}
}

// The imported digest must be the one that ends up in user_credentials, and it
// must still verify — that is the whole point of a pre-hashed import.
func TestCommitImport_PreservesHashAndItVerifies(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	const pw = "the-original-password"
	hash := bcryptHash(t, pw)

	res, err := f.svc.CommitImport(ctx, f.tenantID, &f.appID, admin.ImportDocument{
		Users: []admin.ImportUser{{
			Email:        "migrated@example.com",
			FirstName:    "Mig",
			LastName:     "Rated",
			PasswordHash: hash,
		}},
	})
	if err != nil {
		t.Fatalf("CommitImport() error = %v", err)
	}
	if res.Created != 1 {
		t.Fatalf("created = %d, want 1; rows=%+v", res.Created, res.Rows)
	}

	var stored string
	if err := f.pool.QueryRow(ctx, `
		SELECT uc.password_hash FROM user_credentials uc
		JOIN users u ON u.id = uc.user_id
		WHERE u.email = 'migrated@example.com'`).Scan(&stored); err != nil {
		t.Fatalf("read stored hash: %v", err)
	}
	if stored != hash {
		t.Errorf("stored hash was rewritten:\n got %q\nwant %q", stored, hash)
	}

	// The migrated corpus must authenticate on arrival.
	h := password.NewHasher(password.Params{})
	if err := h.Verify(ctx, pw, stored); err != nil {
		t.Errorf("imported hash does not verify the original password: %v", err)
	}
	// ...and be scheduled for upgrade to the current Argon2id parameters.
	if !h.NeedsRehash(stored) {
		t.Error("imported bcrypt hash not marked for rehash; it would never converge")
	}
}

// A file must not be able to grant an administrative role. This is the bulk
// equivalent of the ErrSystemRole refusal in CreateUser/AssignUserRole.
func TestImport_RefusesSystemRole(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	var sysRole string
	if err := f.pool.QueryRow(ctx, `
		SELECT name FROM roles
		WHERE tenant_id = $1 AND is_system = true AND deleted_at IS NULL
		LIMIT 1`, f.tenantID).Scan(&sysRole); err != nil {
		t.Fatalf("find a system role: %v", err)
	}

	res, err := f.svc.ValidateImport(ctx, f.tenantID, &f.appID, admin.ImportDocument{
		Users: []admin.ImportUser{{
			Email:        "escalate@example.com",
			Role:         sysRole,
			PasswordHash: bcryptHash(t, "pw"),
		}},
	})
	if err != nil {
		t.Fatalf("ValidateImport() error = %v", err)
	}
	row := rowByEmail(t, res, "escalate@example.com")
	if row.Outcome != admin.ImportOutcomeReject {
		t.Errorf("system role %q was accepted (outcome %q) — privilege escalation via upload",
			sysRole, row.Outcome)
	}
}

// A role belonging to another application must not be reachable from this
// import's scope.
func TestImport_RefusesCrossScopeRole(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	// A tenant-level role (application_id IS NULL) is out of scope for an
	// application-scoped import.
	role, err := f.svc.CreateRole(ctx, f.tenantID, nil, "tenant-only-role", nil)
	if err != nil {
		t.Fatalf("CreateRole() error = %v", err)
	}
	_ = role

	res, err := f.svc.ValidateImport(ctx, f.tenantID, &f.appID, admin.ImportDocument{
		Users: []admin.ImportUser{{
			Email:        "crossscope@example.com",
			Role:         "tenant-only-role",
			PasswordHash: bcryptHash(t, "pw"),
		}},
	})
	if err != nil {
		t.Fatalf("ValidateImport() error = %v", err)
	}
	row := rowByEmail(t, res, "crossscope@example.com")
	if row.Outcome != admin.ImportOutcomeReject {
		t.Errorf("out-of-scope role accepted (outcome %q)", row.Outcome)
	}
}

// Only digests password.Verify can read are accepted. Anything else would
// create an account that exists and can never be logged into.
func TestImport_RejectsUnsupportedHashes(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	cases := map[string]string{
		"plaintext":       "hunter2",
		"md5":             "5f4dcc3b5aa765d61d8327deb882cf99",
		"sha1-prefixed":   "{SHA}5en6G6MezRroT3XKqkdPOmY/BfQ=",
		"malformed-argon": "$argon2id$v=19$m=notanumber,t=1,p=1$c2FsdA$aGFzaA",
	}
	for name, hash := range cases {
		t.Run(name, func(t *testing.T) {
			email := name + "@example.com"
			res, err := f.svc.ValidateImport(ctx, f.tenantID, &f.appID, admin.ImportDocument{
				Users: []admin.ImportUser{{Email: email, PasswordHash: hash}},
			})
			if err != nil {
				t.Fatalf("ValidateImport() error = %v", err)
			}
			if row := rowByEmail(t, res, email); row.Outcome != admin.ImportOutcomeReject {
				t.Errorf("hash %q accepted (outcome %q, reason %q)", hash, row.Outcome, row.Reason)
			}
		})
	}
}

// A well-formed Argon2id PHC digest is native and must be accepted.
func TestImport_AcceptsArgon2idPHC(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	h := password.NewHasher(password.Params{})
	phc, err := h.Hash(ctx, "native-password")
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}

	res, err := f.svc.ValidateImport(ctx, f.tenantID, &f.appID, admin.ImportDocument{
		Users: []admin.ImportUser{{Email: "native@example.com", PasswordHash: phc}},
	})
	if err != nil {
		t.Fatalf("ValidateImport() error = %v", err)
	}
	if row := rowByEmail(t, res, "native@example.com"); row.Outcome != admin.ImportOutcomeCreate {
		t.Errorf("argon2id PHC rejected: outcome %q, reason %q", row.Outcome, row.Reason)
	}
}

// Re-running the same import must not duplicate users: the second run reports
// skips, and the row count is unchanged.
func TestCommitImport_IsIdempotent(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	doc := admin.ImportDocument{Users: []admin.ImportUser{{
		Email:        "twice@example.com",
		PasswordHash: bcryptHash(t, "pw"),
	}}}

	first, err := f.svc.CommitImport(ctx, f.tenantID, &f.appID, doc)
	if err != nil {
		t.Fatalf("first CommitImport() error = %v", err)
	}
	if first.Created != 1 {
		t.Fatalf("first run created %d, want 1", first.Created)
	}

	second, err := f.svc.CommitImport(ctx, f.tenantID, &f.appID, doc)
	if err != nil {
		t.Fatalf("second CommitImport() error = %v", err)
	}
	if second.Created != 0 || second.Skipped != 1 {
		t.Errorf("second run created=%d skipped=%d, want 0/1", second.Created, second.Skipped)
	}

	var n int
	if err := f.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM users WHERE email = 'twice@example.com' AND deleted_at IS NULL`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Errorf("user row count = %d, want 1", n)
	}
}

// Two rows in ONE file with the same address: the second must be rejected at
// validation rather than failing at the unique index during commit.
func TestImport_DetectsDuplicatesWithinFile(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	hash := bcryptHash(t, "pw")
	res, err := f.svc.ValidateImport(ctx, f.tenantID, &f.appID, admin.ImportDocument{
		Users: []admin.ImportUser{
			{Email: "dup@example.com", PasswordHash: hash},
			{Email: "DUP@Example.com", PasswordHash: hash}, // same address, different case
		},
	})
	if err != nil {
		t.Fatalf("ValidateImport() error = %v", err)
	}
	if res.Created != 1 || res.Rejected != 1 {
		t.Errorf("created=%d rejected=%d, want 1/1; rows=%+v", res.Created, res.Rejected, res.Rows)
	}
}

// A row with no credential and no federated identity would import an account
// that cannot authenticate at all.
func TestImport_RejectsUnauthenticatableRow(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	res, err := f.svc.ValidateImport(ctx, f.tenantID, &f.appID, admin.ImportDocument{
		Users: []admin.ImportUser{{Email: "nologin@example.com", FirstName: "No"}},
	})
	if err != nil {
		t.Fatalf("ValidateImport() error = %v", err)
	}
	if row := rowByEmail(t, res, "nologin@example.com"); row.Outcome != admin.ImportOutcomeReject {
		t.Errorf("outcome = %q, want reject", row.Outcome)
	}
}

// Federated identities must be written, preserving provider_sub exactly — a
// changed subject silently turns a migrated user into a new account at first
// social login.
func TestCommitImport_WritesIdentities(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	const sub = "108127461982736451923"
	res, err := f.svc.CommitImport(ctx, f.tenantID, &f.appID, admin.ImportDocument{
		Users: []admin.ImportUser{{
			Email: "federated@example.com",
			// Required alongside an identity: without it neither the subject nor
			// the email fallback can ever link the account.
			EmailVerified: true,
			Identities:    []admin.ImportIdentity{{Provider: "google", ProviderSub: sub, ProviderEmail: "fed@gmail.com"}},
		}},
	})
	if err != nil {
		t.Fatalf("CommitImport() error = %v", err)
	}
	if res.Created != 1 {
		t.Fatalf("created = %d, want 1; rows=%+v", res.Created, res.Rows)
	}

	var gotProvider, gotSub string
	if err := f.pool.QueryRow(ctx, `
		SELECT ui.provider, ui.provider_sub FROM user_identities ui
		JOIN users u ON u.id = ui.user_id
		WHERE u.email = 'federated@example.com'`).Scan(&gotProvider, &gotSub); err != nil {
		t.Fatalf("read identity: %v", err)
	}
	if gotProvider != "google" || gotSub != sub {
		t.Errorf("identity = (%q,%q), want (google,%q)", gotProvider, gotSub, sub)
	}
}

// user_identities.application_id is NOT NULL, so an identity cannot belong to a
// tenant-level user. Rejected explicitly rather than silently dropped.
func TestImport_RejectsIdentityOnTenantLevelImport(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	res, err := f.svc.ValidateImport(ctx, f.tenantID, nil, admin.ImportDocument{
		Users: []admin.ImportUser{{
			Email:      "tenantfed@example.com",
			Identities: []admin.ImportIdentity{{Provider: "google", ProviderSub: "x"}},
		}},
	})
	if err != nil {
		t.Fatalf("ValidateImport() error = %v", err)
	}
	if row := rowByEmail(t, res, "tenantfed@example.com"); row.Outcome != admin.ImportOutcomeReject {
		t.Errorf("outcome = %q, want reject", row.Outcome)
	}
}

// password_changed_at must come from the source export, not default to NOW():
// an imported credential was not just rotated.
func TestCommitImport_PreservesPasswordChangedAt(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	old := time.Date(2021, 3, 14, 15, 9, 26, 0, time.UTC)
	if _, err := f.svc.CommitImport(ctx, f.tenantID, &f.appID, admin.ImportDocument{
		Users: []admin.ImportUser{{
			Email:             "aged@example.com",
			PasswordHash:      bcryptHash(t, "pw"),
			PasswordChangedAt: &old,
		}},
	}); err != nil {
		t.Fatalf("CommitImport() error = %v", err)
	}

	var got time.Time
	if err := f.pool.QueryRow(ctx, `
		SELECT uc.password_changed_at FROM user_credentials uc
		JOIN users u ON u.id = uc.user_id
		WHERE u.email = 'aged@example.com'`).Scan(&got); err != nil {
		t.Fatalf("read password_changed_at: %v", err)
	}
	if !got.UTC().Equal(old) {
		t.Errorf("password_changed_at = %s, want %s", got.UTC(), old)
	}
}

// An absent is_active must import an ACTIVE user; an explicit false must be
// honoured. The zero value of bool cannot express that distinction, so the
// custom UnmarshalJSON is load-bearing.
func TestImportUser_IsActiveDefaultsTrue(t *testing.T) {
	var doc admin.ImportDocument
	if err := json.Unmarshal([]byte(`{"users":[
		{"email":"a@example.com"},
		{"email":"b@example.com","is_active":false},
		{"email":"c@example.com","is_active":true}
	]}`), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	want := []bool{true, false, true}
	for i, w := range want {
		if doc.Users[i].IsActive != w {
			t.Errorf("users[%d].IsActive = %v, want %v", i, doc.Users[i].IsActive, w)
		}
	}
}

// The scope an import runs against comes from the caller, so a document cannot
// reach another tenant. Importing into tenant A must not be visible in B.
func TestCommitImport_ScopeIsolation(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	var otherTenant int64
	if err := f.pool.QueryRow(ctx, `
		INSERT INTO tenants (name, slug, jwt_secret, is_active)
		VALUES ('Import Isolation', 'import-isolation', 'test-secret-not-used', true)
		RETURNING id`).Scan(&otherTenant); err != nil {
		t.Fatalf("create foreign tenant: %v", err)
	}

	if _, err := f.svc.CommitImport(ctx, f.tenantID, &f.appID, admin.ImportDocument{
		Users: []admin.ImportUser{{Email: "scoped@example.com", PasswordHash: bcryptHash(t, "pw")}},
	}); err != nil {
		t.Fatalf("CommitImport() error = %v", err)
	}

	var n int
	if err := f.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM users WHERE tenant_id = $1`, otherTenant).Scan(&n); err != nil {
		t.Fatalf("count foreign tenant users: %v", err)
	}
	if n != 0 {
		t.Errorf("import leaked %d users into another tenant", n)
	}
}

// A document larger than the cap is refused outright rather than partially
// applied.
func TestImport_RefusesOversizedDocument(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	users := make([]admin.ImportUser, 5001)
	for i := range users {
		users[i] = admin.ImportUser{Email: "x@example.com", PasswordHash: "irrelevant"}
	}
	if _, err := f.svc.ValidateImport(ctx, f.tenantID, &f.appID, admin.ImportDocument{Users: users}); err == nil {
		t.Error("oversized document accepted, want ErrImportTooLarge")
	}
}

// A role name padded with whitespace — the shape a spreadsheet export produces —
// must still resolve. The padding is invisible to whoever wrote the file, so
// rejecting it would be a puzzle with no clue attached.
func TestImport_TrimsRoleName(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	if _, err := f.svc.CreateRole(ctx, f.tenantID, &f.appID, "EMC", nil); err != nil {
		t.Fatalf("CreateRole() error = %v", err)
	}

	res, err := f.svc.CommitImport(ctx, f.tenantID, &f.appID, admin.ImportDocument{
		Users: []admin.ImportUser{{
			Email:        "padded@example.com",
			Role:         "  EMC  ",
			PasswordHash: bcryptHash(t, "pw"),
		}},
	})
	if err != nil {
		t.Fatalf("CommitImport() error = %v", err)
	}
	if res.Created != 1 {
		t.Fatalf("created = %d, want 1; rows = %+v", res.Created, res.Rows)
	}

	var roleName string
	if err := f.pool.QueryRow(ctx, `
		SELECT r.name FROM users u JOIN roles r ON r.id = u.role_id
		WHERE u.email = 'padded@example.com'`).Scan(&roleName); err != nil {
		t.Fatalf("read assigned role: %v", err)
	}
	if roleName != "EMC" {
		t.Errorf("assigned role = %q, want %q", roleName, "EMC")
	}
}

// Case is NOT folded: roles.name is unique per (tenant, application)
// case-sensitively, so "emc" and "EMC" can both exist and guessing between them
// would hand out the wrong one.
func TestImport_RoleNameIsCaseSensitive(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	if _, err := f.svc.CreateRole(ctx, f.tenantID, &f.appID, "EMC", nil); err != nil {
		t.Fatalf("CreateRole() error = %v", err)
	}

	res, err := f.svc.ValidateImport(ctx, f.tenantID, &f.appID, admin.ImportDocument{
		Users: []admin.ImportUser{{
			Email:        "wrongcase@example.com",
			Role:         "emc",
			PasswordHash: bcryptHash(t, "pw"),
		}},
	})
	if err != nil {
		t.Fatalf("ValidateImport() error = %v", err)
	}
	if row := rowByEmail(t, res, "wrongcase@example.com"); row.Outcome != admin.ImportOutcomeReject {
		t.Errorf("lowercase role accepted (outcome %q) — would assign the wrong role", row.Outcome)
	}
}

// A role that exists in ANOTHER application must not be reachable, and the row
// must be rejected rather than imported role-less. Importing it without the role
// would be worse than failing: the operator would believe the role was applied.
func TestImport_RejectsRoleFromAnotherApplication(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	appSvc := auth.NewApplicationService(f.pool, testhelper.TestLogger())
	otherApp, err := appSvc.CreateApplication(ctx, f.tenantID,
		"role-scope-app-"+time.Now().Format("150405.000000000"), "web", nil)
	if err != nil {
		t.Fatalf("CreateApplication() error = %v", err)
	}
	var otherAppID int64
	if err := f.pool.QueryRow(ctx,
		`SELECT id FROM oauth_clients WHERE client_id = $1`, otherApp.ClientID).Scan(&otherAppID); err != nil {
		t.Fatalf("fetch other app id: %v", err)
	}
	if _, err := f.svc.CreateRole(ctx, f.tenantID, &otherAppID, "ForeignRole", nil); err != nil {
		t.Fatalf("CreateRole() error = %v", err)
	}

	res, err := f.svc.ValidateImport(ctx, f.tenantID, &f.appID, admin.ImportDocument{
		Users: []admin.ImportUser{{
			Email:        "foreignrole@example.com",
			Role:         "ForeignRole",
			PasswordHash: bcryptHash(t, "pw"),
		}},
	})
	if err != nil {
		t.Fatalf("ValidateImport() error = %v", err)
	}
	row := rowByEmail(t, res, "foreignrole@example.com")
	if row.Outcome != admin.ImportOutcomeReject {
		t.Fatalf("another application's role was accepted (outcome %q)", row.Outcome)
	}
	if !strings.Contains(row.Reason, "not available in this application") {
		t.Errorf("reason = %q, want it to say the role is unavailable here", row.Reason)
	}
	// The message must not confirm whether the role exists elsewhere.
	if strings.Contains(strings.ToLower(row.Reason), "system") {
		t.Errorf("reason leaks why the role is unavailable: %q", row.Reason)
	}
}

// A row that names no role takes the application's DEFAULT role — the same one
// self-registration applies — so a migrated user and a user who signs up a
// minute later land identically.
func TestImport_AppliesDefaultRoleWhenRowNamesNone(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	role, err := f.svc.CreateRole(ctx, f.tenantID, &f.appID, "DefaultMember", nil)
	if err != nil {
		t.Fatalf("CreateRole() error = %v", err)
	}
	if err := f.svc.SetDefaultRole(ctx, f.tenantID, f.appID, parseID(t, role.ID)); err != nil {
		t.Fatalf("SetDefaultRole() error = %v", err)
	}

	if _, err := f.svc.CommitImport(ctx, f.tenantID, &f.appID, admin.ImportDocument{
		Users: []admin.ImportUser{{
			Email:        "norole@example.com",
			PasswordHash: bcryptHash(t, "pw"),
		}},
	}); err != nil {
		t.Fatalf("CommitImport() error = %v", err)
	}

	var got string
	if err := f.pool.QueryRow(ctx, `
		SELECT COALESCE(r.name, '') FROM users u
		LEFT JOIN roles r ON r.id = u.role_id
		WHERE u.email = 'norole@example.com'`).Scan(&got); err != nil {
		t.Fatalf("read assigned role: %v", err)
	}
	if got != "DefaultMember" {
		t.Errorf("assigned role = %q, want the application default %q", got, "DefaultMember")
	}
}

// With no default configured, a row naming no role imports with no role —
// blank, not an error.
func TestImport_NoRoleAndNoDefaultLeavesBlank(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	if _, err := f.svc.CommitImport(ctx, f.tenantID, &f.appID, admin.ImportDocument{
		Users: []admin.ImportUser{{
			Email:        "blankrole@example.com",
			PasswordHash: bcryptHash(t, "pw"),
		}},
	}); err != nil {
		t.Fatalf("CommitImport() error = %v", err)
	}

	var roleID *int64
	if err := f.pool.QueryRow(ctx,
		`SELECT role_id FROM users WHERE email = 'blankrole@example.com'`).Scan(&roleID); err != nil {
		t.Fatalf("read role_id: %v", err)
	}
	if roleID != nil {
		t.Errorf("role_id = %v, want NULL when no role is named and none is default", *roleID)
	}
}

// An explicitly named role always wins over the default.
func TestImport_NamedRoleBeatsDefault(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	def, err := f.svc.CreateRole(ctx, f.tenantID, &f.appID, "DefaultMember", nil)
	if err != nil {
		t.Fatalf("CreateRole(default) error = %v", err)
	}
	if err := f.svc.SetDefaultRole(ctx, f.tenantID, f.appID, parseID(t, def.ID)); err != nil {
		t.Fatalf("SetDefaultRole() error = %v", err)
	}
	if _, err := f.svc.CreateRole(ctx, f.tenantID, &f.appID, "EMC", nil); err != nil {
		t.Fatalf("CreateRole(EMC) error = %v", err)
	}

	if _, err := f.svc.CommitImport(ctx, f.tenantID, &f.appID, admin.ImportDocument{
		Users: []admin.ImportUser{{
			Email:        "named@example.com",
			Role:         "EMC",
			PasswordHash: bcryptHash(t, "pw"),
		}},
	}); err != nil {
		t.Fatalf("CommitImport() error = %v", err)
	}

	var got string
	if err := f.pool.QueryRow(ctx, `
		SELECT COALESCE(r.name, '') FROM users u
		LEFT JOIN roles r ON r.id = u.role_id
		WHERE u.email = 'named@example.com'`).Scan(&got); err != nil {
		t.Fatalf("read assigned role: %v", err)
	}
	if got != "EMC" {
		t.Errorf("assigned role = %q, want the named role %q", got, "EMC")
	}
}

// --- update_existing -----------------------------------------------------

// The default must stay non-destructive: without the flag, an existing user is
// skipped and nothing about them changes.
func TestImport_WithoutUpdateExisting_LeavesUserAlone(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	viewer, err := f.svc.CreateRole(ctx, f.tenantID, &f.appID, "Viewer", nil)
	if err != nil {
		t.Fatalf("CreateRole() error = %v", err)
	}
	if _, err := f.svc.CreateRole(ctx, f.tenantID, &f.appID, "EMC", nil); err != nil {
		t.Fatalf("CreateRole(EMC) error = %v", err)
	}
	viewerID := parseID(t, viewer.ID)
	if _, err := f.svc.CreateUser(ctx, f.tenantID, &f.appID,
		"existing@example.com", "pw-existing-12345", "Ex", "Isting", &viewerID); err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}

	res, err := f.svc.CommitImport(ctx, f.tenantID, &f.appID, admin.ImportDocument{
		Users: []admin.ImportUser{{
			Email:        "existing@example.com",
			FirstName:    "Overwritten",
			Role:         "EMC",
			PasswordHash: bcryptHash(t, "pw"),
		}},
	})
	if err != nil {
		t.Fatalf("CommitImport() error = %v", err)
	}
	if res.Skipped != 1 || res.Updated != 0 {
		t.Errorf("skipped=%d updated=%d, want 1/0", res.Skipped, res.Updated)
	}

	var roleName, firstName string
	if err := f.pool.QueryRow(ctx, `
		SELECT COALESCE(r.name, ''), u.first_name FROM users u
		LEFT JOIN roles r ON r.id = u.role_id
		WHERE u.email = 'existing@example.com'`).Scan(&roleName, &firstName); err != nil {
		t.Fatalf("read user: %v", err)
	}
	if roleName != "Viewer" || firstName != "Ex" {
		t.Errorf("user was modified without update_existing: role=%q first_name=%q", roleName, firstName)
	}
}

// With the flag on, the role is amended and the dry run names the change before
// anything is written.
func TestImport_UpdateExisting_AmendsRoleAndReportsChange(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	viewer, err := f.svc.CreateRole(ctx, f.tenantID, &f.appID, "Viewer", nil)
	if err != nil {
		t.Fatalf("CreateRole() error = %v", err)
	}
	if _, err := f.svc.CreateRole(ctx, f.tenantID, &f.appID, "EMC", nil); err != nil {
		t.Fatalf("CreateRole(EMC) error = %v", err)
	}
	viewerID := parseID(t, viewer.ID)
	if _, err := f.svc.CreateUser(ctx, f.tenantID, &f.appID,
		"promote@example.com", "pw-promote-12345", "Pro", "Mote", &viewerID); err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}

	doc := admin.ImportDocument{
		UpdateExisting: true,
		Users: []admin.ImportUser{{
			Email:        "promote@example.com",
			Role:         "EMC",
			PasswordHash: bcryptHash(t, "pw"),
		}},
	}

	dry, err := f.svc.ValidateImport(ctx, f.tenantID, &f.appID, doc)
	if err != nil {
		t.Fatalf("ValidateImport() error = %v", err)
	}
	row := rowByEmail(t, dry, "promote@example.com")
	if row.Outcome != admin.ImportOutcomeUpdate {
		t.Fatalf("dry-run outcome = %q, want update", row.Outcome)
	}
	if !strings.Contains(row.Reason, "Viewer") || !strings.Contains(row.Reason, "EMC") {
		t.Errorf("dry run does not name the change: %q", row.Reason)
	}

	// The dry run must still have written nothing.
	var beforeRole string
	if err := f.pool.QueryRow(ctx, `
		SELECT COALESCE(r.name, '') FROM users u LEFT JOIN roles r ON r.id = u.role_id
		WHERE u.email = 'promote@example.com'`).Scan(&beforeRole); err != nil {
		t.Fatal(err)
	}
	if beforeRole != "Viewer" {
		t.Errorf("dry run amended the role: %q", beforeRole)
	}

	if _, err := f.svc.CommitImport(ctx, f.tenantID, &f.appID, doc); err != nil {
		t.Fatalf("CommitImport() error = %v", err)
	}
	var afterRole string
	if err := f.pool.QueryRow(ctx, `
		SELECT COALESCE(r.name, '') FROM users u LEFT JOIN roles r ON r.id = u.role_id
		WHERE u.email = 'promote@example.com'`).Scan(&afterRole); err != nil {
		t.Fatal(err)
	}
	if afterRole != "EMC" {
		t.Errorf("role after update = %q, want EMC", afterRole)
	}
}

// An update must never rewrite a credential. A file that could overwrite
// password_hash on live accounts is an account-takeover primitive.
func TestImport_UpdateExisting_NeverTouchesCredentials(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	if _, err := f.svc.CreateUser(ctx, f.tenantID, &f.appID,
		"keepcreds@example.com", "the-real-password", "Keep", "Creds", nil); err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	var before string
	if err := f.pool.QueryRow(ctx, `
		SELECT uc.password_hash FROM user_credentials uc
		JOIN users u ON u.id = uc.user_id WHERE u.email = 'keepcreds@example.com'`).Scan(&before); err != nil {
		t.Fatal(err)
	}

	if _, err := f.svc.CommitImport(ctx, f.tenantID, &f.appID, admin.ImportDocument{
		UpdateExisting: true,
		Users: []admin.ImportUser{{
			Email:        "keepcreds@example.com",
			PasswordHash: bcryptHash(t, "attacker-chosen-password"),
		}},
	}); err != nil {
		t.Fatalf("CommitImport() error = %v", err)
	}

	var after string
	if err := f.pool.QueryRow(ctx, `
		SELECT uc.password_hash FROM user_credentials uc
		JOIN users u ON u.id = uc.user_id WHERE u.email = 'keepcreds@example.com'`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Error("update_existing overwrote a live credential — account takeover via upload")
	}
	// And the original password must still work.
	h := password.NewHasher(password.Params{})
	if err := h.Verify(ctx, "the-real-password", after); err != nil {
		t.Errorf("original password no longer verifies: %v", err)
	}
}

// A file listing only emails and roles must not blank everybody's name.
func TestImport_UpdateExisting_KeepsAbsentProfileFields(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	if _, err := f.svc.CreateUser(ctx, f.tenantID, &f.appID,
		"keepname@example.com", "pw-keepname-1234", "Original", "Name", nil); err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}

	if _, err := f.svc.CommitImport(ctx, f.tenantID, &f.appID, admin.ImportDocument{
		UpdateExisting: true,
		Users:          []admin.ImportUser{{Email: "keepname@example.com", PasswordHash: bcryptHash(t, "pw")}},
	}); err != nil {
		t.Fatalf("CommitImport() error = %v", err)
	}

	var first, last string
	if err := f.pool.QueryRow(ctx,
		`SELECT first_name, last_name FROM users WHERE email = 'keepname@example.com'`).Scan(&first, &last); err != nil {
		t.Fatal(err)
	}
	if first != "Original" || last != "Name" {
		t.Errorf("absent profile fields were blanked: %q %q", first, last)
	}
}

// An update still cannot reach a system role — the same refusal as creation.
func TestImport_UpdateExisting_StillRefusesSystemRole(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	if _, err := f.svc.CreateUser(ctx, f.tenantID, &f.appID,
		"noescalate@example.com", "pw-noescalate-12", "No", "Escalate", nil); err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}

	res, err := f.svc.ValidateImport(ctx, f.tenantID, &f.appID, admin.ImportDocument{
		UpdateExisting: true,
		Users: []admin.ImportUser{{
			Email:        "noescalate@example.com",
			Role:         "owner",
			PasswordHash: bcryptHash(t, "pw"),
		}},
	})
	if err != nil {
		t.Fatalf("ValidateImport() error = %v", err)
	}
	if row := rowByEmail(t, res, "noescalate@example.com"); row.Outcome != admin.ImportOutcomeReject {
		t.Errorf("update path granted a system role (outcome %q)", row.Outcome)
	}
}

// --- plaintext passwords -------------------------------------------------

// A row may carry a hash or a plaintext password, never both. Silently
// preferring one would give the operator an account whose password is not the
// one they believe they imported.
func TestImport_RejectsBothHashAndPlaintext(t *testing.T) {
	f := newAdminFixture(t)
	res, err := f.svc.ValidateImport(context.Background(), f.tenantID, &f.appID, admin.ImportDocument{
		Users: []admin.ImportUser{{
			Email:        "both@example.com",
			PasswordHash: bcryptHash(t, "pw"),
			Password:     "PlaintextToo123",
		}},
	})
	if err != nil {
		t.Fatalf("ValidateImport() error = %v", err)
	}
	row := rowByEmail(t, res, "both@example.com")
	if row.Outcome != admin.ImportOutcomeReject {
		t.Fatalf("row carrying both credentials accepted (outcome %q)", row.Outcome)
	}
	if !strings.Contains(row.Reason, "exactly one") {
		t.Errorf("reason = %q, want it to say exactly one is required", row.Reason)
	}
}

// A plaintext password is hashed with current parameters and authenticates.
func TestImport_HashesPlaintextPassword(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	const pw = "Plaintext!Migrate1"
	if _, err := f.svc.CommitImport(ctx, f.tenantID, &f.appID, admin.ImportDocument{
		Users: []admin.ImportUser{{Email: "plain@example.com", Password: pw}},
	}); err != nil {
		t.Fatalf("CommitImport() error = %v", err)
	}

	var stored string
	if err := f.pool.QueryRow(ctx, `
		SELECT uc.password_hash FROM user_credentials uc
		JOIN users u ON u.id = uc.user_id
		WHERE u.email = 'plain@example.com'`).Scan(&stored); err != nil {
		t.Fatalf("read stored hash: %v", err)
	}

	// Stored at CURRENT parameters, so unlike an imported bcrypt digest it is
	// not scheduled for upgrade.
	h := password.NewHasher(password.Params{})
	if password.Identify(stored) != password.AlgorithmArgon2id {
		t.Errorf("stored algorithm = %q, want argon2id", password.Identify(stored))
	}
	if err := h.Verify(ctx, pw, stored); err != nil {
		t.Errorf("hashed plaintext does not verify: %v", err)
	}
	if h.NeedsRehash(stored) {
		t.Error("freshly hashed credential marked for rehash")
	}
	// The plaintext must not have been stored anywhere.
	if strings.Contains(stored, pw) {
		t.Error("plaintext leaked into the stored credential")
	}
}

// A digest in the plaintext field is the likeliest export-script mistake, and
// hashing it twice would leave an account whose password nobody knows.
func TestImport_RejectsHashInPlaintextField(t *testing.T) {
	f := newAdminFixture(t)
	res, err := f.svc.ValidateImport(context.Background(), f.tenantID, &f.appID, admin.ImportDocument{
		Users: []admin.ImportUser{{Email: "wrongfield@example.com", Password: bcryptHash(t, "pw")}},
	})
	if err != nil {
		t.Fatalf("ValidateImport() error = %v", err)
	}
	if row := rowByEmail(t, res, "wrongfield@example.com"); row.Outcome != admin.ImportOutcomeReject {
		t.Errorf("hash in the password field accepted (outcome %q)", row.Outcome)
	}
}

// The import must not accept weaker passwords than the product's own
// set-password flows, or it becomes a way around the policy.
func TestImport_RejectsShortPlaintext(t *testing.T) {
	f := newAdminFixture(t)
	res, err := f.svc.ValidateImport(context.Background(), f.tenantID, &f.appID, admin.ImportDocument{
		Users: []admin.ImportUser{{Email: "short@example.com", Password: "abc"}},
	})
	if err != nil {
		t.Fatalf("ValidateImport() error = %v", err)
	}
	if row := rowByEmail(t, res, "short@example.com"); row.Outcome != admin.ImportOutcomeReject {
		t.Errorf("short password accepted (outcome %q)", row.Outcome)
	}
}

// A mixed file — some rows pre-hashed, some plaintext — is the realistic
// migration shape and must work.
func TestImport_AcceptsMixedCredentialForms(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	res, err := f.svc.CommitImport(ctx, f.tenantID, &f.appID, admin.ImportDocument{
		Users: []admin.ImportUser{
			{Email: "mix-hashed@example.com", PasswordHash: bcryptHash(t, "hashed-one")},
			{Email: "mix-plain@example.com", Password: "Plaintext!One23"},
			{Email: "mix-fed@example.com", EmailVerified: true, Identities: []admin.ImportIdentity{
				{Provider: "google", ProviderSub: "900112233445566778"},
			}},
		},
	})
	if err != nil {
		t.Fatalf("CommitImport() error = %v", err)
	}
	if res.Created != 3 {
		t.Fatalf("created = %d, want 3; rows = %+v", res.Created, res.Rows)
	}

	h := password.NewHasher(password.Params{})
	for email, pw := range map[string]string{
		"mix-hashed@example.com": "hashed-one",
		"mix-plain@example.com":  "Plaintext!One23",
	} {
		var stored string
		if err := f.pool.QueryRow(ctx, `
			SELECT uc.password_hash FROM user_credentials uc
			JOIN users u ON u.id = uc.user_id WHERE u.email = $1`, email).Scan(&stored); err != nil {
			t.Fatalf("read %s: %v", email, err)
		}
		if err := h.Verify(ctx, pw, stored); err != nil {
			t.Errorf("%s does not authenticate: %v", email, err)
		}
	}
}

// --- federated identity guard --------------------------------------------

// An identity on an unverified address is a dead end in both directions: the
// imported subject only matches if this application shares the source's OAuth
// client, and the email fallback that would otherwise link the account is
// refused for an unverified address. The row would create a user who can never
// sign in.
func TestImport_RejectsIdentityWithoutVerifiedEmail(t *testing.T) {
	f := newAdminFixture(t)
	res, err := f.svc.ValidateImport(context.Background(), f.tenantID, &f.appID, admin.ImportDocument{
		Users: []admin.ImportUser{{
			Email:         "unverified.fed@example.com",
			EmailVerified: false,
			Identities:    []admin.ImportIdentity{{Provider: "google", ProviderSub: "1078"}},
		}},
	})
	if err != nil {
		t.Fatalf("ValidateImport() error = %v", err)
	}
	row := rowByEmail(t, res, "unverified.fed@example.com")
	if row.Outcome != admin.ImportOutcomeReject {
		t.Fatalf("identity on an unverified email accepted (outcome %q)", row.Outcome)
	}
	if !strings.Contains(row.Reason, "email_verified") {
		t.Errorf("reason does not name the missing flag: %q", row.Reason)
	}
}

// The migration shape recommended in the docs: no identity at all, a verified
// address, and the link created at first social sign-in. This must import
// cleanly even though the row carries no credential of any kind.
func TestImport_AcceptsSocialUserWithoutIdentity(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	res, err := f.svc.CommitImport(ctx, f.tenantID, &f.appID, admin.ImportDocument{
		Users: []admin.ImportUser{{
			Email:         "social.pending@example.com",
			FirstName:     "Social",
			EmailVerified: true,
			// No password_hash, no password, no identities — the account is
			// claimed by the provider at first sign-in.
		}},
	})
	if err != nil {
		t.Fatalf("CommitImport() error = %v", err)
	}
	if res.Created != 1 {
		t.Fatalf("created = %d, want 1; rows = %+v", res.Created, res.Rows)
	}

	// Verified, and holding neither a credential nor an identity — exactly the
	// state the email fallback needs to link against.
	var verified bool
	var creds, idents int
	if err := f.pool.QueryRow(ctx, `
		SELECT u.email_verified,
		       (SELECT COUNT(*) FROM user_credentials uc WHERE uc.user_id = u.id),
		       (SELECT COUNT(*) FROM user_identities ui WHERE ui.user_id = u.id)
		FROM users u WHERE u.email = 'social.pending@example.com'`).Scan(&verified, &creds, &idents); err != nil {
		t.Fatalf("read imported user: %v", err)
	}
	if !verified {
		t.Error("email_verified was not preserved; the social link would be refused")
	}
	if creds != 0 || idents != 0 {
		t.Errorf("credentials=%d identities=%d, want 0/0", creds, idents)
	}
}

// A verified address with an identity is still accepted — the same-OAuth-client
// case, where the imported subject genuinely matches.
func TestImport_AcceptsIdentityWithVerifiedEmail(t *testing.T) {
	f := newAdminFixture(t)
	res, err := f.svc.ValidateImport(context.Background(), f.tenantID, &f.appID, admin.ImportDocument{
		Users: []admin.ImportUser{{
			Email:         "verified.fed@example.com",
			EmailVerified: true,
			Identities:    []admin.ImportIdentity{{Provider: "google", ProviderSub: "1078"}},
		}},
	})
	if err != nil {
		t.Fatalf("ValidateImport() error = %v", err)
	}
	if row := rowByEmail(t, res, "verified.fed@example.com"); row.Outcome != admin.ImportOutcomeCreate {
		t.Errorf("outcome = %q (%s), want create", row.Outcome, row.Reason)
	}
}

// --- update_existing: an absent role is not an instruction ----------------

// A row that names no role must keep the role the user already has.
//
// The update wrote role_id unconditionally, so an omitted column silently
// applied the application default — the tier meant for a user being CREATED.
// A stale export listing only emails, fed back with update_existing, therefore
// demoted the entire directory in one upload. The dry run disclosed it, but
// "absent means reset" is not a reading of a migration file anyone expects.
func TestImport_UpdateExisting_AbsentRoleKeepsCurrentRole(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	def, err := f.svc.CreateRole(ctx, f.tenantID, &f.appID, "DefaultMember", nil)
	if err != nil {
		t.Fatalf("CreateRole(default) error = %v", err)
	}
	if err := f.svc.SetDefaultRole(ctx, f.tenantID, f.appID, parseID(t, def.ID)); err != nil {
		t.Fatalf("SetDefaultRole() error = %v", err)
	}
	elevated, err := f.svc.CreateRole(ctx, f.tenantID, &f.appID, "Manager", nil)
	if err != nil {
		t.Fatalf("CreateRole(Manager) error = %v", err)
	}

	u, err := f.svc.CreateUser(ctx, f.tenantID, &f.appID,
		"keeprole@example.com", "pw-keeprole-1234", "Keep", "Role", nil)
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	if err := f.svc.AssignUserRole(ctx, f.tenantID, &f.appID,
		parseID(t, u.ID), parseID(t, elevated.ID)); err != nil {
		t.Fatalf("AssignUserRole() error = %v", err)
	}

	// The row carries no Role — exactly the shape of an export trimmed to
	// emails, or a file written by hand that only means to fix a name.
	res, err := f.svc.CommitImport(ctx, f.tenantID, &f.appID, admin.ImportDocument{
		UpdateExisting: true,
		Users: []admin.ImportUser{{
			Email:        "keeprole@example.com",
			FirstName:    "Renamed",
			PasswordHash: bcryptHash(t, "pw"),
		}},
	})
	if err != nil {
		t.Fatalf("CommitImport() error = %v", err)
	}

	var role, first string
	if err := f.pool.QueryRow(ctx, `
		SELECT COALESCE(r.name, ''), u.first_name FROM users u
		LEFT JOIN roles r ON r.id = u.role_id
		WHERE u.email = 'keeprole@example.com'`).Scan(&role, &first); err != nil {
		t.Fatalf("read role: %v", err)
	}
	if role != "Manager" {
		t.Errorf("role = %q, want Manager kept — an absent role demoted the user", role)
	}
	// The rest of the update must still apply; "keep the role" is not "skip
	// the row".
	if first != "Renamed" {
		t.Errorf("first_name = %q, want Renamed — the update did not apply", first)
	}
	if row := rowByEmail(t, res, "keeprole@example.com"); row.Reason != "profile updated; role unchanged" {
		t.Errorf("reason = %q, want the unchanged-role wording", row.Reason)
	}
}

// The same rule protects a system role, which matters more: the importer
// refuses to GRANT one, so an unconditional write could strip a tier it has no
// way to restore. An owner listed in a file that names no role stays an owner.
func TestImport_UpdateExisting_AbsentRoleKeepsSystemRole(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	u, err := f.svc.CreateUser(ctx, f.tenantID, &f.appID,
		"keepsystem@example.com", "pw-keepsystem-12", "Keep", "System", nil)
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	// Set directly: CreateUser and AssignUserRole both refuse a system role,
	// which is the asymmetry under test — the row still exists in production.
	sysRoleID := seedSystemRoleID(t, f)
	if _, err := f.pool.Exec(ctx,
		`UPDATE users SET role_id = $1 WHERE id = $2`, sysRoleID, parseID(t, u.ID)); err != nil {
		t.Fatalf("set system role: %v", err)
	}

	if _, err := f.svc.CommitImport(ctx, f.tenantID, &f.appID, admin.ImportDocument{
		UpdateExisting: true,
		Users: []admin.ImportUser{{
			Email:        "keepsystem@example.com",
			PasswordHash: bcryptHash(t, "pw"),
		}},
	}); err != nil {
		t.Fatalf("CommitImport() error = %v", err)
	}

	var gotID int64
	if err := f.pool.QueryRow(ctx,
		`SELECT COALESCE(role_id, 0) FROM users WHERE email = 'keepsystem@example.com'`).Scan(&gotID); err != nil {
		t.Fatalf("read role id: %v", err)
	}
	if gotID != sysRoleID {
		t.Errorf("role_id = %d, want the system role %d kept — "+
			"an import stripped a tier it cannot grant back", gotID, sysRoleID)
	}
}

// Naming a role must still change it. The fix is "absent means keep", not
// "updates never touch the role" — without this the previous two tests would
// pass against a version that simply ignored the column.
func TestImport_UpdateExisting_NamedRoleStillChanges(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	from, err := f.svc.CreateRole(ctx, f.tenantID, &f.appID, "Before", nil)
	if err != nil {
		t.Fatalf("CreateRole(Before) error = %v", err)
	}
	if _, err := f.svc.CreateRole(ctx, f.tenantID, &f.appID, "After", nil); err != nil {
		t.Fatalf("CreateRole(After) error = %v", err)
	}

	u, err := f.svc.CreateUser(ctx, f.tenantID, &f.appID,
		"changerole@example.com", "pw-changerole-12", "Change", "Role", nil)
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	if err := f.svc.AssignUserRole(ctx, f.tenantID, &f.appID,
		parseID(t, u.ID), parseID(t, from.ID)); err != nil {
		t.Fatalf("AssignUserRole() error = %v", err)
	}

	res, err := f.svc.CommitImport(ctx, f.tenantID, &f.appID, admin.ImportDocument{
		UpdateExisting: true,
		Users: []admin.ImportUser{{
			Email:        "changerole@example.com",
			Role:         "After",
			PasswordHash: bcryptHash(t, "pw"),
		}},
	})
	if err != nil {
		t.Fatalf("CommitImport() error = %v", err)
	}

	var role string
	if err := f.pool.QueryRow(ctx, `
		SELECT COALESCE(r.name, '') FROM users u
		LEFT JOIN roles r ON r.id = u.role_id
		WHERE u.email = 'changerole@example.com'`).Scan(&role); err != nil {
		t.Fatalf("read role: %v", err)
	}
	if role != "After" {
		t.Errorf("role = %q, want After — a named role no longer applies", role)
	}
	if row := rowByEmail(t, res, "changerole@example.com"); row.Reason != "role Before → After" {
		t.Errorf("reason = %q, want the role change spelled out", row.Reason)
	}
}
