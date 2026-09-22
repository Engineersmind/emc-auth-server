package admin_test

import (
	"context"
	"strings"
	"testing"

	"github.com/engineersmind/emc-auth-server/internal/admin"
)

// A role change applied by the WORKER must be reported as a role change, with
// or without an auth service wired.
//
// The reason string used to be built inside the `s.authSvc != nil` branch, so
// the two facts were welded together: no auth service meant no session
// revocation AND a demotion reported back to the operator as "profile updated;
// role unchanged". The dry run, which computes the reason from the role diff
// alone, said "role Manager → DefaultMember" for the same file — so the preview
// and the commit disagreed, in the direction that hides the change.
//
// The fixture builds the service without WithAuthService, which is exactly the
// configuration that exposed it: this test fails against the previous code.
func TestImportWorker_ReportsRoleChangeWithoutAuthService(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	def, err := f.svc.CreateRole(ctx, f.tenantID, &f.appID, "DefaultMember", nil)
	if err != nil {
		t.Fatalf("CreateRole(default) error = %v", err)
	}
	if err := f.svc.SetDefaultRole(ctx, f.tenantID, f.appID, parseID(t, def.ID)); err != nil {
		t.Fatalf("SetDefaultRole() error = %v", err)
	}
	if _, err := f.svc.CreateRole(ctx, f.tenantID, &f.appID, "Manager", nil); err != nil {
		t.Fatalf("CreateRole(Manager) error = %v", err)
	}

	u, err := f.svc.CreateUser(ctx, f.tenantID, &f.appID,
		"workerrole@example.com", "pw-workerrole-12", "Worker", "Role", nil)
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	var mgrID int64
	if err := f.pool.QueryRow(ctx,
		`SELECT id FROM roles WHERE name = 'Manager' AND tenant_id = $1`, f.tenantID).Scan(&mgrID); err != nil {
		t.Fatalf("read Manager id: %v", err)
	}
	if err := f.svc.AssignUserRole(ctx, f.tenantID, &f.appID, parseID(t, u.ID), mgrID); err != nil {
		t.Fatalf("AssignUserRole() error = %v", err)
	}

	// Demote through the async path, naming the role explicitly so this is a
	// real change rather than the absent-role case the other tests cover.
	queued, err := f.svc.EnqueueImport(ctx, f.tenantID, &f.appID, admin.ImportDocument{
		UpdateExisting: true,
		Users: []admin.ImportUser{{
			Email:        "workerrole@example.com",
			Role:         "DefaultMember",
			PasswordHash: bcryptHash(t, "pw"),
		}},
	}, nil, "operator@example.com")
	if err != nil {
		t.Fatalf("EnqueueImport() error = %v", err)
	}
	id := jobIDOf(t, queued)

	job := drainJob(t, f, id, &f.appID)
	if job.Status != admin.ImportJobCompleted {
		t.Fatalf("status = %q, want completed", job.Status)
	}
	if job.Updated != 1 {
		t.Fatalf("updated = %d, want 1", job.Updated)
	}

	// The role really did change — the report must not describe it otherwise.
	var role string
	if err := f.pool.QueryRow(ctx, `
		SELECT COALESCE(r.name, '') FROM users u
		LEFT JOIN roles r ON r.id = u.role_id
		WHERE u.email = 'workerrole@example.com'`).Scan(&role); err != nil {
		t.Fatalf("read role: %v", err)
	}
	if role != "DefaultMember" {
		t.Fatalf("role = %q, want DefaultMember — the import did not apply the change", role)
	}

	rows, err := f.svc.ListImportJobRows(ctx, f.tenantID, &f.appID, id, 100)
	if err != nil {
		t.Fatalf("ListImportJobRows() error = %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	if got := rows[0].Reason; !strings.Contains(got, "→") {
		t.Errorf("reason = %q, want the role change reported — "+
			"a demotion reported as unchanged hides it from the operator", got)
	}
	if got := rows[0].Reason; strings.Contains(got, "role unchanged") {
		t.Errorf("reason = %q, want the role change reported, not the unchanged wording", got)
	}
}

// A row that fails for an infrastructure reason on every attempt must not
// retry forever.
//
// Leaving the row pending is right for a transient blip — that fix stopped one
// dropped connection from writing off every remaining row of a large file. But
// with no bound the mirror-image failure appears: a row that fails identically
// every time keeps the job in `running` indefinitely, reclaimed each lease TTL,
// and GetImportJob cannot tell an operator the difference between a slow import
// and one wedged on row N since Tuesday.
//
// The failure is made reproducible rather than simulated: the row's application
// is deleted out from under the job, so every attempt hits the same foreign-key
// failure on insert. Past maxImportRowAttempts the row becomes a rejection
// carrying the reason, and the job finishes.
func TestImportWorker_StopsRetryingAPermanentlyFailingRow(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	queued, err := f.svc.EnqueueImport(ctx, f.tenantID, &f.appID, admin.ImportDocument{
		Users: []admin.ImportUser{
			{Email: "stuck@example.com", PasswordHash: bcryptHash(t, "pw")},
		},
	}, nil, "operator@example.com")
	if err != nil {
		t.Fatalf("EnqueueImport() error = %v", err)
	}
	id := jobIDOf(t, queued)

	// Force every insert for this job to fail the same way, permanently: the
	// job's application row is gone, so the user insert's FK can never be
	// satisfied no matter how many times the row is retried.
	if _, err := f.pool.Exec(ctx,
		`UPDATE user_import_jobs SET application_id = 2147483647 WHERE id = $1`, id); err != nil {
		t.Fatalf("point the job at a missing application: %v", err)
	}

	job := drainJob(t, f, id, &f.appID)

	// Whatever terminal state it reaches, the point is that it reaches one:
	// before the attempt bound this test hung until drainJob's deadline.
	if job.Status == admin.ImportJobRunning || job.Status == admin.ImportJobPending {
		t.Fatalf("status = %q, want a terminal state — the job never stopped retrying", job.Status)
	}

	var attempts int
	if err := f.pool.QueryRow(ctx,
		`SELECT attempts FROM user_import_job_rows WHERE job_id = $1`, id).Scan(&attempts); err != nil {
		t.Fatalf("read attempts: %v", err)
	}
	if attempts == 0 {
		t.Error("attempts = 0, want the retries counted — an uncounted retry cannot be bounded")
	}

	// The cause is kept for whoever has to work out why the row never landed.
	var lastErr string
	if err := f.pool.QueryRow(ctx,
		`SELECT last_error FROM user_import_job_rows WHERE job_id = $1`, id).Scan(&lastErr); err != nil {
		t.Fatalf("read last_error: %v", err)
	}
	if lastErr == "" {
		t.Error("last_error is empty, want the failure recorded — " +
			"a count with no cause says something failed and nothing about what")
	}
}

// The attempt bound must not cost a row that fails once and then succeeds.
//
// Without this the previous test would pass against a version that simply
// rejected on the first infrastructure error, which is the behaviour the
// pending-on-infra-failure fix exists to prevent.
func TestImportWorker_TransientFailureStillImportsTheRow(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	queued, err := f.svc.EnqueueImport(ctx, f.tenantID, &f.appID, admin.ImportDocument{
		Users: []admin.ImportUser{
			{Email: "transient@example.com", PasswordHash: bcryptHash(t, "pw")},
		},
	}, nil, "operator@example.com")
	if err != nil {
		t.Fatalf("EnqueueImport() error = %v", err)
	}
	id := jobIDOf(t, queued)

	// One attempt already spent, as if a worker had hit a blip here and left
	// the row pending. Well under the bound, so the row must still be applied.
	if _, err := f.pool.Exec(ctx, `
		UPDATE user_import_job_rows
		SET attempts = 1, last_error = 'simulated transient failure'
		WHERE job_id = $1`, id); err != nil {
		t.Fatalf("seed a spent attempt: %v", err)
	}

	job := drainJob(t, f, id, &f.appID)
	if job.Status != admin.ImportJobCompleted {
		t.Fatalf("status = %q, want completed", job.Status)
	}
	if job.Created != 1 {
		t.Errorf("created = %d, want 1 — a row that already failed once was written off", job.Created)
	}
}
