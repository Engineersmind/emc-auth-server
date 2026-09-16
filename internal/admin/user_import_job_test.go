package admin_test

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/engineersmind/emc-auth-server/internal/admin"
	"github.com/engineersmind/emc-auth-server/internal/password"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// drainJob runs the worker until the job leaves a running state, or fails the
// test. Exercises the real StartImportWorker rather than an inlined loop, so the
// claim, lease and completion paths are all covered.
func drainJob(t *testing.T, f adminFixture, id int64, appID *int64) *admin.ImportJob {
	t.Helper()
	ctx := context.Background()
	stop := f.svc.StartImportWorker(testhelper.TestLogger())
	defer stop()

	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		job, err := f.svc.GetImportJob(ctx, f.tenantID, appID, id)
		if err != nil {
			t.Fatalf("GetImportJob: %v", err)
		}
		switch job.Status {
		case admin.ImportJobCompleted, admin.ImportJobFailed, admin.ImportJobCancelled:
			return job
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatal("job did not finish within the deadline")
	return nil
}

func jobIDOf(t *testing.T, j *admin.ImportJob) int64 {
	t.Helper()
	id, err := strconv.ParseInt(j.ID, 10, 64)
	if err != nil {
		t.Fatalf("parse job id %q: %v", j.ID, err)
	}
	return id
}

// The queue must accept a document, report its shape immediately, and create
// nothing until the worker runs.
func TestEnqueueImport_WritesNothingBeforeTheWorkerRuns(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	job, err := f.svc.EnqueueImport(ctx, f.tenantID, &f.appID, admin.ImportDocument{
		Users: []admin.ImportUser{
			{Email: "queued-a@example.com", Password: "Queued!Pass123"},
			{Email: "queued-b@example.com", PasswordHash: bcryptHash(t, "pw")},
		},
	}, nil, "operator@example.com")
	if err != nil {
		t.Fatalf("EnqueueImport() error = %v", err)
	}

	if job.Status != admin.ImportJobPending {
		t.Errorf("status = %q, want pending", job.Status)
	}
	if job.TotalRows != 2 {
		t.Errorf("total_rows = %d, want 2", job.TotalRows)
	}

	var n int
	if err := f.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM users WHERE email LIKE 'queued-%@example.com'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("enqueue created %d users, want 0", n)
	}
}

// The worker drains the job, hashes the plaintext row, and both users
// authenticate afterwards.
func TestImportWorker_DrainsJobAndCredentialsWork(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	queued, err := f.svc.EnqueueImport(ctx, f.tenantID, &f.appID, admin.ImportDocument{
		Users: []admin.ImportUser{
			{Email: "drain-plain@example.com", Password: "Drain!Plain123"},
			{Email: "drain-hashed@example.com", PasswordHash: bcryptHash(t, "drain-hashed-pw")},
		},
	}, nil, "operator@example.com")
	if err != nil {
		t.Fatalf("EnqueueImport() error = %v", err)
	}

	job := drainJob(t, f, jobIDOf(t, queued), &f.appID)
	if job.Status != admin.ImportJobCompleted {
		t.Fatalf("status = %q (error %q), want completed", job.Status, job.Error)
	}
	if job.Created != 2 || job.ProcessedRows != 2 {
		t.Errorf("created=%d processed=%d, want 2/2", job.Created, job.ProcessedRows)
	}

	h := password.NewHasher(password.Params{})
	for email, pw := range map[string]string{
		"drain-plain@example.com":  "Drain!Plain123",
		"drain-hashed@example.com": "drain-hashed-pw",
	} {
		var stored string
		if err := f.pool.QueryRow(ctx, `
			SELECT uc.password_hash FROM user_credentials uc
			JOIN users u ON u.id = uc.user_id WHERE u.email = $1`, email).Scan(&stored); err != nil {
			t.Fatalf("read %s: %v", email, err)
		}
		if err := h.Verify(ctx, pw, stored); err != nil {
			t.Errorf("%s does not authenticate after the job: %v", email, err)
		}
	}
}

// A plaintext password is stored only until the row that consumes it is
// processed. Leaving live credentials at rest after the job would be the worst
// property of making the import durable.
func TestImportWorker_ErasesPlaintextAfterProcessing(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	queued, err := f.svc.EnqueueImport(ctx, f.tenantID, &f.appID, admin.ImportDocument{
		Users: []admin.ImportUser{{Email: "erase@example.com", Password: "Erase!Me12345"}},
	}, nil, "operator@example.com")
	if err != nil {
		t.Fatalf("EnqueueImport() error = %v", err)
	}
	id := jobIDOf(t, queued)

	// Present while queued — that is what makes the job resumable.
	var before int
	if err := f.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM user_import_job_rows WHERE job_id = $1 AND plaintext_password IS NOT NULL`,
		id).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if before != 1 {
		t.Fatalf("queued plaintext rows = %d, want 1", before)
	}

	drainJob(t, f, id, &f.appID)

	var after int
	if err := f.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM user_import_job_rows WHERE job_id = $1 AND plaintext_password IS NOT NULL`,
		id).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != 0 {
		t.Errorf("%d plaintext passwords still stored after the job", after)
	}
}

// Rejections are settled at enqueue and never claimed by the worker, so the
// report is complete without the worker re-deriving verdicts.
func TestEnqueueImport_RecordsRejectionsUpFront(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	queued, err := f.svc.EnqueueImport(ctx, f.tenantID, &f.appID, admin.ImportDocument{
		Users: []admin.ImportUser{
			{Email: "good@example.com", Password: "Good!Password1"},
			{Email: "not-an-email", Password: "Good!Password1"},
			{Email: "nocreds@example.com"},
		},
	}, nil, "operator@example.com")
	if err != nil {
		t.Fatalf("EnqueueImport() error = %v", err)
	}
	if queued.Rejected != 2 {
		t.Errorf("rejected = %d, want 2", queued.Rejected)
	}

	job := drainJob(t, f, jobIDOf(t, queued), &f.appID)
	if job.Created != 1 || job.Rejected != 2 {
		t.Errorf("created=%d rejected=%d, want 1/2", job.Created, job.Rejected)
	}

	rows, err := f.svc.ListImportJobRows(ctx, f.tenantID, &f.appID, jobIDOf(t, queued), 0)
	if err != nil {
		t.Fatalf("ListImportJobRows: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("report has %d rows, want 3", len(rows))
	}
	// Problems first.
	if rows[0].Outcome != admin.ImportOutcomeReject {
		t.Errorf("first reported row is %q, want a rejection", rows[0].Outcome)
	}
}

// A job id from another tenant must not be readable.
func TestGetImportJob_ScopeIsolation(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	queued, err := f.svc.EnqueueImport(ctx, f.tenantID, &f.appID, admin.ImportDocument{
		Users: []admin.ImportUser{{Email: "scoped@example.com", Password: "Scoped!Pass12"}},
	}, nil, "operator@example.com")
	if err != nil {
		t.Fatalf("EnqueueImport() error = %v", err)
	}

	var otherTenant int64
	if err := f.pool.QueryRow(ctx, `
		INSERT INTO tenants (name, slug, jwt_secret, is_active)
		VALUES ('Job Isolation', 'job-isolation', 'test-secret-not-used', true)
		RETURNING id`).Scan(&otherTenant); err != nil {
		t.Fatal(err)
	}

	if _, err := f.svc.GetImportJob(ctx, otherTenant, nil, jobIDOf(t, queued)); err == nil {
		t.Error("a job was readable from another tenant")
	}
}

// Cancelling stops further processing, and clears the credentials of rows that
// will now never run.
func TestCancelImportJob_StopsProcessing(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	queued, err := f.svc.EnqueueImport(ctx, f.tenantID, &f.appID, admin.ImportDocument{
		Users: []admin.ImportUser{{Email: "cancel@example.com", Password: "Cancel!Pass12"}},
	}, nil, "operator@example.com")
	if err != nil {
		t.Fatalf("EnqueueImport() error = %v", err)
	}
	id := jobIDOf(t, queued)

	if err := f.svc.CancelImportJob(ctx, f.tenantID, &f.appID, id); err != nil {
		t.Fatalf("CancelImportJob: %v", err)
	}

	job, err := f.svc.GetImportJob(ctx, f.tenantID, &f.appID, id)
	if err != nil {
		t.Fatal(err)
	}
	if job.Status != admin.ImportJobCancelled {
		t.Errorf("status = %q, want cancelled", job.Status)
	}

	var live int
	if err := f.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM user_import_job_rows WHERE job_id = $1 AND plaintext_password IS NOT NULL`,
		id).Scan(&live); err != nil {
		t.Fatal(err)
	}
	if live != 0 {
		t.Errorf("%d plaintext passwords left after cancellation", live)
	}
}

// A job abandoned mid-run — the shape a crash or a deploy leaves behind — must
// be reclaimed and finished, not stranded.
func TestImportWorker_ResumesAbandonedJob(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	queued, err := f.svc.EnqueueImport(ctx, f.tenantID, &f.appID, admin.ImportDocument{
		Users: []admin.ImportUser{
			{Email: "resume-a@example.com", PasswordHash: bcryptHash(t, "pw")},
			{Email: "resume-b@example.com", PasswordHash: bcryptHash(t, "pw")},
		},
	}, nil, "operator@example.com")
	if err != nil {
		t.Fatalf("EnqueueImport() error = %v", err)
	}
	id := jobIDOf(t, queued)

	// Simulate a worker that claimed the job and died: status running, lease
	// long expired, no rows processed.
	if _, err := f.pool.Exec(ctx, `
		UPDATE user_import_jobs
		SET status = 'running', locked_at = NOW() - INTERVAL '1 hour', locked_by = 'dead-worker'
		WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}

	job := drainJob(t, f, id, &f.appID)
	if job.Status != admin.ImportJobCompleted {
		t.Fatalf("status = %q, want completed after reclaim", job.Status)
	}
	if job.Created != 2 {
		t.Errorf("created = %d, want 2", job.Created)
	}
}
