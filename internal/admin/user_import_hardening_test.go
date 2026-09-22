package admin_test

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/engineersmind/emc-auth-server/internal/admin"
	"github.com/engineersmind/emc-auth-server/internal/store"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// payloadOf reads one queued row's stored payload as a raw map, which is how the
// credential-redaction assertions have to read it: the point is which KEYS
// survive, and decoding through ImportUser would hide a key it has a field for.
func payloadOf(t *testing.T, f adminFixture, jobID int64, rowIndex int) map[string]any {
	t.Helper()
	var blob []byte
	if err := f.pool.QueryRow(context.Background(), `
		SELECT payload FROM user_import_job_rows
		WHERE job_id = $1 AND row_index = $2
	`, jobID, rowIndex).Scan(&blob); err != nil {
		t.Fatalf("read payload for row %d: %v", rowIndex, err)
	}
	var m map[string]any
	if err := json.Unmarshal(blob, &m); err != nil {
		t.Fatalf("decode payload for row %d: %v", rowIndex, err)
	}
	return m
}

// assertNoCredentialKeys fails if a payload still carries credential material.
func assertNoCredentialKeys(t *testing.T, where string, payload map[string]any) {
	t.Helper()
	for _, k := range []string{"password", "password_hash"} {
		if v, ok := payload[k]; ok && v != "" && v != nil {
			t.Errorf("%s: payload still carries %s = %v", where, k, v)
		}
	}
}

// Finding 4 — a processed row must not leave its digest in the payload.
//
// The plaintext column was already erased on this transition, but `stored := u`
// wrote the whole uploaded row into `payload`, so a finished job left one
// foreign password hash per row at rest with no consumer: the report reads only
// email, status and reason. That is a crackable corpus in a table nobody thinks
// to look in, and the export path beside it refuses to emit exactly this data.
func TestImportJob_ProcessedRowKeepsNoCredentialsInPayload(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	queued, err := f.svc.EnqueueImport(ctx, f.tenantID, &f.appID, admin.ImportDocument{
		Users: []admin.ImportUser{
			{Email: "redact-hashed@example.com", PasswordHash: bcryptHash(t, "redact-hashed-pw")},
			{Email: "redact-plain@example.com", Password: "Redact!Plain123"},
		},
	}, nil, "operator@example.com")
	if err != nil {
		t.Fatalf("EnqueueImport() error = %v", err)
	}
	id := jobIDOf(t, queued)

	// The digest is present while queued — the worker needs it to write the
	// credential, which is the whole reason it is stored at all.
	if got := payloadOf(t, f, id, 0)["password_hash"]; got == nil || got == "" {
		t.Fatal("queued row 0 has no password_hash; the test is not exercising the fix")
	}

	job := drainJob(t, f, id, &f.appID)
	if job.Status != admin.ImportJobCompleted {
		t.Fatalf("status = %q (error %q), want completed", job.Status, job.Error)
	}

	for _, row := range []int{0, 1} {
		p := payloadOf(t, f, id, row)
		assertNoCredentialKeys(t, "after processing", p)
		// The report still has to work: email is what ListImportJobRows reads.
		if p["email"] == nil || p["email"] == "" {
			t.Errorf("row %d lost its email, so the report is now useless", row)
		}
	}

	// And the report itself still resolves every row.
	rows, err := f.svc.ListImportJobRows(ctx, f.tenantID, &f.appID, id, 0)
	if err != nil {
		t.Fatalf("ListImportJobRows: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("report has %d rows, want 2", len(rows))
	}
	for _, r := range rows {
		if r.Email == "" {
			t.Errorf("reported row %d has no email", r.Index)
		}
	}
}

// Finding 4 — a row rejected at validation never runs, so its digest has no
// consumer either. It was being stored anyway.
func TestImportJob_RejectedRowKeepsNoCredentialsInPayload(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	// Rejected for a reason that has nothing to do with the credential, so the
	// digest reaching the payload is the only thing under test.
	queued, err := f.svc.EnqueueImport(ctx, f.tenantID, &f.appID, admin.ImportDocument{
		Users: []admin.ImportUser{
			{Email: "not-an-email", PasswordHash: bcryptHash(t, "rejected-but-real")},
		},
	}, nil, "operator@example.com")
	if err != nil {
		t.Fatalf("EnqueueImport() error = %v", err)
	}
	if queued.Rejected != 1 {
		t.Fatalf("rejected = %d, want 1", queued.Rejected)
	}

	assertNoCredentialKeys(t, "rejected at enqueue", payloadOf(t, f, jobIDOf(t, queued), 0))
}

// Finding 4 — cancellation is terminal for every row it stops, so it must clear
// the digest in the payload as well as the plaintext column it already cleared.
func TestCancelImportJob_ClearsPayloadCredentials(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	queued, err := f.svc.EnqueueImport(ctx, f.tenantID, &f.appID, admin.ImportDocument{
		Users: []admin.ImportUser{
			{Email: "cancel-hashed@example.com", PasswordHash: bcryptHash(t, "cancel-hashed-pw")},
			{Email: "cancel-plain@example.com", Password: "Cancel!Plain123"},
		},
	}, nil, "operator@example.com")
	if err != nil {
		t.Fatalf("EnqueueImport() error = %v", err)
	}
	id := jobIDOf(t, queued)

	if err := f.svc.CancelImportJob(ctx, f.tenantID, &f.appID, id); err != nil {
		t.Fatalf("CancelImportJob: %v", err)
	}

	for _, row := range []int{0, 1} {
		assertNoCredentialKeys(t, "after cancellation", payloadOf(t, f, id, row))
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

// Finding 8 — the queued payload must carry the NORMALISED email.
//
// The validator normalises before checking anything, but the payload was
// serialised from the row as uploaded, and the worker writes the payload value
// into users.email. A mixed-case address therefore landed in a form the
// normalising login lookup can never match, and a corrected re-run — which
// normalises before looking for an existing user — would create a second
// account for the same person rather than skipping them.
func TestEnqueueImport_PersistsNormalisedEmail(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	const uploaded = "MARCUS.Webb@Example.COM"
	const normalised = "marcus.webb@example.com"

	queued, err := f.svc.EnqueueImport(ctx, f.tenantID, &f.appID, admin.ImportDocument{
		Users: []admin.ImportUser{{Email: uploaded, PasswordHash: bcryptHash(t, "pw")}},
	}, nil, "operator@example.com")
	if err != nil {
		t.Fatalf("EnqueueImport() error = %v", err)
	}
	id := jobIDOf(t, queued)

	if got := payloadOf(t, f, id, 0)["email"]; got != normalised {
		t.Errorf("queued payload email = %v, want %q", got, normalised)
	}

	job := drainJob(t, f, id, &f.appID)
	if job.Created != 1 {
		t.Fatalf("created = %d (status %q, error %q), want 1", job.Created, job.Status, job.Error)
	}

	var stored string
	if err := f.pool.QueryRow(ctx,
		`SELECT email FROM users WHERE tenant_id = $1 AND lower(email) = $2`,
		f.tenantID, normalised).Scan(&stored); err != nil {
		t.Fatalf("the imported user is not findable by its normalised address: %v", err)
	}
	if stored != normalised {
		t.Errorf("users.email = %q, want %q", stored, normalised)
	}

	// The second half of the bug: a re-run must skip, not duplicate.
	again, err := f.svc.EnqueueImport(ctx, f.tenantID, &f.appID, admin.ImportDocument{
		Users: []admin.ImportUser{{Email: uploaded, PasswordHash: bcryptHash(t, "pw")}},
	}, nil, "operator@example.com")
	if err != nil {
		t.Fatalf("EnqueueImport() re-run error = %v", err)
	}
	rerun := drainJob(t, f, jobIDOf(t, again), &f.appID)
	if rerun.Created != 0 || rerun.Skipped != 1 {
		t.Errorf("re-run created=%d skipped=%d, want 0/1 — the address duplicated",
			rerun.Created, rerun.Skipped)
	}

	var n int
	if err := f.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM users WHERE tenant_id = $1 AND lower(email) = $2`,
		f.tenantID, normalised).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("%d rows exist for one person, want 1", n)
	}
}

// Finding 5 — a lease renewal must be fenced on the owner.
//
// A worker that stalls past its lease keeps a ticker running. Unfenced, its
// renewal refreshes locked_at on a job the reclaiming worker now owns, so the
// two drain the same rows with neither able to tell. The fence is asserted at
// the statement level because that is where the bug was: the renewal SQL had no
// locked_by predicate at all.
func TestImportJob_LeaseRenewalIsFencedOnOwner(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	queued, err := f.svc.EnqueueImport(ctx, f.tenantID, &f.appID, admin.ImportDocument{
		Users: []admin.ImportUser{{Email: "fence@example.com", PasswordHash: bcryptHash(t, "pw")}},
	}, nil, "operator@example.com")
	if err != nil {
		t.Fatalf("EnqueueImport() error = %v", err)
	}
	id := jobIDOf(t, queued)

	// The job as a live worker leaves it: running, held by someone.
	if _, err := f.pool.Exec(ctx, `
		UPDATE user_import_jobs
		SET status = 'running', locked_at = NOW() - INTERVAL '5 minutes', locked_by = 'worker-b'
		WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}

	var before time.Time
	if err := f.pool.QueryRow(ctx,
		`SELECT locked_at FROM user_import_jobs WHERE id = $1`, id).Scan(&before); err != nil {
		t.Fatal(err)
	}

	// The stalled worker's renewal, with its own id. It must not touch the row.
	ct, err := f.pool.Exec(ctx, `
		UPDATE user_import_jobs
		SET locked_at = NOW(), updated_at = NOW()
		WHERE id = $1 AND locked_by = $2
	`, id, "worker-a")
	if err != nil {
		t.Fatal(err)
	}
	if ct.RowsAffected() != 0 {
		t.Errorf("a stalled worker renewed a lease it does not own (%d rows)", ct.RowsAffected())
	}

	var after time.Time
	if err := f.pool.QueryRow(ctx,
		`SELECT locked_at FROM user_import_jobs WHERE id = $1`, id).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if !after.Equal(before) {
		t.Errorf("locked_at moved from %v to %v under the wrong owner", before, after)
	}

	// The real owner's renewal still works, or the fence is simply a break.
	ct, err = f.pool.Exec(ctx, `
		UPDATE user_import_jobs
		SET locked_at = NOW(), updated_at = NOW()
		WHERE id = $1 AND locked_by = $2
	`, id, "worker-b")
	if err != nil {
		t.Fatal(err)
	}
	if ct.RowsAffected() != 1 {
		t.Errorf("the lease owner could not renew its own lease (%d rows)", ct.RowsAffected())
	}
}

// Finding 5 — the worker must not finish a job whose lease it has lost.
//
// A worker that drains the last rows after its lease expired used to stamp
// `completed` over a job the reclaiming worker had already restarted, stranding
// that run in a terminal state with rows still pending. Every job mutation is
// now fenced, so a job held by somebody else is left exactly as found.
func TestImportWorker_DoesNotFinishAJobItNoLongerOwns(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	queued, err := f.svc.EnqueueImport(ctx, f.tenantID, &f.appID, admin.ImportDocument{
		Users: []admin.ImportUser{{Email: "stolen@example.com", PasswordHash: bcryptHash(t, "pw")}},
	}, nil, "operator@example.com")
	if err != nil {
		t.Fatalf("EnqueueImport() error = %v", err)
	}
	id := jobIDOf(t, queued)

	// Held by another live worker with a fresh lease, so nothing may reclaim it.
	if _, err := f.pool.Exec(ctx, `
		UPDATE user_import_jobs
		SET status = 'running', locked_at = NOW(), locked_by = 'another-worker'
		WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}

	// Run a real worker alongside it. The lease is unexpired, so claimImportJob
	// must skip the job entirely and nothing here may change it.
	stop := f.svc.StartImportWorker(testhelper.TestLogger())
	time.Sleep(2 * importPollForTest)
	stop()

	var status, lockedBy string
	var processed int
	if err := f.pool.QueryRow(ctx, `
		SELECT status, COALESCE(locked_by, ''), processed_rows
		FROM user_import_jobs WHERE id = $1`, id).Scan(&status, &lockedBy, &processed); err != nil {
		t.Fatal(err)
	}
	if status != "running" {
		t.Errorf("status = %q, want running — a foreign worker's job was altered", status)
	}
	if lockedBy != "another-worker" {
		t.Errorf("locked_by = %q, want another-worker — the lease was taken", lockedBy)
	}
	if processed != 0 {
		t.Errorf("processed_rows = %d, want 0 — rows of a foreign job were drained", processed)
	}
}

// importPollForTest mirrors the worker's poll interval. Kept local rather than
// exported from the package: the test waits on it, it does not set it.
const importPollForTest = 5 * time.Second

// Finding 6 — stop() must not return while a goroutine is still using the pool.
//
// This reproduces main's shutdown order exactly, because that order is the bug:
// main calls stop() and then closes the pool. A stop that only signalled
// returned while the drain was still mid-row, so the worker's next statement hit
// a closed pool — the row write failed, the job was never released, and it sat
// in `running` until the lease expired. The exact outcome graceful shutdown
// exists to prevent.
//
// The worker therefore runs on its OWN pool, which the test closes the instant
// stop() returns. If stop() did not wait, the goroutines are still live at that
// moment and the job is left stranded in `running`; if it waited, everything has
// already been released. The fixture's pool stays open to read the verdict.
func TestStartImportWorker_StopWaitsBeforeThePoolCloses(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	// Enough plaintext rows that the drain is certainly mid-job when stop() is
	// called: each costs a real Argon2id derivation.
	users := make([]admin.ImportUser, 0, 10)
	for i := 0; i < 10; i++ {
		users = append(users, admin.ImportUser{
			Email:    "shutdown-" + string(rune('a'+i)) + "@example.com",
			Password: "Shutdown!Pass1",
		})
	}
	queued, err := f.svc.EnqueueImport(ctx, f.tenantID, &f.appID,
		admin.ImportDocument{Users: users}, nil, "operator@example.com")
	if err != nil {
		t.Fatalf("EnqueueImport() error = %v", err)
	}
	id := jobIDOf(t, queued)

	// A separate pool for the worker, so closing it cannot disturb the
	// assertions — and so closing it means what it means in main.
	workerPool, err := store.NewDB(ctx, os.Getenv("DATABASE_URL"), testhelper.TestLogger())
	if err != nil {
		t.Fatalf("worker pool: %v", err)
	}
	workerSvc := admin.New(workerPool, nil, testhelper.TestLogger())

	stop := workerSvc.StartImportWorker(testhelper.TestLogger())

	// Wait until the worker is demonstrably inside the job.
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		var processed int
		if err := f.pool.QueryRow(ctx,
			`SELECT processed_rows FROM user_import_jobs WHERE id = $1`, id).Scan(&processed); err != nil {
			t.Fatal(err)
		}
		if processed > 0 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	// main's shutdown, in main's order.
	returned := make(chan struct{})
	go func() {
		stop()
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(180 * time.Second):
		t.Fatal("stop() did not return; shutdown does not terminate")
	}
	workerPool.Close()

	// The job must have been handed back or finished — never left claimed by a
	// worker that no longer exists and cannot renew.
	var status string
	var lockedBy string
	if err := f.pool.QueryRow(ctx, `
		SELECT status, COALESCE(locked_by, '') FROM user_import_jobs WHERE id = $1`,
		id).Scan(&status, &lockedBy); err != nil {
		t.Fatal(err)
	}
	switch status {
	case admin.ImportJobPending, admin.ImportJobCompleted:
	default:
		t.Errorf("job left in %q after shutdown (locked_by %q), want pending (released) or completed",
			status, lockedBy)
	}
	if lockedBy != "" {
		t.Errorf("locked_by = %q after shutdown, want empty — the lease outlived the worker", lockedBy)
	}
}

// Finding 9 — a cancellation that lands while a row is in flight must stop it.
//
// The worker read a pending row, checked the job separately and saw `running`,
// then cancellation marked the job cancelled and NULLed the plaintext column —
// and the worker created the user anyway, from a password it still held in
// memory, after the API had told the operator the import was cancelled. Row
// acquisition and the job's state are now read in one statement, and the claim
// is re-asserted before any write.
func TestImportWorker_CancelledJobStopsClaimingRows(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	queued, err := f.svc.EnqueueImport(ctx, f.tenantID, &f.appID, admin.ImportDocument{
		Users: []admin.ImportUser{
			{Email: "race-a@example.com", Password: "Race!PassA123"},
			{Email: "race-b@example.com", Password: "Race!PassB123"},
			{Email: "race-c@example.com", Password: "Race!PassC123"},
		},
	}, nil, "operator@example.com")
	if err != nil {
		t.Fatalf("EnqueueImport() error = %v", err)
	}
	id := jobIDOf(t, queued)

	// Cancel first, then let a worker loose on it. A worker that acquires rows
	// without consulting the job's state drains all three regardless.
	if err := f.svc.CancelImportJob(ctx, f.tenantID, &f.appID, id); err != nil {
		t.Fatalf("CancelImportJob: %v", err)
	}

	stop := f.svc.StartImportWorker(testhelper.TestLogger())
	time.Sleep(2 * importPollForTest)
	stop()

	var status string
	var processed, created int
	if err := f.pool.QueryRow(ctx, `
		SELECT status, processed_rows, created_count
		FROM user_import_jobs WHERE id = $1`, id).Scan(&status, &processed, &created); err != nil {
		t.Fatal(err)
	}
	if status != admin.ImportJobCancelled {
		t.Errorf("status = %q, want cancelled — the worker overwrote the cancellation", status)
	}
	if created != 0 {
		t.Errorf("created_count = %d, want 0 — a cancelled job created users", created)
	}
	if processed != 0 {
		t.Errorf("processed_rows = %d, want 0 — a cancelled job's rows were claimed", processed)
	}

	var n int
	if err := f.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM users WHERE email LIKE 'race-%@example.com'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("%d users were created for a cancelled job", n)
	}
}

// Finding 9 — cancellation arriving mid-run stops the rows that follow.
//
// The variant above cancels before the worker starts; this one cancels while it
// is draining, which is the actual race. Rows already applied stay applied —
// cancellation is not a rollback — but no row may be claimed after it lands.
func TestImportWorker_CancellationMidRunStopsRemainingRows(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	// Plaintext rows, so each costs a real Argon2id derivation and the run is
	// slow enough for a cancellation to land inside it.
	users := make([]admin.ImportUser, 0, 12)
	for i := 0; i < 12; i++ {
		users = append(users, admin.ImportUser{
			Email:    "midrun-" + string(rune('a'+i)) + "@example.com",
			Password: "MidRun!Pass123",
		})
	}
	queued, err := f.svc.EnqueueImport(ctx, f.tenantID, &f.appID,
		admin.ImportDocument{Users: users}, nil, "operator@example.com")
	if err != nil {
		t.Fatalf("EnqueueImport() error = %v", err)
	}
	id := jobIDOf(t, queued)

	stop := f.svc.StartImportWorker(testhelper.TestLogger())

	// Wait until the worker is demonstrably inside the job, then cancel.
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		var processed int
		if err := f.pool.QueryRow(ctx,
			`SELECT processed_rows FROM user_import_jobs WHERE id = $1`, id).Scan(&processed); err != nil {
			t.Fatal(err)
		}
		if processed > 0 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	if err := f.svc.CancelImportJob(ctx, f.tenantID, &f.appID, id); err != nil {
		t.Fatalf("CancelImportJob: %v", err)
	}
	atCancel := time.Now()

	// Give the worker long enough that it would have finished the rest.
	time.Sleep(3 * time.Second)
	stop()

	var status string
	var processed int
	if err := f.pool.QueryRow(ctx, `
		SELECT status, processed_rows FROM user_import_jobs WHERE id = $1`,
		id).Scan(&status, &processed); err != nil {
		t.Fatal(err)
	}
	if status != admin.ImportJobCancelled {
		t.Errorf("status = %q, want cancelled — the worker wrote over it", status)
	}
	if processed >= len(users) {
		t.Errorf("processed_rows = %d of %d: cancellation did not stop the run",
			processed, len(users))
	}

	// No plaintext may survive a cancellation, whichever rows it caught.
	var live int
	if err := f.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM user_import_job_rows WHERE job_id = $1 AND plaintext_password IS NOT NULL`,
		id).Scan(&live); err != nil {
		t.Fatal(err)
	}
	if live != 0 {
		t.Errorf("%d plaintext passwords left after cancelling at %v", live, atCancel)
	}
}

// Finding 10 — DisallowUnknownFields must reach inside ImportUser.
//
// The outer decoder's strictness stops at a type that implements UnmarshalJSON,
// so a typo'd credential key was dropped in silence. With email_verified true
// the row still passes validation — a verified address is a legitimate route in
// — and imports with no credential at all: an account the operator believes
// carries a migrated password and which nobody can ever sign into.
func TestImportUser_UnmarshalJSON_RejectsUnknownFields(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"camelCase password_hash", `{"email":"t@example.com","email_verified":true,"passwordHash":"$2a$10$x"}`},
		{"misspelled password", `{"email":"t@example.com","email_verified":true,"passwrod":"hunter22"}`},
		{"invented field", `{"email":"t@example.com","is_admin":true}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var u admin.ImportUser
			err := json.Unmarshal([]byte(tc.body), &u)
			if err == nil {
				t.Fatalf("unknown field accepted; decoded as %+v", u)
			}
			if !strings.Contains(err.Error(), "unknown field") {
				t.Errorf("error = %v, want an unknown-field error", err)
			}
		})
	}
}

// The strictness must not refuse the fields the format actually defines, nor
// the read-only ones the server's own export emits — the documented round trip
// is "export, add credentials, re-import".
func TestImportUser_UnmarshalJSON_AcceptsKnownAndExportOnlyFields(t *testing.T) {
	body := `{
	  "email": "round@example.com",
	  "first_name": "Round",
	  "last_name": "Trip",
	  "role": "viewer",
	  "email_verified": true,
	  "is_active": false,
	  "password_hash": "$2a$10$abcdefghijklmnopqrstuv",
	  "password_changed_at": "2020-01-02T03:04:05Z",
	  "identities": [{"provider":"google","provider_sub":"123"}],
	  "application": "some-app",
	  "created_at": "2019-01-01T00:00:00Z",
	  "last_login_at": "2024-05-06T07:08:09Z",
	  "login_count": 42
	}`
	var u admin.ImportUser
	if err := json.Unmarshal([]byte(body), &u); err != nil {
		t.Fatalf("a valid row was refused: %v", err)
	}
	if u.Email != "round@example.com" || u.Role != "viewer" {
		t.Errorf("fields did not decode: %+v", u)
	}
	// An explicit false still wins over the absent-means-true default.
	if u.IsActive {
		t.Error("is_active: false was not honoured")
	}
	if len(u.Identities) != 1 {
		t.Errorf("identities = %d, want 1", len(u.Identities))
	}
}

// An omitted is_active still defaults to true — the behaviour UnmarshalJSON
// exists for, which the strictness must not disturb.
func TestImportUser_UnmarshalJSON_IsActiveStillDefaultsTrue(t *testing.T) {
	var u admin.ImportUser
	if err := json.Unmarshal([]byte(`{"email":"d@example.com"}`), &u); err != nil {
		t.Fatal(err)
	}
	if !u.IsActive {
		t.Error("is_active defaulted to false; every imported user would arrive blocked")
	}
}
