// user_import_job.go — durable queue for bulk user imports.
//
// # Why a job at all
//
// A pre-hashed import is cheap: each row is an INSERT of a string somebody else
// already derived. A plaintext import is not. Every plaintext row costs one
// Argon2id derivation at m=47104 — ~65ms — against a process-wide semaphore
// sized to NumCPU, because that bound is what keeps peak memory predictable.
// Thousands of those cannot run inside an HTTP request: the request would time
// out, and long before that the import would fill the semaphore and queue every
// concurrent login behind it.
//
// So the work is written to the database and drained by a worker that takes a
// deliberately small slice of that semaphore. The import is slower than it could
// be, and the front door stays open — which is the correct trade for an
// operation nobody is watching in real time.
//
// # Why the rows are stored
//
// Holding the document in the worker's memory would make the job as fragile as
// the process: a deploy at row 3,000 of 5,000 would lose the position and, on
// restart, either redo the work or abandon it. Rows are written once, claimed
// individually, and marked as they complete, so a restarted worker resumes at
// the first row still marked pending. That is also what bounds the worker's
// footprint regardless of how large the uploaded file was.
package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Job lifecycle.
const (
	ImportJobPending   = "pending"
	ImportJobRunning   = "running"
	ImportJobCompleted = "completed"
	ImportJobFailed    = "failed"
	ImportJobCancelled = "cancelled"
)

// ImportJob is a queued or finished import.
type ImportJob struct {
	ID             string     `json:"id"`
	TenantID       string     `json:"tenant_id"`
	ApplicationID  *string    `json:"application_id"`
	Status         string     `json:"status"`
	UpdateExisting bool       `json:"update_existing"`
	TotalRows      int        `json:"total_rows"`
	ProcessedRows  int        `json:"processed_rows"`
	Created        int        `json:"created"`
	Updated        int        `json:"updated"`
	Skipped        int        `json:"skipped"`
	Rejected       int        `json:"rejected"`
	ActorEmail     string     `json:"actor_email"`
	Error          string     `json:"error,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	StartedAt      *time.Time `json:"started_at,omitempty"`
	FinishedAt     *time.Time `json:"finished_at,omitempty"`
}

// ErrJobNotFound is returned when a job id does not exist in the caller's scope.
var ErrJobNotFound = errors.New("import job not found")

// EnqueueImport validates a document and writes it to the queue.
//
// Validation runs here, synchronously, rather than in the worker: a file whose
// rows are malformed should be refused while the operator is still looking at
// the upload, not accepted and then reported as thousands of failures minutes
// later. What the worker does is the expensive part — hashing and writing — not
// deciding whether a row is sound.
//
// The rows written are only those validation accepted. A row it rejected is
// recorded with its reason and never claimed, so the report is complete without
// the worker having to re-derive verdicts it cannot reach the file to check.
func (s *Service) EnqueueImport(
	ctx context.Context,
	tenantID int64,
	applicationID *int64,
	doc ImportDocument,
	actorID *int64,
	actorEmail string,
) (*ImportJob, error) {
	// The same dry run the operator reviewed, re-run server-side. The client
	// cannot be trusted to have run it, and the roles or defaults it resolved
	// against may have changed since.
	res, err := s.ValidateImport(ctx, tenantID, applicationID, doc)
	if err != nil {
		return nil, err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("enqueue import: begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var jobID int64
	err = tx.QueryRow(ctx, `
		INSERT INTO user_import_jobs
		    (tenant_id, application_id, update_existing, total_rows, created_by, actor_email)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id
	`, tenantID, applicationID, doc.UpdateExisting, len(doc.Users), actorID, actorEmail).Scan(&jobID)
	if err != nil {
		return nil, fmt.Errorf("enqueue import: insert job: %w", err)
	}

	// Verdicts are keyed by row index so a rejected row can be written with its
	// reason without re-validating it in the worker.
	verdict := make(map[int]ImportRowResult, len(res.Rows))
	for _, r := range res.Rows {
		verdict[r.Index] = r
	}

	rows := make([][]any, 0, len(doc.Users))
	for i, u := range doc.Users {
		v, ok := verdict[i]
		status := ImportRowPending
		reason := ""
		if ok && v.Outcome == ImportOutcomeReject {
			// Settled now; the worker never claims it.
			status = ImportOutcomeReject
			reason = v.Reason
		}

		// The credentials are split out of the payload so they have a different
		// lifetime from the report. The plaintext goes to its own column, erased
		// the moment the row is processed; the digest is not needed after the
		// row is applied either, and a terminal row's payload keeps only what
		// the report reads — email, status and reason.
		plaintext := u.Password
		stored := u
		stored.Password = ""

		// The normalised address, not the one the file spelled. The worker reads
		// the payload and writes it straight into users.email, so a row uploaded
		// as "MARCUS.Webb@Example.COM" would be stored in a form the normalising
		// login lookup can never match — and a re-run, which normalises before
		// checking for an existing user, would create a second account for the
		// same person instead of skipping it.
		if v, ok := verdict[i]; ok && v.Email != "" {
			stored.Email = v.Email
		}

		// A rejected row never runs, so its digest has no consumer. Leaving it
		// here would make the payload column a durable corpus of foreign hashes
		// — exactly what the export path refuses to emit — for no benefit.
		if status == ImportOutcomeReject {
			redactImportCredentials(&stored)
		}

		blob, err := json.Marshal(stored)
		if err != nil {
			return nil, fmt.Errorf("enqueue import: encode row %d: %w", i, err)
		}

		var pw *string
		if plaintext != "" && status == ImportRowPending {
			pw = &plaintext
		}
		rows = append(rows, []any{jobID, i, blob, pw, status, reason})
	}

	if _, err := tx.CopyFrom(ctx,
		pgx.Identifier{"user_import_job_rows"},
		[]string{"job_id", "row_index", "payload", "plaintext_password", "status", "reason"},
		pgx.CopyFromRows(rows),
	); err != nil {
		return nil, fmt.Errorf("enqueue import: insert rows: %w", err)
	}

	// Rejections are counted at enqueue so the job's totals are right before the
	// worker has touched it — an operator polling immediately sees the real
	// shape of their file rather than zeroes.
	if res.Rejected > 0 {
		if _, err := tx.Exec(ctx,
			`UPDATE user_import_jobs SET rejected_count = $1, processed_rows = $1 WHERE id = $2`,
			res.Rejected, jobID); err != nil {
			return nil, fmt.Errorf("enqueue import: seed counts: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("enqueue import: commit: %w", err)
	}

	return s.GetImportJob(ctx, tenantID, applicationID, jobID)
}

// ImportRowPending marks a row the worker has yet to claim.
const ImportRowPending = "pending"

// redactImportCredentials strips every credential field from a row payload.
//
// Called wherever a row reaches a terminal state. The payload exists to answer
// "what happened to row 41?" — ListImportJobRows reads email, status and reason
// out of it and nothing else — but it was serialised from the whole uploaded
// row, so a finished job left one password_hash per row at rest indefinitely.
// That is a crackable corpus with no consumer, sitting in a table an operator
// would never think to look in; the plaintext column beside it is already
// erased on exactly this transition, and the digest deserves the same treatment.
//
// A new credential field on ImportUser must be added here too, which is why
// this is one function rather than a line repeated at four call sites.
func redactImportCredentials(u *ImportUser) {
	u.Password = ""
	u.PasswordHash = ""
}

// redactPayloadCredentialsSQL is redactImportCredentials as an UPDATE
// expression, for the terminal transitions that never decode the row into Go.
//
// Deleting the keys rather than blanking them: an absent password_hash and an
// empty one mean the same thing to every reader of this payload, and a key that
// is gone cannot be mistaken for a value that was imported.
const redactPayloadCredentialsSQL = `payload = (payload - 'password_hash' - 'password')`

// GetImportJob reads one job, scoped to the caller's tenant and application.
//
// The scope is re-checked here rather than trusted from the job id, so a job id
// leaked or guessed from another tenant reads as not found.
func (s *Service) GetImportJob(ctx context.Context, tenantID int64, applicationID *int64, jobID int64) (*ImportJob, error) {
	var j ImportJob
	var id, tid int64
	var appID *int64
	err := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, application_id, status, update_existing,
		       total_rows, processed_rows, created_count, updated_count,
		       skipped_count, rejected_count, actor_email, error,
		       created_at, started_at, finished_at
		FROM user_import_jobs
		WHERE id = $1
		  AND tenant_id = $2
		  AND application_id IS NOT DISTINCT FROM $3
	`, jobID, tenantID, applicationID).Scan(
		&id, &tid, &appID, &j.Status, &j.UpdateExisting,
		&j.TotalRows, &j.ProcessedRows, &j.Created, &j.Updated,
		&j.Skipped, &j.Rejected, &j.ActorEmail, &j.Error,
		&j.CreatedAt, &j.StartedAt, &j.FinishedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrJobNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get import job: %w", err)
	}
	j.ID = fmt.Sprint(id)
	j.TenantID = fmt.Sprint(tid)
	if appID != nil {
		s := fmt.Sprint(*appID)
		j.ApplicationID = &s
	}
	return &j, nil
}

// ListImportJobRows returns the per-row report for a job, problems first.
//
// Ordered by outcome rather than position: a file with four bad rows in two
// thousand should not make the operator page through the successes to find
// them.
func (s *Service) ListImportJobRows(ctx context.Context, tenantID int64, applicationID *int64, jobID int64, limit int) ([]ImportRowResult, error) {
	if _, err := s.GetImportJob(ctx, tenantID, applicationID, jobID); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}

	rows, err := s.pool.Query(ctx, `
		SELECT row_index, payload->>'email', status, reason
		FROM user_import_job_rows
		WHERE job_id = $1 AND status <> 'pending'
		ORDER BY CASE status
		             WHEN 'reject' THEN 0
		             WHEN 'update' THEN 1
		             WHEN 'skip'   THEN 2
		             ELSE 3
		         END,
		         row_index
		LIMIT $2
	`, jobID, limit)
	if err != nil {
		return nil, fmt.Errorf("list import job rows: %w", err)
	}
	defer rows.Close()

	out := []ImportRowResult{}
	for rows.Next() {
		var r ImportRowResult
		var email *string
		if err := rows.Scan(&r.Index, &email, &r.Outcome, &r.Reason); err != nil {
			return nil, fmt.Errorf("scan import job row: %w", err)
		}
		if email != nil {
			r.Email = *email
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ListImportJobs returns a tenant's recent jobs, newest first.
func (s *Service) ListImportJobs(ctx context.Context, tenantID int64, applicationID *int64, limit int) ([]ImportJob, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, application_id, status, update_existing,
		       total_rows, processed_rows, created_count, updated_count,
		       skipped_count, rejected_count, actor_email, error,
		       created_at, started_at, finished_at
		FROM user_import_jobs
		WHERE tenant_id = $1 AND application_id IS NOT DISTINCT FROM $2
		ORDER BY created_at DESC
		LIMIT $3
	`, tenantID, applicationID, limit)
	if err != nil {
		return nil, fmt.Errorf("list import jobs: %w", err)
	}
	defer rows.Close()

	out := []ImportJob{}
	for rows.Next() {
		var j ImportJob
		var id, tid int64
		var appID *int64
		if err := rows.Scan(&id, &tid, &appID, &j.Status, &j.UpdateExisting,
			&j.TotalRows, &j.ProcessedRows, &j.Created, &j.Updated,
			&j.Skipped, &j.Rejected, &j.ActorEmail, &j.Error,
			&j.CreatedAt, &j.StartedAt, &j.FinishedAt); err != nil {
			return nil, fmt.Errorf("scan import job: %w", err)
		}
		j.ID = fmt.Sprint(id)
		j.TenantID = fmt.Sprint(tid)
		if appID != nil {
			s := fmt.Sprint(*appID)
			j.ApplicationID = &s
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// CancelImportJob stops a job that has not finished.
//
// Rows already written stay written: the import is not transactional across
// rows by design, and undoing created accounts would be a far more dangerous
// operation than the one being cancelled. Cancellation means "process no more",
// not "roll back".
func (s *Service) CancelImportJob(ctx context.Context, tenantID int64, applicationID *int64, jobID int64) error {
	ct, err := s.pool.Exec(ctx, `
		UPDATE user_import_jobs
		SET status = 'cancelled', finished_at = NOW(), updated_at = NOW()
		WHERE id = $1
		  AND tenant_id = $2
		  AND application_id IS NOT DISTINCT FROM $3
		  AND status IN ('pending', 'running')
	`, jobID, tenantID, applicationID)
	if err != nil {
		return fmt.Errorf("cancel import job: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrJobNotFound
	}
	// The credentials of rows that will now never run have no reason to remain
	// at rest — the plaintext column and the digest carried in the payload
	// alike. Cancellation is terminal for these rows, so this is the same
	// erasure a processed row gets.
	if _, err := s.pool.Exec(ctx, `
		UPDATE user_import_job_rows
		SET plaintext_password = NULL, `+redactPayloadCredentialsSQL+`
		WHERE job_id = $1 AND status = 'pending'
	`, jobID); err != nil {
		return fmt.Errorf("cancel import job: clear credentials: %w", err)
	}
	return nil
}
