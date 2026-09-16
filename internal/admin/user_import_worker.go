// user_import_worker.go — the background drain for queued user imports.
//
// # The constraint this is built around
//
// Hashing a plaintext password costs one Argon2id derivation at m=47104 against
// a process-wide semaphore sized to NumCPU. That semaphore is what keeps peak
// memory predictable, and it is shared with every login. So the worker's job is
// not to go fast — it is to make progress without ever being the reason a login
// waits.
//
// Two rules follow, and everything else here is detail:
//
//   - The worker uses the SHARED hasher, never its own. A second hasher would
//     let the process run twice the intended concurrent derivations and double
//     the memory ceiling the deployment was sized against.
//   - It processes rows ONE AT A TIME. One slot of NumCPU leaves the rest for
//     logins. On a 12-core box that is ~15 rows/second; on a 2-core box, ~2.
//     Both are acceptable for an operation nobody watches in real time.
//
// # Crash safety
//
// A job is claimed under a lease. If the process dies mid-run the lease expires
// and another worker — or the same one after a restart — reclaims it and
// resumes at the first row still marked pending. Rows already applied are not
// reapplied: each is marked in the same transaction that created its user.
package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog"
)

const (
	// How often an idle worker looks for a job. Imports are operator-initiated
	// and rare, so a slow poll costs nothing and keeps the database quiet.
	importPollInterval = 5 * time.Second

	// A claim older than this is treated as abandoned. Long enough that a
	// worker processing a slow row is never mistaken for a dead one, short
	// enough that a crashed job resumes within a deploy cycle.
	importLeaseTTL = 2 * time.Minute

	// How often a running worker renews its lease.
	importLeaseRenew = 30 * time.Second
)

// StartImportWorker launches the background drain and returns a stop function.
//
// Mirrors audit.StartRetention: a goroutine with a done channel, stopped during
// graceful shutdown so an in-flight row finishes rather than being torn off
// mid-transaction.
func (s *Service) StartImportWorker(logger zerolog.Logger) (stop func()) {
	done := make(chan struct{})
	host, _ := os.Hostname()
	id := fmt.Sprintf("%s/%d", host, os.Getpid())

	go func() {
		ticker := time.NewTicker(importPollInterval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				// One job per tick. Draining several in a row would hold the
				// hasher slot for longer than necessary with no benefit — the
				// next tick is five seconds away.
				if err := s.drainOneImportJob(done, logger, id); err != nil &&
					!errors.Is(err, context.Canceled) {
					logger.Error().Err(err).Msg("import worker: job failed")
				}
			}
		}
	}()

	return func() { close(done) }
}

// drainOneImportJob claims a job and processes it to completion.
func (s *Service) drainOneImportJob(done <-chan struct{}, logger zerolog.Logger, workerID string) error {
	ctx := context.Background()

	job, err := s.claimImportJob(ctx, workerID)
	if err != nil {
		return err
	}
	if job == nil {
		return nil // nothing queued
	}

	log := logger.With().Int64("job_id", job.id).Int64("tenant_id", job.tenantID).Logger()
	log.Info().Int("total", job.total).Msg("import worker: job claimed")

	// Renew the lease while we work, so a long job is not reclaimed underneath
	// us by a worker that thinks we died.
	renewDone := make(chan struct{})
	defer close(renewDone)
	go func() {
		t := time.NewTicker(importLeaseRenew)
		defer t.Stop()
		for {
			select {
			case <-renewDone:
				return
			case <-t.C:
				_, _ = s.pool.Exec(ctx,
					`UPDATE user_import_jobs SET locked_at = NOW(), updated_at = NOW() WHERE id = $1`,
					job.id)
			}
		}
	}()

	roles, err := s.importRoleMap(ctx, job.tenantID, job.applicationID)
	if err != nil {
		return s.failImportJob(ctx, job.id, err)
	}
	defaultRoleID, err := s.importDefaultRole(ctx, job.tenantID, job.applicationID)
	if err != nil {
		return s.failImportJob(ctx, job.id, err)
	}

	for {
		// Shutdown between rows rather than during one: the row in flight owns
		// a transaction and a hasher slot, and abandoning it would leave the
		// lease to expire instead of releasing cleanly.
		select {
		case <-done:
			log.Info().Msg("import worker: releasing job for shutdown")
			return s.releaseImportJob(ctx, job.id)
		default:
		}

		row, err := s.nextImportRow(ctx, job.id)
		if err != nil {
			return s.failImportJob(ctx, job.id, err)
		}
		if row == nil {
			break // no rows left
		}

		// A job cancelled mid-run stops here; rows already applied stay.
		var status string
		if err := s.pool.QueryRow(ctx,
			`SELECT status FROM user_import_jobs WHERE id = $1`, job.id).Scan(&status); err == nil &&
			status == ImportJobCancelled {
			log.Info().Msg("import worker: job cancelled")
			return nil
		}

		s.processImportRow(ctx, job, row, roles, defaultRoleID, log)
	}

	return s.completeImportJob(ctx, job.id, log)
}

type claimedImportJob struct {
	id             int64
	tenantID       int64
	applicationID  *int64
	updateExisting bool
	total          int
}

// claimImportJob takes the oldest claimable job.
//
// FOR UPDATE SKIP LOCKED is what makes this safe with several replicas running:
// each worker takes a different row instead of blocking on the same one, and a
// job is never processed twice concurrently. `pending` OR an expired lease
// covers both the normal case and reclaiming after a crash.
func (s *Service) claimImportJob(ctx context.Context, workerID string) (*claimedImportJob, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("claim import job: begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var j claimedImportJob
	err = tx.QueryRow(ctx, `
		SELECT id, tenant_id, application_id, update_existing, total_rows
		FROM user_import_jobs
		WHERE status = 'pending'
		   OR (status = 'running' AND locked_at < NOW() - $1::interval)
		ORDER BY created_at
		FOR UPDATE SKIP LOCKED
		LIMIT 1
	`, importLeaseTTL.String()).Scan(&j.id, &j.tenantID, &j.applicationID, &j.updateExisting, &j.total)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("claim import job: select: %w", err)
	}

	if _, err := tx.Exec(ctx, `
		UPDATE user_import_jobs
		SET status = 'running',
		    locked_at = NOW(),
		    locked_by = $2,
		    started_at = COALESCE(started_at, NOW()),
		    updated_at = NOW()
		WHERE id = $1
	`, j.id, workerID); err != nil {
		return nil, fmt.Errorf("claim import job: mark running: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("claim import job: commit: %w", err)
	}
	return &j, nil
}

type pendingImportRow struct {
	id        int64
	index     int
	user      ImportUser
	plaintext string
}

// nextImportRow reads the job's next unprocessed row.
func (s *Service) nextImportRow(ctx context.Context, jobID int64) (*pendingImportRow, error) {
	var r pendingImportRow
	var blob []byte
	var pw *string
	err := s.pool.QueryRow(ctx, `
		SELECT id, row_index, payload, plaintext_password
		FROM user_import_job_rows
		WHERE job_id = $1 AND status = 'pending'
		ORDER BY row_index
		LIMIT 1
	`, jobID).Scan(&r.id, &r.index, &blob, &pw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("next import row: %w", err)
	}
	if err := json.Unmarshal(blob, &r.user); err != nil {
		return nil, fmt.Errorf("next import row: decode: %w", err)
	}
	if pw != nil {
		r.plaintext = *pw
		r.user.Password = *pw
	}
	return &r, nil
}

// processImportRow applies one row and records its outcome.
//
// Never returns an error: a row that cannot be applied is recorded as rejected
// and the job continues. A single malformed row must not end an import that has
// thousands of good ones behind it.
func (s *Service) processImportRow(
	ctx context.Context,
	job *claimedImportJob,
	row *pendingImportRow,
	roles map[string]int64,
	defaultRoleID *int64,
	log zerolog.Logger,
) {
	outcome, reason := s.applyImportRow(ctx, job, row, roles, defaultRoleID)

	// The credential is erased in the same statement that records the outcome,
	// so a plaintext password never outlives the row that consumed it.
	if _, err := s.pool.Exec(ctx, `
		UPDATE user_import_job_rows
		SET status = $2, reason = $3, plaintext_password = NULL, processed_at = NOW()
		WHERE id = $1
	`, row.id, outcome, reason); err != nil {
		log.Error().Err(err).Int("row", row.index).Msg("import worker: row status write failed")
		return
	}

	column := map[string]string{
		ImportOutcomeCreate: "created_count",
		ImportOutcomeUpdate: "updated_count",
		ImportOutcomeSkip:   "skipped_count",
		ImportOutcomeReject: "rejected_count",
	}[outcome]
	if _, err := s.pool.Exec(ctx, fmt.Sprintf(`
		UPDATE user_import_jobs
		SET processed_rows = processed_rows + 1, %s = %s + 1, updated_at = NOW()
		WHERE id = $1
	`, column, column), job.id); err != nil {
		log.Error().Err(err).Int("row", row.index).Msg("import worker: progress write failed")
	}
}

// applyImportRow performs one row's database work and returns its verdict.
func (s *Service) applyImportRow(
	ctx context.Context,
	job *claimedImportJob,
	row *pendingImportRow,
	roles map[string]int64,
	defaultRoleID *int64,
) (outcome, reason string) {
	u := row.user
	email := u.Email // normalised at enqueue, when the row was validated

	roleID, ok := resolveImportRole(u.Role, roles, defaultRoleID)
	if !ok {
		return ImportOutcomeReject, fmt.Sprintf(
			"role %q is not available in this application — create it first, or correct the name",
			u.Role)
	}

	existing, err := s.importUserExists(ctx, job.tenantID, job.applicationID, email)
	if err != nil {
		return ImportOutcomeReject, "lookup failed"
	}

	if existing != nil {
		if !job.updateExisting {
			return ImportOutcomeSkip, "user already exists"
		}
		newRole := roleNameFor(roles, roleID)
		changed := newRole != existing.roleName
		if err := s.updateImportedUser(ctx, job.tenantID, existing.id, u, roleID); err != nil {
			return ImportOutcomeReject, "update failed"
		}
		if changed && s.authSvc != nil {
			// A role change does not reach an already-issued access token:
			// permissions are baked in at login. Without this the demotion is
			// advisory until the token expires.
			s.authSvc.DenyUserSessions(ctx, existing.id, job.tenantID)
			return ImportOutcomeUpdate, fmt.Sprintf("role %s → %s",
				displayRole(existing.roleName), displayRole(newRole))
		}
		return ImportOutcomeUpdate, "profile updated; role unchanged"
	}

	if err := s.insertImportedUser(ctx, job.tenantID, job.applicationID, email, u, roleID); err != nil {
		if isDuplicateErr(err) {
			// Lost a race with a concurrent create. The desired end state holds.
			return ImportOutcomeSkip, "user already exists"
		}
		// The underlying error can carry column values and constraint names,
		// and this reason is handed back over the API.
		return ImportOutcomeReject, "write failed"
	}
	return ImportOutcomeCreate, ""
}

// resolveImportRole applies the three-tier rule: a named role, else the
// application default, else none. ok is false when a named role is unavailable.
func resolveImportRole(name string, roles map[string]int64, defaultRoleID *int64) (*int64, bool) {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return defaultRoleID, true
	}
	id, ok := roles[trimmed]
	if !ok {
		return nil, false
	}
	return &id, true
}

func (s *Service) completeImportJob(ctx context.Context, jobID int64, log zerolog.Logger) error {
	if _, err := s.pool.Exec(ctx, `
		UPDATE user_import_jobs
		SET status = 'completed', finished_at = NOW(), locked_at = NULL,
		    locked_by = NULL, updated_at = NOW()
		WHERE id = $1 AND status = 'running'
	`, jobID); err != nil {
		return fmt.Errorf("complete import job: %w", err)
	}
	log.Info().Msg("import worker: job completed")
	return nil
}

// failImportJob records a job-level failure — one that prevented the run from
// continuing at all, as opposed to a row that simply could not be applied.
func (s *Service) failImportJob(ctx context.Context, jobID int64, cause error) error {
	if _, err := s.pool.Exec(ctx, `
		UPDATE user_import_jobs
		SET status = 'failed', error = $2, finished_at = NOW(),
		    locked_at = NULL, locked_by = NULL, updated_at = NOW()
		WHERE id = $1
	`, jobID, cause.Error()); err != nil {
		return fmt.Errorf("fail import job: %w", err)
	}
	// Nothing further will run, so the queued credentials have no reason to
	// remain at rest.
	_, _ = s.pool.Exec(ctx,
		`UPDATE user_import_job_rows SET plaintext_password = NULL WHERE job_id = $1 AND status = 'pending'`,
		jobID)
	return cause
}

// releaseImportJob hands a partially-processed job back to the queue at
// shutdown, so the next worker resumes it rather than waiting out the lease.
func (s *Service) releaseImportJob(ctx context.Context, jobID int64) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE user_import_jobs
		SET status = 'pending', locked_at = NULL, locked_by = NULL, updated_at = NOW()
		WHERE id = $1 AND status = 'running'
	`, jobID)
	if err != nil {
		return fmt.Errorf("release import job: %w", err)
	}
	return nil
}
