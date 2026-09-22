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
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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

	// How often finished jobs are swept, and how long they are kept.
	//
	// A finished job's rows are a report: which addresses were created, which
	// were rejected and why. Nobody reads that a fortnight later, but until
	// this existed nothing deleted it either, so every import a deployment had
	// ever run stayed in the table permanently. The payloads no longer carry
	// credentials — the row write erases both the plaintext and the digest —
	// but they are still a list of every email address ever imported, kept
	// forever for no one.
	//
	// Fourteen days is chosen to outlast the conversation an import starts: an
	// operator reconciling "why is this person missing" is doing it the same
	// week, not the next quarter.
	importSweepInterval = 6 * time.Hour
	importJobRetention  = 14 * 24 * time.Hour

	// How many infrastructure failures one row may cost before it is written
	// off as a rejection and the job carries on without it.
	//
	// An infra failure leaves the row pending so a transient blip does not
	// become a permanent verdict, but "pending forever" is its own outage: the
	// job never completes, and the progress response cannot distinguish a slow
	// import from one wedged on row N. Five attempts spread over five lease
	// cycles is roughly ten minutes of a failure reproducing identically —
	// past that it is a property of the row or its surroundings, not weather.
	maxImportRowAttempts = 5
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

	// The stop function must not return until every goroutine that touches the
	// pool has returned. main closes the pool as soon as stop() does, so a
	// signal-only stop left the worker mid-transaction against a closing pool:
	// the row write fails, the job is never released, and it sits in `running`
	// until the lease expires — the exact failure shutdown was supposed to
	// avoid. The renewal goroutine is registered on the same group because it
	// issues its own UPDATE on the same pool.
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(importPollInterval)
		defer ticker.Stop()
		sweep := time.NewTicker(importSweepInterval)
		defer sweep.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				// One job per tick. Draining several in a row would hold the
				// hasher slot for longer than necessary with no benefit — the
				// next tick is five seconds away.
				if err := s.drainOneImportJob(done, &wg, logger, id); err != nil &&
					!errors.Is(err, context.Canceled) {
					logger.Error().Err(err).Msg("import worker: job failed")
				}
			case <-sweep.C:
				// Retention runs on the same goroutine as the drain, not its
				// own: both touch the same pool and the shutdown contract above
				// is already written for one. A sweep and a job never overlap,
				// which also keeps the delete off the hasher's critical path.
				s.sweepFinishedImportJobs(logger)
			}
		}
	}()

	return func() {
		close(done)
		wg.Wait()
	}
}

// drainOneImportJob claims a job and processes it to completion.
func (s *Service) drainOneImportJob(done <-chan struct{}, wg *sync.WaitGroup, logger zerolog.Logger, workerID string) error {
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
	//
	// lost is closed when a renewal finds the lease is no longer ours. It is
	// read by the row loop, which stops rather than carrying on against a job
	// another worker now owns.
	renewDone := make(chan struct{})
	lost := make(chan struct{})
	defer close(renewDone)
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(importLeaseRenew)
		defer t.Stop()
		for {
			select {
			case <-renewDone:
				return
			case <-t.C:
				// Fenced on locked_by. An unfenced renewal is worse than no
				// renewal: a worker that stalled long enough for its lease to
				// expire — a paused VM, a long GC, a blocked query — would
				// keep refreshing locked_at on a job the reclaiming worker is
				// already draining, and the two would process the same rows
				// with neither able to tell. Zero rows affected means the
				// lease is gone, so we stop renewing and let the loop abandon
				// the job to its real owner.
				ct, err := s.pool.Exec(ctx, `
					UPDATE user_import_jobs
					SET locked_at = NOW(), updated_at = NOW()
					WHERE id = $1 AND locked_by = $2
				`, job.id, workerID)
				if err != nil {
					// A transient failure is not proof the lease was taken;
					// the next tick, or the lease TTL, settles it.
					continue
				}
				if ct.RowsAffected() == 0 {
					log.Warn().Msg("import worker: lease lost, abandoning job")
					close(lost)
					return
				}
			}
		}
	}()

	roles, err := s.importRoleMap(ctx, job.tenantID, job.applicationID)
	if err != nil {
		return s.failImportJob(ctx, job.id, workerID, err)
	}
	defaultRoleID, err := s.importDefaultRole(ctx, job.tenantID, job.applicationID)
	if err != nil {
		return s.failImportJob(ctx, job.id, workerID, err)
	}

	for {
		// Shutdown between rows rather than during one: the row in flight owns
		// a transaction and a hasher slot, and abandoning it would leave the
		// lease to expire instead of releasing cleanly.
		select {
		case <-done:
			log.Info().Msg("import worker: releasing job for shutdown")
			return s.releaseImportJob(ctx, job.id, workerID)
		case <-lost:
			// Deliberately no write of any kind: the job row belongs to
			// another worker now, and every statement in this file that could
			// touch it is fenced on locked_by anyway.
			return nil
		default:
		}

		row, err := s.nextImportRow(ctx, job.id, workerID)
		if err != nil {
			return s.failImportJob(ctx, job.id, workerID, err)
		}
		if row == nil {
			break // no rows left
		}

		if !s.processImportRow(ctx, job, row, roles, defaultRoleID, log, workerID) {
			return nil
		}
	}

	return s.completeImportJob(ctx, job.id, workerID, log)
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
	// attempts already spent on this row before this one. Zero on the first
	// pass; non-zero means a worker — this one on an earlier pass, or whoever
	// held the lease before it turned over — hit an infrastructure failure
	// here and left the row pending for a retry.
	attempts int
}

// nextImportRow reads the job's next unprocessed row.
//
// The job's own state is joined into the same statement rather than checked
// beforehand. A separate "is this job still running?" query is a race with a
// window the width of the whole row: the worker read a pending row, saw
// `running`, then CancelImportJob marked the job cancelled and NULLed the
// plaintext column — and the worker went on to create the user anyway, from a
// password it was still holding in memory, after the API had told the operator
// the import was cancelled. Reading the row and the job's status together means
// a cancellation that lands first is seen, and one that lands after is caught by
// the same check in the write (see processImportRow).
//
// Fenced on locked_by for the same reason every other statement here is: the
// row is only ours to take while the lease is.
func (s *Service) nextImportRow(ctx context.Context, jobID int64, workerID string) (*pendingImportRow, error) {
	var r pendingImportRow
	var blob []byte
	var pw *string
	err := s.pool.QueryRow(ctx, `
		SELECT r.id, r.row_index, r.payload, r.plaintext_password, r.attempts
		FROM user_import_job_rows r
		JOIN user_import_jobs j ON j.id = r.job_id
		WHERE r.job_id = $1
		  AND r.status = 'pending'
		  AND j.status = 'running'
		  AND j.locked_by = $2
		ORDER BY r.row_index
		LIMIT 1
	`, jobID, workerID).Scan(&r.id, &r.index, &blob, &pw, &r.attempts)
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
//
// Returns false when the job is no longer ours to write to — cancelled, or the
// lease taken — so the caller stops instead of grinding through the rest of a
// job somebody else now owns.
func (s *Service) processImportRow(
	ctx context.Context,
	job *claimedImportJob,
	row *pendingImportRow,
	roles map[string]int64,
	defaultRoleID *int64,
	log zerolog.Logger,
	workerID string,
) bool {
	// The second half of the cancellation fence. nextImportRow read the row and
	// the job's status together, but the row's own work takes ~65ms of Argon2id
	// and a cancellation can land inside that window — so the claim is
	// re-asserted before anything is written. Both halves are needed: without
	// this one a cancelled job still records outcomes and bumps counters after
	// the API reported it stopped; without the first one the expensive work
	// happens before we find out.
	//
	// The cost of losing the race is bounded and deliberate: the user may have
	// been created (that is what "cancellation is not a rollback" means here)
	// but the job's counters and report do not claim a row it no longer owns.
	claimed, err := s.claimImportRow(ctx, job.id, row.id, workerID)
	if err != nil {
		log.Error().Err(err).Int("row", row.index).Msg("import worker: row claim failed")
		return false
	}
	if !claimed {
		log.Info().Int("row", row.index).Msg("import worker: job no longer claimable, stopping")
		return false
	}

	outcome, reason, infra := s.applyImportRow(ctx, job, row, roles, defaultRoleID)
	if infra != nil {
		// The row could not be judged, so it gets no verdict. It stays pending
		// with its credential intact and is picked up again — by this worker on
		// the next pass, or by whoever reclaims the job after the lease expires.
		//
		// Recording `reject` here, which is what this used to do, turned a
		// transient database failure into a permanent one: rejected rows are
		// never retried on resume, so a connection blip part-way through a
		// 10,000-row job wrote off every remaining row as invalid and the
		// operator's only recourse was to re-upload the whole file and hope.
		//
		// But an unbounded retry is the mirror-image failure. A row that fails
		// the same way every time — an application deleted mid-import, a value
		// the database will never accept — leaves the job in `running` forever,
		// reclaimed every lease TTL, with nothing in the progress response
		// separating "slow" from "stuck on row N since Tuesday". So the attempt
		// is counted, and past the bound the row is written off as a rejection
		// carrying the failure that caused it, and the job moves on.
		//
		// Retrying stays free for the transient case, which is the common one:
		// maxImportRowAttempts blips in a row on the same row is already not a
		// blip.
		attempt := row.attempts + 1
		if attempt < maxImportRowAttempts {
			if err := s.recordImportRowFailure(ctx, row.id, infra); err != nil {
				log.Error().Err(err).Int("row", row.index).
					Msg("import worker: row attempt write failed")
				return false
			}
			log.Warn().Err(infra).Int("row", row.index).Int("attempt", attempt).
				Msg("import worker: row left pending after an infrastructure failure")
			// Returning false stops the job rather than grinding the rest of
			// the file through the same broken connection.
			return false
		}

		log.Error().Err(infra).Int("row", row.index).Int("attempt", attempt).
			Msg("import worker: row rejected after repeated infrastructure failures")
		outcome, reason = ImportOutcomeReject, fmt.Sprintf(
			"could not be applied after %d attempts — the row was not imported; retry it once the cause is resolved",
			attempt)
	}

	// The credentials are erased in the same statement that records the
	// outcome, so neither a plaintext password nor an imported digest outlives
	// the row that consumed it. The report reads email, status and reason out
	// of the payload; nothing downstream reads the credential fields, and a
	// finished job that kept them would be a hash corpus at rest with no
	// consumer. See redactImportCredentials.
	if _, err := s.pool.Exec(ctx, `
		UPDATE user_import_job_rows
		SET status = $2, reason = $3, plaintext_password = NULL,
		    `+redactPayloadCredentialsSQL+`, processed_at = NOW()
		WHERE id = $1
	`, row.id, outcome, reason); err != nil {
		log.Error().Err(err).Int("row", row.index).Msg("import worker: row status write failed")
		return false
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
		WHERE id = $1 AND locked_by = $2
	`, column, column), job.id, workerID); err != nil {
		log.Error().Err(err).Int("row", row.index).Msg("import worker: progress write failed")
	}
	return true
}

// claimImportRow re-asserts, in one statement, that the row is still pending
// and the job is still running under our lease.
//
// Nothing about the row changes — the status it moves to depends on work that
// has not happened yet — so this is a read whose predicate is the whole fence:
// the row, the job's status and the lease owner, evaluated together under one
// snapshot. A cancellation or a reclaim that commits before this returns false;
// one that commits after is what the row-status write catches.
func (s *Service) claimImportRow(ctx context.Context, jobID, rowID int64, workerID string) (bool, error) {
	var ok bool
	err := s.pool.QueryRow(ctx, `
		SELECT TRUE
		FROM user_import_job_rows r
		JOIN user_import_jobs j ON j.id = r.job_id
		WHERE r.id = $1
		  AND r.job_id = $2
		  AND r.status = 'pending'
		  AND j.status = 'running'
		  AND j.locked_by = $3
	`, rowID, jobID, workerID).Scan(&ok)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("claim import row: %w", err)
	}
	return ok, nil
}

// recordImportRowFailure counts one infrastructure failure against a row and
// stores its cause, leaving the row pending for a retry.
//
// The count is what bounds the retry; the cause is what makes a stuck row
// diagnosable. They are written together because a count with no cause tells an
// operator that something failed four times and nothing about what.
//
// last_error is deliberately not the row's `reason`: `reason` is the verdict an
// operator reads in the report, and a driver error string carries connection
// details and constraint names that have no place there. This column is only
// read by an administrator looking into a job that has stopped making progress.
func (s *Service) recordImportRowFailure(ctx context.Context, rowID int64, cause error) error {
	if _, err := s.pool.Exec(ctx, `
		UPDATE user_import_job_rows
		SET attempts = attempts + 1, last_error = $2
		WHERE id = $1
	`, rowID, cause.Error()); err != nil {
		return fmt.Errorf("record import row failure: %w", err)
	}
	return nil
}

// applyImportRow performs one row's database work and returns its verdict.
//
// A non-nil infra error means the row could not be judged — the database was
// unreachable, not the row invalid. It is returned separately from the verdict
// because the two must not share a fate: see processImportRow.
func (s *Service) applyImportRow(
	ctx context.Context,
	job *claimedImportJob,
	row *pendingImportRow,
	roles map[string]int64,
	defaultRoleID *int64,
) (outcome, reason string, infra error) {
	u := row.user
	email := u.Email // normalised at enqueue, when the row was validated

	roleID, ok := resolveImportRole(u.Role, roles, defaultRoleID)
	if !ok {
		return ImportOutcomeReject, fmt.Sprintf(
			"role %q is not available in this application — create it first, or correct the name",
			u.Role), nil
	}

	existing, err := s.importUserExists(ctx, job.tenantID, job.applicationID, email)
	if err != nil {
		// The row is fine; we could not ask about it. Rejecting here turned a
		// connection blip into a permanent verdict on a valid row.
		return "", "", fmt.Errorf("existence check: %w", err)
	}

	if existing != nil {
		if !job.updateExisting {
			return ImportOutcomeSkip, "user already exists", nil
		}
		// An absent role keeps the one they have, so it is not a change to
		// report and must not deny their sessions either.
		role := amendRole(u.Role, roleID)
		newRole := existing.roleName
		if role.set {
			newRole = roleNameFor(roles, role.id)
		}
		changed := newRole != existing.roleName
		if err := s.updateImportedUser(ctx, job.tenantID, existing.id, u, role); err != nil {
			return "", "", fmt.Errorf("update user: %w", err)
		}
		if !changed {
			return ImportOutcomeUpdate, "profile updated; role unchanged", nil
		}

		// The reason is computed from the role diff alone, exactly as the dry
		// run computes it (see runImport). It was previously written inside the
		// authSvc branch, which meant a deployment that had not wired the auth
		// service reported a real demotion back to the operator as "role
		// unchanged" — the preview and the commit disagreeing about what the
		// same file did, in the direction that hides it. What the report says
		// happened must not depend on whether a collaborator is present.
		reason := fmt.Sprintf("role %s → %s",
			displayRole(existing.roleName), displayRole(newRole))

		if s.authSvc == nil {
			// Not fatal — the role change is committed and correct — but the
			// user keeps an access token carrying the old permissions until it
			// expires, so this is a real gap and is logged as one rather than
			// skipped in silence. routes.go wires the auth service; reaching
			// here in production means that wiring was lost.
			s.logger.Error().
				Int64("user_id", existing.id).Int64("tenant_id", job.tenantID).
				Str("from", existing.roleName).Str("to", newRole).
				Msg("import worker: role changed without session revocation — auth service not wired")
			return ImportOutcomeUpdate, reason, nil
		}

		// A role change does not reach an already-issued access token:
		// permissions are baked in at login. Without this the demotion is
		// advisory until the token expires.
		//
		// Returns nothing by design and logs its own Redis failures
		// (session denylist: account-wide write failed), with the same
		// fail-open posture every other caller gets. Not fatal to the row:
		// the role change is committed, and the denial has no retry to
		// offer — the window it leaves is one access-token lifetime.
		s.authSvc.DenyUserSessions(ctx, existing.id, job.tenantID)
		return ImportOutcomeUpdate, reason, nil
	}

	if err := s.insertImportedUser(ctx, job.tenantID, job.applicationID, email, u, roleID); err != nil {
		if isDuplicateErr(err) {
			// Lost a race with a concurrent create. The desired end state holds.
			return ImportOutcomeSkip, "user already exists", nil
		}
		// A constraint violation is the row's own fault and is a verdict; any
		// other write error is the database being unavailable and is not.
		if !isRowDataErr(err) {
			return "", "", fmt.Errorf("insert user: %w", err)
		}
		// The underlying error can carry column values and constraint names,
		// and this reason is handed back over the API.
		return ImportOutcomeReject, "write failed", nil
	}
	return ImportOutcomeCreate, "", nil
}

// sweepFinishedImportJobs deletes jobs that reached a terminal state longer
// ago than importJobRetention.
//
// Only terminal jobs: `pending` and `running` are excluded by the status
// predicate, so a long import is never swept out from under its own worker no
// matter how long it has been going. finished_at, not created_at, for the same
// reason — the clock starts when the job stopped.
//
// The rows go with it through ON DELETE CASCADE on user_import_job_rows.job_id,
// which is why this deletes the parent rather than the rows: a sweep of rows
// alone would leave a job reporting counts for a report that no longer exists.
//
// Failure is logged and retried on the next tick. Retention lag is not an
// availability problem, and this must never be able to stop the drain.
func (s *Service) sweepFinishedImportJobs(logger zerolog.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	tag, err := s.pool.Exec(ctx, `
		DELETE FROM user_import_jobs
		WHERE status IN ('completed', 'failed', 'cancelled')
		  AND finished_at IS NOT NULL
		  AND finished_at < NOW() - $1::INTERVAL
	`, importJobRetention.String())
	if err != nil {
		logger.Error().Err(err).Msg("import worker: retention sweep failed")
		return
	}
	if n := tag.RowsAffected(); n > 0 {
		logger.Info().Int64("jobs", n).
			Dur("retention", importJobRetention).
			Msg("import worker: swept finished import jobs")
	}
}

// isRowDataErr reports whether err is the row's own fault — a constraint or a
// value the database refused — as opposed to the database being unreachable.
//
// The distinction decides whether a failed row gets a permanent verdict or is
// left pending for the next attempt. Class 23 is integrity_constraint_violation
// and class 22 is data_exception (a value too long for its column, a bad
// encoding); both are reproducible properties of the row, so retrying it would
// fail identically and `reject` is the honest answer. Everything else —
// connection loss, admin shutdown, a full disk — says nothing about the row.
//
// A non-PgError (a dial failure, a context deadline) never reaches here as a
// data error, which is the conservative direction: the row stays pending and
// gets another attempt rather than being written off.
func isRowDataErr(err error) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}
	return strings.HasPrefix(pgErr.Code, "23") || strings.HasPrefix(pgErr.Code, "22")
}

// resolveImportRole applies the three-tier rule: a named role, else the
// application default, else none. ok is false when a named role is unavailable.
//
// The default-role tier is for a CREATE, where it stops a migrated user being
// less privileged than the identical user who signs up through /register a
// minute later. An update reads the same row through amendRole instead, because
// on a user who already exists that tier would be a demotion.
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

// amendRole decides what an update does to role_id, given the role the row
// named and the id it resolved to.
//
// A row that names a role changes it. A row that names none leaves it alone —
// the application default applies to a user being created, never to one who
// already has a role, since "the column was absent from the file" is not an
// instruction to demote anybody.
func amendRole(name string, roleID *int64) amendedRole {
	if strings.TrimSpace(name) == "" {
		return amendedRole{}
	}
	return amendedRole{set: true, id: roleID}
}

// completeImportJob marks a finished job done, if it is still ours.
//
// locked_by, like every other job mutation here: a worker whose lease expired
// while it drained the last rows must not stamp `completed` over a job the
// reclaiming worker has already restarted, which would strand that run in a
// terminal state with rows still pending.
func (s *Service) completeImportJob(ctx context.Context, jobID int64, workerID string, log zerolog.Logger) error {
	if _, err := s.pool.Exec(ctx, `
		UPDATE user_import_jobs
		SET status = 'completed', finished_at = NOW(), locked_at = NULL,
		    locked_by = NULL, updated_at = NOW()
		WHERE id = $1 AND status = 'running' AND locked_by = $2
	`, jobID, workerID); err != nil {
		return fmt.Errorf("complete import job: %w", err)
	}
	log.Info().Msg("import worker: job completed")
	return nil
}

// failImportJob records a job-level failure — one that prevented the run from
// continuing at all, as opposed to a row that simply could not be applied.
//
// Fenced on the lease so a stalled worker cannot fail a job another one is
// running successfully. The error is still returned either way: the caller logs
// it, and swallowing it because the row was not ours would hide a real fault.
func (s *Service) failImportJob(ctx context.Context, jobID int64, workerID string, cause error) error {
	if _, err := s.pool.Exec(ctx, `
		UPDATE user_import_jobs
		SET status = 'failed', error = $2, finished_at = NOW(),
		    locked_at = NULL, locked_by = NULL, updated_at = NOW()
		WHERE id = $1 AND locked_by = $3
	`, jobID, cause.Error(), workerID); err != nil {
		return fmt.Errorf("fail import job: %w", err)
	}
	// Nothing further will run, so the queued credentials — the plaintext
	// column and the digest in the payload alike — have no reason to remain at
	// rest.
	_, _ = s.pool.Exec(ctx, `
		UPDATE user_import_job_rows
		SET plaintext_password = NULL, `+redactPayloadCredentialsSQL+`
		WHERE job_id = $1 AND status = 'pending'
	`, jobID)
	return cause
}

// releaseImportJob hands a partially-processed job back to the queue at
// shutdown, so the next worker resumes it rather than waiting out the lease.
func (s *Service) releaseImportJob(ctx context.Context, jobID int64, workerID string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE user_import_jobs
		SET status = 'pending', locked_at = NULL, locked_by = NULL, updated_at = NOW()
		WHERE id = $1 AND status = 'running' AND locked_by = $2
	`, jobID, workerID)
	if err != nil {
		return fmt.Errorf("release import job: %w", err)
	}
	return nil
}
