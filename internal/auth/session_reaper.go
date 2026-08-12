package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	"github.com/engineersmind/emc-auth-server/internal/metrics"
)

// SessionReaper deletes refresh-token rows that can never be used again.
//
// Nothing had ever deleted from these tables. refresh_tokens gains a row per login
// AND per token rotation — at a 15-minute access-token TTL that is roughly 96
// rows per active session per day — and every one of them was kept forever. The
// liveness filters keep dead rows out of query RESULTS, but they still have to be
// scanned, indexed, vacuumed, and backed up.
//
// This is deliberately not a "session cleanup" that decides policy: liveness is
// already decided by LiveSessionWhere, and the reaper only removes rows that
// predicate has permanently excluded, after a retention margin. If the two ever
// disagree the reaper is the one that must be more conservative, which is why its
// condition is written in terms of "cannot possibly be live" rather than by
// negating the liveness predicate.
type SessionReaper struct {
	pool   *pgxpool.Pool
	logger zerolog.Logger

	// interval is how often a replica attempts a run.
	interval time.Duration
	// retention is how long a dead row is kept for forensics before deletion.
	retention time.Duration
	// batchSize bounds one DELETE statement.
	batchSize int
}

// Reaper defaults.
const (
	// defaultReapInterval — hourly. The work is proportional to what died in the
	// last hour, so frequent small runs keep each one cheap; there is no benefit
	// to batching a day's worth of deletions into one long transaction.
	defaultReapInterval = time.Hour

	// defaultReapRetention keeps dead rows for a week after they die.
	//
	// Not zero, because a revoked session is evidence: "when was this session
	// terminated, from what IP, on what device" is asked during an incident, and
	// asked days later. Not longer, because the durable record of the same events
	// is the audit trail, which has its own retention and immutability guarantees
	// (migration 00056). This table is operational state; deleting from it must
	// never be the thing that loses history.
	defaultReapRetention = 7 * 24 * time.Hour

	// defaultReapBatchSize bounds one DELETE so the statement holds locks briefly
	// and can be interrupted at a batch boundary on shutdown.
	defaultReapBatchSize = 5000

	// reapLockID is the advisory-lock key that elects one reaper across replicas.
	//
	// Every replica runs its own ticker — there is no leader election in this
	// service and adding one for a cleanup job would be disproportionate — so
	// without this lock N replicas would issue N concurrent DELETE batches against
	// the same rows, contending on the same pages to do the same work N times.
	// pg_try_advisory_lock returns immediately rather than queueing, so the losers
	// skip the run instead of piling up behind the winner.
	reapLockID = 0x656D63_72656170 // "emc" "reap"
)

// NewSessionReaper creates a reaper with default timings.
func NewSessionReaper(pool *pgxpool.Pool, logger zerolog.Logger) *SessionReaper {
	return &SessionReaper{
		pool:      pool,
		logger:    logger,
		interval:  defaultReapInterval,
		retention: defaultReapRetention,
		batchSize: defaultReapBatchSize,
	}
}

// Run reaps on a ticker until ctx is cancelled. Intended to be started in its own
// goroutine by main.
//
// Runs once immediately rather than waiting out the first interval: on a
// deployment that has never reaped, the backlog is the whole table, and making an
// operator wait an hour to see whether the job works at all is unkind. Errors are
// logged and the loop continues — a reaper that stops on its first failure is a
// reaper that is silently off for the rest of the process's life.
func (r *SessionReaper) Run(ctx context.Context) {
	r.logger.Info().
		Dur("interval", r.interval).
		Dur("retention", r.retention).
		Msg("session reaper: started")

	for {
		if err := r.RunOnce(ctx); err != nil && !errors.Is(err, context.Canceled) {
			r.logger.Error().Err(err).Msg("session reaper: run failed")
		}

		select {
		case <-ctx.Done():
			r.logger.Info().Msg("session reaper: stopped")
			return
		case <-time.After(r.interval):
		}
	}
}

// RunOnce performs a single reaping pass. Exported so it can be triggered
// directly from a test or an operational one-shot command.
func (r *SessionReaper) RunOnce(ctx context.Context) error {
	conn, err := r.pool.Acquire(ctx)
	if err != nil {
		metrics.SessionReaperRuns.WithLabelValues("failure").Inc()
		return fmt.Errorf("reaper: acquire connection: %w", err)
	}
	// The advisory lock is session-scoped, so it is held by this specific
	// connection and must be released on it. Returning the connection to the pool
	// while still holding the lock would leak it until the connection is recycled,
	// blocking every future run.
	defer conn.Release()

	var locked bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, int64(reapLockID)).Scan(&locked); err != nil {
		metrics.SessionReaperRuns.WithLabelValues("failure").Inc()
		return fmt.Errorf("reaper: acquire advisory lock: %w", err)
	}
	if !locked {
		// Another replica is reaping. Expected and normal, not a fault.
		metrics.SessionReaperRuns.WithLabelValues("skipped_locked").Inc()
		r.logger.Debug().Msg("session reaper: another replica holds the lock, skipping")
		return nil
	}
	defer func() {
		// Best-effort unlock on a context that cannot already be cancelled: using
		// the caller's ctx here would skip the unlock during shutdown, which is
		// exactly when it matters.
		unlockCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := conn.Exec(unlockCtx, `SELECT pg_advisory_unlock($1)`, int64(reapLockID)); err != nil {
			r.logger.Warn().Err(err).Msg("session reaper: advisory unlock failed")
		}
	}()

	cutoff := time.Now().UTC().Add(-r.retention)
	var total int64

	for {
		// Stop at a batch boundary on shutdown rather than mid-statement: each
		// batch is committed independently, so an interrupted pass leaves the table
		// consistent and the next pass simply continues.
		if err := ctx.Err(); err != nil {
			r.logger.Info().Int64("deleted", total).Msg("session reaper: interrupted, will resume next run")
			metrics.SessionReaperRuns.WithLabelValues("success").Inc()
			return nil
		}

		// Sessions are deleted, and their tokens go with them by ON DELETE CASCADE.
		//
		// Deleting the parent rather than sweeping tokens independently is what keeps
		// the two tables from diverging: there is no state in which a token survives
		// the session it belongs to, or a session lingers with no tokens. A row is
		// deletable when it can never be used again AND its retention margin has
		// passed — it was revoked, or both of its deadlines fell.
		ct, err := conn.Exec(ctx, `
			DELETE FROM user_sessions
			WHERE id IN (
				SELECT id FROM user_sessions
				WHERE (revoked_at IS NOT NULL AND revoked_at < $1)
				   OR GREATEST(idle_expires_at, absolute_expires_at) < $1
				LIMIT $2
			)
		`, cutoff, r.batchSize)
		if err != nil {
			metrics.SessionReaperRuns.WithLabelValues("failure").Inc()
			return fmt.Errorf("reaper: delete session batch: %w", err)
		}

		n := ct.RowsAffected()
		total += n
		metrics.SessionsReaped.Add(float64(n))
		if n < int64(r.batchSize) {
			break
		}
	}

	// Tokens with no session to cascade from: rows written by a binary that predates
	// migration 00069, plus anything orphaned by a partial backfill. Swept by their
	// own expiry so they cannot accumulate forever, and separately from the loop
	// above because they have no parent to delete.
	if _, err := conn.Exec(ctx, `
		DELETE FROM refresh_tokens
		WHERE session_id IS NULL
		  AND ((revoked_at IS NOT NULL AND revoked_at < $1) OR expires_at < $1)
	`, cutoff); err != nil {
		metrics.SessionReaperRuns.WithLabelValues("failure").Inc()
		return fmt.Errorf("reaper: delete orphaned tokens: %w", err)
	}

	metrics.SessionReaperRuns.WithLabelValues("success").Inc()
	if total > 0 {
		r.logger.Info().Int64("deleted", total).Time("cutoff", cutoff).
			Msg("session reaper: removed expired refresh tokens")
	}
	return nil
}
