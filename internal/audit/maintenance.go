// maintenance.go — retention purge + GDPR erasure, executed through the
// SECURITY DEFINER SQL functions installed by migration 00056 (which set the
// append-only trigger's maintenance flag). Both are privileged operations
// invoked by admins or the background retention worker, never on the auth path.

package audit

import (
	"context"
	"fmt"
	"time"
)

// PurgeOlderThan deletes audit rows older than retentionDays via the
// purge_audit_logs SQL function. Returns the number of rows purged.
func (l *Logger) PurgeOlderThan(ctx context.Context, retentionDays int) (int64, error) {
	var purged int64
	if err := l.pool.QueryRow(ctx, `SELECT purge_audit_logs($1)`, retentionDays).Scan(&purged); err != nil {
		return 0, fmt.Errorf("purge audit logs: %w", err)
	}
	// A purge can truncate the tail of the hash chain; re-seed on next flush.
	// Guarded by chainMu since the flush worker reads chainSeeded concurrently.
	l.chainMu.Lock()
	l.chainSeeded = false
	l.chainMu.Unlock()
	return purged, nil
}

// PseudonymizeUser scrubs one user's PII from the audit trail (GDPR erasure)
// via pseudonymize_user_audit, preserving the non-PII security event trail and
// the tamper-evidence chain. Returns the number of rows affected.
func (l *Logger) PseudonymizeUser(ctx context.Context, userID int64) (int64, error) {
	var affected int64
	if err := l.pool.QueryRow(ctx, `SELECT pseudonymize_user_audit($1)`, userID).Scan(&affected); err != nil {
		return 0, fmt.Errorf("pseudonymize user audit: %w", err)
	}
	return affected, nil
}

// retentionStartupDelay defers the first retention purge past the deploy
// window. Running eagerly on every process start would fire a mass DELETE (up
// to 5 minutes of DB work) right as a new build is stabilising — exactly when
// the deploy is most fragile. Delaying the first run avoids that without
// materially changing retention behaviour (the purge is a daily job anyway).
const retentionStartupDelay = 30 * time.Minute

// StartRetention launches a background worker that purges audit rows older than
// retentionDays once per day. A no-op when retentionDays <= 0. The returned
// stop function ends the worker. Failures are logged and retried next tick —
// retention lag never affects auth. The first purge is deferred by
// retentionStartupDelay so a deploy never triggers an immediate mass delete.
func (l *Logger) StartRetention(retentionDays int) (stop func()) {
	if retentionDays <= 0 {
		return func() {}
	}
	done := make(chan struct{})
	go func() {
		run := func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			purged, err := l.PurgeOlderThan(ctx, retentionDays)
			if err != nil {
				l.logger.Error().Err(err).Int("retention_days", retentionDays).Msg("audit retention purge failed")
				return
			}
			if purged > 0 {
				l.logger.Info().Int64("purged", purged).Int("retention_days", retentionDays).Msg("audit retention purge")
			}
		}

		// Wait out the startup delay first (interruptible by shutdown).
		startup := time.NewTimer(retentionStartupDelay)
		defer startup.Stop()
		select {
		case <-startup.C:
			run()
		case <-done:
			return
		}

		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				run()
			case <-done:
				return
			}
		}
	}()
	return func() { close(done) }
}
