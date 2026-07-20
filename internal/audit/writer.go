// writer.go — the asynchronous batch pipeline behind Logger.Log().
//
// Design (heavy-load safety):
//
//	handler → Log(e) → buffered channel → single worker → CopyFrom batch
//	           │ returns instantly           │ flush on batchSize or flushInterval
//	           └ drops + counts when full    └ one retry, then drop + count
//
// Invariants:
//   - Log() never blocks and never touches Postgres on the caller's goroutine,
//     so audit writes add zero latency to auth requests.
//   - The single worker uses at most one pool connection at a time, so audit
//     traffic can never starve the main pgx pool.
//   - Failure degrades the completeness of the audit trail (visible via
//     emc_auth_audit_events_dropped_total), never the availability of auth.
package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/engineersmind/emc-auth-server/internal/metrics"
)

const (
	// defaultQueueSize bounds worst-case buffer memory (~1KB/event → ~10MB)
	// while absorbing bursts of thousands of audited operations per second.
	defaultQueueSize = 10_000
	// defaultBatchSize: one CopyFrom round-trip per 500 events instead of
	// 500 single-row INSERTs.
	defaultBatchSize = 500
	// defaultFlushInterval caps event staleness — an event is durable at
	// most one second after Log() under light traffic.
	defaultFlushInterval = time.Second
	// flushTimeout bounds a single batch insert so a hung DB cannot wedge
	// the worker indefinitely.
	flushTimeout = 5 * time.Second
	// retryBackoff is the pause before the single retry of a failed batch.
	retryBackoff = 250 * time.Millisecond
	// maxMetadataBytes caps the serialized metadata payload. Beyond this the
	// payload is replaced with a truncation marker — a runaway detail map must
	// never bloat a row or the in-memory buffer.
	maxMetadataBytes = 8 * 1024
	// sheddingThresholdPct is the queue-fullness (% of capacity) above which the
	// worker skips the expensive per-event DB enrichment (geo/risk/stats) so a
	// burst degrades enrichment detail before it degrades event durability.
	sheddingThresholdPct = 80
)

// auditColumns is the CopyFrom column list — must match copyBatch row order.
var auditColumns = []string{
	"tenant_id", "user_id", "agent_id", "application_id",
	"actor_email", "action", "auth_method", "resource_type", "resource_id",
	"ip_address", "user_agent", "status", "http_status", "request_id",
	"metadata", "created_at", "row_hash", "prev_hash",
}

// sensitiveKeyPart flags metadata keys whose values must never be persisted,
// even if a caller accidentally threads a secret through Event.Metadata. Match
// is case-insensitive substring, so "client_secret", "refresh_token", and
// "totp_secret" are all caught.
var sensitiveKeyParts = []string{
	"password", "passwd", "secret", "token", "authorization",
	"api_key", "apikey", "private_key", "otp", "backup_code", "credential",
}

func isSensitiveKey(key string) bool {
	k := strings.ToLower(key)
	for _, part := range sensitiveKeyParts {
		if strings.Contains(k, part) {
			return true
		}
	}
	return false
}

// Redact deep-copies v, replacing values under secret-looking keys with
// "[REDACTED]". Exported so response-body capture (middleware) can scrub a
// parsed JSON body — e.g. a login response's access_token/refresh_token — with
// the exact same rules used for metadata. Never mutates the input.
func Redact(v any) any { return redact(v) }

// redact returns a deep copy of v with sensitive map values replaced by
// "[REDACTED]". Walks nested maps and slices; leaves scalars untouched.
func redact(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			if isSensitiveKey(k) {
				out[k] = "[REDACTED]"
			} else {
				out[k] = redact(val)
			}
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = redact(val)
		}
		return out
	default:
		return v
	}
}

// buildMetadata serializes an event's metadata into safe JSONB text: redacted,
// size-capped, and never failing. Returns "{}" for empty or unmarshalable input
// so an enrichment bug can never drop or block an audit write.
func buildMetadata(m map[string]any) string {
	if len(m) == 0 {
		return "{}"
	}
	b, err := json.Marshal(redact(m))
	if err != nil {
		return "{}"
	}
	if len(b) > maxMetadataBytes {
		marker, _ := json.Marshal(map[string]any{"_truncated": true, "_original_bytes": len(b)})
		return string(marker)
	}
	return string(b)
}

// run is the background worker loop. It exits only when quit is closed,
// after draining and flushing everything still buffered.
func (l *Logger) run() {
	defer close(l.done)

	batch := make([]Event, 0, l.batchSize)
	ticker := time.NewTicker(l.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case e := <-l.queue:
			batch = append(batch, e)
			if len(batch) >= l.batchSize {
				l.flush(batch)
				batch = batch[:0]
			}
		case <-ticker.C:
			if len(batch) > 0 {
				l.flush(batch)
				batch = batch[:0]
			}
		case <-l.quit:
			// Shutdown: drain the buffer, flush the remainder, exit.
			for {
				select {
				case e := <-l.queue:
					batch = append(batch, e)
					if len(batch) >= l.batchSize {
						l.flush(batch)
						batch = batch[:0]
					}
				default:
					if len(batch) > 0 {
						l.flush(batch)
					}
					return
				}
			}
		}
	}
}

// flush persists one batch with a single retry. On second failure the batch
// is dropped and counted — the worker must keep consuming the queue rather
// than build an unbounded backlog against a dying database.
func (l *Logger) flush(batch []Event) {
	start := time.Now()
	err := l.copyBatch(batch)
	if err != nil {
		time.Sleep(retryBackoff)
		err = l.copyBatch(batch)
	}
	metrics.AuditFlushDuration.Observe(time.Since(start).Seconds())
	metrics.AuditQueueDepth.Set(float64(len(l.queue)))

	if err != nil {
		metrics.AuditEventsDropped.WithLabelValues("db_error").Add(float64(len(batch)))
		l.logger.Error().Err(err).Int("events", len(batch)).
			Msg("audit: batch insert failed after retry — events dropped")
		return
	}
	metrics.AuditEventsWritten.Add(float64(len(batch)))

	// Stream the durably-written batch to the external sink (SIEM), if any.
	// Emit is non-blocking and best-effort — it must never slow the worker.
	if l.sink != nil {
		l.sink.Emit(batch)
	}
}

// copyBatch bulk-inserts the batch via the Postgres COPY protocol.
// It runs on its own background-derived context (bounded by flushTimeout):
// request contexts are long gone by the time a batch flushes, and a
// cancelled request must never cancel an audit write.
func (l *Logger) copyBatch(batch []Event) error {
	ctx, cancel := context.WithTimeout(context.Background(), flushTimeout)
	defer cancel()

	l.seedChain(ctx)
	// Shed the expensive per-event enrichment (geo/risk/stats DB work) when the
	// queue is backing up, so a burst degrades enrichment detail before it
	// degrades event durability. The core row + hash chain are always written.
	shed := len(l.queue) >= cap(l.queue)*sheddingThresholdPct/100

	rows := make([][]any, len(batch))
	for i, e := range batch {
		// uuid.UUID → [16]byte: pgx encodes [16]byte as a binary uuid,
		// which CopyFrom's binary protocol requires.
		var agentID any
		if e.AgentID != nil {
			agentID = [16]byte(*e.AgentID)
		}
		status := e.Status
		if status == "" {
			status = StatusSuccess
		}
		// Zero HTTPStatus → NULL (unknown), never a literal 0 status code.
		var httpStatus any
		if e.HTTPStatus != 0 {
			httpStatus = int16(e.HTTPStatus) // #nosec G115 -- HTTP status codes are 100–599, well within int16
		}
		meta := e.Metadata
		if shed {
			metrics.AuditEnrichmentErrors.WithLabelValues("shed").Inc()
		} else {
			l.backfillApplication(ctx, &e) // inherit the user's application (sets e.ApplicationID)
			meta = l.enrichedMetadata(e)
			meta = l.assessRisk(ctx, e, meta)
			meta = l.recordLoginStats(ctx, e, meta)
		}

		// Tamper-evidence: chain each row to the previous. The hash covers the
		// non-PII security skeleton only, so GDPR pseudonymization of PII fields
		// never breaks chain verification.
		prevHash := l.lastHash
		rowHash := chainHash(prevHash, e, status, e.HTTPStatus)
		l.lastHash = rowHash

		rows[i] = []any{
			e.TenantID, e.UserID, agentID, e.ApplicationID,
			e.ActorEmail, e.Action, e.AuthMethod, e.ResourceType, e.ResourceID,
			parseINET(e.IPAddress), e.UserAgent,
			status, httpStatus, e.RequestID, buildMetadata(meta), e.createdAt,
			rowHash, prevHash,
		}
	}

	_, err := l.pool.CopyFrom(ctx, pgx.Identifier{"audit_logs"}, auditColumns, pgx.CopyFromRows(rows))
	return err
}

// seedChain initialises the hash chain from the most recent persisted row_hash
// so the chain continues unbroken across restarts. Runs once, lazily, on the
// first flush. A read error leaves the chain unseeded (genesis) rather than
// blocking writes — worst case is a chain that restarts, which verification
// reports as a single boundary, never a false tamper alarm on good data.
//
// NOTE: the chain assumes a single writer (one worker goroutine per process).
// For multi-replica deployments, run the audit writer as a singleton/leader or
// give each replica its own chain partition — otherwise concurrent writers
// interleave and the linear chain is not meaningful.
func (l *Logger) seedChain(ctx context.Context) {
	if l.chainSeeded {
		return
	}
	l.chainSeeded = true
	var last *string
	err := l.pool.QueryRow(ctx,
		`SELECT row_hash FROM audit_logs WHERE row_hash IS NOT NULL ORDER BY id DESC LIMIT 1`,
	).Scan(&last)
	if err == nil && last != nil {
		l.lastHash = *last
	}
}

// chainHash computes the SHA-256 tamper-evidence hash for a row: the previous
// row's hash folded over the event's non-PII security skeleton. PII/erasable
// fields (actor_email, ip_address, user_agent, metadata) are deliberately
// excluded so GDPR pseudonymization can scrub them without breaking the chain.
func chainHash(prevHash string, e Event, status string, httpStatus int) string {
	var b strings.Builder
	b.WriteString(prevHash)
	b.WriteByte('|')
	b.WriteString(e.Action)
	b.WriteByte('|')
	b.WriteString(e.AuthMethod)
	b.WriteByte('|')
	b.WriteString(status)
	b.WriteByte('|')
	fmt.Fprintf(&b, "%d|", httpStatus)
	fmt.Fprintf(&b, "%s|%s|", derefInt(e.TenantID), derefInt(e.UserID))
	if e.AgentID != nil {
		b.WriteString(e.AgentID.String())
	}
	b.WriteByte('|')
	fmt.Fprintf(&b, "%s|", derefInt(e.ApplicationID))
	b.WriteString(e.ResourceType)
	b.WriteByte('|')
	b.WriteString(e.ResourceID)
	b.WriteByte('|')
	b.WriteString(e.RequestID)
	b.WriteByte('|')
	// UnixMicro (not Nano): Postgres timestamptz is microsecond-precision, so
	// the value read back for verification would not match a nanosecond hash.
	fmt.Fprintf(&b, "%d", e.createdAt.UnixMicro())
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

func derefInt(p *int64) string {
	if p == nil {
		return ""
	}
	return fmt.Sprintf("%d", *p)
}

// parseINET converts a remote-IP string into a value pgx can encode as INET.
// Non-IP strings become NULL — the correct sentinel for "IP unavailable"
// (mirrors migration 00029). One malformed IP must not sink a whole batch.
func parseINET(s string) any {
	if s == "" {
		return nil
	}
	if addr, err := netip.ParseAddr(s); err == nil {
		return addr
	}
	return nil
}

// Close stops accepting new events, drains the buffer, flushes the final
// batch, and waits for the worker to finish — bounded by ctx. Call during
// graceful shutdown after the HTTP server has stopped, and before the pgx
// pool closes. Safe to call more than once.
func (l *Logger) Close(ctx context.Context) error {
	if !l.closed.Swap(true) {
		close(l.quit)
	}
	select {
	case <-l.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
