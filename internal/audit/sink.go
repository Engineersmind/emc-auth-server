// sink.go — optional streaming of persisted audit events to an external
// destination (SIEM / log stream). The sink receives each durably-written
// batch after a successful COPY. Implementations must be non-blocking and
// best-effort: streaming lag or a downstream outage must never slow or fail the
// audit writer (and therefore never touch the auth path).

package audit

import "time"

// Sink receives batches of audit events that have been durably persisted.
// Emit must return promptly (enqueue-and-return); it must not block on network.
//
// IMPORTANT for implementors: the slice handed to Emit is the writer's own
// reused backing array, and the events in it are the RAW ones — the enrichment
// the writer performs (geo, risk, application backfill, metadata redaction) is
// applied to a copy destined for the database and is not visible here. A sink
// that keeps the batch beyond the call must copy it first, and one that exports
// metadata must redact it itself via Redact.
type Sink interface {
	Emit(events []Event)
	Close()
}

// CreatedAt exposes the enqueue timestamp for sinks/serializers (the field is
// otherwise package-private so callers cannot forge it).
func (e Event) CreatedAt() time.Time { return e.createdAt }
