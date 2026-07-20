// sink.go — optional streaming of persisted audit events to an external
// destination (SIEM / log stream). The sink receives each durably-written
// batch after a successful COPY. Implementations must be non-blocking and
// best-effort: streaming lag or a downstream outage must never slow or fail the
// audit writer (and therefore never touch the auth path).

package audit

import "time"

// Sink receives batches of audit events that have been durably persisted.
// Emit must return promptly (enqueue-and-return); it must not block on network.
type Sink interface {
	Emit(events []Event)
	Close()
}

// CreatedAt exposes the enqueue timestamp for sinks/serializers (the field is
// otherwise package-private so callers cannot forge it).
func (e Event) CreatedAt() time.Time { return e.createdAt }
