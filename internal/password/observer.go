package password

import "time"

// Observer receives timing and lifecycle events from a Hasher.
//
// An interface with an injected implementation, rather than the package calling
// internal/metrics directly: password hashing is a security primitive and must
// not require a telemetry backend to be wired before it works. A nil Observer is
// valid and disables reporting, which is what keeps the package usable from
// tests, tooling, and the seed path.
type Observer interface {
	// ObserveHash reports a completed derivation.
	ObserveHash(algorithm Algorithm, operation string, d time.Duration)
	// ObserveQueueWait reports time spent waiting for a concurrency slot. Called
	// only when the wait was contended.
	ObserveQueueWait(d time.Duration)
	// SetInFlight reports the current number of running derivations.
	SetInFlight(n int)
}

// WithObserver attaches an Observer. Returns the receiver for chaining.
func (h *Hasher) WithObserver(o Observer) *Hasher {
	h.observer = o
	if o != nil {
		h.guard.onWait = o.ObserveQueueWait
	}
	return h
}

func (h *Hasher) observeHash(alg Algorithm, op string, d time.Duration) {
	if h.observer != nil {
		h.observer.ObserveHash(alg, op, d)
	}
}

func (h *Hasher) observeInFlight() {
	if h.observer != nil {
		h.observer.SetInFlight(h.guard.inFlight())
	}
}
