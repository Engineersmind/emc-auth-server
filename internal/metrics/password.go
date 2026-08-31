package metrics

import (
	"time"

	"github.com/engineersmind/emc-auth-server/internal/password"
)

// PasswordObserver adapts the password package's Observer interface onto the
// Prometheus registry.
//
// The adapter lives here rather than in internal/password so that the hashing
// primitive carries no dependency on a telemetry backend — a password can be
// hashed correctly in a test, a seed, or an offline tool with no registry wired.
type PasswordObserver struct{}

// NewPasswordObserver returns the metrics adapter for a password.Hasher.
func NewPasswordObserver() *PasswordObserver { return &PasswordObserver{} }

// ObserveHash records derivation latency by algorithm and operation.
func (PasswordObserver) ObserveHash(alg password.Algorithm, op string, d time.Duration) {
	PasswordHashDuration.WithLabelValues(string(alg), op).Observe(d.Seconds())
}

// ObserveQueueWait records time spent waiting for a concurrency slot.
func (PasswordObserver) ObserveQueueWait(d time.Duration) {
	PasswordHashQueueWait.Observe(d.Seconds())
}

// SetInFlight records the number of running derivations.
func (PasswordObserver) SetInFlight(n int) {
	PasswordHashInFlight.Set(float64(n))
}
