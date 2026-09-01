package password

import (
	"context"
	"fmt"
	"runtime"
	"time"
)

// memoryGuard bounds how many Argon2id derivations run at once.
//
// This is the load-bearing difference between Argon2id and bcrypt in production.
// Bcrypt's ~4KiB per comparison means concurrency costs nothing in memory, so an
// unbounded number of in-flight logins degrades gracefully into CPU contention.
// Argon2id at 46MiB does not: 500 concurrent logins is 23GB of live allocation,
// and the process is killed by the OOM killer rather than slowed. An
// authentication server that dies under a login spike has converted a latency
// problem into an outage, and an attacker who notices can trigger it deliberately
// with unauthenticated requests.
//
// So derivations are gated by a counting semaphore. Requests past the limit WAIT
// rather than fail: a login that takes longer under load is correct behaviour,
// while a login that returns 503 because other people are also signing in is not.
// The queue is bounded in practice by the HTTP server's own connection limits and
// by each caller's context deadline, which the acquire respects.
type memoryGuard struct {
	sem chan struct{}
	// onWait reports contended queue time. Injected rather than calling the
	// metrics package directly: internal/metrics is free to import this package
	// in future, and a hashing primitive should not depend on a telemetry
	// backend to function.
	onWait func(time.Duration)
}

// newMemoryGuard sizes the semaphore from the configured concurrency.
func newMemoryGuard(maxConcurrent int) *memoryGuard {
	if maxConcurrent < 1 {
		maxConcurrent = 1
	}
	return &memoryGuard{sem: make(chan struct{}, maxConcurrent)}
}

// acquire blocks until a slot is free or ctx is done.
//
// Honouring ctx matters under exactly the conditions the guard exists for: when
// a spike has filled the semaphore, a client that has already hung up must not
// hold a queue position, and a request whose deadline has passed must not go on
// to spend 46MiB deriving a hash nobody will read.
func (g *memoryGuard) acquire(ctx context.Context) error {
	// Fast path: a free slot costs no timer and no clock read, which matters
	// because the uncontended case is the common one.
	select {
	case g.sem <- struct{}{}:
		return nil
	default:
	}

	start := time.Now()
	select {
	case g.sem <- struct{}{}:
		g.observeWait(time.Since(start))
		return nil
	case <-ctx.Done():
		g.observeWait(time.Since(start))
		return ctx.Err()
	}
}

func (g *memoryGuard) observeWait(d time.Duration) {
	if g.onWait != nil {
		g.onWait(d)
	}
}

func (g *memoryGuard) release() { <-g.sem }

// inFlight reports how many derivations hold a slot. For metrics and tests.
func (g *memoryGuard) inFlight() int { return len(g.sem) }

// DefaultMaxConcurrent returns the default cap on simultaneous derivations.
//
// NumCPU, floored at 2. Argon2id is CPU-saturating as well as memory-hungry, so
// allowing more concurrent derivations than cores buys no throughput — the
// derivations simply timeshare, every one of them holding its full memory
// allocation for longer. Matching cores keeps peak memory predictable
// (NumCPU x Memory) while running the hardware flat out.
//
// At the default 46MiB this is ~46MiB x NumCPU: 368MiB on 8 cores, 552MiB on 12.
// Size the container above that plus normal heap, or lower MaxConcurrent.
func DefaultMaxConcurrent() int {
	if n := runtime.NumCPU(); n > 2 {
		return n
	}
	return 2
}

// PeakMemoryBytes is the worst-case memory the hasher can hold at once.
//
// Exposed so a deployment can assert its container limit against it at startup
// rather than discovering the ceiling as an OOM kill under load.
func (h *Hasher) PeakMemoryBytes() uint64 {
	// maxConcurrent is >= 1 by construction (DefaultMaxConcurrent floors at 2,
	// WithMaxConcurrent rejects anything lower), but the compiler cannot see that
	// through the field, and a negative would wrap to an enormous uint64 — an
	// answer a deployment might size a container against. Clamp rather than
	// suppress: the guard costs nothing and the invariant becomes checkable.
	n := h.maxConcurrent
	if n < 1 {
		n = 1
	}
	return uint64(h.params.Memory) * 1024 * uint64(n)
}

// String renders the configuration for startup logging.
func (h *Hasher) String() string {
	return fmt.Sprintf(
		"argon2id(m=%dKiB,t=%d,p=%d) max_concurrent=%d peak_memory=%dMiB",
		h.params.Memory, h.params.Iterations, h.params.Parallelism,
		h.maxConcurrent, h.PeakMemoryBytes()/(1024*1024),
	)
}
