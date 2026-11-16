package metrics

import (
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
)

// pgx pool saturation metrics (issue #217).
//
// pgxpool.Stat answers on demand but is a snapshot struct of unexported
// fields — it cannot be handed to a GaugeFunc per method, and the package has
// no exported way to ask "which pool belongs to this process". The bridge is a
// pull collector: store.NewDB registers the live pool once it has pinged, and
// every scrape reads a fresh Stat off it. Before NewDB succeeds, and after
// CloseDB clears it, the emc_auth_db_pool_* families are ABSENT from /metrics
// rather than frozen at their last reading — a closed pool's Stat still
// answers, and stale numbers that look alive are worse than no series.
//
// Set/Clear go through a compare-and-swap so that closing a secondary pool —
// a test's throwaway NewDB, say — can never blank the server's registered
// pool out from under the scrape path.

// PoolStats is one scrape's worth of pgxpool.Stat readings — one field per
// Stat method, so a new upstream reading is a one-line addition here and in
// PoolStatsFrom rather than a collector rewrite.
type PoolStats struct {
	AcquireCount            int64
	AcquireDuration         time.Duration
	AcquiredConns           int32
	CanceledAcquireCount    int64
	ConstructingConns       int32
	EmptyAcquireCount       int64
	IdleConns               int32
	MaxConns                int32
	TotalConns              int32
	NewConnsCount           int64
	MaxLifetimeDestroyCount int64
	MaxIdleDestroyCount     int64
	EmptyAcquireWaitTime    time.Duration
}

// PoolStatsFrom adapts a *pgxpool.Pool into a PoolStats source for
// NewPoolCollector. A nil pool yields a source that always reports the stats
// unavailable, which makes "no pool registered" indistinguishable-safe: the
// collector emits nothing rather than panicking or reporting zeros.
func PoolStatsFrom(p *pgxpool.Pool) func() (PoolStats, bool) {
	return func() (PoolStats, bool) {
		if p == nil {
			return PoolStats{}, false
		}
		s := p.Stat()
		return PoolStats{
			AcquireCount:            s.AcquireCount(),
			AcquireDuration:         s.AcquireDuration(),
			AcquiredConns:           s.AcquiredConns(),
			CanceledAcquireCount:    s.CanceledAcquireCount(),
			ConstructingConns:       s.ConstructingConns(),
			EmptyAcquireCount:       s.EmptyAcquireCount(),
			IdleConns:               s.IdleConns(),
			MaxConns:                s.MaxConns(),
			TotalConns:              s.TotalConns(),
			NewConnsCount:           s.NewConnsCount(),
			MaxLifetimeDestroyCount: s.MaxLifetimeDestroyCount(),
			MaxIdleDestroyCount:     s.MaxIdleDestroyCount(),
			EmptyAcquireWaitTime:    s.EmptyAcquireWaitTime(),
		}, true
	}
}

// poolMetric is one emc_auth_db_pool_* series: its short name, help text,
// Prometheus value type, and how to read it out of a PoolStats snapshot.
type poolMetric struct {
	name  string
	help  string
	typ   prometheus.ValueType
	value func(PoolStats) float64
}

// dbPoolNamespace is the family prefix every pool series shares.
const dbPoolNamespace = "emc_auth_db_pool_"

// poolMetrics is the single source of truth for the series set: the
// collector's descs, PoolMetricNames, and the dashboard/rules contract all
// read this table.
var poolMetrics = []poolMetric{
	{"acquired_conns", "pgx pool connections currently checked out to callers.", prometheus.GaugeValue,
		func(s PoolStats) float64 { return float64(s.AcquiredConns) }},
	{"idle_conns", "pgx pool connections sitting idle and reusable.", prometheus.GaugeValue,
		func(s PoolStats) float64 { return float64(s.IdleConns) }},
	{"total_conns", "pgx pool connections total — acquired plus idle.", prometheus.GaugeValue,
		func(s PoolStats) float64 { return float64(s.TotalConns) }},
	{"constructing_conns", "pgx pool connections being established right now.", prometheus.GaugeValue,
		func(s PoolStats) float64 { return float64(s.ConstructingConns) }},
	{"max_conns", "pgx pool size cap from configuration.", prometheus.GaugeValue,
		func(s PoolStats) float64 { return float64(s.MaxConns) }},
	{"acquires_total", "Cumulative successful pgx pool Acquire calls.", prometheus.CounterValue,
		func(s PoolStats) float64 { return float64(s.AcquireCount) }},
	{"canceled_acquires_total", "Cumulative pgx pool Acquire calls canceled by context.", prometheus.CounterValue,
		func(s PoolStats) float64 { return float64(s.CanceledAcquireCount) }},
	{"empty_acquires_total", "Cumulative pgx pool Acquire calls that waited for a free connection.", prometheus.CounterValue,
		func(s PoolStats) float64 { return float64(s.EmptyAcquireCount) }},
	{"new_conns_total", "Cumulative new connections the pgx pool created.", prometheus.CounterValue,
		func(s PoolStats) float64 { return float64(s.NewConnsCount) }},
	{"max_lifetime_destroys_total", "Cumulative pgx pool connections closed for reaching MaxConnLifetime.", prometheus.CounterValue,
		func(s PoolStats) float64 { return float64(s.MaxLifetimeDestroyCount) }},
	{"max_idle_destroys_total", "Cumulative pgx pool connections closed for reaching MaxConnIdleTime.", prometheus.CounterValue,
		func(s PoolStats) float64 { return float64(s.MaxIdleDestroyCount) }},
	{"acquire_duration_seconds_total", "Cumulative wall time spent inside pgx pool Acquire, in seconds.", prometheus.CounterValue,
		func(s PoolStats) float64 { return s.AcquireDuration.Seconds() }},
	{"empty_acquire_wait_seconds_total", "Cumulative time pgx pool Acquire calls waited on an empty pool, in seconds.", prometheus.CounterValue,
		func(s PoolStats) float64 { return s.EmptyAcquireWaitTime.Seconds() }},
}

// PoolMetricNames returns the fully qualified name of every series the pool
// collector can emit — emc_auth_db_pool_<name> — in table order. Tests and
// the observability drift checks compare against this list rather than a
// second hand-kept copy of the names.
func PoolMetricNames() []string {
	names := make([]string, len(poolMetrics))
	for i, m := range poolMetrics {
		names[i] = dbPoolNamespace + m.name
	}
	return names
}

// poolCollector reads a PoolStats source once per Collect and emits either
// every pool series (source ok) or none of them (source reports the pool
// unavailable). Describe always advertises the full set — Prometheus needs a
// stable descriptor list; absence is expressed by emitting no samples.
type poolCollector struct {
	source func() (PoolStats, bool)
	descs  []*prometheus.Desc
}

// NewPoolCollector builds a Collector over an arbitrary PoolStats source so
// tests can drive it with fixtures; the process wiring uses
// NewPoolCollector(currentPoolStats), registered in init.
func NewPoolCollector(source func() (PoolStats, bool)) prometheus.Collector {
	descs := make([]*prometheus.Desc, len(poolMetrics))
	for i, m := range poolMetrics {
		descs[i] = prometheus.NewDesc(dbPoolNamespace+m.name, m.help, nil, nil)
	}
	return &poolCollector{source: source, descs: descs}
}

func (c *poolCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range c.descs {
		ch <- d
	}
}

func (c *poolCollector) Collect(ch chan<- prometheus.Metric) {
	stats, ok := c.source()
	if !ok {
		return
	}
	for i, m := range poolMetrics {
		ch <- prometheus.MustNewConstMetric(c.descs[i], m.typ, m.value(stats))
	}
}

// currentPool is the pool the registered collector reports on. It is set
// once by store.NewDB on the success path and cleared by store.CloseDB.
var currentPool atomic.Pointer[pgxpool.Pool]

// SetDBPool makes p the pool reported by the emc_auth_db_pool_* series.
// Called by store.NewDB only after the pool has pinged — a pool that never
// connected is never advertised.
func SetDBPool(p *pgxpool.Pool) {
	currentPool.Store(p)
}

// ClearDBPool unregisters p ONLY if p is the pool currently being reported.
// Closing a secondary pool must not blank the server's: tests and retries
// create pools of their own, and a naive unconditional clear would let any
// one of them stop the server's metrics mid-flight.
func ClearDBPool(p *pgxpool.Pool) {
	currentPool.CompareAndSwap(p, nil)
}

// currentPoolStats is the registered collector's source: the live pool's
// Stat, or unavailable when no pool is registered.
func currentPoolStats() (PoolStats, bool) {
	return PoolStatsFrom(currentPool.Load())()
}

// init registers the process-wide collector on the default registry — the
// same lifetime as the promauto metrics above, so there is no
// AlreadyRegisteredError path and no ordering dependency on main().
func init() {
	prometheus.MustRegister(NewPoolCollector(currentPoolStats))
}
