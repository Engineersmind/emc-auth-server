package metrics

import (
	"context"
	"regexp"
	"sort"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// why: #217 — the collector is the whole contract the dashboards and rules
// depend on: every emc_auth_db_pool_* series must be emitted with the right
// name, Prometheus type (gauge vs counter) and exact value, straight out of a
// pgxpool.Stat snapshot. A wrong type or a dropped field would read green on
// "series exists" checks while silently breaking panel queries.
func TestPoolCollector_ReportsStats(t *testing.T) {
	stats := PoolStats{
		AcquireCount:            11,
		AcquireDuration:         7 * time.Second,
		AcquiredConns:           3,
		CanceledAcquireCount:    13,
		ConstructingConns:       2,
		EmptyAcquireCount:       17,
		IdleConns:               5,
		MaxConns:                25,
		TotalConns:              8,
		NewConnsCount:           19,
		MaxLifetimeDestroyCount: 23,
		MaxIdleDestroyCount:     29,
		EmptyAcquireWaitTime:    3 * time.Second,
	}
	want := map[string]struct {
		typ   dto.MetricType
		value float64
	}{
		"emc_auth_db_pool_acquires_total":                   {dto.MetricType_COUNTER, 11},
		"emc_auth_db_pool_acquire_duration_seconds_total":   {dto.MetricType_COUNTER, 7},
		"emc_auth_db_pool_acquired_conns":                   {dto.MetricType_GAUGE, 3},
		"emc_auth_db_pool_canceled_acquires_total":          {dto.MetricType_COUNTER, 13},
		"emc_auth_db_pool_constructing_conns":               {dto.MetricType_GAUGE, 2},
		"emc_auth_db_pool_empty_acquires_total":             {dto.MetricType_COUNTER, 17},
		"emc_auth_db_pool_idle_conns":                       {dto.MetricType_GAUGE, 5},
		"emc_auth_db_pool_max_conns":                        {dto.MetricType_GAUGE, 25},
		"emc_auth_db_pool_total_conns":                      {dto.MetricType_GAUGE, 8},
		"emc_auth_db_pool_new_conns_total":                  {dto.MetricType_COUNTER, 19},
		"emc_auth_db_pool_max_lifetime_destroys_total":      {dto.MetricType_COUNTER, 23},
		"emc_auth_db_pool_max_idle_destroys_total":          {dto.MetricType_COUNTER, 29},
		"emc_auth_db_pool_empty_acquire_wait_seconds_total": {dto.MetricType_COUNTER, 3},
	}
	if len(want) != len(poolMetrics) {
		t.Fatalf("test fixture covers %d series but the collector defines %d — update one side", len(want), len(poolMetrics))
	}

	reg := prometheus.NewRegistry()
	reg.MustRegister(NewPoolCollector(func() (PoolStats, bool) { return stats, true }))

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}
	got := map[string]*dto.MetricFamily{}
	for _, f := range families {
		got[f.GetName()] = f
	}
	for name, w := range want {
		f, ok := got[name]
		if !ok {
			t.Errorf("metric family %s absent from gather", name)
			continue
		}
		if f.GetType() != w.typ {
			t.Errorf("%s type = %s, want %s", name, f.GetType(), w.typ)
		}
		if len(f.GetMetric()) != 1 {
			t.Fatalf("%s has %d metrics, want 1", name, len(f.GetMetric()))
		}
		var v float64
		switch w.typ {
		case dto.MetricType_GAUGE:
			v = f.GetMetric()[0].GetGauge().GetValue()
		case dto.MetricType_COUNTER:
			v = f.GetMetric()[0].GetCounter().GetValue()
		}
		if v != w.value {
			t.Errorf("%s value = %v, want %v", name, v, w.value)
		}
	}
}

// why: #217 — before store.NewDB succeeds, after CloseDB, and for a nil pool,
// the families must be ABSENT, not emitted as zeros: a scrape that reads 0
// acquired conns on a server with no pool looks like a healthy idle one.
// PoolStatsFrom(nil) must also never panic — it is what the process-wide
// source resolves to at startup.
func TestPoolCollector_SourceUnavailable(t *testing.T) {
	sources := map[string]func() (PoolStats, bool){
		"explicit unavailable": func() (PoolStats, bool) { return PoolStats{}, false },
		"nil pool":             PoolStatsFrom(nil),
		"no pool registered":   currentPoolStats,
	}

	prev := currentPool.Load()
	currentPool.Store(nil)
	t.Cleanup(func() { currentPool.Store(prev) })

	for name, src := range sources {
		reg := prometheus.NewRegistry()
		reg.MustRegister(NewPoolCollector(src))
		families, err := reg.Gather()
		if err != nil {
			t.Fatalf("%s: Gather() error = %v", name, err)
		}
		for _, f := range families {
			if len(f.GetMetric()) != 0 {
				t.Errorf("%s: family %s emitted %d metrics, want 0", name, f.GetName(), len(f.GetMetric()))
			}
		}
	}
}

// why: #217 — Describe must advertise exactly what Collect can emit. A
// mismatch either fails registration (unchecked collectors panic on a
// desc-less Collect) or, worse, registers fine while Gather drops series it
// cannot reconcile — the failure mode where the metric exists in code but
// never reaches Prometheus.
func TestPoolCollector_DescribeMatchesCollect(t *testing.T) {
	fqName := regexp.MustCompile(`fqName: "([^"]+)"`)

	descNames := map[string]bool{}
	collector := NewPoolCollector(func() (PoolStats, bool) { return PoolStats{MaxConns: 25}, true })
	descCh := make(chan *prometheus.Desc, len(poolMetrics))
	collector.Describe(descCh)
	close(descCh)
	for d := range descCh {
		m := fqName.FindStringSubmatch(d.String())
		if m == nil {
			t.Fatalf("desc %q has no fqName", d.String())
		}
		descNames[m[1]] = true
	}

	collectNames := map[string]bool{}
	metricCh := make(chan prometheus.Metric, len(poolMetrics))
	collector.Collect(metricCh)
	close(metricCh)
	for m := range metricCh {
		match := fqName.FindStringSubmatch(m.Desc().String())
		if match == nil {
			t.Fatalf("metric %q has no fqName", m.Desc().String())
		}
		collectNames[match[1]] = true
		if !descNames[match[1]] {
			t.Errorf("Collect emitted %s which Describe did not advertise", match[1])
		}
	}

	want := map[string]bool{}
	for _, n := range PoolMetricNames() {
		want[n] = true
	}
	for n := range want {
		if !collectNames[n] {
			t.Errorf("PoolMetricNames lists %s but Collect did not emit it", n)
		}
		if !descNames[n] {
			t.Errorf("PoolMetricNames lists %s but Describe did not advertise it", n)
		}
	}
	if len(collectNames) != len(want) || len(descNames) != len(want) {
		t.Errorf("cardinality mismatch: collect=%d describe=%d want=%d", len(collectNames), len(descNames), len(want))
	}
}

// why: #217 — ClearDBPool must only clear the registration for THE pool it is
// given. Tests (and any future secondary pool) call CloseDB on their own
// pools; an unconditional clear would let a short-lived test pool unregister
// the server's live one and make the whole emc_auth_db_pool_* family
// disappear mid-scrape.
func TestPoolCollector_ClearOnlyCurrent(t *testing.T) {
	newPool := func(t *testing.T) *pgxpool.Pool {
		t.Helper()
		cfg, err := pgxpool.ParseConfig("postgres://u:p@127.0.0.1:1/unreachable")
		if err != nil {
			t.Fatalf("ParseConfig() error = %v", err)
		}
		cfg.MinConns = 0
		// NewWithConfig is lazy: it validates the config but never dials, so
		// an unreachable DSN still yields a usable *Pool.
		p, err := pgxpool.NewWithConfig(context.Background(), cfg)
		if err != nil {
			t.Skipf("pgxpool.NewWithConfig dialed or failed at construction — cannot build a no-DB pool fixture: %v", err)
		}
		t.Cleanup(p.Close)
		return p
	}

	prev := currentPool.Load()
	t.Cleanup(func() { currentPool.Store(prev) })

	a, b := newPool(t), newPool(t)

	SetDBPool(a)
	ClearDBPool(b)
	if got := currentPool.Load(); got != a {
		t.Fatalf("ClearDBPool(b) cleared current pool: got %p, want %p (a)", got, a)
	}
	ClearDBPool(a)
	if got := currentPool.Load(); got != nil {
		t.Fatalf("ClearDBPool(a) left current pool set: got %p, want nil", got)
	}
}

// why: #217 — PoolMetricNames is the drift-check contract: tests, dashboards
// and alert rules all compare against it, so it must list every defined
// series exactly once, sorted or not, with no extras.
func TestPoolMetricNames_Complete(t *testing.T) {
	names := PoolMetricNames()
	if len(names) != len(poolMetrics) {
		t.Fatalf("PoolMetricNames() has %d entries, collector defines %d", len(names), len(poolMetrics))
	}
	sorted := append([]string(nil), names...)
	sort.Strings(sorted)
	for i := 1; i < len(sorted); i++ {
		if sorted[i] == sorted[i-1] {
			t.Errorf("duplicate metric name %q", sorted[i])
		}
	}
	for _, n := range names {
		if len(n) <= len(dbPoolNamespace) || n[:len(dbPoolNamespace)] != dbPoolNamespace {
			t.Errorf("metric name %q does not start with %q", n, dbPoolNamespace)
		}
	}
}
