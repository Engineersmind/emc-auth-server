// Package metrics defines the Prometheus metric descriptors for emc-auth-server.
// All metrics use the "emc_auth" namespace for easy dashboard filtering.
//
// Metric inventory:
//   - emc_auth_http_request_duration_seconds — per-route latency histogram
//   - emc_auth_http_requests_in_flight       — active request gauge
//   - emc_auth_operations_total              — named auth operation counter
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// HTTPRequestDuration tracks end-to-end HTTP request latency.
	// Labels: method (GET/POST/…), path (Echo route template), status (200/401/…).
	HTTPRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "emc_auth",
			Name:      "http_request_duration_seconds",
			Help:      "HTTP request latency bucketed by method, route, and status code.",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"method", "path", "status"},
	)

	// HTTPRequestsInFlight is the count of requests currently being handled.
	HTTPRequestsInFlight = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "emc_auth",
			Name:      "http_requests_in_flight",
			Help:      "Number of HTTP requests currently in flight.",
		},
	)

	// AuthOperations counts discrete auth events with an outcome label.
	// operation values: login, login_otp, register, token_refresh, logout,
	//                   password_reset_request, password_reset_complete,
	//                   totp_enroll, totp_activate, totp_disable, totp_verify,
	//                   api_key_create, api_key_revoke, api_key_auth
	// outcome values: success, failure
	AuthOperations = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "emc_auth",
			Name:      "operations_total",
			Help:      "Total number of auth operations by type and outcome.",
		},
		[]string{"operation", "outcome"},
	)

	// RateLimitHits counts requests blocked by rate limiting.
	// Labels: limiter (ip, tenant, app).
	RateLimitHits = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "emc_auth",
			Name:      "rate_limit_hits_total",
			Help:      "Total number of requests rejected by rate limiters.",
		},
		[]string{"limiter"},
	)
)

// RecordOp is a convenience wrapper around AuthOperations.WithLabelValues.
func RecordOp(operation, outcome string) {
	AuthOperations.WithLabelValues(operation, outcome).Inc()
}
