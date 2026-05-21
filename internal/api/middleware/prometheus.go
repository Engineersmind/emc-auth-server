package middleware

import (
	"net/http"
	"strconv"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/engineersmind/emc-auth-server/internal/metrics"
)

// PrometheusMetrics returns middleware that records per-request latency and
// tracks in-flight request count using Prometheus metrics.
//
// Attaches AFTER RequestID and security headers but BEFORE business handlers
// so that the full processing time (including auth middleware) is captured.
//
// Recorded metrics:
//   - emc_auth_http_request_duration_seconds{method, path, status}
//   - emc_auth_http_requests_in_flight
func PrometheusMetrics() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			start := time.Now()
			metrics.HTTPRequestsInFlight.Inc()

			err := next(c)

			metrics.HTTPRequestsInFlight.Dec()

			// Resolve the final HTTP status code.
			status := c.Response().Status
			if err != nil {
				if he, ok := err.(*echo.HTTPError); ok {
					status = he.Code
				} else {
					status = http.StatusInternalServerError
				}
			}

			// Use Echo's matched route template (e.g. /api/v1/auth/:id) rather
			// than the raw URL path to avoid high-cardinality label explosion.
			route := c.Path()
			if route == "" {
				route = "unknown"
			}

			metrics.HTTPRequestDuration.
				WithLabelValues(c.Request().Method, route, strconv.Itoa(status)).
				Observe(time.Since(start).Seconds())

			return err
		}
	}
}
