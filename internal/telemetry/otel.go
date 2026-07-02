// Package telemetry initialises the OpenTelemetry trace + log pipelines.
// Both pipelines are no-ops when OTEL_EXPORTER_OTLP_ENDPOINT is unset, so
// local development and CI need no extra configuration.
package telemetry

import (
	"context"
	"fmt"
	"net/url"
	"os"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	otellog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/global"
	"go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

// ShutdownFunc flushes and closes all exporters. Call it on graceful shutdown.
type ShutdownFunc func(context.Context) error

// Init sets up OTel trace + log pipelines and returns a shutdown function.
// If OTEL_EXPORTER_OTLP_ENDPOINT is empty, Init is a no-op.
func Init(ctx context.Context) (ShutdownFunc, error) {
	endpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	if endpoint == "" {
		return func(context.Context) error { return nil }, nil
	}

	serviceName := os.Getenv("OTEL_SERVICE_NAME")
	if serviceName == "" {
		serviceName = "emc-auth-server"
	}

	// NewSchemaless has no schema URL, so Merge won't conflict with
	// resource.Default() which uses the SDK's own semconv schema (v1.41.x).
	res, err := resource.Merge(
		resource.Default(),
		resource.NewSchemaless(semconv.ServiceName(serviceName)),
	)
	if err != nil {
		return nil, fmt.Errorf("otel resource: %w", err)
	}

	// Resolve host:port for the otlphttp exporters.
	// Accept both "http://host:port" (url.Parse yields u.Host) and bare "host:port"
	// (url.Parse treats it as a path; fall back to using the raw value).
	hostPort := endpoint
	if u, parseErr := url.Parse(endpoint); parseErr == nil && u.Host != "" {
		hostPort = u.Host
	}
	if hostPort == "" {
		return nil, fmt.Errorf("invalid OTEL_EXPORTER_OTLP_ENDPOINT %q: cannot determine host:port", endpoint)
	}

	// ── Traces ──────────────────────────────────────────────────────────────
	traceExp, err := otlptracehttp.New(ctx,
		otlptracehttp.WithEndpoint(hostPort),
		otlptracehttp.WithInsecure(),
		otlptracehttp.WithURLPath("/v1/traces"),
	)
	if err != nil {
		return nil, fmt.Errorf("otel trace exporter: %w", err)
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(traceExp),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)

	// ── Logs ────────────────────────────────────────────────────────────────
	// ERROR+ zerolog events are forwarded here via OTelHook.
	logExp, err := otlploghttp.New(ctx,
		otlploghttp.WithEndpoint(hostPort),
		otlploghttp.WithInsecure(),
		otlploghttp.WithURLPath("/v1/logs"),
	)
	if err != nil {
		return nil, fmt.Errorf("otel log exporter: %w", err)
	}
	lp := log.NewLoggerProvider(
		log.WithProcessor(log.NewBatchProcessor(logExp)),
		log.WithResource(res),
	)
	global.SetLoggerProvider(lp)

	shutdown := func(ctx context.Context) error {
		err1 := tp.Shutdown(ctx)
		err2 := lp.Shutdown(ctx)
		if err1 != nil {
			return err1
		}
		return err2
	}
	return shutdown, nil
}

// Logger returns the OTel logger for the given scope (used by OTelHook).
func Logger(scope string) otellog.Logger {
	return global.GetLoggerProvider().Logger(scope)
}
