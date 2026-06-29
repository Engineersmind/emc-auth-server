package telemetry

import (
	"os"
	"time"

	"github.com/getsentry/sentry-go"
)

// InitSentry initialises the Sentry SDK.
// No-ops when SENTRY_DSN is unset, so local dev needs no configuration.
// Point SENTRY_DSN at devops-copilot: http://ingest@<host>:5000/1
func InitSentry(env string) error {
	dsn := os.Getenv("SENTRY_DSN")
	if dsn == "" {
		return nil
	}

	return sentry.Init(sentry.ClientOptions{
		Dsn:              dsn,
		Environment:      env,
		TracesSampleRate: 0, // tracing handled by OTel — avoid double-counting
		// Attach the request URL, method, and headers to every event.
		SendDefaultPII: false,
	})
}

// FlushSentry waits up to 2 s for buffered events to drain to the DSN endpoint.
// Call this during graceful shutdown, before process exit.
func FlushSentry() {
	sentry.Flush(2 * time.Second)
}
