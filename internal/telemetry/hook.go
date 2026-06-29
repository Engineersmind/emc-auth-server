package telemetry

import (
	"context"

	"github.com/rs/zerolog"
	otellog "go.opentelemetry.io/otel/log"
)

// OTelHook is a zerolog hook that forwards ERROR and FATAL log events to the
// OTel log pipeline. devops-copilot ingests these as issues via /v1/logs.
// WARN and below are omitted to keep the issue feed signal-to-noise high.
type OTelHook struct {
	logger otellog.Logger
}

// NewOTelHook creates a hook bound to the global OTel logger provider.
// Call this after telemetry.Init() so the global provider is already set.
func NewOTelHook() zerolog.Hook {
	return &OTelHook{logger: Logger("emc-auth-server")}
}

func (h *OTelHook) Run(_ *zerolog.Event, level zerolog.Level, msg string) {
	if level < zerolog.ErrorLevel {
		return
	}

	sev := otellog.SeverityError
	if level == zerolog.FatalLevel || level == zerolog.PanicLevel {
		sev = otellog.SeverityFatal
	}

	var rec otellog.Record
	rec.SetSeverity(sev)
	rec.SetSeverityText(level.String())
	rec.SetBody(otellog.StringValue(msg))

	h.logger.Emit(context.Background(), rec)
}
