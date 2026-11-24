package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"sort"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/attribute"
	otellog "go.opentelemetry.io/otel/log"
)

const (
	maxAttrs    = 40
	maxAttrText = 500
)

// OTelWriter is a zerolog.LevelWriter that forwards ERROR and FATAL events to the OTel log
// pipeline together with every field the event was logged with (path, status, error, request
// id …). A zerolog.Hook only sees the message string, so an issue made from it says "request"
// and nothing else; the writer sees the whole JSON line.
//
// It is meant to sit next to the normal writer: zerolog.MultiLevelWriter(os.Stdout, NewOTelWriter()).
type OTelWriter struct {
	logger otellog.Logger
}

// NewOTelWriter binds to the global OTel logger provider; call it after Init.
func NewOTelWriter() *OTelWriter { return &OTelWriter{logger: Logger("emc-auth-server")} }

// Write satisfies io.Writer; zerolog calls WriteLevel on a LevelWriter.
func (w *OTelWriter) Write(p []byte) (int, error) { return len(p), nil }

func (w *OTelWriter) WriteLevel(level zerolog.Level, p []byte) (int, error) {
	if level >= zerolog.ErrorLevel {
		w.emit(level, p)
	}
	return len(p), nil
}

func (w *OTelWriter) emit(level zerolog.Level, line []byte) {
	sev := otellog.SeverityError
	if level == zerolog.FatalLevel || level == zerolog.PanicLevel {
		sev = otellog.SeverityFatal
	}

	var rec otellog.Record
	rec.SetSeverity(sev)
	rec.SetSeverityText(level.String())

	// The line is only valid for this call (zerolog reuses its buffer): parse it now.
	fields := map[string]any{}
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.UseNumber()
	if err := dec.Decode(&fields); err != nil {
		rec.SetBody(attribute.StringValue(trim(string(bytes.TrimSpace(line)))))
		w.logger.Emit(context.Background(), rec)
		return
	}

	msg, _ := fields["message"].(string)
	rec.SetBody(attribute.StringValue(msg))

	keys := make([]string, 0, len(fields))
	for k := range fields {
		if k != "message" && k != "level" && k != "time" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	if len(keys) > maxAttrs {
		keys = keys[:maxAttrs]
	}
	attrs := make([]attribute.KeyValue, 0, len(keys))
	for _, k := range keys {
		switch v := fields[k].(type) {
		case string:
			attrs = append(attrs, attribute.String(k, trim(v)))
		case bool:
			attrs = append(attrs, attribute.Bool(k, v))
		case json.Number:
			if i, err := v.Int64(); err == nil {
				attrs = append(attrs, attribute.Int64(k, i))
			} else if f, err := v.Float64(); err == nil {
				attrs = append(attrs, attribute.Float64(k, f))
			}
		case nil:
		default:
			if b, err := json.Marshal(v); err == nil {
				attrs = append(attrs, attribute.String(k, trim(string(b))))
			}
		}
	}
	rec.AddAttributes(attrs...)
	w.logger.Emit(context.Background(), rec)
}

func trim(s string) string {
	if len(s) > maxAttrText {
		return s[:maxAttrText]
	}
	return s
}
