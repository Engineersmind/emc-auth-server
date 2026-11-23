package telemetry

import (
	"context"
	"testing"

	"github.com/rs/zerolog"
	otellog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/embedded"
)

// recordingLogger captures every Record Emit is handed so the test can assert
// on the record the hook built — not just that a call happened.
type recordingLogger struct {
	embedded.Logger
	records []otellog.Record
}

func (l *recordingLogger) Emit(_ context.Context, r otellog.Record) {
	l.records = append(l.records, r)
}

func (l *recordingLogger) Enabled(_ context.Context, _ otellog.EnabledParameters) bool {
	return true
}

// why: otel/log v0.21.0 changed Record.SetBody to take attribute.Value and
// dropped otellog.StringValue. Without this test, a wrong body type or a
// silently dropped severity mapping compiles only because it isn't exercised.
func TestOTelHook_Run(t *testing.T) {
	tests := []struct {
		name      string
		level     zerolog.Level
		wantEmit  bool
		wantSev   otellog.Severity
		wantSevTx string
	}{
		{"debug is filtered", zerolog.DebugLevel, false, 0, ""},
		{"info is filtered", zerolog.InfoLevel, false, 0, ""},
		{"warn is filtered", zerolog.WarnLevel, false, 0, ""},
		{"error maps to SeverityError", zerolog.ErrorLevel, true, otellog.SeverityError, "error"},
		{"fatal maps to SeverityFatal", zerolog.FatalLevel, true, otellog.SeverityFatal, "fatal"},
		{"panic maps to SeverityFatal", zerolog.PanicLevel, true, otellog.SeverityFatal, "panic"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			l := &recordingLogger{}
			h := &OTelHook{logger: l}

			h.Run(nil, tc.level, "boom")

			if !tc.wantEmit {
				if len(l.records) != 0 {
					t.Fatalf("expected no emitted record for level %s, got %d", tc.level, len(l.records))
				}
				return
			}

			if len(l.records) != 1 {
				t.Fatalf("expected exactly 1 emitted record, got %d", len(l.records))
			}
			rec := l.records[0]
			if rec.Severity() != tc.wantSev {
				t.Errorf("severity = %v, want %v", rec.Severity(), tc.wantSev)
			}
			if rec.SeverityText() != tc.wantSevTx {
				t.Errorf("severityText = %q, want %q", rec.SeverityText(), tc.wantSevTx)
			}
			if got := rec.Body().AsString(); got != "boom" {
				t.Errorf("body = %q, want %q", got, "boom")
			}
		})
	}
}
