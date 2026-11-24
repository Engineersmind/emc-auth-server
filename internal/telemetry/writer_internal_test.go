package telemetry

import (
	"testing"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/attribute"
	otellog "go.opentelemetry.io/otel/log"
)

func attrsOf(r otellog.Record) map[string]attribute.Value {
	m := map[string]attribute.Value{}
	r.WalkAttributes(func(kv attribute.KeyValue) bool { m[string(kv.Key)] = kv.Value; return true })
	return m
}

// why: an issue built from "request" alone is useless; the status, route and error text the
// app logged with it must reach the log record.
func TestOTelWriter_ForwardsFields(t *testing.T) {
	rl := &recordingLogger{}
	w := &OTelWriter{logger: rl}
	line := []byte(`{"level":"error","error":"code=404, message=Not Found","method":"GET","status":404,"latency":0.014,"ok":false,"uri":"/.git/config","message":"request","time":1794981321237}`)

	if _, err := w.WriteLevel(zerolog.ErrorLevel, line); err != nil {
		t.Fatal(err)
	}
	if len(rl.records) != 1 {
		t.Fatalf("want 1 record, got %d", len(rl.records))
	}
	r := rl.records[0]
	if got := r.Body().AsString(); got != "request" {
		t.Errorf("body = %q, want request", got)
	}
	if r.Severity() != otellog.SeverityError {
		t.Errorf("severity = %v", r.Severity())
	}
	a := attrsOf(r)
	if a["uri"].AsString() != "/.git/config" || a["method"].AsString() != "GET" || a["error"].AsString() != "code=404, message=Not Found" {
		t.Errorf("string fields lost: %v", a)
	}
	if a["status"].AsInt64() != 404 {
		t.Errorf("status = %v, want 404 as an int", a["status"])
	}
	if _, ok := a["message"]; ok {
		t.Error("message must be the body, not an attribute")
	}
	if _, ok := a["level"]; ok {
		t.Error("level must not be an attribute")
	}
}

func TestOTelWriter_Levels(t *testing.T) {
	rl := &recordingLogger{}
	w := &OTelWriter{logger: rl}
	for _, lvl := range []zerolog.Level{zerolog.DebugLevel, zerolog.InfoLevel, zerolog.WarnLevel} {
		_, _ = w.WriteLevel(lvl, []byte(`{"message":"x"}`))
	}
	if len(rl.records) != 0 {
		t.Fatalf("below error must not be forwarded, got %d", len(rl.records))
	}
	_, _ = w.WriteLevel(zerolog.FatalLevel, []byte(`{"message":"boom"}`))
	if len(rl.records) != 1 || rl.records[0].Severity() != otellog.SeverityFatal {
		t.Fatalf("fatal must be forwarded as fatal: %+v", rl.records)
	}
}

func TestOTelWriter_NotJSONStillForwarded(t *testing.T) {
	rl := &recordingLogger{}
	w := &OTelWriter{logger: rl}
	_, _ = w.WriteLevel(zerolog.ErrorLevel, []byte("plain text line\n"))
	if len(rl.records) != 1 || rl.records[0].Body().AsString() != "plain text line" {
		t.Fatalf("got %+v", rl.records)
	}
}
