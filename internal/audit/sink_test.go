package audit_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/engineersmind/emc-auth-server/internal/audit"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// recordingSink captures the batches it is handed, deep-copying each one. The
// copy is the point: the writer reuses its backing array, so a sink that keeps
// the slice sees it change underneath. Every real sink must copy, and this
// stand-in does the same so the assertions describe what a correct sink sees.
type recordingSink struct {
	mu      sync.Mutex
	batches [][]audit.Event
}

func (s *recordingSink) Emit(events []audit.Event) {
	cp := make([]audit.Event, len(events))
	copy(cp, events)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.batches = append(s.batches, cp)
}

// Close is a no-op here. The Logger never closes its sinks — main.go owns their
// lifecycle via defer — so there is nothing for a stand-in to record.
func (s *recordingSink) Close() {}

func (s *recordingSink) events() []audit.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	var all []audit.Event
	for _, b := range s.batches {
		all = append(all, b...)
	}
	return all
}

// TestWithSink_FansOutToEverySink is the point of the change: WithSink used to
// hold ONE sink and silently overwrite on a second call, so registering a
// notification sink alongside the SIEM stream would have disabled the SIEM
// stream with no error anywhere.
func TestWithSink_FansOutToEverySink(t *testing.T) {
	pool := testhelper.NewTestDB(t)
	action := uniqueAction(t)
	cleanupRows(t, pool, action)

	first, second := &recordingSink{}, &recordingSink{}
	l := audit.New(pool, testhelper.TestLogger(),
		audit.WithFlushInterval(50*time.Millisecond),
		audit.WithSink(first),
		audit.WithSink(second),
	)

	l.Log(context.Background(), audit.Event{
		ActorEmail: "fanout@example.com",
		Action:     action,
	})

	closeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := l.Close(closeCtx); err != nil {
		t.Fatalf("Close: %v", err)
	}

	for name, s := range map[string]*recordingSink{"first": first, "second": second} {
		got := s.events()
		if len(got) != 1 {
			t.Fatalf("%s sink received %d events, want 1", name, len(got))
		}
		if got[0].Action != action {
			t.Errorf("%s sink got action %q, want %q", name, got[0].Action, action)
		}
	}
}

// A nil sink must not be stored: the writer's "any sinks?" check would become
// always-true and every batch would pay for a fan-out to nothing.
func TestWithSink_IgnoresNil(t *testing.T) {
	pool := testhelper.NewTestDB(t)
	action := uniqueAction(t)
	cleanupRows(t, pool, action)

	l := audit.New(pool, testhelper.TestLogger(),
		audit.WithFlushInterval(50*time.Millisecond),
		audit.WithSink(nil),
	)
	l.Log(context.Background(), audit.Event{ActorEmail: "nil-sink@example.com", Action: action})

	closeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := l.Close(closeCtx); err != nil {
		t.Fatalf("Close with a nil sink: %v", err)
	}
	// The event still persists — a nil sink disables streaming, not auditing.
	if n := countRows(t, pool, action); n != 1 {
		t.Errorf("rows = %d, want 1", n)
	}
}

// TestSink_OnlySeesPersistedBatches documents the ordering guarantee sinks rely
// on: Emit happens after a successful COPY, so a sink can never report an event
// that is not in the table.
func TestSink_OnlySeesPersistedBatches(t *testing.T) {
	pool := testhelper.NewTestDB(t)
	action := uniqueAction(t)
	cleanupRows(t, pool, action)

	sink := &recordingSink{}
	l := audit.New(pool, testhelper.TestLogger(),
		audit.WithFlushInterval(50*time.Millisecond),
		audit.WithSink(sink),
	)
	l.Log(context.Background(), audit.Event{ActorEmail: "persisted@example.com", Action: action})

	closeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := l.Close(closeCtx); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if got := len(sink.events()); got != countRows(t, pool, action) {
		t.Errorf("sink saw %d events but %d rows were written", got, countRows(t, pool, action))
	}
}
