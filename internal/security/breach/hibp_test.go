package breach

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

func testLogger() zerolog.Logger { return zerolog.Nop() }

// TestCount_MatchesSuffixAndSendsOnlyPrefix is the core k-anonymity guarantee:
// the request carries a 5-character hash prefix and nothing else, and the match
// is made locally against the returned suffixes.
func TestCount_MatchesSuffixAndSendsOnlyPrefix(t *testing.T) {
	const password = "Password123!"
	suffix := HashSuffixForTest(password)

	var gotPath, gotPadding string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotPadding = r.Header.Get("Add-Padding")
		_, _ = w.Write([]byte("0000000000000000000000000000000000A:7\r\n" + suffix + ":4242\r\n"))
	}))
	defer srv.Close()

	c := NewForTest(srv.URL+"/", testLogger())
	if got := c.Count(context.Background(), password); got != 4242 {
		t.Errorf("Count = %d, want 4242", got)
	}

	prefix := strings.TrimPrefix(gotPath, "/")
	if len(prefix) != 5 {
		t.Errorf("requested path %q carries %d characters, want exactly the 5-char prefix", gotPath, len(prefix))
	}
	if strings.Contains(suffix, prefix) && len(prefix) != 5 {
		t.Error("request leaked more than the prefix")
	}
	// The full hash must never appear in the request.
	if strings.Contains(gotPath, suffix) {
		t.Errorf("request path %q contains the hash suffix — k-anonymity broken", gotPath)
	}
	if gotPadding != "true" {
		t.Errorf("Add-Padding header = %q, want \"true\" so response size reveals nothing", gotPadding)
	}
}

// TestCount_MissAndPaddingAreZero proves an absent password and a padding entry
// (count 0) both read as not-breached.
func TestCount_MissAndPaddingAreZero(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("0000000000000000000000000000000000A:5\r\n" +
			HashSuffixForTest("padded-entry") + ":0\r\n"))
	}))
	defer srv.Close()

	c := NewForTest(srv.URL+"/", testLogger())
	if got := c.Count(context.Background(), "SomeOtherPassphrase!7"); got != 0 {
		t.Errorf("Count(miss) = %d, want 0", got)
	}
	if got := c.Count(context.Background(), "padded-entry"); got != 0 {
		t.Errorf("Count(padding entry) = %d, want 0", got)
	}
}

// TestCount_FailsOpen proves every failure mode is treated as not-breached: the
// check is advisory and must never block or delay authentication.
func TestCount_FailsOpen(t *testing.T) {
	ctx := context.Background()

	if got := (*Checker)(nil).Count(ctx, "anything"); got != 0 {
		t.Errorf("nil checker Count = %d, want 0", got)
	}
	if got := NewForTest("http://127.0.0.1:1/", testLogger()).Count(ctx, "anything"); got != 0 {
		t.Errorf("unreachable API Count = %d, want 0", got)
	}
	if got := New(false, testLogger()).Count(ctx, "anything"); got != 0 {
		t.Errorf("disabled checker Count = %d, want 0", got)
	}

	errSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer errSrv.Close()
	if got := NewForTest(errSrv.URL+"/", testLogger()).Count(ctx, "anything"); got != 0 {
		t.Errorf("429 response Count = %d, want 0", got)
	}

	garbage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(HashSuffixForTest("garbage-count") + ":not-a-number\r\n"))
	}))
	defer garbage.Close()
	if got := NewForTest(garbage.URL+"/", testLogger()).Count(ctx, "garbage-count"); got != 0 {
		t.Errorf("unparseable count = %d, want 0", got)
	}
}

// TestNew_DisabledIsNil proves the feature flag yields a nil (no-op) checker.
func TestNew_DisabledIsNil(t *testing.T) {
	if New(false, testLogger()) != nil {
		t.Error("New(false) should return nil so callers skip the check entirely")
	}
	if New(true, testLogger()) == nil {
		t.Error("New(true) should return a usable checker")
	}
	if c := New(true, testLogger()); c.endpoint != rangeEndpoint {
		t.Errorf("production endpoint = %q, want the pinned %q", c.endpoint, rangeEndpoint)
	}
}

// TestDescribe covers the audit/log rendering of a count.
func TestDescribe(t *testing.T) {
	if got := Describe(0); !strings.Contains(got, "not found") {
		t.Errorf("Describe(0) = %q", got)
	}
	if got := Describe(3); !strings.Contains(got, "3") {
		t.Errorf("Describe(3) = %q", got)
	}
}
