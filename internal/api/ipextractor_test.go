package api_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/engineersmind/emc-auth-server/internal/api"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

func req(remoteAddr, xff string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = remoteAddr
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	return r
}

func TestNewIPExtractor_NoTrustedProxiesIgnoresXFF(t *testing.T) {
	extractor := api.NewIPExtractor(nil, testhelper.TestLogger())

	// A client-controlled XFF must NOT override the connection address —
	// this is what let callers spoof rate-limit and audit IPs.
	got := extractor(req("198.51.100.10:4433", "1.1.1.1"))
	if got != "198.51.100.10" {
		t.Errorf("extracted %q, want connection addr 198.51.100.10", got)
	}
}

func TestNewIPExtractor_TrustedProxyHonoursXFF(t *testing.T) {
	extractor := api.NewIPExtractor([]string{"10.0.0.0/8"}, testhelper.TestLogger())

	// Request arrives from a trusted proxy; the leftmost untrusted XFF
	// entry is the real client.
	got := extractor(req("10.0.0.5:4433", "203.0.113.7"))
	if got != "203.0.113.7" {
		t.Errorf("extracted %q, want 203.0.113.7", got)
	}
}

func TestNewIPExtractor_UntrustedPeerCannotForgeXFF(t *testing.T) {
	extractor := api.NewIPExtractor([]string{"10.0.0.0/8"}, testhelper.TestLogger())

	// Direct connection from an untrusted address: its claimed XFF must be
	// ignored, so it cannot hide behind a forged forwarded chain.
	got := extractor(req("198.51.100.99:4433", "1.1.1.1"))
	if got != "198.51.100.99" {
		t.Errorf("extracted %q, want 198.51.100.99", got)
	}
}

func TestNewIPExtractor_BareIPAndMalformedEntries(t *testing.T) {
	logger := testhelper.TestLogger()
	extractor := api.NewIPExtractor([]string{"not-a-cidr", "10.1.2.3"}, logger)

	got := extractor(req("10.1.2.3:4433", "203.0.113.7"))
	if got != "203.0.113.7" {
		t.Errorf("bare-IP trust: extracted %q, want 203.0.113.7", got)
	}
}
