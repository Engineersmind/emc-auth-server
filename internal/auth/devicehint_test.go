package auth_test

import (
	"testing"

	"github.com/engineersmind/emc-auth-server/internal/auth"
)

func TestDeviceHint(t *testing.T) {
	cases := map[string]struct{ ua, want string }{
		// The case that prompted this. Node's built-in fetch (undici) sends exactly
		// "node" — no version, no product — so the generic fallback rendered a bare
		// "node" in the session list, which told an operator nothing.
		"node fetch": {"node", "Node.js client"},
		"undici":     {"undici", "Node.js client"},
		"axios":      {"axios/1.7.2", "Node.js client (axios)"},
		"python":     {"python-requests/2.31.0", "Python client"},
		"go":         {"Go-http-client/2.0", "Go client"},
		"postman":    {"PostmanRuntime/7.37.0", "Postman"},

		// iOS before macOS, and the order is load-bearing: every iPhone User-Agent
		// contains the literal "like Mac OS X", so a macOS test placed first labels
		// every phone as a Mac.
		"iphone": {
			"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Version/17.0 Mobile/15E148 Safari/604.1",
			"Safari on iOS",
		},
		"real mac": {
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			"Chrome on macOS",
		},
		// Edge and Chrome both carry "Chrome/" and "Safari/", so ordering decides
		// these too.
		"edge": {
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36 Edg/120.0",
			"Edge on Windows",
		},
		"chrome windows": {
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			"Chrome on Windows",
		},
		"firefox linux": {
			"Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
			"Firefox on Linux",
		},
		"android": {
			"Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/120.0.0.0 Mobile Safari/537.36",
			"Chrome on Android",
		},

		// No header at all: what every session row showed before the server began
		// recording one.
		"empty": {"", ""},
		// Unrecognised clients keep a truncated slice of the real string, which is
		// still more use for telling two sessions apart than the word "Unknown".
		"unknown short": {"SomeBespokeClient/2.1", "SomeBespokeClient/2.1"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := auth.DeviceHint(tc.ua); got != tc.want {
				t.Errorf("DeviceHint(%q) = %q, want %q", tc.ua, got, tc.want)
			}
		})
	}
}

// A very long unrecognised agent must be truncated rather than stored whole in a
// label meant to fit one line.
func TestDeviceHint_TruncatesLongUnknownAgent(t *testing.T) {
	long := "ThisIsAVeryLongCustomUserAgentStringThatKeepsGoingWellPastAnythingUseful/9.9"
	got := auth.DeviceHint(long)
	if len(got) != 32 {
		t.Errorf("DeviceHint(long) length = %d, want 32", len(got))
	}
	if got != long[:32] {
		t.Errorf("DeviceHint(long) = %q, want the first 32 characters", got)
	}
}
