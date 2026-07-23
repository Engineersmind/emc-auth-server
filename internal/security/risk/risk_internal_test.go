package risk

import (
	"math"
	"testing"

	"github.com/rs/zerolog"
)

func TestHaversineKM(t *testing.T) {
	// Bengaluru → Moscow is ~5,600 km. Allow a wide tolerance.
	d := haversineKM(12.9719, 77.5937, 55.7558, 37.6173)
	if d < 5000 || d > 6200 {
		t.Errorf("Bengaluru→Moscow = %.0f km, want ~5600", d)
	}
	// Same point → ~0.
	if d0 := haversineKM(12.97, 77.59, 12.97, 77.59); math.Abs(d0) > 0.001 {
		t.Errorf("same point = %.4f km, want 0", d0)
	}
}

func TestScore(t *testing.T) {
	tests := []struct {
		newDevice, impossible, untrusted bool
		want                             string
	}{
		{false, false, false, "low"},
		{true, false, false, "medium"},
		{false, true, false, "high"},
		{false, false, true, "high"},
		{true, true, true, "high"},
	}
	for _, tt := range tests {
		if got := score(tt.newDevice, tt.impossible, tt.untrusted); got != tt.want {
			t.Errorf("score(%v,%v,%v) = %q, want %q",
				tt.newDevice, tt.impossible, tt.untrusted, got, tt.want)
		}
	}
}

func TestUntrustedIP(t *testing.T) {
	a := New(nil, []string{"203.0.113.0/24", "bad-cidr-ignored"}, zerolog.Nop())
	if !a.isUntrustedIP("203.0.113.42") {
		t.Error("203.0.113.42 should be flagged (in denylist CIDR)")
	}
	if a.isUntrustedIP("8.8.8.8") {
		t.Error("8.8.8.8 should not be flagged")
	}
	if a.isUntrustedIP("not-an-ip") {
		t.Error("invalid IP should not be flagged")
	}
}
