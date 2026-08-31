package admin

import "testing"

// TestMomPct covers the month-over-month percentage helper, including the case
// that motivated rounding it: 12 against a prior 11 produced
// 109.09090909090908, which the dashboard rendered in full.
func TestMomPct(t *testing.T) {
	cases := []struct {
		name           string
		current, prior int
		want           int
	}{
		// 23 users this month against 11 last month: 109.0909…% growth, the value
		// the dashboard rendered in full.
		{"the repeating decimal that started this", 23, 11, 109},
		{"no prior baseline, growth from zero", 5, 0, 100},
		{"no prior baseline, still zero", 0, 0, 0},
		{"flat", 10, 10, 0},
		{"doubled", 20, 10, 100},
		{"halved", 5, 10, -50},
		{"down to zero", 0, 10, -100},
		{"rounds up at .5", 11, 8, 38},           // 37.5 -> 38
		{"rounds down below .5", 4, 3, 33},       // 33.33 -> 33
		{"thirds round consistently", 2, 3, -33}, // -33.33 -> -33
		{"large growth", 500, 4, 12400},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := momPct(c.current, c.prior); got != c.want {
				t.Fatalf("momPct(%d, %d) = %d, want %d", c.current, c.prior, got, c.want)
			}
		})
	}
}

// TestMomPct_NeverProducesFractionalOutput is the regression guard. The bug was
// not a wrong number — it was a correct number carrying sixteen digits of
// precision that the underlying counts do not support. Changing the return type
// back to a float would reintroduce it silently, so the type itself is asserted.
func TestMomPct_NeverProducesFractionalOutput(t *testing.T) {
	var got any = momPct(12, 11)
	if _, ok := got.(int); !ok {
		t.Fatalf("momPct returned %T, want int — a float reintroduces the "+
			"109.09090909090908 rendering bug in every consumer", got)
	}
}
