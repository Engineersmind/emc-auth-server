package auth

import (
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/engineersmind/emc-auth-server/internal/metrics"
)

// Unit tests for the loginAttempt classification rule (#226). The op label is
// test-only so the counts never alias a real login method's series.

func TestLoginAttempt_Record(t *testing.T) {
	const op = "login_unit_test"
	cases := []struct {
		name                 string
		notAttempt, verified bool
		err                  error
		wantSuccess          float64
		wantFailure          float64
	}{
		{"not counted before any comparison", true, false, errors.New("refused before a check"), 0, 0},
		{"not counted even on success return", true, false, nil, 0, 0},
		{"verified credential then a later refusal", false, true, errors.New("role refused"), 1, 0},
		{"verified credential clean return", false, true, nil, 1, 0},
		{"unmarked error is a failure", false, false, errors.New("wrong password"), 0, 1},
		{"nil error is a success", false, false, nil, 1, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sBefore := testutil.ToFloat64(metrics.AuthOperations.WithLabelValues(op, "success"))
			fBefore := testutil.ToFloat64(metrics.AuthOperations.WithLabelValues(op, "failure"))

			att := &loginAttempt{op: op, notAttempt: tc.notAttempt, verified: tc.verified}
			att.record(tc.err)

			if d := testutil.ToFloat64(metrics.AuthOperations.WithLabelValues(op, "success")) - sBefore; d != tc.wantSuccess {
				t.Errorf("success delta = %v, want %v", d, tc.wantSuccess)
			}
			if d := testutil.ToFloat64(metrics.AuthOperations.WithLabelValues(op, "failure")) - fBefore; d != tc.wantFailure {
				t.Errorf("failure delta = %v, want %v", d, tc.wantFailure)
			}
		})
	}
}
