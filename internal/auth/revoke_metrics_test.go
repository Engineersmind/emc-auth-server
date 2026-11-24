package auth_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/metrics"
)

// No-DB tests for post-commit revocation counting (#226).
//
// fakeTx pretends both UPDATEs inside RevokeAllSessionsTx touched 3 rows; a
// real pgx.Tx is embedded so only Exec needs an implementation.
type fakeTx struct {
	pgx.Tx
}

func (fakeTx) Exec(_ context.Context, _ string, _ ...any) (pgconn.CommandTag, error) {
	return pgconn.NewCommandTag("UPDATE 3"), nil
}

// Counting inside the caller's transaction is wrong: a rollback undoes the
// revocation but not the count. The fake transaction can never commit or roll
// back, so anything the counters moved during the call was moved early.
func TestRevokeAllSessionsTx_DoesNotCountBeforeCommit(t *testing.T) {
	const reason = "unit_test_revoke_before_commit"
	sBefore := testutil.ToFloat64(metrics.SessionRevocations.WithLabelValues(reason))
	tBefore := testutil.ToFloat64(metrics.TokensRevoked.WithLabelValues(reason))

	n, err := auth.RevokeAllSessionsTx(context.Background(), fakeTx{}, 1, 1, reason)
	if err != nil {
		t.Fatalf("RevokeAllSessionsTx: %v", err)
	}
	if n != 3 {
		t.Fatalf("RevokeAllSessionsTx n = %d, want 3", n)
	}

	if d := testutil.ToFloat64(metrics.SessionRevocations.WithLabelValues(reason)) - sBefore; d != 0 {
		t.Errorf("session_revocations{%s} delta = %v, want 0 — counted before commit", reason, d)
	}
	if d := testutil.ToFloat64(metrics.TokensRevoked.WithLabelValues(reason)) - tBefore; d != 0 {
		t.Errorf("tokens_revoked{%s} delta = %v, want 0 — counted before commit", reason, d)
	}
}

func TestRecordSessionRevocations(t *testing.T) {
	const reason = "unit_test_record_revocations"
	sBefore := testutil.ToFloat64(metrics.SessionRevocations.WithLabelValues(reason))
	tBefore := testutil.ToFloat64(metrics.TokensRevoked.WithLabelValues(reason))

	auth.RecordSessionRevocations(reason, 2)

	if d := testutil.ToFloat64(metrics.SessionRevocations.WithLabelValues(reason)) - sBefore; d != 2 {
		t.Errorf("session_revocations{%s} delta = %v, want 2", reason, d)
	}
	if d := testutil.ToFloat64(metrics.TokensRevoked.WithLabelValues(reason)) - tBefore; d != 2 {
		t.Errorf("tokens_revoked{%s} delta = %v, want 2", reason, d)
	}

	// n <= 0 must not create a zero-valued series.
	sBefore = testutil.ToFloat64(metrics.SessionRevocations.WithLabelValues(reason))
	tBefore = testutil.ToFloat64(metrics.TokensRevoked.WithLabelValues(reason))
	auth.RecordSessionRevocations(reason, 0)
	if d := testutil.ToFloat64(metrics.SessionRevocations.WithLabelValues(reason)) - sBefore; d != 0 {
		t.Errorf("session_revocations{%s} delta after n=0 = %v, want 0", reason, d)
	}
	if d := testutil.ToFloat64(metrics.TokensRevoked.WithLabelValues(reason)) - tBefore; d != 0 {
		t.Errorf("tokens_revoked{%s} delta after n=0 = %v, want 0", reason, d)
	}
}
