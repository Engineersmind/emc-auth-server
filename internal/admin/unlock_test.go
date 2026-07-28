package admin_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/engineersmind/emc-auth-server/internal/admin"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// fakeResetter records the emails whose failure counters were cleared, standing
// in for *auth.AuthService so the admin package's tests need no Redis.
type fakeResetter struct {
	calls []string
	err   error
}

func (f *fakeResetter) ResetLoginFailures(_ context.Context, email string) error {
	f.calls = append(f.calls, email)
	return f.err
}

// lockUser stamps a brute-force lock directly, standing in for the login path
// having tripped the hard tier.
func lockUser(t *testing.T, f adminFixture, userID int64, until time.Time) {
	t.Helper()
	if _, err := f.pool.Exec(context.Background(), `
		UPDATE users SET locked_until = $1, locked_reason = 'brute_force' WHERE id = $2
	`, until, userID); err != nil {
		t.Fatalf("lock user: %v", err)
	}
}

// TestUnlockUser_ClearsLockAndCounter is the happy path for issue #72's admin
// escape hatch: both halves of the lock — the persisted column and the Redis
// counter — have to go, since either one alone still refuses the login.
func TestUnlockUser_ClearsLockAndCounter(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	resetter := &fakeResetter{}
	svc := admin.New(f.pool, nil, testhelper.TestLogger()).WithLockoutReset(resetter)

	userID := createTestUser(t, f, "unlock-me@example.com")
	lockUser(t, f, userID, time.Now().Add(time.Hour))

	result, err := svc.UnlockUser(ctx, f.tenantID, nil, userID)
	if err != nil {
		t.Fatalf("UnlockUser error = %v", err)
	}
	if result.LockedUntil != nil {
		t.Errorf("LockedUntil = %v after unlock, want nil", result.LockedUntil)
	}

	var until *time.Time
	var reason *string
	if err := f.pool.QueryRow(ctx,
		`SELECT locked_until, locked_reason FROM users WHERE id = $1`, userID).Scan(&until, &reason); err != nil {
		t.Fatalf("read lock state: %v", err)
	}
	if until != nil {
		t.Errorf("locked_until = %v in the database, want NULL", until)
	}
	if reason != nil {
		t.Errorf("locked_reason = %q, want NULL", *reason)
	}

	if len(resetter.calls) != 1 || resetter.calls[0] != "unlock-me@example.com" {
		t.Errorf("failure-counter reset calls = %v, want exactly [unlock-me@example.com] — "+
			"without it the soft lock outlives the unlock", resetter.calls)
	}
}

// TestUnlockUser_DoesNotReinstateBlockedUser is the separation-of-concerns
// guarantee: an account can be both brute-force locked and administratively
// blocked, and lifting the lock must not quietly undo the admin's decision.
func TestUnlockUser_DoesNotReinstateBlockedUser(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	svc := admin.New(f.pool, nil, testhelper.TestLogger()).WithLockoutReset(&fakeResetter{})

	userID := createTestUser(t, f, "blocked-and-locked@example.com")
	if _, err := svc.SetUserActive(ctx, f.tenantID, nil, userID, false); err != nil {
		t.Fatalf("SetUserActive(block): %v", err)
	}
	lockUser(t, f, userID, time.Now().Add(time.Hour))

	result, err := svc.UnlockUser(ctx, f.tenantID, nil, userID)
	if err != nil {
		t.Fatalf("UnlockUser error = %v", err)
	}
	if result.LockedUntil != nil {
		t.Error("lock was not cleared")
	}
	if result.IsActive {
		t.Error("UnlockUser re-activated an administratively blocked user; " +
			"is_active and locked_until are independent states")
	}
}

// TestUnlockUser_Idempotent — the admin UI may fire this against a user whose
// lock has already elapsed; that must succeed rather than 404 or error.
func TestUnlockUser_Idempotent(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()
	svc := admin.New(f.pool, nil, testhelper.TestLogger()).WithLockoutReset(&fakeResetter{})

	userID := createTestUser(t, f, "never-locked@example.com")

	for i := 0; i < 2; i++ {
		result, err := svc.UnlockUser(ctx, f.tenantID, nil, userID)
		if err != nil {
			t.Fatalf("UnlockUser call %d error = %v", i+1, err)
		}
		if result.LockedUntil != nil {
			t.Errorf("call %d: LockedUntil = %v, want nil", i+1, result.LockedUntil)
		}
	}
}

// TestUnlockUser_ElapsedLockReportsAsUnlocked pins the API contract the admin UI
// relies on: LockedUntil is non-nil only while the lock is CURRENTLY in force,
// so the badge needs no clock arithmetic on the client.
func TestUnlockUser_ElapsedLockReportsAsUnlocked(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()
	svc := admin.New(f.pool, nil, testhelper.TestLogger())

	userID := createTestUser(t, f, "lock-elapsed@example.com")
	lockUser(t, f, userID, time.Now().Add(-time.Minute)) // already expired

	users, err := svc.ListUsers(ctx, f.tenantID, nil, "lock-elapsed@example.com", 1, 100)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	found := false
	for _, u := range users.Users {
		if u.Email != "lock-elapsed@example.com" {
			continue
		}
		found = true
		if u.LockedUntil != nil {
			t.Errorf("LockedUntil = %v for an already-elapsed lock, want nil", u.LockedUntil)
		}
	}
	if !found {
		t.Fatalf("user %d not returned by ListUsers", userID)
	}
}

// TestUnlockUser_NotFound mirrors SetUserActive's contract for a missing id.
func TestUnlockUser_NotFound(t *testing.T) {
	f := newAdminFixture(t)
	svc := admin.New(f.pool, nil, testhelper.TestLogger())
	if _, err := svc.UnlockUser(context.Background(), f.tenantID, nil, 999999); !errors.Is(err, admin.ErrNotFound) {
		t.Errorf("UnlockUser(missing id) error = %v, want ErrNotFound", err)
	}
}

// TestUnlockUser_SurvivesCounterResetFailure — a Redis outage must not fail an
// unlock that already succeeded in the database; the soft lock then simply
// expires on its own.
func TestUnlockUser_SurvivesCounterResetFailure(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	resetter := &fakeResetter{err: errors.New("redis down")}
	svc := admin.New(f.pool, nil, testhelper.TestLogger()).WithLockoutReset(resetter)

	userID := createTestUser(t, f, "redis-down@example.com")
	lockUser(t, f, userID, time.Now().Add(time.Hour))

	result, err := svc.UnlockUser(ctx, f.tenantID, nil, userID)
	if err != nil {
		t.Fatalf("UnlockUser error = %v, want nil despite the counter reset failing", err)
	}
	if result.LockedUntil != nil {
		t.Error("persisted lock was not cleared")
	}
}
