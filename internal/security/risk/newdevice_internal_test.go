package risk

import (
	"context"
	"testing"

	"github.com/engineersmind/emc-auth-server/internal/audit"
	"github.com/engineersmind/emc-auth-server/internal/store"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// The new-device signal is a comparison against a baseline, so it must stay silent
// until there is one.
//
// It previously fired on every account's FIRST login — necessarily, since a first
// login is always from an unseen device. That told the owner their own sign-up looked
// suspicious, recorded a risk event on every new account, and made the signal
// worthless: one that fires 100% of the time teaches operators to ignore the ones
// that matter.
func TestIsNewDevice_SilentWithoutABaseline(t *testing.T) {
	pool := testhelper.NewTestDB(t)
	testhelper.CleanupTables(t, pool)
	logger := testhelper.TestLogger()
	ctx := context.Background()

	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}

	var tenantID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM tenants WHERE slug = 'emc'`).Scan(&tenantID); err != nil {
		t.Fatalf("tenant id: %v", err)
	}
	var userID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO users (tenant_id, email, first_name, last_name, is_active)
		VALUES ($1, 'newdevice@example.com', 'New', 'Device', true) RETURNING id
	`, tenantID).Scan(&userID); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	a := New(pool, nil, logger)
	const chrome = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	const firefox = "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0"

	in := audit.RiskInput{
		UserID:    &userID,
		TenantID:  &tenantID,
		Action:    audit.ActionAuthLogin,
		UserAgent: chrome,
	}

	// No login history at all — the first sign-in.
	if a.isNewDevice(ctx, in) {
		t.Error("first login flagged as a new device; there is no baseline to deviate from")
	}

	// Record that first login, establishing the baseline.
	if _, err := pool.Exec(ctx, `
		INSERT INTO audit_logs (tenant_id, user_id, action, status, user_agent, created_at)
		VALUES ($1, $2, $3, 'success', $4, NOW())
	`, tenantID, userID, audit.ActionAuthLogin, chrome); err != nil {
		t.Fatalf("seed login history: %v", err)
	}

	// The same device again is not new.
	if a.isNewDevice(ctx, in) {
		t.Error("a repeat login from the same device family was flagged as new")
	}

	// A different device family now IS a deviation, which is the whole point of the
	// signal — the fix must not have silenced it outright.
	other := in
	other.UserAgent = firefox
	if !a.isNewDevice(ctx, other) {
		t.Error("a genuinely unseen device was not flagged once a baseline existed")
	}
}

// A first LOGIN is not a first APPEARANCE. Registration, an accepted invitation
// and a social sign-in all prove which device the user was on, so any of them is a
// valid baseline.
//
// Reported from production: a user registered in their browser, signed in from that
// same browser moments later, and was emailed "unusual sign-in detected". The
// baseline query only matched action = 'auth.login', so the auth.register row
// recording that very browser was invisible and the sign-in looked like it came
// from a device the user had never used.
func TestIsNewDevice_RegistrationEstablishesTheBaseline(t *testing.T) {
	pool := testhelper.NewTestDB(t)
	testhelper.CleanupTables(t, pool)
	logger := testhelper.TestLogger()
	ctx := context.Background()

	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}
	var tenantID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM tenants WHERE slug = 'emc'`).Scan(&tenantID); err != nil {
		t.Fatalf("tenant id: %v", err)
	}

	const chrome = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	const firefox = "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0"
	a := New(pool, nil, logger)

	for _, tc := range []struct {
		name   string
		action string
	}{
		{"registration", audit.ActionAuthRegister},
		{"accepted invitation", audit.ActionAuthInvitationAccepted},
		{"social sign-in", audit.ActionAuthGoogleLogin},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var userID int64
			if err := pool.QueryRow(ctx, `
				INSERT INTO users (tenant_id, email, first_name, last_name, is_active)
				VALUES ($1, $2, 'B', 'L', true) RETURNING id
			`, tenantID, tc.name+"-baseline@example.com").Scan(&userID); err != nil {
				t.Fatalf("seed user: %v", err)
			}
			if _, err := pool.Exec(ctx, `
				INSERT INTO audit_logs (tenant_id, user_id, action, status, user_agent, created_at)
				VALUES ($1, $2, $3, 'success', $4, NOW())
			`, tenantID, userID, tc.action, chrome); err != nil {
				t.Fatalf("seed %s history: %v", tc.action, err)
			}

			in := audit.RiskInput{
				UserID: &userID, TenantID: &tenantID,
				Action: audit.ActionAuthLogin, UserAgent: chrome,
			}
			if a.isNewDevice(ctx, in) {
				t.Errorf("signing in from the same browser as the %s was flagged as a new device", tc.name)
			}

			// The signal must still work — this is a baseline, not a blanket silence.
			other := in
			other.UserAgent = firefox
			if !a.isNewDevice(ctx, other) {
				t.Errorf("a different device was not flagged against the %s baseline", tc.name)
			}
		})
	}
}
