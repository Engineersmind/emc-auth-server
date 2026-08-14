package admin_test

import (
	"context"
	"errors"
	"testing"

	"github.com/engineersmind/emc-auth-server/internal/admin"
	"github.com/engineersmind/emc-auth-server/internal/auth"
)

func intPtr(v int) *int    { return &v }
func boolPtr(v bool) *bool { return &v }

// The platform default seeded by migration 00067 and the compiled-in
// DefaultSessionPolicy are two copies of the same numbers, and the Go copy is what
// runs when the policy table cannot be read. If they drift, a database outage
// silently changes every tenant's session lifetimes instead of preserving them —
// the one situation where the fallback most needs to be a no-op.
func TestSessionPolicy_SeededDefaultMatchesCompiledDefault(t *testing.T) {
	f := newAdminFixture(t)

	got, err := f.svc.GetSessionPolicy(context.Background(), f.tenantID, nil)
	if err != nil {
		t.Fatalf("GetSessionPolicy() error = %v", err)
	}
	if got.Scope != "platform" || !got.Inherited {
		t.Errorf("scope = %q inherited = %v, want platform/true for a tenant with no policy", got.Scope, got.Inherited)
	}

	want := auth.DefaultSessionPolicy
	if got.IdleTTLSeconds != int(want.IdleTTL.Seconds()) {
		t.Errorf("seeded idle_ttl = %d, compiled default = %d", got.IdleTTLSeconds, int(want.IdleTTL.Seconds()))
	}
	if got.NonPersistentIdleTTLSeconds != int(want.NonPersistentIdleTTL.Seconds()) {
		t.Errorf("seeded non_persistent_idle_ttl = %d, compiled default = %d",
			got.NonPersistentIdleTTLSeconds, int(want.NonPersistentIdleTTL.Seconds()))
	}
	if got.AbsoluteTTLSeconds != int(want.AbsoluteTTL.Seconds()) {
		t.Errorf("seeded absolute_ttl = %d, compiled default = %d", got.AbsoluteTTLSeconds, int(want.AbsoluteTTL.Seconds()))
	}
	if got.MaxConcurrentSessions != want.MaxConcurrentSessions {
		t.Errorf("seeded max_sessions = %d, compiled default = %d", got.MaxConcurrentSessions, want.MaxConcurrentSessions)
	}
	if got.AllowPersistent != want.AllowPersistent {
		t.Errorf("seeded allow_persistent = %v, compiled default = %v", got.AllowPersistent, want.AllowPersistent)
	}
}

// A partial update must inherit the fields it does not mention from what was
// actually in force. Overwriting them with compiled-in defaults instead would mean
// changing a tenant's idle timeout silently reset their session cap — a change the
// operator never requested and cannot see in their own request body.
func TestSessionPolicy_PartialUpdatePreservesOtherFields(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	if _, err := f.svc.SetSessionPolicy(ctx, f.tenantID, nil, admin.SessionPolicyInput{
		MaxConcurrentSessions: intPtr(3),
		AllowPersistent:       boolPtr(false),
	}); err != nil {
		t.Fatalf("SetSessionPolicy(first) error = %v", err)
	}

	got, err := f.svc.SetSessionPolicy(ctx, f.tenantID, nil, admin.SessionPolicyInput{
		IdleTTLSeconds: intPtr(3600),
	})
	if err != nil {
		t.Fatalf("SetSessionPolicy(second) error = %v", err)
	}

	if got.IdleTTLSeconds != 3600 {
		t.Errorf("idle_ttl = %d, want 3600", got.IdleTTLSeconds)
	}
	if got.MaxConcurrentSessions != 3 {
		t.Errorf("max_sessions = %d, want 3 preserved from the earlier update", got.MaxConcurrentSessions)
	}
	if got.AllowPersistent {
		t.Error("allow_persistent = true, want false preserved from the earlier update")
	}
	if got.Scope != "tenant" || got.Inherited {
		t.Errorf("scope = %q inherited = %v, want tenant/false", got.Scope, got.Inherited)
	}
}

// An idle clock longer than the absolute cap can never fire, which quietly
// restores the unbounded-session behaviour the idle clock exists to prevent. It
// must be refused rather than clamped.
func TestSessionPolicy_RejectsIdleBeyondAbsolute(t *testing.T) {
	f := newAdminFixture(t)

	_, err := f.svc.SetSessionPolicy(context.Background(), f.tenantID, nil, admin.SessionPolicyInput{
		IdleTTLSeconds:     intPtr(7200),
		AbsoluteTTLSeconds: intPtr(3600),
	})
	if !errors.Is(err, admin.ErrInvalidSessionPolicy) {
		t.Fatalf("SetSessionPolicy(idle > absolute) error = %v, want ErrInvalidSessionPolicy", err)
	}
}

func TestSessionPolicy_RejectsOutOfRangeValues(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	cases := map[string]admin.SessionPolicyInput{
		"idle below floor":   {IdleTTLSeconds: intPtr(1)},
		"idle above cap":     {IdleTTLSeconds: intPtr(100 * 24 * 3600)},
		"absolute too low":   {AbsoluteTTLSeconds: intPtr(10)},
		"zero session cap":   {MaxConcurrentSessions: intPtr(0)},
		"absurd session cap": {MaxConcurrentSessions: intPtr(10_000)},
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := f.svc.SetSessionPolicy(ctx, f.tenantID, nil, in); !errors.Is(err, admin.ErrInvalidSessionPolicy) {
				t.Fatalf("error = %v, want ErrInvalidSessionPolicy", err)
			}
		})
	}
}

// Resolution is most-specific-wins: an application policy must override its
// tenant's, and deleting it must fall back rather than revert to platform defaults.
func TestSessionPolicy_ApplicationOverridesTenantAndFallsBack(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	if _, err := f.svc.SetSessionPolicy(ctx, f.tenantID, nil, admin.SessionPolicyInput{
		IdleTTLSeconds: intPtr(3600),
	}); err != nil {
		t.Fatalf("SetSessionPolicy(tenant) error = %v", err)
	}
	if _, err := f.svc.SetSessionPolicy(ctx, f.tenantID, &f.appID, admin.SessionPolicyInput{
		IdleTTLSeconds: intPtr(600),
	}); err != nil {
		t.Fatalf("SetSessionPolicy(app) error = %v", err)
	}

	appPolicy, err := f.svc.GetSessionPolicy(ctx, f.tenantID, &f.appID)
	if err != nil {
		t.Fatalf("GetSessionPolicy(app) error = %v", err)
	}
	if appPolicy.IdleTTLSeconds != 600 || appPolicy.Scope != "application" {
		t.Errorf("app policy idle = %d scope = %q, want 600/application", appPolicy.IdleTTLSeconds, appPolicy.Scope)
	}

	tenantPolicy, err := f.svc.GetSessionPolicy(ctx, f.tenantID, nil)
	if err != nil {
		t.Fatalf("GetSessionPolicy(tenant) error = %v", err)
	}
	if tenantPolicy.IdleTTLSeconds != 3600 {
		t.Errorf("tenant policy idle = %d, want 3600 — the app policy must not leak upward", tenantPolicy.IdleTTLSeconds)
	}

	if err := f.svc.DeleteSessionPolicy(ctx, f.tenantID, &f.appID); err != nil {
		t.Fatalf("DeleteSessionPolicy(app) error = %v", err)
	}
	after, err := f.svc.GetSessionPolicy(ctx, f.tenantID, &f.appID)
	if err != nil {
		t.Fatalf("GetSessionPolicy(app, after delete) error = %v", err)
	}
	if after.IdleTTLSeconds != 3600 || after.Scope != "tenant" || !after.Inherited {
		t.Errorf("after delete: idle = %d scope = %q inherited = %v, want 3600/tenant/true",
			after.IdleTTLSeconds, after.Scope, after.Inherited)
	}
}

func TestSessionPolicy_DeleteWithoutOverrideIsNotFound(t *testing.T) {
	f := newAdminFixture(t)

	if err := f.svc.DeleteSessionPolicy(context.Background(), f.tenantID, nil); !errors.Is(err, admin.ErrNotFound) {
		t.Fatalf("DeleteSessionPolicy(no override) error = %v, want ErrNotFound", err)
	}
}
