package notify

import (
	"testing"

	"github.com/engineersmind/emc-auth-server/internal/audit"
)

// The catalogue is opt-in: an action nobody listed produces no email. A
// catalogue that opted OUT would quietly start notifying about every action
// anyone adds later, and the channel is only worth reading while everything in
// it was chosen.
func TestLookup_UncataloguedActionIsNotNotable(t *testing.T) {
	for _, action := range []string{
		audit.ActionAuthLogin,
		audit.ActionAuthTokenRefresh,
		audit.ActionAdminApplicationDeleted,
		audit.ActionAdminTenantAdminInvited,
		"admin.some_action_added_next_year",
		"",
	} {
		if _, ok := lookup(action); ok {
			t.Errorf("action %q is notable; only catalogued actions should be", action)
		}
	}
}

// Exactly two actions notify, each to its own scope.
func TestLookup_CatalogueIsSecretRotationAndTenantDeactivation(t *testing.T) {
	if len(notableActions) != 2 {
		t.Errorf("catalogue has %d entries, want 2: %v", len(notableActions), notableActions)
	}
	cases := map[string]scope{
		audit.ActionAdminApplicationSecretRotated: scopeApplication,
		audit.ActionAdminTenantDeactivated:        scopeTenant,
	}
	for action, want := range cases {
		n, ok := lookup(action)
		if !ok {
			t.Errorf("%s is not notable", action)
			continue
		}
		if n.scope != want {
			t.Errorf("%s scope = %d, want %d", action, n.scope, want)
		}
		if n.phrase == "" {
			t.Errorf("%s has empty phrasing; the subject line would read blank", action)
		}
	}
}

// The sink audits its own deliveries, and those audit rows come straight back
// through it. Without this guard, one notification would beget another forever.
func TestLookup_NeverNotifiesAboutItsOwnNotifications(t *testing.T) {
	for _, action := range []string{
		audit.ActionNotificationSent,
		audit.ActionNotificationSuppressed,
		"notification.anything_added_later",
	} {
		if _, ok := lookup(action); ok {
			t.Errorf("action %q is notable — this is a notification feedback loop", action)
		}
	}

	// The guard must hold even if someone adds a notification action to the
	// catalogue without thinking about the cycle, which is the realistic way
	// this breaks.
	notableActions[audit.ActionNotificationSent] = notable{phrase: "sent a notification", scope: scopeTenant}
	defer delete(notableActions, audit.ActionNotificationSent)
	if _, ok := lookup(audit.ActionNotificationSent); ok {
		t.Error("a catalogued notification.* action slipped through the loop guard")
	}
}
