package notify

import (
	"testing"

	"github.com/engineersmind/emc-auth-server/internal/audit"
)

// The catalogue is opt-in: an action nobody listed produces no email. A
// catalogue that opted OUT would quietly start notifying about every action
// anyone adds later, and the channel is only worth reading while everything in
// it was chosen.
func TestLabel_UncataloguedActionIsNotNotable(t *testing.T) {
	for _, action := range []string{
		audit.ActionAuthLogin,
		audit.ActionAuthTokenRefresh,
		"admin.some_action_added_next_year",
		"",
	} {
		if _, ok := label(action); ok {
			t.Errorf("action %q is notable; only catalogued actions should be", action)
		}
	}
}

// The sink audits its own deliveries, and those audit rows come straight back
// through it. Without this guard, one notification would beget another forever.
func TestLabel_NeverNotifiesAboutItsOwnNotifications(t *testing.T) {
	for _, action := range []string{
		audit.ActionNotificationSent,
		audit.ActionNotificationSuppressed,
		"notification.anything_added_later",
	} {
		if _, ok := label(action); ok {
			t.Errorf("action %q is notable — this is a notification feedback loop", action)
		}
	}

	// The guard must hold even if someone adds a notification action to the
	// catalogue without thinking about the cycle, which is the realistic way
	// this breaks.
	notableActions[audit.ActionNotificationSent] = "sent a notification"
	defer delete(notableActions, audit.ActionNotificationSent)
	if _, ok := label(audit.ActionNotificationSent); ok {
		t.Error("a catalogued notification.* action slipped through the loop guard")
	}
}

func TestLabel_CataloguedActionsHavePhrasing(t *testing.T) {
	if _, ok := label(audit.ActionAdminApplicationSecretRotated); !ok {
		t.Fatal("secret rotation must be notable — it is the worked example")
	}
	phrase, _ := label(audit.ActionAdminApplicationSecretRotated)
	if phrase == "" {
		t.Error("notable action has empty phrasing; the subject line would read blank")
	}
	for action, p := range notableActions {
		if p == "" {
			t.Errorf("action %q has empty phrasing", action)
		}
	}
}

// Everything the actor is told about must itself be notable, or the sensitive
// list would name actions that never produce an email at all.
func TestSelfNotify_IsASubsetOfTheCatalogue(t *testing.T) {
	for action := range selfNotify {
		if _, ok := notableActions[action]; !ok {
			t.Errorf("action %q is in selfNotify but is not catalogued, so nothing is ever sent", action)
		}
	}
}
