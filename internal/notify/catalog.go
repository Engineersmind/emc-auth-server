// Package notify turns persisted audit events into emails to the administrators
// responsible for what changed: everyone who administers the application or
// tenant an action touched.
//
// It plugs in as an audit.Sink, so it only ever sees events that were durably
// written — a notification can never describe something that did not happen.
package notify

import "github.com/engineersmind/emc-auth-server/internal/audit"

// scope says whose administrators hear about an action.
type scope int

const (
	// scopeApplication reaches everyone who administers the event's
	// application: the tenant's owners, who administer every application, and
	// the co-owners granted that one.
	scopeApplication scope = iota + 1
	// scopeTenant reaches every administrator of the tenant, owners and
	// co-owners alike.
	scopeTenant
)

// notable is one catalogued action: how the email phrases it, and who hears.
type notable struct {
	phrase string
	scope  scope
}

// notableActions lists the actions that raise an email.
//
// Absence is the default: an action not listed here produces no notification.
// That is deliberate — a catalogue that opts out would quietly start emailing
// about every new action anyone adds, and the channel is only useful while
// everything in it is worth reading.
//
// Deliberately two entries. Each is a change every administrator of the
// affected scope must know about at once: a rotated secret breaks every
// integration still holding the old one, and a deactivated tenant stops all of
// its sign-ins. Everything else an administrator does — applications, roles,
// permissions, MFA policy, administrator grants — was catalogued once and
// withdrawn as noise. It remains in the audit log and in Monitoring.
//
// The actor is not special-cased. They are an administrator of the scope, so
// they receive the same email, which is how a stolen session is discovered.
var notableActions = map[string]notable{
	audit.ActionAdminApplicationSecretRotated: {phrase: "rotated a client secret", scope: scopeApplication},
	audit.ActionAdminTenantDeactivated:        {phrase: "deactivated the tenant", scope: scopeTenant},
}

// Notifications are sent only for actions that SUCCEEDED.
//
// Failure volume is bounded by nothing: it is chosen by whoever is probing, and
// the per-recipient hourly cap would then fill with near-identical emails, which
// is how a channel gets filtered to junk — losing the successful-action notices
// that share it. Refusals are still audited (audit.ActionAdminAccessDenied) and
// queryable in Monitoring; only the email is withheld.

// lookup returns the catalogue entry for an action, and whether it is notable
// at all.
//
// Events this package itself emits are never notable, whatever the catalogue
// says: they are audited, so they come straight back through the sink, and a
// notification about a notification is an infinite loop. The map does not
// contain them today; this guard is what keeps that true after someone adds an
// entry without thinking about the cycle.
func lookup(action string) (notable, bool) {
	if isNotificationAction(action) {
		return notable{}, false
	}
	n, ok := notableActions[action]
	return n, ok
}

func isNotificationAction(action string) bool {
	const prefix = "notification."
	return len(action) >= len(prefix) && action[:len(prefix)] == prefix
}
