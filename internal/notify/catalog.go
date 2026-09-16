// Package notify turns persisted audit events into emails to the people
// accountable for them: the tier above the actor (a platform admin for an
// owner's action, the tenant's owners for a co-owner's), and for sensitive
// actions the actor themselves.
//
// It plugs in as an audit.Sink, so it only ever sees events that were durably
// written — a notification can never describe something that did not happen.
package notify

import "github.com/engineersmind/emc-auth-server/internal/audit"

// notableActions maps an audit action to the phrasing used in the email.
//
// Absence is the default: an action not listed here produces no notification.
// That is deliberate — a catalogue that opts out would quietly start emailing
// about every new action anyone adds, and the channel is only useful while
// everything in it is worth reading.
//
// The phrasing lives here rather than in the template because a template
// branching on a dozen action keys becomes unreadable, and adding an action
// would then mean editing the template too.
var notableActions = map[string]string{
	audit.ActionAdminApplicationSecretRotated: "rotated a client secret",
	audit.ActionAdminApplicationDeleted:       "deleted an application",
	audit.ActionAdminApplicationCreated:       "created an application",
	audit.ActionAdminRolePermissionsUpdated:   "changed a role's permissions",
	audit.ActionAdminRoleDeleted:              "deleted a role",
	audit.ActionAdminPermissionCreated:        "created a permission",
	audit.ActionAdminPermissionUpdated:        "changed a permission",
	audit.ActionAdminPermissionDeleted:        "deleted a permission",
	audit.ActionAdminTenantAdminInvited:       "added an administrator",
	audit.ActionAdminTenantAdminGrantsSet:     "changed an administrator's applications",
	audit.ActionAdminTenantAdminRemoved:       "removed an administrator",
	audit.ActionAdminMFAPolicyUpdated:         "changed an application's MFA policy",
	audit.ActionAdminTenantDeactivated:        "deactivated the tenant",
}

// Notifications are sent only for actions that SUCCEEDED.
//
// Failures were briefly reported too — a refused privileged request being the
// one case, since the handler never runs and the refusal is a probe's only
// trace. That is withdrawn deliberately.
//
// Success volume is bounded by how much an operator can actually do. Failure
// volume is bounded by nothing: it is chosen by whoever is probing, and a
// co-owner walking a tenant's applications produces a distinct resource id per
// attempt, so collapsing folds none of it. The per-recipient hourly cap then
// caps the DAMAGE at twenty near-identical emails, which is how a channel gets
// filtered to junk — losing the successful-action notices that share it.
//
// It is also the wrong channel economically: email is metered per message, so
// an unbounded attacker-controlled stream is a billing surface as well as a
// noise one.
//
// Nothing is lost from the record. audit.ActionAdminAccessDenied is still
// written on every refusal by internal/api/middleware/permission.go and
// internal/api/handlers/admin.go, and is still queryable in Monitoring. Only
// the email is withdrawn. When a non-metered channel exists (Teams is the
// intended one), failure alerts belong there.

// selfNotify lists the actions whose actor also receives a copy.
//
// The reasoning is the one behind the existing password_changed email: for a
// change this sensitive, a copy of your own action is how you discover it was
// not you. A stolen owner session rotating a secret is exactly the case this
// catches, and it is the only signal the real owner would get.
//
// Deliberately not every action — a copy of everything you do trains you to
// ignore the channel, which costs more than it buys.
var selfNotify = map[string]bool{
	audit.ActionAdminApplicationSecretRotated: true,
	audit.ActionAdminRolePermissionsUpdated:   true,
	audit.ActionAdminPermissionCreated:        true,
	audit.ActionAdminPermissionUpdated:        true,
	audit.ActionAdminPermissionDeleted:        true,
	audit.ActionAdminTenantAdminGrantsSet:     true,
	audit.ActionAdminTenantAdminRemoved:       true,
	audit.ActionAdminTenantAdminInvited:       true,
}

// subjectLabels phrase an access change in the SECOND person, for the notice
// sent to the person it was made to.
//
// Separate from notableActions because the audience is different: an observer
// reads "removed an administrator", the person removed reads "your access was
// withdrawn". Reusing one phrasing would make one of the two emails read like a
// mistake.
var subjectLabels = map[string]string{
	audit.ActionAdminTenantAdminInvited:   "You were given administrator access",
	audit.ActionAdminTenantAdminGrantsSet: "The applications you administer were changed",
	audit.ActionAdminTenantAdminRemoved:   "Your administrator access was withdrawn",
}

// subjectLabel returns the second-person phrasing for an action that changes
// somebody's own access, and whether this is such an action.
func subjectLabel(action string) (string, bool) {
	phrase, ok := subjectLabels[action]
	return phrase, ok
}

// label returns the human phrasing for an action, and whether it is notable at
// all.
//
// Events this package itself emits are never notable, whatever the catalogue
// says: they are audited, so they come straight back through the sink, and a
// notification about a notification is an infinite loop. The map does not
// contain them today; this guard is what keeps that true after someone adds an
// entry without thinking about the cycle.
func label(action string) (string, bool) {
	if isNotificationAction(action) {
		return "", false
	}
	phrase, ok := notableActions[action]
	return phrase, ok
}

func isNotificationAction(action string) bool {
	const prefix = "notification."
	return len(action) >= len(prefix) && action[:len(prefix)] == prefix
}
