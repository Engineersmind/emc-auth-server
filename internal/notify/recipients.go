package notify

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/engineersmind/emc-auth-server/internal/emailaddr"
)

// Administrative tiers, matching tenant_admins.admin_role. Kept as local
// constants rather than importing internal/admin, which would pull the whole
// admin service in for two strings.
const (
	roleOwner   = "owner"
	roleCoOwner = "co_owner"
)

// audience is who should hear about one event, and how the actor is described.
type audience struct {
	// to is the deduplicated recipient list. Empty means nobody is notified.
	to []string
	// actorRole is spelled for humans ("owner", "co-owner"), so the reader can
	// judge whether the action suited whoever took it.
	actorRole string
}

// resolveAudience decides who hears about an event: the usable administrators
// of the scope the catalogue names for the action, plus the platform tier when
// the entry carries oversight.
//
//	scopeApplication  → the tenant's owners + the co-owners granted appID
//	scopeTenantOwners → the tenant's owners only
//
// The actor is included when they are one of those administrators. That is the
// point for these actions: a copy of a secret rotation you did not make is how
// a stolen session is discovered.
//
// An application-scoped action with no application resolves to nobody rather
// than widening to the tenant: telling co-owners of unrelated applications
// about it would be exactly the noise the catalogue was cut down to avoid.
func (s *EmailSink) resolveAudience(ctx context.Context, tenantID int64, appID, actorUserID *int64, actorEmail, action string) (audience, error) {
	var out audience
	entry, ok := lookup(action)
	if !ok || tenantID == 0 {
		return out, nil
	}

	role, err := s.describeActor(ctx, tenantID, actorUserID, actorEmail)
	if err != nil {
		return out, err
	}
	out.actorRole = role

	var to []string
	switch entry.scope {
	case scopeApplication:
		if appID == nil {
			return out, nil
		}
		to, err = s.administrators(ctx, tenantID, appID)
	default: // scopeTenantOwners
		to, err = s.tenantOwners(ctx, tenantID)
	}
	if err != nil {
		return out, err
	}

	if entry.oversight {
		var oversight []string
		oversight, err = s.platformRecipients(ctx)
		if err != nil {
			return out, err
		}
		to = append(to, oversight...)
	}

	seen := make(map[string]struct{}, len(to))
	for _, addr := range to {
		if addr == "" {
			continue
		}
		key := strings.ToLower(addr)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out.to = append(out.to, addr)
	}
	return out, nil
}

// describeActor phrases who acted, for the email.
func (s *EmailSink) describeActor(ctx context.Context, tenantID int64, actorUserID *int64, actorEmail string) (string, error) {
	switch {
	case actorEmail == "":
		return "", nil // the template reads "An administrator"
	case isMachineActor(actorEmail):
		return "API key", nil
	}
	role, err := s.actorRole(ctx, tenantID, actorUserID, actorEmail)
	if err != nil {
		return "", err
	}
	switch role {
	case roleOwner:
		return "owner", nil
	case roleCoOwner:
		return "co-owner", nil
	default:
		// Acting in a tenant without being one of its administrators means
		// holding tenant:manage — the routes admit nobody else.
		return "platform administrator", nil
	}
}

// isMachineActor reports whether an event came from an API-key management
// token. SignManagement mints those with a synthetic address, which is the only
// marker on the audit event distinguishing automation from a person.
func isMachineActor(email string) bool {
	return strings.HasSuffix(email, "@apikey")
}

// actorRole reports the actor's tier in this tenant, or "" when they are not an
// administrator of it.
//
// Matched on user id when the event carries one, which admin actions do. The id
// is stable; the email is not. Someone who changes their address leaves
// historical events holding the old one, and an email-only lookup would then
// describe one of the tenant's own administrators as a platform administrator.
// Email remains the fallback for events raised without a user id.
//
// Only an ACTIVATED grant counts. An administrator who has been invited but has
// not accepted holds no role and cannot act.
func (s *EmailSink) actorRole(ctx context.Context, tenantID int64, userID *int64, email string) (string, error) {
	// Audit events can carry an actor email captured before normalization.
	email = emailaddr.Normalize(email)
	var role string
	var err error
	if userID != nil {
		err = s.pool.QueryRow(ctx, `
			SELECT admin_role FROM tenant_admins
			WHERE tenant_id = $1 AND user_id = $2
			  AND deleted_at IS NULL AND activated_at IS NOT NULL
		`, tenantID, *userID).Scan(&role)
	} else {
		err = s.pool.QueryRow(ctx, `
			SELECT ta.admin_role
			FROM tenant_admins ta
			JOIN users u ON u.id = ta.user_id
			WHERE ta.tenant_id = $1
			  AND u.email = $2
			  AND u.application_id IS NULL
			  AND ta.deleted_at IS NULL
			  AND ta.activated_at IS NOT NULL
		`, tenantID, email).Scan(&role)
	}
	if err != nil {
		if isNoRows(err) {
			return "", nil
		}
		return "", fmt.Errorf("resolve actor role: %w", err)
	}
	return role, nil
}

// administrators returns the addresses of the tenant's usable administrators —
// active, verified, unblocked, with an accepted grant. Notifying somebody who
// cannot sign in achieves nothing.
//
// With appID nil that is every owner and co-owner. With appID set it is the
// owners (who administer every application) plus the co-owners granted that
// application — and nobody at all when the application is not this tenant's,
// so a mis-attributed event cannot mail another tenant's administrators.
func (s *EmailSink) administrators(ctx context.Context, tenantID int64, appID *int64) ([]string, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT u.email
		FROM tenant_admins ta
		JOIN users u ON u.id = ta.user_id
		WHERE ta.tenant_id = $1
		  AND ta.deleted_at IS NULL
		  AND ta.activated_at IS NOT NULL
		  AND u.deleted_at IS NULL
		  AND u.is_active
		  AND u.blocked_at IS NULL
		  AND u.email_verified
		  AND (
		        $2::bigint IS NULL
		     OR (
		          EXISTS (SELECT 1 FROM oauth_clients oc WHERE oc.id = $2 AND oc.tenant_id = $1)
		          AND (
		                ta.admin_role = $3
		             OR EXISTS (
		                  SELECT 1 FROM tenant_admin_app_scopes sc
		                  WHERE sc.admin_id = ta.id AND sc.application_id = $2
		                )
		          )
		        )
		  )
		ORDER BY u.email
	`, tenantID, appID, roleOwner)
	if err != nil {
		return nil, fmt.Errorf("resolve administrators: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var email string
		if err := rows.Scan(&email); err != nil {
			return nil, fmt.Errorf("scan administrator email: %w", err)
		}
		out = append(out, email)
	}
	return out, rows.Err()
}

// tenantOwners returns the addresses of owners who can actually act — the same
// "usable" predicate administrators applies. scopeTenantOwners uses it for
// tenant deactivation, which owner-tier oversight has always owned; co-owners
// were never in that audience and the rewrite adding them was reverted.
func (s *EmailSink) tenantOwners(ctx context.Context, tenantID int64) ([]string, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT u.email
		FROM tenant_admins ta
		JOIN users u ON u.id = ta.user_id
		WHERE ta.tenant_id = $1
		  AND ta.admin_role = $2
		  AND ta.deleted_at IS NULL
		  AND ta.activated_at IS NOT NULL
		  AND u.deleted_at IS NULL
		  AND u.is_active
		  AND u.blocked_at IS NULL
		  AND u.email_verified
		ORDER BY u.email
	`, tenantID, roleOwner)
	if err != nil {
		return nil, fmt.Errorf("resolve tenant owners: %w", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var email string
		if err := rows.Scan(&email); err != nil {
			return nil, fmt.Errorf("scan owner email: %w", err)
		}
		out = append(out, email)
	}
	return out, rows.Err()
}

// platformRecipients returns the platform tier.
//
// A configured address wins outright: a deployment that names one wants its
// oversight mail in a shared mailbox or a ticket queue, and fanning out to every
// super_admin as well would duplicate it. Without one, fall back to the
// super_admin users so the feature works with no configuration at all.
//
// Deliberately NOT filtered on email_verified, unlike the owner lookup.
// Verification is a self-service concept: a super_admin is provisioned by
// whoever deployed the system, and the seeded one has email_verified = false to
// this day. Requiring it meant the platform tier resolved to nobody and every
// owner's action went unreported — with no error, because "no recipients" is a
// legitimate outcome for a platform admin's own actions.
func (s *EmailSink) platformRecipients(ctx context.Context) ([]string, error) {
	if len(s.platformEmails) > 0 {
		return s.platformEmails, nil
	}
	rows, err := s.pool.Query(ctx, `
		SELECT u.email
		FROM users u
		JOIN roles r ON r.id = u.role_id
		WHERE r.name = 'super_admin'
		  AND r.is_system = true
		  AND r.application_id IS NULL
		  AND r.deleted_at IS NULL
		  AND u.deleted_at IS NULL
		  AND u.is_active
	`)
	if err != nil {
		return nil, fmt.Errorf("resolve platform recipients: %w", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var email string
		if err := rows.Scan(&email); err != nil {
			return nil, fmt.Errorf("scan platform email: %w", err)
		}
		out = append(out, email)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		// Say so loudly. Silence here is indistinguishable from "nothing worth
		// reporting", and it means every owner action in the system is going
		// unreported — which is precisely the state this feature exists to end.
		s.logger.Warn().Msg("notify: no platform recipients — owner activity is going unreported; set PLATFORM_NOTIFY_EMAIL")
	}
	return out, nil
}

// accessChangeSubject resolves who an access change was made TO, and which
// applications they administer afterwards.
//
// The handlers log these with resource_type "tenant_admin" and the
// tenant_admins row id, which is the only link back to the person — the audit
// event carries the ACTOR, never the subject.
//
// Soft-deleted rows are included deliberately: a withdrawal deletes the row, and
// telling somebody their access was removed is the single most important message
// in this whole feature. Excluding them would silently drop exactly that one.
func (s *EmailSink) accessChangeSubject(ctx context.Context, tenantID int64, resourceType, resourceID string) (email string, apps string, activated bool) {
	if resourceType != "tenant_admin" || resourceID == "" {
		return "", "", false
	}
	adminID, err := strconv.ParseInt(resourceID, 10, 64)
	if err != nil {
		return "", "", false
	}

	// activated_at is selected so a grant the recipient has not accepted can be
	// skipped by the caller. Not filtered in SQL: a withdrawal must still notify
	// (see the comment above about soft-deleted rows), and a row can be both
	// deleted and never activated.
	err = s.pool.QueryRow(ctx, `
		SELECT u.email,
		       COALESCE((
		           SELECT string_agg(oc.name, ', ' ORDER BY oc.name)
		           FROM tenant_admin_app_scopes sc
		           JOIN oauth_clients oc ON oc.id = sc.application_id
		           WHERE sc.admin_id = ta.id
		       ), ''),
		       ta.activated_at IS NOT NULL
		FROM tenant_admins ta
		JOIN users u ON u.id = ta.user_id
		WHERE ta.id = $1 AND ta.tenant_id = $2
	`, adminID, tenantID).Scan(&email, &apps, &activated)
	if err != nil {
		return "", "", false
	}
	return email, apps, activated
}

// tenantName resolves the display name for the email body. Falls back to the
// id rather than failing: an unnamed tenant is still worth reporting.
func (s *EmailSink) tenantName(ctx context.Context, tenantID int64) string {
	var name string
	err := s.pool.QueryRow(ctx,
		`SELECT COALESCE(NULLIF(display_name, ''), name) FROM tenants WHERE id = $1`, tenantID,
	).Scan(&name)
	if err != nil || name == "" {
		return "tenant " + strconv.FormatInt(tenantID, 10)
	}
	return name
}

// eventApplication resolves the application an event concerns.
//
// It cannot rely on Event.ApplicationID alone: the audit writer's application
// backfill runs on a copy destined for the database, so the sink sees the field
// exactly as the handler set it. The resource is the fallback, which for a
// secret rotation is the application itself.
func eventApplication(appID *int64, resourceType, resourceID string) *int64 {
	if appID != nil && *appID != 0 {
		return appID
	}
	if resourceType == "application" && resourceID != "" {
		if parsed, err := strconv.ParseInt(resourceID, 10, 64); err == nil {
			return &parsed
		}
	}
	return nil
}

// applicationName returns the application's name for the email body, or ""
// when the event concerns no application; the template omits the row rather
// than showing a blank one.
func (s *EmailSink) applicationName(ctx context.Context, appID *int64) string {
	if appID == nil {
		return ""
	}
	var name string
	if err := s.pool.QueryRow(ctx, `SELECT name FROM oauth_clients WHERE id = $1`, *appID).Scan(&name); err != nil {
		return ""
	}
	return name
}
