package admin

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/emailaddr"
)

// ---------------------------------------------------------------------------
// Tenant administration (issue #97).
//
// Two tiers live in tenant_admins; the platform tier (super_admin) does not,
// because it is cross-tenant and authorised by permission rather than by
// membership.
//
//	owner     every application in the tenant, present and future. Holds no
//	          rows in tenant_admin_app_scopes — see migration 00062 for why
//	          "absence means all" beats a grant per application.
//	co_owner  only the applications granted to them. Holds the same RBAC
//	          permission names as an owner: a permission says WHAT an
//	          administrator may do, the grants say WHICH application they may do
//	          it to. Tenant-level routes are closed to them by
//	          RequireTenantSelfOrAny, per-application routes by RequireAppScope.
// ---------------------------------------------------------------------------

// Sentinel errors for tenant administration.
var (
	// ErrLastOwner is returned when an operation would leave a tenant with no
	// usable owner, which would make it permanently unadministrable by anyone
	// short of a platform admin.
	ErrLastOwner = errors.New("tenant would be left without a usable owner")
	// ErrAlreadyAdmin is returned when an invitation would add nothing: the
	// address already administers the tenant with exactly the requested reach.
	ErrAlreadyAdmin = errors.New("already an administrator with these grants")
	// ErrGrantsRequired is returned when a co-owner is invited with no
	// applications. Empty grants mean no access at all, never all access, so
	// such an invitation could only produce an administrator who can do nothing.
	ErrGrantsRequired = errors.New("a co-owner must be granted at least one application")
	// ErrGrantsForOwner is returned when application grants are supplied for an
	// owner, whose reach is defined by the absence of grants.
	ErrGrantsForOwner = errors.New("an owner administers every application and cannot be granted specific ones")
	// ErrUnknownApplication is returned when a grant names an application that
	// does not belong to the tenant.
	ErrUnknownApplication = errors.New("application does not belong to this tenant")
	// ErrTooManyAdmins is returned when a tenant is already at maxTenantAdmins.
	ErrTooManyAdmins = fmt.Errorf("a tenant may have at most %d administrators", maxTenantAdmins)
	// ErrInviteCooldown is returned when an invitation for the same account was
	// sent moments ago. The route's rate limiter bounds requests per caller; this
	// bounds mail per recipient, which is the quantity a mailbox owner and the
	// sending domain's reputation actually feel.
	ErrInviteCooldown = errors.New("an invitation was sent to this address moments ago; wait before resending")
	// ErrInviteWouldDemote is returned when a co-owner invitation names somebody
	// who already owns the tenant.
	//
	// An invitation may only ADD reach. Owner already means every application in
	// the tenant, so co-owner of one application is a strict subset — the request
	// is not a widening but a contradiction, and it used to be resolved by
	// silently choosing the narrower role: upsertTenantAdmin wrote
	// admin_role = 'co_owner', the grants mirror deleted the owner's
	// NULL-application row in favour of app-scoped ones, and
	// revokeAdminScopeTokens signed the person out because their live reach had
	// narrowed. An owner adding themselves as co-owner therefore demoted
	// themselves to a single application, with no confirmation.
	//
	// Demotion is a legitimate operation, but it is a deliberate role change with
	// consequences worth stating — not a side effect of an invitation.
	ErrInviteWouldDemote = errors.New("this account already owns the tenant, which includes every application; an invitation cannot reduce an owner to a co-owner")
)

// inviteResendCooldown is the minimum gap between two invitations for one
// account.
const inviteResendCooldown = 60 * time.Second

// maxTenantAdmins caps administrators per tenant. The limit exists to bound the
// invitation endpoint as a mail-sending primitive, and to keep admin_apps small
// enough that a token stays a reasonable size.
const maxTenantAdmins = 25

// TenantAdminResult is the public representation of one tenant administrator.
type TenantAdminResult struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
	// Role is "owner" or "co_owner".
	Role string `json:"role"`
	// Applications is empty for an owner — not because they administer none,
	// but because they administer all of them. Read it together with Role.
	Applications []string `json:"applications"`
	IsPrimary    bool     `json:"is_primary"`
	// Status is "active" once the invitation has been accepted and the address
	// verified, "pending_invitation" until then. An administrator who is
	// pending does not count toward the last-usable-owner guard.
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

// InviteTenantAdminInput carries everything InviteTenantAdmin accepts.
type InviteTenantAdminInput struct {
	TenantID int64
	Email    string
	// Role is auth.AdminRoleOwner or auth.AdminRoleCoOwner.
	Role string
	// ApplicationIDs must be non-empty for a co-owner and empty for an owner.
	ApplicationIDs []int64
	// InviterAdminID is the tenant_admins row of the administrator who
	// triggered this, when there is one. Nil for a platform admin, who is not a
	// tenant administrator.
	InviterAdminID *int64
	InviterName    string

	// Actor is who is performing this write, for the privilege-escalation rules in
	// grant_escalation.go. The route already decided WHETHER the caller may write
	// here; these rules decide what the write may CONTAIN — most importantly that
	// an owner may create co-owners but not peer owners, so ownership cannot
	// propagate itself.
	//
	// NIL means the caller has already established its own authority and the rules
	// are skipped: the platform-admin paths (CreateTenant seeding the first owner)
	// and tests. HTTP handlers must always set it — see grantActorFromClaims.
	//
	// Deliberately a pointer rather than a zero-value struct. A zero GrantActor has
	// UserID 0 and IsPlatformAdmin false, which reads as "a non-platform actor who
	// is nobody" and would refuse every write — including the ones that legitimately
	// have no actor. Making the absence explicit keeps "not checked" distinct from
	// "checked and denied".
	Actor *GrantActor
}

// InviteTenantAdminResult reports what an invitation actually did, which is not
// always what the caller literally asked for.
type InviteTenantAdminResult struct {
	Admin TenantAdminResult `json:"admin"`
	// Action is one of:
	//
	//	invited            a new account was created and an invitation sent
	//	grants_added       the address was already a tenant-level user; it was
	//	                   made an administrator (or its grants widened) without
	//	                   creating a second identity
	//	invitation_resent  an invitation was already outstanding and has been
	//	                   superseded by a fresh one
	Action      string `json:"action"`
	InviteSent  bool   `json:"invite_sent"`
	InviteError string `json:"invite_error,omitempty"`
}

// InviteTenantAdmin adds an administrator to a tenant.
//
// The address is matched against the tenant's TENANT-LEVEL users only. An
// application-scoped row with the same address is a different person as far as
// this is concerned — someone may be a customer of an application and an
// administrator of the same tenant without the two identities touching, which
// is the user-base isolation migration 00042 exists to provide.
//
// Consequently there is no "email already exists" rejection here. An address
// that is already a tenant-level user is promoted in place rather than
// duplicated; only an invitation that would change nothing is refused.
func (s *Service) InviteTenantAdmin(ctx context.Context, in InviteTenantAdminInput) (*InviteTenantAdminResult, error) {
	addr, err := mail.ParseAddress(in.Email)
	if err != nil {
		return nil, fmt.Errorf("email must be a valid email address")
	}
	// Store the canonical address: mail.ParseAddress accepts "Jane <jane@x.com>",
	// and Login matches users.email as an exact string. Normalizing also keeps
	// the promote-in-place lookup below from missing an existing account that
	// differs only in casing and creating a second, parallel admin row.
	email := emailaddr.Normalize(addr.Address)

	switch in.Role {
	case auth.AdminRoleOwner:
		if len(in.ApplicationIDs) > 0 {
			return nil, ErrGrantsForOwner
		}
	case auth.AdminRoleCoOwner:
		if len(in.ApplicationIDs) == 0 {
			return nil, ErrGrantsRequired
		}
	default:
		return nil, fmt.Errorf("role must be %q or %q", auth.AdminRoleOwner, auth.AdminRoleCoOwner)
	}

	if err := s.assertApplicationsInTenant(ctx, in.TenantID, in.ApplicationIDs); err != nil {
		return nil, err
	}

	// An administrator with no way to be told they are one is not an
	// administrator; it is an inert row and a support ticket. Refused before
	// anything is written, so a misconfigured server creates nothing rather than
	// half of something.
	//
	// Kept strict even though a widening for an already-active administrator sends
	// no mail: whether this call is a widening is not known until the row is
	// locked and read, well inside the transaction below. Relaxing it would mean
	// opening a transaction on a server that cannot invite anybody, to discover
	// afterwards whether it needed to — and a server with no invitation service is
	// misconfigured for the common case regardless.
	if s.invSvc == nil {
		return nil, ErrInvitationsUnavailable
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin invite admin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// Serialise every admin mutation for this tenant on the tenants row before
	// counting. The count and the insert it authorises have to be one atomic
	// decision: read outside the transaction, two concurrent invitations at
	// count = maxTenantAdmins-1 both see room and both insert, and the cap that
	// bounds the admin_apps claim is silently exceeded. The lock is per tenant,
	// so it costs nothing beyond serialising writes that were already rare.
	// The cap itself is enforced in upsertTenantAdmin, where it is known whether
	// a row is actually being added — re-inviting someone who already
	// administers the tenant adds nobody and must not be refused at the cap.
	if _, err = tx.Exec(ctx, `SELECT 1 FROM tenants WHERE id = $1 FOR UPDATE`, in.TenantID); err != nil {
		return nil, fmt.Errorf("lock tenant for admin invite: %w", err)
	}

	// Privilege-escalation rules, INSIDE the transaction and after the tenant
	// lock: an owner whose own grant is revoked concurrently must not have their
	// in-flight invitation succeed on a stale read.
	//
	// targetUserID is 0 because the recipient is identified by email and may not
	// have an account yet, so rule 4 (nobody modifies their own grant) cannot be
	// evaluated here — AssertMayGrant skips it for an unknown target rather than
	// matching a zero actor against a zero target. What IS enforced is rule 1: an
	// owner may create co-owners only.
	if in.Actor != nil {
		if err = AssertMayGrant(ctx, tx, *in.Actor, in.TenantID, 0, in.Role); err != nil {
			return nil, err
		}
	}

	// Seed the role now even though nobody is assigned to it yet: confirmation
	// attaches it, and creating it up front means that path cannot fail because
	// the tenant never had the role to begin with.
	if _, err = s.ensureAdminRole(ctx, tx, in.TenantID, in.Role); err != nil {
		return nil, err
	}

	// Existing tenant-level identity for this address, ACROSS tenants.
	//
	// Deliberately NOT scoped to in.TenantID, and that is the whole fix. An
	// administrator may now administer several tenants (migration 00078), so the
	// same person invited to a second tenant must be FOUND and granted, never
	// re-created. Scoping this lookup to the invited tenant is what produced
	// parallel accounts: one users row per tenant, each with its own password
	// hash, MFA enrolment and audit history, sharing only the email string — so
	// both passwords worked, each signing the operator in as a different person
	// holding exactly one tenant, and neither could reach the other's.
	//
	// users.tenant_id on the row that comes back is the account's HOME tenant,
	// where its credentials live, and is deliberately not compared to in.TenantID:
	// authority comes from the grant, not from where the password is stored.
	//
	// LIMIT 1 over a deterministic order rather than a bare single-row scan.
	// users_tenant_email_tenant_level_key (migration 00042) is unique per TENANT,
	// so duplicates predating this fix can still exist; picking the lowest id
	// makes the choice stable instead of leaving it to the planner.
	// scripts/phase0_duplicate_admins.sql is how those get merged.
	var userID int64
	var previousRoleID *int64
	var homeTenantID int64
	err = tx.QueryRow(ctx, `
		SELECT id, role_id, tenant_id FROM users
		WHERE email = $1 AND application_id IS NULL AND deleted_at IS NULL
		ORDER BY id
		LIMIT 1
	`, email).Scan(&userID, &previousRoleID, &homeTenantID)

	action := "grants_added"
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		action = "invited"
		// role_id stays NULL: the grant is not effective until confirmed, and
		// the role is what carries its permissions.
		//
		// The new account's home tenant is the one being administered, because
		// there is nowhere else for its credentials to live.
		if err = tx.QueryRow(ctx, `
			INSERT INTO users (tenant_id, email, first_name, last_name, is_active)
			VALUES ($1, $2, '', '', true)
			RETURNING id
		`, in.TenantID, email).Scan(&userID); err != nil {
			return nil, fmt.Errorf("create administrator user: %w", err)
		}
	case err != nil:
		return nil, fmt.Errorf("look up administrator user: %w", err)
	default:
		// previousRoleID is what removal restores, and it is only meaningful when
		// the role belongs to the tenant being administered.
		//
		// For a cross-tenant invitation it never is: users.role_id names a role in
		// the account's HOME tenant, so restoring it when this administration is
		// withdrawn would attach a foreign tenant's role — meaningless at best,
		// and at worst one carrying permissions nobody intended here. Nil is the
		// honest answer, and removal then simply strips the administrative role.
		if homeTenantID != in.TenantID {
			previousRoleID = nil
		}
		// An administrative role is never a sensible thing to "restore" to: it
		// is one this flow attached, and treating it as the pre-promotion state
		// would make removal a no-op. Only a genuine non-admin role is kept.
		if previousRoleID != nil {
			var name string
			var isSystem bool
			if err = tx.QueryRow(ctx,
				`SELECT name, is_system FROM roles WHERE id = $1`, *previousRoleID,
			).Scan(&name, &isSystem); err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return nil, fmt.Errorf("inspect previous role: %w", err)
			}
			if isSystem && (name == auth.AdminRoleOwner || name == auth.AdminRoleCoOwner) {
				previousRoleID = nil
			}
		}
		// Deliberately NOT assigning the administrative role here. An existing
		// user keeps exactly the permissions they already had until they follow
		// the emailed link; auth.activatePendingAdminGrant attaches the role on
		// confirmation. Granting it now is what let a re-added administrator
		// regain authority with no involvement from them at all.
	}

	adminID, existed, err := upsertTenantAdmin(ctx, tx, in.TenantID, userID, in.Role, in.InviterAdminID, previousRoleID)
	if err != nil {
		return nil, err
	}

	changed, err := replaceGrants(ctx, tx, adminID, in.ApplicationIDs)
	if err != nil {
		return nil, err
	}

	// Mirror to admin_grants (00078) now that role and grants are both settled.
	// Inside the same transaction, so the two models cannot diverge on a rollback.
	if err = mirrorAdminGrants(ctx, tx, in.TenantID, userID); err != nil {
		return nil, err
	}

	// An invitation that changes nothing is an error rather than a silent
	// success, so an operator who expected it to do something finds out.
	if existed && !changed && action == "grants_added" {
		if pending, perr := hasPendingInvitation(ctx, tx, userID); perr != nil {
			return nil, perr
		} else if !pending {
			return nil, ErrAlreadyAdmin
		}
		action = "invitation_resent"
	}

	// Per-recipient cooldown, bounding mail per mailbox where the route's rate
	// limiter bounds requests per caller. A resend loop targets one address, so
	// the caller-side limit alone still lets an operator hammer a single inbox and
	// the sending domain's reputation with it.
	//
	// Confined to the pure-resend path, which is the one with no other bound on
	// it. A call that genuinely changes something — a new administrator, widened
	// grants, someone re-added after removal — is a deliberate operation whose
	// mail is incidental, and refusing it would make an operator wait out a
	// cooldown to do real work. A call that changes nothing at all has already
	// been refused above as ErrAlreadyAdmin; what is left here is a resend, whose
	// entire effect IS the mail.
	//
	// Read under the tenant lock, so two concurrent resends cannot both find the
	// field clear.
	if action == "invitation_resent" {
		var recent bool
		if err = tx.QueryRow(ctx, `
			SELECT EXISTS (
			    SELECT 1 FROM user_invitations
			    WHERE user_id = $1 AND created_at > NOW() - $2::interval
			)
		`, userID, inviteResendCooldown.String()).Scan(&recent); err != nil {
			return nil, fmt.Errorf("check invitation cooldown: %w", err)
		}
		if recent {
			return nil, ErrInviteCooldown
		}
	}

	// Changing who administers what invalidates any token that still asserts the
	// old reach. Access tokens carry admin_scope/admin_apps, so a narrowed grant
	// would otherwise stay usable until the token expired.
	//
	// Gated on the grant already being live. A grant that is still pending carries
	// no reach at all — no RBAC role is attached and loadAdminScope skips it — so
	// creating one changes nothing that a token could be asserting, and revoking
	// on it would sign an ordinary tenant user out of their work merely because
	// somebody invited them to administer something. What must revoke is a change
	// to an ALREADY ACTIVE grant: a demotion from owner to co-owner narrows reach
	// the moment it is written, and the session that predates it does not know.
	//
	// Activation itself revokes separately, in auth.activatePendingAdminGrant —
	// which is where the reach actually starts.
	// Read once, inside the transaction, and used for two decisions: whether to
	// revoke tokens below, and whether an invitation is required after the commit.
	// Both turn on the same fact — is this grant already live — so reading it
	// twice would risk the two answers disagreeing.
	var alreadyActive bool
	if err = tx.QueryRow(ctx,
		`SELECT activated_at IS NOT NULL FROM tenant_admins WHERE id = $1`, adminID,
	).Scan(&alreadyActive); err != nil {
		return nil, fmt.Errorf("check grant activation: %w", err)
	}

	if (changed || !existed) && alreadyActive {
		if err = revokeAdminScopeTokens(ctx, tx, in.TenantID, userID); err != nil {
			return nil, err
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit invite admin tx: %w", err)
	}

	res := &InviteTenantAdminResult{Action: action}

	// A PENDING grant is confirmed by the recipient, including one for an address
	// that is already verified and already has a password. Skipping the email for
	// those was what let an operator re-instate a removed administrator with no
	// involvement from them; being verified proves the address is theirs, not that
	// they agreed to administer anything.
	//
	// For an account that already has a password the link only confirms — it does
	// not reset the password or end their sessions. See
	// auth.InvitationService.Accept.
	//
	// An ALREADY ACTIVE grant is different, and is deliberately not re-invited.
	// Widening a role the person already accepted and is actively using takes
	// effect the instant the row is written — upsertTenantAdmin never clears
	// activated_at — so the mail would gate nothing. Worse, invite() supersedes
	// every outstanding invitation for that account
	// (`UPDATE user_invitations SET used_at = NOW() WHERE user_id = $1`), so
	// promoting an active co-owner in one tenant silently killed a genuine, live
	// invitation they were holding for another, and minted a fresh claim token
	// nobody needed. The consent argument does not apply either: they already
	// consented to administering this tenant.
	//
	// Re-instatement stays safe because removal soft-deletes the tenant_admins
	// row, so a re-invite falls to upsertTenantAdmin's ErrNoRows branch and
	// INSERTs a fresh row with activated_at NULL — pending, and therefore invited.
	if alreadyActive {
		s.logger.Info().Str("email", email).Int64("tenant_id", in.TenantID).
			Str("role", in.Role).
			Msg("admin: grant widened for an already-active administrator; no invitation needed")
	} else if err := s.invSvc.InviteRequired(ctx, in.TenantID, nil, userID, email, in.InviterName, nil); err != nil {
		// s.invSvc is non-nil: checked before the transaction opened.
		res.InviteError = err.Error()
		s.logger.Error().Err(err).Str("email", email).Int64("tenant_id", in.TenantID).
			Msg("admin: administrator added but the confirmation was not delivered")
	} else {
		res.InviteSent = true
	}

	admin, err := s.getTenantAdmin(ctx, in.TenantID, adminID)
	if err != nil {
		return nil, err
	}
	res.Admin = *admin

	s.logger.Info().
		Int64("tenant_id", in.TenantID).
		Int64("admin_id", adminID).
		Str("email", email).
		Str("role", in.Role).
		Str("action", action).
		Msg("admin: tenant administrator invited")

	return res, nil
}

// SetTenantAdminGrants replaces a co-owner's set of granted applications.
//
// Passing an empty set is rejected rather than treated as "revoke everything":
// an administrator who can reach nothing is almost certainly not what the
// caller meant, and RemoveTenantAdmin expresses that intent unambiguously.
func (s *Service) SetTenantAdminGrants(ctx context.Context, tenantID, adminID int64, appIDs []int64) (*TenantAdminResult, error) {
	if len(appIDs) == 0 {
		return nil, ErrGrantsRequired
	}
	if err := s.assertApplicationsInTenant(ctx, tenantID, appIDs); err != nil {
		return nil, err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin set grants tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var userID int64
	var role string
	// FOR UPDATE, as in RemoveTenantAdmin: without it a concurrent removal can
	// commit between this read and replaceGrants, leaving grant rows attached to
	// a soft-deleted administrator.
	err = tx.QueryRow(ctx, `
		SELECT user_id, admin_role FROM tenant_admins
		WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL
		FOR UPDATE
	`, adminID, tenantID).Scan(&userID, &role)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("load administrator: %w", err)
	}
	if role == auth.AdminRoleOwner {
		return nil, ErrGrantsForOwner
	}

	changed, err := replaceGrants(ctx, tx, adminID, appIDs)
	if err != nil {
		return nil, err
	}
	// Mirror to admin_grants (00078), inside the same transaction.
	if err = mirrorAdminGrants(ctx, tx, tenantID, userID); err != nil {
		return nil, err
	}
	if changed {
		if err = revokeAdminScopeTokens(ctx, tx, tenantID, userID); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit set grants tx: %w", err)
	}
	return s.getTenantAdmin(ctx, tenantID, adminID)
}

// RemoveTenantAdmin revokes a tenant administrator, without escalation checks.
//
// Retained for callers that have already established authority themselves —
// platform-admin paths and tests. Prefer RemoveTenantAdminAs, which enforces the
// rules in grant_escalation.go: an owner may remove a co-owner in their own tenant
// but not a peer owner, and nobody may remove themselves.
func (s *Service) RemoveTenantAdmin(ctx context.Context, tenantID, adminID int64) error {
	return s.removeTenantAdmin(ctx, tenantID, adminID, nil)
}

// RemoveTenantAdminAs revokes a tenant administrator on behalf of an actor, with
// the escalation rules enforced.
//
// Rule 5 is the one that matters here: removing a peer owner is reserved to the
// platform tier. Two owners able to remove each other means the tenant belongs to
// whoever committed first, which is not a resolution anybody chose.
func (s *Service) RemoveTenantAdminAs(ctx context.Context, tenantID, adminID int64, actor GrantActor) error {
	return s.removeTenantAdmin(ctx, tenantID, adminID, &actor)
}

// removeTenantAdmin is the shared implementation. actor nil skips the
// escalation rules; non-nil enforces them inside the transaction.
func (s *Service) removeTenantAdmin(ctx context.Context, tenantID, adminID int64, actor *GrantActor) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin remove admin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var userID int64
	var role string
	var previousRoleID *int64
	var wasActivated bool
	err = tx.QueryRow(ctx, `
		SELECT user_id, admin_role, previous_role_id, activated_at IS NOT NULL
		FROM tenant_admins
		WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL
		FOR UPDATE
	`, adminID, tenantID).Scan(&userID, &role, &previousRoleID, &wasActivated)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("load administrator: %w", err)
	}

	// Escalation rules, inside the transaction and after the FOR UPDATE above, so
	// the target's role cannot change underneath the decision.
	if actor != nil {
		if err = AssertMayRemove(ctx, tx, *actor, tenantID, userID); err != nil {
			return err
		}
	}

	// tenant_id in the predicate as well as id. The FOR UPDATE select above
	// already established both, so this is defence in depth rather than a fix:
	// the statement should not be capable of crossing a tenant boundary when read
	// on its own, by a script or a test helper that skipped the select.
	if _, err = tx.Exec(ctx,
		`UPDATE tenant_admins SET deleted_at = NOW(), updated_at = NOW()
		 WHERE id = $1 AND tenant_id = $2`, adminID, tenantID,
	); err != nil {
		return fmt.Errorf("remove administrator: %w", err)
	}

	// Take the administrative role back off the user, restoring whatever they
	// held before promotion (NULL when they held nothing).
	//
	// Leaving it attached does not merely fail to revoke — it ESCALATES. The
	// tenant_admins row is gone, so the next token carries no admin_scope, and
	// RequireTenantSelfOrAny treats an absent scope as tenant-wide so that
	// tokens predating the claim keep working. A removed co-owner would sign
	// back in holding every tenant-admin permission across the whole tenant,
	// which is more than they ever had while they were a co-owner.
	if _, err = tx.Exec(ctx,
		`UPDATE users SET role_id = $1, updated_at = NOW() WHERE id = $2`, previousRoleID, userID,
	); err != nil {
		return fmt.Errorf("strip administrative role: %w", err)
	}
	// The FK is ON DELETE SET NULL, which a soft delete does not trigger.
	if _, err = tx.Exec(ctx,
		`UPDATE tenants SET primary_admin_id = NULL WHERE id = $1 AND primary_admin_id = $2`, tenantID, adminID,
	); err != nil {
		return fmt.Errorf("clear primary administrator: %w", err)
	}
	// Retire the mirror rows for THIS tenant only. A multi-tenant administrator
	// removed here keeps whatever they administer elsewhere.
	if err = mirrorAdminGrants(ctx, tx, tenantID, userID); err != nil {
		return err
	}

	// Two distinct guards, because "the tenant still has an owner" and "the
	// tenant still has anybody" are different failures.
	//
	// Removing an owner must leave a usable owner: only an owner can appoint
	// administrators, so an owner-less tenant cannot repair itself even while a
	// co-owner is still working in it.
	//
	// Removing a co-owner must leave a usable administrator of either tier. That
	// case is not covered by the owner guard and is reachable: a tenant whose only
	// owner never accepted their invitation is being administered by its co-owner
	// alone, and removing that co-owner empties it. Nobody can sign in afterwards
	// and no endpoint can put it right, because every route that could is guarded
	// by the administrator who just left.
	//
	// Conditional on the co-owner having been usable, and that condition is not a
	// softening of the rule — it is the rule. Removing a co-owner who never
	// accepted cannot reduce the number of people who can sign in, because they
	// were not one of them. Guarding it anyway would refuse to clean up a
	// mistyped invitation in exactly the tenant that most needs the mistake
	// undone: one whose owner has not accepted either. The owner branch is
	// deliberately unconditional by contrast — a tenant must be left with an
	// owner who can appoint administrators, whether or not the departing one
	// could.
	if role == auth.AdminRoleOwner {
		if err := assertUsableOwnerRemains(ctx, tx, tenantID); err != nil {
			return err
		}
	} else if wasActivated {
		if err := assertUsableAdminRemains(ctx, tx, tenantID); err != nil {
			return err
		}
	}

	if err = revokeAdminScopeTokens(ctx, tx, tenantID, userID); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit remove admin tx: %w", err)
	}
	s.logger.Info().Int64("tenant_id", tenantID).Int64("admin_id", adminID).Msg("admin: tenant administrator removed")
	return nil
}

// ListTenantAdmins returns every live administrator of a tenant.
func (s *Service) ListTenantAdmins(ctx context.Context, tenantID int64) ([]TenantAdminResult, error) {
	rows, err := s.pool.Query(ctx, tenantAdminSelect+`
		WHERE ta.tenant_id = $1 AND ta.deleted_at IS NULL
		ORDER BY ta.admin_role, ta.created_at, ta.id
	`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list tenant admins: %w", err)
	}
	defer rows.Close()

	out := []TenantAdminResult{}
	for rows.Next() {
		r, err := scanTenantAdmin(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate tenant admins: %w", err)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// internals
// ---------------------------------------------------------------------------

// tenantAdminSelect projects one administrator plus their grants. The
// applications array is aggregated in SQL so listing N administrators stays one
// round trip rather than N+1.
const tenantAdminSelect = `
	SELECT ta.id, u.email,
	       TRIM(CONCAT(u.first_name, ' ', u.last_name)),
	       ta.admin_role,
	       COALESCE((
	           SELECT array_agg(s.application_id::text ORDER BY s.application_id)
	           FROM tenant_admin_app_scopes s WHERE s.admin_id = ta.id
	       ), '{}'),
	       (t.primary_admin_id = ta.id),
	       (ta.activated_at IS NOT NULL AND u.is_active AND u.blocked_at IS NULL),
	       ta.created_at
	FROM tenant_admins ta
	JOIN users u   ON u.id = ta.user_id
	JOIN tenants t ON t.id = ta.tenant_id
`

func scanTenantAdmin(row pgx.Row) (*TenantAdminResult, error) {
	var r TenantAdminResult
	var id int64
	var isPrimary *bool
	var usable bool
	if err := row.Scan(&id, &r.Email, &r.Name, &r.Role, &r.Applications, &isPrimary, &usable, &r.CreatedAt); err != nil {
		return nil, fmt.Errorf("scan tenant admin: %w", err)
	}
	r.ID = strconv.FormatInt(id, 10)
	r.IsPrimary = isPrimary != nil && *isPrimary
	r.Status = "pending_invitation"
	if usable {
		r.Status = "active"
	}
	return &r, nil
}

func (s *Service) getTenantAdmin(ctx context.Context, tenantID, adminID int64) (*TenantAdminResult, error) {
	row := s.pool.QueryRow(ctx, tenantAdminSelect+`
		WHERE ta.id = $1 AND ta.tenant_id = $2 AND ta.deleted_at IS NULL
	`, adminID, tenantID)
	r, err := scanTenantAdmin(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return r, nil
}

// assertApplicationsInTenant rejects a grant naming an application of another
// tenant. The DB trigger catches this too, but a 400 naming the offending id is
// more use to the caller than a constraint violation.
func (s *Service) assertApplicationsInTenant(ctx context.Context, tenantID int64, appIDs []int64) error {
	if len(appIDs) == 0 {
		return nil
	}
	var found int
	if err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM oauth_clients WHERE tenant_id = $1 AND id = ANY($2)`, tenantID, appIDs,
	).Scan(&found); err != nil {
		return fmt.Errorf("verify applications: %w", err)
	}
	if found != len(appIDs) {
		return ErrUnknownApplication
	}
	return nil
}

// ensureAdminRole returns the tenant's system role for an administration tier,
// creating it with the full tenant-admin permission catalog if absent.
//
// Both tiers hold the SAME permissions. That is deliberate: a permission
// answers "may this administrator manage users?", not "of which application?".
// The second question is answered by admin_scope/admin_apps in the token and
// enforced by RequireAppScope and RequireTenantSelfOrAny. Encoding reach into
// permission names instead would need a parallel catalog per application.
func (s *Service) ensureAdminRole(ctx context.Context, tx pgx.Tx, tenantID int64, adminRole string) (int64, error) {
	var roleID int64
	err := tx.QueryRow(ctx, `
		SELECT id FROM roles
		WHERE tenant_id = $1 AND name = $2 AND application_id IS NULL AND deleted_at IS NULL
	`, tenantID, adminRole).Scan(&roleID)
	if err == nil {
		return roleID, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return 0, fmt.Errorf("look up %s role: %w", adminRole, err)
	}

	if err = tx.QueryRow(ctx, `
		INSERT INTO roles (tenant_id, name, is_system, created_at)
		VALUES ($1, $2, true, NOW())
		RETURNING id
	`, tenantID, adminRole).Scan(&roleID); err != nil {
		return 0, fmt.Errorf("create %s role: %w", adminRole, err)
	}

	// Attach the tenant's existing permission catalog, seeding any entry a
	// tenant created before that permission existed is missing.
	names := make([]string, len(defaultPermissions))
	for i, p := range defaultPermissions {
		names[i] = p.name
		if _, err = tx.Exec(ctx, `
			INSERT INTO permissions (tenant_id, name, description)
			VALUES ($1, $2, $3)
			ON CONFLICT (tenant_id, name) WHERE application_id IS NULL AND deleted_at IS NULL DO NOTHING
		`, tenantID, p.name, p.description); err != nil {
			return 0, fmt.Errorf("seed permission %s: %w", p.name, err)
		}
	}
	if _, err = tx.Exec(ctx, `
		INSERT INTO role_permissions (role_id, permission_id, tenant_id)
		SELECT $1, p.id, $2 FROM permissions p
		WHERE p.tenant_id = $2 AND p.application_id IS NULL AND p.deleted_at IS NULL AND p.name = ANY($3)
		ON CONFLICT DO NOTHING
	`, roleID, tenantID, names); err != nil {
		return 0, fmt.Errorf("attach permissions to %s role: %w", adminRole, err)
	}
	return roleID, nil
}

// upsertTenantAdmin creates or revives an administration row. Reports whether a
// live row already existed, which distinguishes "made an administrator" from
// "already was one".
func upsertTenantAdmin(ctx context.Context, tx pgx.Tx, tenantID, userID int64, role string, inviterAdminID, previousRoleID *int64) (int64, bool, error) {
	var adminID int64
	var existingRole string
	err := tx.QueryRow(ctx, `
		SELECT id, admin_role FROM tenant_admins
		WHERE user_id = $1 AND tenant_id = $2 AND deleted_at IS NULL
		FOR UPDATE
	`, userID, tenantID).Scan(&adminID, &existingRole)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		// Counted here, inside the caller's transaction and under its per-tenant
		// lock, and only on the branch that adds a row.
		var count int
		if err = tx.QueryRow(ctx,
			`SELECT count(*) FROM tenant_admins WHERE tenant_id = $1 AND deleted_at IS NULL`, tenantID,
		).Scan(&count); err != nil {
			return 0, false, fmt.Errorf("count tenant admins: %w", err)
		}
		if count >= maxTenantAdmins {
			return 0, false, ErrTooManyAdmins
		}
		if err = tx.QueryRow(ctx, `
			INSERT INTO tenant_admins (tenant_id, user_id, admin_role, invited_by, previous_role_id)
			VALUES ($1, $2, $3, $4, $5)
			RETURNING id
		`, tenantID, userID, role, inviterAdminID, previousRoleID).Scan(&adminID); err != nil {
			return 0, false, fmt.Errorf("create tenant admin: %w", err)
		}
		return adminID, false, nil
	case err != nil:
		return 0, false, fmt.Errorf("look up tenant admin: %w", err)
	}

	// An invitation may only ADD reach, so the narrowing direction is refused
	// rather than written. Previously this branch fired for any role difference:
	// owner → co_owner wrote through, the mirror replaced the owner's
	// NULL-application grant with app-scoped rows, and the token revoke fired
	// because reach had narrowed — so an owner who invited themselves as co-owner
	// silently demoted themselves to one application and was signed out.
	//
	// Refused here rather than in InviteTenantAdmin because this is the function
	// that holds the FOR UPDATE lock on the row: checking earlier would race a
	// concurrent promotion between the read and the write.
	if existingRole == auth.AdminRoleOwner && role == auth.AdminRoleCoOwner {
		return 0, false, ErrInviteWouldDemote
	}

	if existingRole != role {
		// Only widening reaches here (co_owner → owner). The promote trigger
		// clears any application grants, since an owner's reach is the absence
		// of them.
		if _, err = tx.Exec(ctx,
			`UPDATE tenant_admins SET admin_role = $1, updated_at = NOW() WHERE id = $2`, role, adminID,
		); err != nil {
			return 0, false, fmt.Errorf("change administrator role: %w", err)
		}
		return adminID, false, nil
	}
	return adminID, true, nil
}

// replaceGrants makes an administrator's grants exactly appIDs, reporting
// whether anything actually changed. An owner (appIDs empty) is a no-op beyond
// clearing stale rows, which the DB forbids them from holding anyway.
func replaceGrants(ctx context.Context, tx pgx.Tx, adminID int64, appIDs []int64) (bool, error) {
	var before []int64
	rows, err := tx.Query(ctx, `SELECT application_id FROM tenant_admin_app_scopes WHERE admin_id = $1`, adminID)
	if err != nil {
		return false, fmt.Errorf("read existing grants: %w", err)
	}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return false, fmt.Errorf("scan existing grant: %w", err)
		}
		before = append(before, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("iterate existing grants: %w", err)
	}

	if _, err = tx.Exec(ctx,
		`DELETE FROM tenant_admin_app_scopes WHERE admin_id = $1 AND NOT (application_id = ANY($2))`,
		adminID, appIDs,
	); err != nil {
		return false, fmt.Errorf("revoke grants: %w", err)
	}
	for _, appID := range appIDs {
		if _, err = tx.Exec(ctx, `
			INSERT INTO tenant_admin_app_scopes (admin_id, application_id)
			VALUES ($1, $2) ON CONFLICT DO NOTHING
		`, adminID, appID); err != nil {
			return false, fmt.Errorf("grant application %d: %w", appID, err)
		}
	}

	if len(before) != len(appIDs) {
		return true, nil
	}
	want := make(map[int64]struct{}, len(appIDs))
	for _, id := range appIDs {
		want[id] = struct{}{}
	}
	for _, id := range before {
		if _, ok := want[id]; !ok {
			return true, nil
		}
	}
	return false, nil
}

// revokeAdminScopeTokens invalidates everything a user holds that still asserts
// an administrative reach they no longer have.
//
// Both halves are needed and neither substitutes for the other. The
// token_version bump marks the account; revoking the refresh tokens is what
// stops a new access token being minted with the old reach. Without the second
// step a withdrawn grant survives in whatever session was already open, for as
// long as that session keeps rotating — which is indefinitely.
//
// Access tokens already issued still carry the old admin_scope until they expire
// (15 minutes). Closing that window requires the token_version counter to be
// checked at verification time. Nothing in this codebase does that yet: the
// counter is written by every credential and authority change and read by
// nobody, so it is currently a marker rather than a revocation. Treat the
// refresh-token revocation as the mechanism that works.
func revokeAdminScopeTokens(ctx context.Context, tx pgx.Tx, tenantID, userID int64) error {
	if _, err := tx.Exec(ctx,
		`UPDATE users SET token_version = token_version + 1, updated_at = NOW()
		 WHERE id = $1 AND tenant_id = $2`, userID, tenantID,
	); err != nil {
		return fmt.Errorf("bump token version: %w", err)
	}
	if err := auth.RevokeAllSessionsTx(ctx, tx, userID, tenantID, auth.RevokeReasonCredentialChange); err != nil {
		return fmt.Errorf("revoke sessions: %w", err)
	}
	return nil
}

func hasPendingInvitation(ctx context.Context, tx pgx.Tx, userID int64) (bool, error) {
	var n int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM user_invitations
		WHERE user_id = $1 AND used_at IS NULL AND expires_at > NOW()
	`, userID).Scan(&n); err != nil {
		return false, fmt.Errorf("check pending invitation: %w", err)
	}
	return n > 0, nil
}

// assertUsableOwnerRemains enforces that a tenant always has at least one owner
// who can actually log in.
//
// "Usable" excludes an owner who has not yet accepted their invitation: two
// invited-but-never-accepted owners would satisfy a naive count while nobody
// can enter the tenant at all.
//
// Called inside the mutating transaction, after the mutation, so it sees the
// post-change state and multi-row changes are judged as one unit — a per-row
// trigger would either false-positive on the first row of a two-row demotion or
// miss the case entirely.
func assertUsableOwnerRemains(ctx context.Context, tx pgx.Tx, tenantID int64) error {
	n, err := countUsableAdmins(ctx, tx, tenantID, auth.AdminRoleOwner)
	if err != nil {
		return fmt.Errorf("count usable owners: %w", err)
	}
	if n == 0 {
		return ErrLastOwner
	}
	return nil
}

// assertUsableAdminRemains enforces that a tenant is never emptied of
// administrators outright, whatever tier the last one held. Applied to co-owner
// removal, where assertUsableOwnerRemains does not apply: a tenant whose only
// owner is still unactivated is nonetheless administrable through its co-owner,
// and removing that co-owner is what would strand it.
func assertUsableAdminRemains(ctx context.Context, tx pgx.Tx, tenantID int64) error {
	n, err := countUsableAdmins(ctx, tx, tenantID, "")
	if err != nil {
		return fmt.Errorf("count usable administrators: %w", err)
	}
	if n == 0 {
		return ErrLastOwner
	}
	return nil
}

// countUsableAdmins counts administrators of a tenant who can actually sign in
// and exercise the grant. An empty adminRole counts both tiers.
//
// "Usable" excludes a grant the recipient has not accepted: two
// invited-but-never-accepted owners satisfy a naive count while nobody can enter
// the tenant at all.
func countUsableAdmins(ctx context.Context, tx pgx.Tx, tenantID int64, adminRole string) (int, error) {
	var n int
	err := tx.QueryRow(ctx, `
		SELECT count(*)
		FROM tenant_admins ta
		JOIN users u ON u.id = ta.user_id
		WHERE ta.tenant_id = $1
		  AND ($2 = '' OR ta.admin_role = $2)
		  AND ta.deleted_at IS NULL
		  AND ta.activated_at IS NOT NULL
		  AND u.deleted_at IS NULL
		  AND u.is_active
		  AND u.blocked_at IS NULL
		  AND u.email_verified
	`, tenantID, adminRole).Scan(&n)
	return n, err
}
