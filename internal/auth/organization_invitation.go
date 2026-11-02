package auth

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/engineersmind/emc-auth-server/internal/emailaddr"
	"github.com/engineersmind/emc-auth-server/internal/mailer"
	"github.com/engineersmind/emc-auth-server/internal/password"
)

// ---------------------------------------------------------------------------
// Organisation invitations (migration 00102).
//
// An invitation is addressed to an EMAIL and carries the organisation and the
// roles the invitee receives on accepting. The invitee may already have an
// account in the application (they accept while signed in) or not (they choose
// a password while accepting, and the account is created verified — following
// the link proved control of the inbox).
//
// The raw token is returned to the inviter once and never stored; only its
// SHA-256 is. Delivery is either EMC's own branded mail, or the application's:
// an application that prefers to send its own email takes the token from the
// response and builds its own link.
// ---------------------------------------------------------------------------

// OrganizationInvitationTTL is the default invitation lifetime, matching the
// account invitation (InvitationTTL). Overridable per call up to the maximum.
const (
	OrganizationInvitationTTL    = 72 * time.Hour
	MaxOrganizationInvitationTTL = 30 * 24 * time.Hour
)

var (
	// ErrOrganizationInvitationInvalid covers unknown, expired, used and revoked
	// invitations, a deactivated organisation, and an accepting account that is
	// not the one invited — one answer, so a token cannot be used to probe.
	ErrOrganizationInvitationInvalid = errors.New("invalid or expired invitation")
	// ErrOrganizationInvitationAccountExists is returned when an invitee with an
	// existing account tries to accept by creating a new one. They must sign in
	// and accept as themselves.
	ErrOrganizationInvitationAccountExists = errors.New("an account already exists for this email; sign in to accept the invitation")
	// ErrInvalidInvitationEmail is a malformed invitee address.
	ErrInvalidInvitationEmail = errors.New("a valid email address is required")
	// ErrInvalidInvitationURL is an invitation_url outside the application's
	// registered redirect origins.
	ErrInvalidInvitationURL = errors.New("invitation_url must be an https URL on one of the application's registered redirect URI origins")
	// ErrInvalidInvitationTTL is a lifetime outside 1 hour – 30 days.
	ErrInvalidInvitationTTL = errors.New("expires_in_hours must be between 1 and 720")
	// ErrInvitationLinkRequired means send_email was asked for without a link
	// to put in the email.
	ErrInvitationLinkRequired = errors.New("invitation_url is required when send_email is true")
)

// Invitation status values, derived — never stored.
const (
	InvitationStatusPending  = "pending"
	InvitationStatusAccepted = "accepted"
	InvitationStatusRevoked  = "revoked"
	InvitationStatusExpired  = "expired"
)

// OrganizationInvitation is the external view of an invitation.
type OrganizationInvitation struct {
	ID             string     `json:"id"`
	OrganizationID string     `json:"organization_id"`
	Email          string     `json:"email"`
	Roles          []string   `json:"roles"`
	Status         string     `json:"status"`
	ExpiresAt      time.Time  `json:"expires_at"`
	CreatedAt      time.Time  `json:"created_at"`
	AcceptedAt     *time.Time `json:"accepted_at,omitempty"`
}

// CreatedOrganizationInvitation is returned once, at creation. Token is the
// only copy of the raw secret anywhere.
type CreatedOrganizationInvitation struct {
	OrganizationInvitation
	Token         string `json:"token"`
	InvitationURL string `json:"invitation_url,omitempty"`
	EmailSent     bool   `json:"email_sent"`
}

// CreateOrganizationInvitationInput describes a new invitation.
type CreateOrganizationInvitationInput struct {
	Email string
	Roles []string
	// InvitedBy is the administrator; nil when an application backend invites.
	InvitedBy *int64
	// InvitedByClient is the inviting application's client_id, when it is one.
	InvitedByClient string
	InviterName     string
	// TTL zero means OrganizationInvitationTTL.
	TTL time.Duration
	// InvitationURL, when set, is the page in the APPLICATION that accepts
	// invitations; the token and organisation are appended as query
	// parameters. It must sit on one of the application's registered redirect
	// URI origins, so EMC never emails a link to somewhere the application did
	// not register — the control that stops this endpoint becoming a phishing
	// relay.
	InvitationURL string
	// SendEmail asks EMC to deliver the invitation with the application's
	// branded user_invitation template. Requires InvitationURL.
	SendEmail bool
}

// OrganizationInvitationPreview is what an invitee's client may show before
// accepting.
type OrganizationInvitationPreview struct {
	Organization OrganizationRef `json:"organization"`
	Email        string          `json:"email"`
	Roles        []string        `json:"roles"`
	ExpiresAt    time.Time       `json:"expires_at"`
	// AccountExists tells the client whether to ask the invitee to sign in or
	// to choose a password. Shown only to the holder of the token, who already
	// knows the address it was sent to.
	AccountExists bool `json:"account_exists"`
}

// AcceptOrganizationInvitationInput accepts an invitation.
//
// Exactly one of the two modes applies:
//   - ExistingUserID set: the invitee is signed in. The id and AppRowID come
//     from a VERIFIED access token, never from the request body.
//   - otherwise: a new account is created with Password (and names).
type AcceptOrganizationInvitationInput struct {
	Token          string
	ExistingUserID *int64
	// AppRowID is the access token's application; must be the invitation's.
	AppRowID  int64
	Password  string
	FirstName string
	LastName  string
}

// AcceptedOrganizationInvitation reports a completed acceptance.
type AcceptedOrganizationInvitation struct {
	UserID         string          `json:"user_id"`
	Organization   OrganizationRef `json:"organization"`
	Roles          []string        `json:"roles"`
	AccountCreated bool            `json:"account_created"`

	tenantID, appRowID, orgRowID int64
	invitationID                 string
}

// Scope returns the tenant and application the invitation belonged to, for
// audit attribution by the handler.
func (a *AcceptedOrganizationInvitation) Scope() (OrganizationScope, int64, string) {
	return OrganizationScope{TenantID: a.tenantID, AppRowID: a.appRowID}, a.orgRowID, a.invitationID
}

// WithHasher shares the process-wide password hasher used when an invitation
// creates an account, so the credential matches every other one and counts
// against the same concurrency cap.
func (s *OrganizationService) WithHasher(h *password.Hasher) *OrganizationService {
	s.hasher = h
	return s
}

func newInvitationPublicID() (string, error) {
	r, err := randomBase62(20)
	if err != nil {
		return "", err
	}
	return "inv_" + r, nil
}

func invitationStatus(expiresAt time.Time, acceptedAt, revokedAt *time.Time) string {
	switch {
	case acceptedAt != nil:
		return InvitationStatusAccepted
	case revokedAt != nil:
		return InvitationStatusRevoked
	case time.Now().After(expiresAt):
		return InvitationStatusExpired
	}
	return InvitationStatusPending
}

// invitationLink validates rawURL against the application's redirect origins
// and appends the invitation parameters.
func (s *OrganizationService) invitationLink(ctx context.Context, sc OrganizationScope, rawURL, token, orgPublicID string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" {
		return "", ErrInvalidInvitationURL
	}
	// https anywhere; plain http only on a loopback host (local development).
	if u.Scheme != "https" && (u.Scheme != "http" || !isLoopbackHost(u.Hostname())) {
		return "", ErrInvalidInvitationURL
	}
	var redirects []string
	if err := s.pool.QueryRow(ctx, `
		SELECT redirect_uris FROM oauth_clients WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL
	`, sc.AppRowID, sc.TenantID).Scan(&redirects); err != nil {
		return "", fmt.Errorf("load redirect uris: %w", err)
	}
	allowed := false
	for _, r := range redirects {
		ru, err := url.Parse(r)
		if err == nil && strings.EqualFold(ru.Scheme, u.Scheme) && strings.EqualFold(ru.Host, u.Host) {
			allowed = true
			break
		}
	}
	if !allowed {
		return "", ErrInvalidInvitationURL
	}
	q := u.Query()
	q.Set("invitation", token)
	q.Set("organization", orgPublicID)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func isLoopbackHost(h string) bool {
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}

// CreateInvitation invites an email address to an organisation. An existing
// pending invitation for the same address is revoked and replaced, so a person
// never holds two live tokens for one organisation.
func (s *OrganizationService) CreateInvitation(ctx context.Context, sc OrganizationScope, ref string, in CreateOrganizationInvitationInput) (*CreatedOrganizationInvitation, error) {
	if err := s.guard(); err != nil {
		return nil, err
	}
	email := emailaddr.Normalize(in.Email)
	if addr, err := mail.ParseAddress(email); err != nil || addr.Address != email {
		return nil, ErrInvalidInvitationEmail
	}
	ttl := in.TTL
	if ttl == 0 {
		ttl = OrganizationInvitationTTL
	}
	if ttl < time.Hour || ttl > MaxOrganizationInvitationTTL {
		return nil, ErrInvalidInvitationTTL
	}
	if in.SendEmail && strings.TrimSpace(in.InvitationURL) == "" {
		return nil, ErrInvitationLinkRequired
	}

	token, err := GenerateRefreshToken()
	if err != nil {
		return nil, err
	}
	publicID, err := newInvitationPublicID()
	if err != nil {
		return nil, err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin create invitation: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	org, err := s.getOrganization(ctx, tx, sc, ref, true)
	if err != nil {
		return nil, err
	}
	if !org.IsActive {
		return nil, ErrOrganizationNotFound
	}

	link := ""
	if in.InvitationURL != "" {
		if link, err = s.invitationLink(ctx, sc, in.InvitationURL, token, org.ID); err != nil {
			return nil, err
		}
	}

	names := normaliseRoleNames(in.Roles)
	if len(names) > MaxOrganizationRolesPerMember {
		return nil, ErrOrganizationRoleLimitReached
	}
	ids, err := resolveApplicationRoles(ctx, tx, sc, names)
	if err != nil {
		return nil, err
	}
	roleIDs := make([]int64, 0, len(names))
	for _, n := range names {
		roleIDs = append(roleIDs, ids[n])
	}

	if _, err := tx.Exec(ctx, `
		UPDATE organization_invitations SET revoked_at = NOW()
		WHERE organization_id = $1 AND email = $2 AND accepted_at IS NULL AND revoked_at IS NULL
	`, org.rowID, email); err != nil {
		return nil, fmt.Errorf("replace pending invitation: %w", err)
	}

	out := &CreatedOrganizationInvitation{Token: token, InvitationURL: link}
	out.ID, out.OrganizationID, out.Email, out.Roles = publicID, org.ID, email, names
	out.Status = InvitationStatusPending
	var invitedByClient *string
	if in.InvitedByClient != "" {
		invitedByClient = &in.InvitedByClient
	}
	if err := tx.QueryRow(ctx, `
		INSERT INTO organization_invitations
		    (public_id, organization_id, application_id, tenant_id, email, role_ids,
		     token_hash, invited_by, invited_by_client, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW() + $10::INTERVAL)
		RETURNING expires_at, created_at
	`, publicID, org.rowID, sc.AppRowID, sc.TenantID, email, roleIDs, HashToken(token),
		in.InvitedBy, invitedByClient, fmt.Sprintf("%d seconds", int64(ttl.Seconds()))).
		Scan(&out.ExpiresAt, &out.CreatedAt); err != nil {
		return nil, fmt.Errorf("insert invitation: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit invitation: %w", err)
	}

	if in.SendEmail {
		out.EmailSent = s.sendInvitationEmail(ctx, sc, org.DisplayName, email, link, in.InviterName, ttl)
	}
	return out, nil
}

// sendInvitationEmail delivers the invitation through the application's
// branded user_invitation template. Delivery failure does not undo the
// invitation — the caller still holds the token and the response says the
// mail was not sent.
func (s *OrganizationService) sendInvitationEmail(ctx context.Context, sc OrganizationScope, orgName, email, link, inviter string, ttl time.Duration) bool {
	appRowID := sc.AppRowID
	msg := mailer.InvitationEmail{
		To: email, Link: link, AppName: orgName, InviterName: inviter,
		TTLMinutes: int(ttl.Minutes()),
	}
	sent, err := s.notify.Send(ctx, sc.TenantID, &appRowID, mailer.TemplateUserInvitation,
		func(sender *mailer.SMTPConfig, tmpl *mailer.Template) error {
			return s.notify.mailer.SendInvitation(ctx, sender, tmpl, msg)
		})
	if err != nil {
		s.logger.Warn().Err(err).Int64("application_id", sc.AppRowID).
			Msg("organization invitation: email delivery failed; the token is still valid")
		return false
	}
	return sent
}

// ListInvitations lists an organisation's invitations, newest first. Closed
// ones (accepted, revoked, expired) are included only when includeClosed.
func (s *OrganizationService) ListInvitations(ctx context.Context, sc OrganizationScope, ref string, includeClosed bool) ([]OrganizationInvitation, error) {
	if err := s.guard(); err != nil {
		return nil, err
	}
	org, err := s.getOrganization(ctx, s.pool, sc, ref, false)
	if err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `
		SELECT i.public_id, i.email, i.expires_at, i.created_at, i.accepted_at, i.revoked_at,
		       COALESCE((SELECT ARRAY_AGG(r.name ORDER BY r.name) FROM roles r
		                 WHERE r.id = ANY(i.role_ids) AND r.deleted_at IS NULL), '{}')
		FROM organization_invitations i
		WHERE i.organization_id = $1
		  AND ($2 OR (i.accepted_at IS NULL AND i.revoked_at IS NULL AND i.expires_at > NOW()))
		ORDER BY i.created_at DESC
		LIMIT 500
	`, org.rowID, includeClosed)
	if err != nil {
		return nil, fmt.Errorf("list invitations: %w", err)
	}
	defer rows.Close()
	out := []OrganizationInvitation{}
	for rows.Next() {
		inv := OrganizationInvitation{OrganizationID: org.ID}
		var revokedAt *time.Time
		if err := rows.Scan(&inv.ID, &inv.Email, &inv.ExpiresAt, &inv.CreatedAt, &inv.AcceptedAt,
			&revokedAt, &inv.Roles); err != nil {
			return nil, fmt.Errorf("scan invitation: %w", err)
		}
		inv.Status = invitationStatus(inv.ExpiresAt, inv.AcceptedAt, revokedAt)
		out = append(out, inv)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate invitations: %w", err)
	}
	return out, nil
}

// RevokeInvitation closes a pending invitation. Revoking one that is already
// closed is reported as not found, so the call is idempotent from the
// caller's point of view only in its effect.
func (s *OrganizationService) RevokeInvitation(ctx context.Context, sc OrganizationScope, ref, invitationID string) error {
	if err := s.guard(); err != nil {
		return err
	}
	org, err := s.getOrganization(ctx, s.pool, sc, ref, false)
	if err != nil {
		return err
	}
	ct, err := s.pool.Exec(ctx, `
		UPDATE organization_invitations SET revoked_at = NOW()
		WHERE organization_id = $1 AND public_id = $2
		  AND accepted_at IS NULL AND revoked_at IS NULL
	`, org.rowID, strings.TrimSpace(invitationID))
	if err != nil {
		return fmt.Errorf("revoke invitation: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrOrganizationInvitationInvalid
	}
	return nil
}

type pendingInvitation struct {
	id                         int64
	publicID                   string
	orgRowID, appRowID, tenant int64
	email                      string
	roleIDs                    []int64
	org                        OrganizationRef
	expiresAt                  time.Time
}

func loadPendingInvitation(ctx context.Context, q queryRower, token string, forUpdate bool) (*pendingInvitation, error) {
	if token == "" {
		return nil, ErrOrganizationInvitationInvalid
	}
	sql := `
		SELECT i.id, i.public_id, i.organization_id, i.application_id, i.tenant_id, i.email,
		       i.role_ids, i.expires_at, o.public_id, o.slug, o.display_name
		FROM organization_invitations i
		JOIN organizations o ON o.id = i.organization_id
		WHERE i.token_hash = $1
		  AND i.accepted_at IS NULL AND i.revoked_at IS NULL AND i.expires_at > NOW()
		  AND o.deleted_at IS NULL AND o.is_active = true`
	if forUpdate {
		sql += ` FOR UPDATE OF i`
	}
	var p pendingInvitation
	err := q.QueryRow(ctx, sql, HashToken(token)).Scan(&p.id, &p.publicID, &p.orgRowID, &p.appRowID,
		&p.tenant, &p.email, &p.roleIDs, &p.expiresAt, &p.org.ID, &p.org.Slug, &p.org.DisplayName)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrOrganizationInvitationInvalid
		}
		return nil, fmt.Errorf("load invitation: %w", err)
	}
	p.org.rowID = p.orgRowID
	return &p, nil
}

func liveRoleNames(ctx context.Context, q pgx.Tx, p *pendingInvitation) ([]string, error) {
	var names []string
	if err := q.QueryRow(ctx, `
		SELECT COALESCE(ARRAY_AGG(name ORDER BY name), '{}') FROM roles
		WHERE id = ANY($1) AND tenant_id = $2 AND application_id = $3
		  AND is_system = false AND deleted_at IS NULL
	`, p.roleIDs, p.tenant, p.appRowID).Scan(&names); err != nil {
		return nil, fmt.Errorf("resolve invitation roles: %w", err)
	}
	return names, nil
}

// PreviewInvitation describes a pending invitation to the holder of its token.
func (s *OrganizationService) PreviewInvitation(ctx context.Context, token string) (*OrganizationInvitationPreview, error) {
	if err := s.guard(); err != nil {
		return nil, err
	}
	p, err := loadPendingInvitation(ctx, s.pool, token, false)
	if err != nil {
		return nil, err
	}
	out := &OrganizationInvitationPreview{Organization: p.org, Email: p.email, ExpiresAt: p.expiresAt}
	if err := s.pool.QueryRow(ctx, `
		SELECT COALESCE((SELECT ARRAY_AGG(name ORDER BY name) FROM roles
		                 WHERE id = ANY($1) AND deleted_at IS NULL), '{}'),
		       EXISTS (SELECT 1 FROM users
		               WHERE tenant_id = $2 AND application_id = $3 AND email = $4 AND deleted_at IS NULL)
	`, p.roleIDs, p.tenant, p.appRowID, p.email).Scan(&out.Roles, &out.AccountExists); err != nil {
		return nil, fmt.Errorf("preview invitation: %w", err)
	}
	return out, nil
}

// AcceptInvitation accepts an invitation in one transaction: the account (when
// new), the membership, the organisation roles and the invitation's closure
// either all happen or none do.
func (s *OrganizationService) AcceptInvitation(ctx context.Context, in AcceptOrganizationInvitationInput) (*AcceptedOrganizationInvitation, error) {
	if err := s.guard(); err != nil {
		return nil, err
	}

	// Validate the token BEFORE any password work. Argon2id is deliberately
	// expensive; hashing first would let anyone spend server CPU by posting
	// random tokens with a password. The row is re-read under lock below.
	if _, err := loadPendingInvitation(ctx, s.pool, in.Token, false); err != nil {
		return nil, err
	}

	// Hash before the transaction: Argon2id is deliberately slow and must not
	// hold row locks while it runs.
	var hash string
	if in.ExistingUserID == nil {
		if len(in.Password) < 8 {
			return nil, ErrWeakPassword
		}
		if s.hasher == nil {
			return nil, fmt.Errorf("password hasher not configured")
		}
		h, err := s.hasher.Hash(ctx, in.Password)
		if err != nil {
			return nil, fmt.Errorf("hash password: %w", err)
		}
		hash = string(h)
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin accept invitation: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	p, err := loadPendingInvitation(ctx, tx, in.Token, true)
	if err != nil {
		return nil, err
	}
	sc := OrganizationScope{TenantID: p.tenant, AppRowID: p.appRowID}

	var userID int64
	created := false
	if in.ExistingUserID != nil {
		// The signed-in account must be the invited one, in the invitation's
		// application. Same error as an invalid token for every mismatch.
		if in.AppRowID != p.appRowID {
			return nil, ErrOrganizationInvitationInvalid
		}
		var ok bool
		if err := tx.QueryRow(ctx, `
			SELECT EXISTS (SELECT 1 FROM users
			               WHERE id = $1 AND tenant_id = $2 AND application_id = $3
			                 AND email = $4 AND is_active = true AND deleted_at IS NULL)
		`, *in.ExistingUserID, p.tenant, p.appRowID, p.email).Scan(&ok); err != nil {
			return nil, fmt.Errorf("verify invitee: %w", err)
		}
		if !ok {
			return nil, ErrOrganizationInvitationInvalid
		}
		userID = *in.ExistingUserID
	} else {
		var exists bool
		if err := tx.QueryRow(ctx, `
			SELECT EXISTS (SELECT 1 FROM users
			               WHERE tenant_id = $1 AND application_id = $2 AND email = $3 AND deleted_at IS NULL)
		`, p.tenant, p.appRowID, p.email).Scan(&exists); err != nil {
			return nil, fmt.Errorf("check existing account: %w", err)
		}
		if exists {
			return nil, ErrOrganizationInvitationAccountExists
		}
		if userID, err = createInvitedUser(ctx, tx, p, strings.TrimSpace(in.FirstName), strings.TrimSpace(in.LastName), hash); err != nil {
			return nil, err
		}
		created = true
	}

	// Lock the organisation row so the member cap is enforced against
	// concurrent additions, exactly as AddMember does.
	if _, err := tx.Exec(ctx, `SELECT 1 FROM organizations WHERE id = $1 FOR UPDATE`, p.orgRowID); err != nil {
		return nil, fmt.Errorf("lock organization: %w", err)
	}
	if _, err := s.addMemberTx(ctx, tx, sc, p.orgRowID, userID, nil); err != nil {
		return nil, err
	}
	names, err := liveRoleNames(ctx, tx, p)
	if err != nil {
		return nil, err
	}
	if len(names) > 0 {
		if _, _, err := s.assignRolesTx(ctx, tx, sc, p.orgRowID, userID, names, false, nil); err != nil {
			return nil, err
		}
	}
	if _, err := tx.Exec(ctx, `
		UPDATE organization_invitations SET accepted_at = NOW(), accepted_user_id = $2 WHERE id = $1
	`, p.id, userID); err != nil {
		return nil, fmt.Errorf("close invitation: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit accept invitation: %w", err)
	}

	m, err := s.getMember(ctx, s.pool, sc, p.orgRowID, userID)
	if err != nil {
		return nil, err
	}
	return &AcceptedOrganizationInvitation{
		UserID: strconv.FormatInt(userID, 10), Organization: p.org, Roles: m.Roles,
		AccountCreated: created,
		tenantID:       p.tenant, appRowID: p.appRowID, orgRowID: p.orgRowID, invitationID: p.publicID,
	}, nil
}

// createInvitedUser creates the invitee's account in the invitation's
// application, the same shape Register writes: the application's default role,
// its user_roles grant and a credential. The address is verified — the invitee
// followed a link sent to it.
func createInvitedUser(ctx context.Context, tx pgx.Tx, p *pendingInvitation, first, last, hash string) (int64, error) {
	var roleID *int64
	if err := tx.QueryRow(ctx, `
		SELECT id FROM roles
		WHERE tenant_id = $1 AND application_id = $2 AND is_default = true
		  AND is_system = false AND deleted_at IS NULL
		FOR SHARE
	`, p.tenant, p.appRowID).Scan(&roleID); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return 0, fmt.Errorf("fetch default role: %w", err)
	}
	var userID int64
	if err := tx.QueryRow(ctx, `
		INSERT INTO users (tenant_id, email, first_name, last_name, role_id, application_id,
		                   is_active, email_verified)
		VALUES ($1, $2, $3, $4, $5, $6, true, true)
		RETURNING id
	`, p.tenant, p.email, first, last, roleID, p.appRowID).Scan(&userID); err != nil {
		if isUniqueViolation(err) {
			return 0, ErrOrganizationInvitationAccountExists
		}
		return 0, fmt.Errorf("insert invited user: %w", err)
	}
	if roleID != nil {
		if _, err := tx.Exec(ctx, `
			INSERT INTO user_roles (user_id, role_id, tenant_id, granted_by)
			VALUES ($1, $2, $3, NULL)
			ON CONFLICT (user_id, role_id) DO NOTHING
		`, userID, *roleID, p.tenant); err != nil {
			return 0, fmt.Errorf("record default role grant: %w", err)
		}
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO user_credentials (user_id, tenant_id, password_hash) VALUES ($1, $2, $3)
	`, userID, p.tenant, hash); err != nil {
		return 0, fmt.Errorf("insert credentials: %w", err)
	}
	return userID, nil
}
