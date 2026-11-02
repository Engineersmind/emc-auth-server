package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"

	"github.com/engineersmind/emc-auth-server/internal/metrics"
)

// ---------------------------------------------------------------------------
// Organisation-aware token minting.
//
// Every user token is minted by issueTokenPairWithScope, so this is the single
// place where a session acquires — or keeps — an organisation. Doing it at the
// mint rather than in each login handler means no sign-in method (password,
// MFA completion, magic link, social, passkey, authorization code, refresh,
// switch) can forget to check membership.
// ---------------------------------------------------------------------------

// OrganizationSelectionTTL is how long a selection token stays usable. Matches
// the MFA pending-session lifetime: long enough to pick from a list, short
// enough that a leaked token is worth little.
const OrganizationSelectionTTL = 5 * time.Minute

const orgSelectionKeyPrefix = "org:select:"

// WithOrganizations wires the organisation service into the mint. Without it —
// or with the service switched off — every application behaves as
// organizations_mode 'off'.
func (s *AuthService) WithOrganizations(svc *OrganizationService) *AuthService {
	s.orgSvc = svc
	if svc != nil {
		svc.sessions = s
	}
	return s
}

// Organizations returns the organisation service, or nil.
//
// Safe on a nil receiver, and so is every OrganizationService method the
// sign-in paths call, so a handler built without an AuthService (as some tests
// build the authorize handler) behaves as organisations-off instead of
// panicking.
func (s *AuthService) Organizations() *OrganizationService {
	if s == nil {
		return nil
	}
	return s.orgSvc
}

func countOrganizationParamIgnored() { metrics.OrganizationParamIgnored.Inc() }

func countOrganizationMint(outcome string) {
	metrics.OrganizationMints.WithLabelValues(outcome).Inc()
}

// OrganizationSelectionRequiredError is returned by a sign-in when the
// application requires an organisation and the user belongs to several. No
// session exists yet: the client shows Organizations, then calls
// CompleteOrganizationSelection with SelectionToken and the chosen id.
//
// Returned only AFTER every credential and second-factor check has passed, so
// the list it carries is never shown to someone who has not proved who they are.
type OrganizationSelectionRequiredError struct {
	SelectionToken string            `json:"selection_token"`
	Organizations  []OrganizationRef `json:"organizations"`
	ExpiresIn      int               `json:"expires_in"`
}

func (e *OrganizationSelectionRequiredError) Error() string {
	return "organization selection required"
}

// orgSelectionState is everything needed to resume a mint once the user has
// picked an organisation. Stored in Redis under the token's hash only.
type orgSelectionState struct {
	UserID         int64     `json:"user_id"`
	TenantID       int64     `json:"tenant_id"`
	Email          string    `json:"email"`
	Role           string    `json:"role"`
	Perms          []string  `json:"perms"`
	AppID          string    `json:"app_id"`
	Scope          string    `json:"scope,omitempty"`
	Persistent     bool      `json:"persistent"`
	AMR            []string  `json:"amr"`
	AuthTime       time.Time `json:"auth_time"`
	Grant          string    `json:"grant"`
	ActiveRoles    []string  `json:"active_roles,omitempty"`
	Audience       string    `json:"audience,omitempty"`
	PinnedAudience string    `json:"pinned_audience,omitempty"`
	FilterPerms    bool      `json:"filter_perms,omitempty"`
	// Choices are the organisation row ids offered. Completion must name one of
	// them, so a selection token cannot be spent on an organisation the user was
	// not offered even if their memberships changed in the meantime.
	Choices []int64 `json:"choices"`
}

// resolveMintOrganization decides the organisation half of a mint.
//
// A nil result with a nil error means "no organisation": the token is minted
// exactly as it was before organisations existed.
//
// ROTATION (sess.sessionID set): the session row is the authority. A session
// bound to an organisation keeps it only while the membership is live; if it is
// not — removed, suspended, organisation deactivated, feature or application
// switched off — the session is revoked and the refresh is refused. It never
// degrades to an organisation-less token, because that would quietly change
// what the relying party believes the session is.
//
// NEW SESSION: see OrganizationService.DecideOrganization.
func (s *AuthService) resolveMintOrganization(ctx context.Context, userID, tenantID int64, email, role string, perms []string, sess sessionContext, appID, scope string) (*mintOrganization, error) {
	appRowID := parseAppIDValue(appID)

	if sess.sessionID != nil {
		return s.resolveRotationOrganization(ctx, userID, tenantID, appRowID, *sess.sessionID)
	}

	if sess.org.skip || !s.orgSvc.Enabled() || appRowID == 0 {
		if sess.org.requested != "" && !sess.org.skip {
			countOrganizationParamIgnored()
		}
		return nil, nil
	}

	var orgRowID *int64
	if sess.org.boundID != nil {
		mode, err := s.orgSvc.ApplicationMode(ctx, appRowID)
		if err != nil {
			countOrganizationMint("unavailable")
			return nil, fmt.Errorf("%w: %v", ErrOrganizationUnavailable, err)
		}
		if mode == OrganizationsModeOff {
			return nil, nil
		}
		orgRowID = sess.org.boundID
	} else {
		dec, err := s.orgSvc.DecideOrganization(ctx, userID, appRowID, sess.org.requested, sess.org.personal)
		if err != nil {
			return nil, s.countOrganizationFailure(err)
		}
		if len(dec.Choices) > 0 {
			sel, err := s.storeOrganizationSelection(ctx, userID, tenantID, email, role, perms, sess, appID, scope, dec.Choices)
			if err != nil {
				countOrganizationMint("unavailable")
				return nil, err
			}
			countOrganizationMint("selection_required")
			return nil, sel
		}
		if dec.OrgRowID == nil {
			if dec.applies {
				countOrganizationMint("none")
			}
			return nil, nil
		}
		orgRowID = dec.OrgRowID
	}

	m, err := s.orgSvc.loadMintOrganization(ctx, *orgRowID, userID, appRowID)
	if err != nil {
		return nil, s.countOrganizationFailure(err)
	}
	countOrganizationMint("bound")
	return m, nil
}

func (s *AuthService) countOrganizationFailure(err error) error {
	if errors.Is(err, ErrOrganizationAccessDenied) {
		countOrganizationMint("denied")
	} else {
		countOrganizationMint("unavailable")
	}
	return err
}

// resolveRotationOrganization re-validates the organisation a session was signed
// in to. Runs on every refresh, so it is a single primary-key read for the
// overwhelmingly common case of a session with no organisation.
func (s *AuthService) resolveRotationOrganization(ctx context.Context, userID, tenantID, appRowID, sessionID int64) (*mintOrganization, error) {
	var orgID *int64
	if err := s.pool.QueryRow(ctx, `SELECT organization_id FROM user_sessions WHERE id = $1`, sessionID).Scan(&orgID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrInvalidRefreshToken
		}
		return nil, fmt.Errorf("load session organization: %w", err)
	}

	if orgID == nil {
		// An organisation-less session in an application that now REQUIRES one.
		// SetApplicationMode revokes these when the mode changes; this catches a
		// session minted concurrently with that change.
		if s.orgSvc.Enabled() && appRowID != 0 {
			mode, err := s.orgSvc.ApplicationMode(ctx, appRowID)
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrOrganizationUnavailable, err)
			}
			if mode == OrganizationsModeRequired {
				userApp, err := s.orgSvc.userApplicationID(ctx, userID)
				if err != nil {
					return nil, err
				}
				if userApp != nil && *userApp == appRowID {
					s.endOrganizationSession(ctx, userID, tenantID, sessionID)
					return nil, ErrInvalidRefreshToken
				}
			}
		}
		return nil, nil
	}

	// A bound session survives only while organisations still apply to it.
	if !s.orgSvc.Enabled() || appRowID == 0 {
		s.endOrganizationSession(ctx, userID, tenantID, sessionID)
		return nil, ErrInvalidRefreshToken
	}
	mode, err := s.orgSvc.ApplicationMode(ctx, appRowID)
	if err != nil {
		countOrganizationMint("unavailable")
		return nil, fmt.Errorf("%w: %v", ErrOrganizationUnavailable, err)
	}
	if mode == OrganizationsModeOff {
		s.endOrganizationSession(ctx, userID, tenantID, sessionID)
		return nil, ErrInvalidRefreshToken
	}

	m, err := s.orgSvc.loadMintOrganization(ctx, *orgID, userID, appRowID)
	if err != nil {
		if errors.Is(err, ErrOrganizationAccessDenied) {
			s.endOrganizationSession(ctx, userID, tenantID, sessionID)
			return nil, ErrInvalidRefreshToken
		}
		countOrganizationMint("unavailable")
		return nil, err
	}
	countOrganizationMint("bound")
	return m, nil
}

// endOrganizationSession revokes a session whose organisation access lapsed.
// The refresh that discovered it has already consumed its token; revoking the
// session too means nothing else in the family can be presented afterwards.
func (s *AuthService) endOrganizationSession(ctx context.Context, userID, tenantID, sessionID int64) {
	countOrganizationMint("revoked")
	if _, err := s.revokeSession(ctx, userID, tenantID, sessionID, RevokeReasonOrganization); err != nil {
		s.logger.Warn().Err(err).Int64("session_id", sessionID).
			Msg("organization: could not revoke a session whose organization access lapsed")
	}
}

func (s *AuthService) storeOrganizationSelection(ctx context.Context, userID, tenantID int64, email, role string, perms []string, sess sessionContext, appID, scope string, choices []OrganizationRef) (*OrganizationSelectionRequiredError, error) {
	if s.redisCli == nil {
		return nil, fmt.Errorf("%w: selection storage not configured", ErrOrganizationUnavailable)
	}
	raw, err := GenerateRefreshToken()
	if err != nil {
		return nil, err
	}
	authTime := sess.authTime
	if authTime.IsZero() {
		authTime = time.Now().UTC()
	}
	state := orgSelectionState{
		UserID: userID, TenantID: tenantID, Email: email, Role: role, Perms: perms,
		AppID: appID, Scope: scope, Persistent: sess.persistent, AMR: sess.amr,
		AuthTime: authTime, Grant: sess.grant, ActiveRoles: sess.activeRoles,
		Audience: sess.audience, PinnedAudience: sess.pinnedAudience,
		FilterPerms: sess.filterPermsForClient,
	}
	for _, c := range choices {
		state.Choices = append(state.Choices, c.rowID)
	}
	blob, err := json.Marshal(state)
	if err != nil {
		return nil, fmt.Errorf("encode organization selection: %w", err)
	}
	if err := s.redisCli.Set(ctx, orgSelectionKeyPrefix+HashToken(raw), blob, OrganizationSelectionTTL).Err(); err != nil {
		return nil, fmt.Errorf("%w: store selection: %v", ErrOrganizationUnavailable, err)
	}
	return &OrganizationSelectionRequiredError{
		SelectionToken: raw,
		Organizations:  choices,
		ExpiresIn:      int(OrganizationSelectionTTL.Seconds()),
	}, nil
}

// CompleteOrganizationSelection finishes a sign-in that stopped at an
// organisation choice. The token is single-use: it is deleted before the mint,
// so a replay fails whether or not the first attempt succeeded.
func (s *AuthService) CompleteOrganizationSelection(ctx context.Context, selectionToken, organization string) (*AuthResult, error) {
	if s.redisCli == nil || selectionToken == "" || strings.TrimSpace(organization) == "" {
		return nil, ErrOrganizationSelectionInvalid
	}
	blob, err := s.redisCli.GetDel(ctx, orgSelectionKeyPrefix+HashToken(selectionToken)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, ErrOrganizationSelectionInvalid
		}
		return nil, fmt.Errorf("%w: load selection: %v", ErrOrganizationUnavailable, err)
	}
	var st orgSelectionState
	if err := json.Unmarshal(blob, &st); err != nil {
		return nil, ErrOrganizationSelectionInvalid
	}

	appRowID := parseAppIDValue(st.AppID)
	orgRowID, err := s.orgSvc.resolveOrganizationRowID(ctx, appRowID, organization)
	if err != nil {
		return nil, s.countOrganizationFailure(err)
	}
	offered := false
	for _, id := range st.Choices {
		if id == orgRowID {
			offered = true
			break
		}
	}
	if !offered {
		countOrganizationMint("denied")
		return nil, ErrOrganizationAccessDenied
	}

	sess := sessionContext{
		persistent: st.Persistent, amr: st.AMR, authTime: st.AuthTime,
		activeRoles: st.ActiveRoles, audience: st.Audience, pinnedAudience: st.PinnedAudience,
		filterPermsForClient: st.FilterPerms,
		org:                  orgSessionRequest{boundID: &orgRowID},
	}
	// The grant is the one that began the sign-in. Mapped back to its constant
	// through an allow-list rather than copied from the stored state, so a
	// selection can only ever resume a user sign-in method this server defines.
	switch st.Grant {
	case GrantPassword:
		sess.grant = GrantPassword
	case GrantMagicLink:
		sess.grant = GrantMagicLink
	case GrantSocial:
		sess.grant = GrantSocial
	case GrantPasskey:
		sess.grant = GrantPasskey
	case GrantAuthorizationCode:
		sess.grant = GrantAuthorizationCode
	default:
		return nil, ErrOrganizationSelectionInvalid
	}
	return s.issueTokenPairWithScope(ctx, st.UserID, st.TenantID, st.Email, st.Role, st.Perms, sess, st.AppID, st.Scope)
}

// SwitchOrganizationInput moves a signed-in user to another organisation.
type SwitchOrganizationInput struct {
	// RefreshToken proves the session being switched from.
	RefreshToken string
	// Organization is the target's public id or slug. Empty with Personal set
	// asks for no organisation.
	Organization string
	Personal     bool
}

// SwitchOrganization creates a NEW session in another organisation from an
// existing one, without asking for a password again.
//
// The new session inherits auth_time and amr from the old one, so its absolute
// deadline is computed from the original sign-in: switching can never extend a
// session or upgrade how strongly it was authenticated. The old session is left
// alone — a user may have two tabs in two organisations.
func (s *AuthService) SwitchOrganization(ctx context.Context, in SwitchOrganizationInput) (*AuthResult, error) {
	if !s.orgSvc.Enabled() {
		return nil, ErrOrganizationsNotApplicable
	}
	if in.RefreshToken == "" {
		return nil, ErrInvalidRefreshToken
	}

	var (
		userID, tenantID int64
		appRowID         *int64
		carried          sessionContext
		pinnedAudience   *string
	)
	err := s.pool.QueryRow(ctx, `
		SELECT s.user_id, s.tenant_id, s.application_id,
		       s.is_persistent, s.auth_time, s.amr, rt.audience, rt.active_roles
		FROM refresh_tokens rt
		JOIN user_sessions s ON s.id = rt.session_id
		WHERE rt.token_hash = $1
		  AND `+LiveTokenWhere("rt.")+`
		  AND `+LiveSessionWhere("s."),
		HashToken(in.RefreshToken)).Scan(&userID, &tenantID, &appRowID,
		&carried.persistent, &carried.authTime, &carried.amr, &pinnedAudience, &carried.activeRoles)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrInvalidRefreshToken
		}
		return nil, fmt.Errorf("lookup refresh token for switch: %w", err)
	}
	if appRowID == nil {
		return nil, ErrOrganizationsNotApplicable
	}
	mode, err := s.orgSvc.ApplicationMode(ctx, *appRowID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOrganizationUnavailable, err)
	}
	if mode == OrganizationsModeOff {
		return nil, ErrOrganizationsNotApplicable
	}

	var email, roleName string
	if err := s.pool.QueryRow(ctx, `
		SELECT u.email, COALESCE(r.name, '')
		FROM users u
		LEFT JOIN roles r ON r.id = u.role_id AND r.deleted_at IS NULL
		WHERE u.id = $1 AND u.tenant_id = $2 AND u.application_id = $3
		  AND u.is_active = true AND u.deleted_at IS NULL
	`, userID, tenantID, *appRowID).Scan(&email, &roleName); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrInvalidRefreshToken
		}
		return nil, fmt.Errorf("load user for switch: %w", err)
	}

	perms, err := s.permissionsForRefresh(ctx, userID, tenantID, carried.activeRoles)
	if err != nil {
		s.logger.Warn().Err(err).Msg("organization switch: failed to load permissions, continuing with empty set")
		perms = []string{}
	}

	carried.grant = GrantRefreshToken
	if pinnedAudience != nil {
		carried.pinnedAudience = *pinnedAudience
	}
	carried.org = orgSessionRequest{requested: strings.TrimSpace(in.Organization), personal: in.Personal}
	if carried.org.requested != "" {
		carried.org.personal = false
	}

	result, err := s.issueTokenPair(ctx, userID, tenantID, email, roleName, perms, carried, appIDClaim(appRowID))
	if err != nil {
		metrics.OrganizationSwitches.WithLabelValues("denied").Inc()
		return nil, err
	}
	metrics.OrganizationSwitches.WithLabelValues("ok").Inc()
	return result, nil
}

// ---------------------------------------------------------------------------
// Session revocation driven by organisation changes.
// ---------------------------------------------------------------------------

type sessionRow struct{ id, userID, tenantID int64 }

func (s *AuthService) collectSessions(ctx context.Context, sql string, args ...any) []sessionRow {
	rows, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		s.logger.Error().Err(err).Msg("organization: could not list sessions to revoke")
		return nil
	}
	defer rows.Close()
	var out []sessionRow
	for rows.Next() {
		var r sessionRow
		if err := rows.Scan(&r.id, &r.userID, &r.tenantID); err != nil {
			s.logger.Error().Err(err).Msg("organization: could not scan session to revoke")
			return out
		}
		out = append(out, r)
	}
	return out
}

func (s *AuthService) revokeSessionRows(ctx context.Context, rows []sessionRow) int {
	n := 0
	for _, r := range rows {
		k, err := s.revokeSession(ctx, r.userID, r.tenantID, r.id, RevokeReasonOrganization)
		if err != nil {
			s.logger.Error().Err(err).Int64("session_id", r.id).
				Msg("organization: session revocation failed; it ends at its next refresh instead")
			continue
		}
		n += int(k)
	}
	return n
}

// revokeOrganizationSessions revokes every live session signed in to an
// organisation, or only one member's when userID is set.
func (s *AuthService) revokeOrganizationSessions(ctx context.Context, orgRowID int64, userID *int64) int {
	return s.revokeSessionRows(ctx, s.collectSessions(ctx, `
		SELECT id, user_id, tenant_id FROM user_sessions
		WHERE organization_id = $1 AND ($2::BIGINT IS NULL OR user_id = $2)
		  AND revoked_at IS NULL
	`, orgRowID, userID))
}

// revokeApplicationSessionsByBinding revokes an application's live sessions
// that ARE bound to an organisation (bound=true: the application left
// organisations behind) or that are NOT (bound=false: the application now
// requires one). Tenant-level users signing in through the application are
// never affected by the latter — organisations do not apply to them.
func (s *AuthService) revokeApplicationSessionsByBinding(ctx context.Context, appRowID int64, bound bool) int {
	if bound {
		return s.revokeSessionRows(ctx, s.collectSessions(ctx, `
			SELECT id, user_id, tenant_id FROM user_sessions
			WHERE application_id = $1 AND organization_id IS NOT NULL AND revoked_at IS NULL
		`, appRowID))
	}
	return s.revokeSessionRows(ctx, s.collectSessions(ctx, `
		SELECT s.id, s.user_id, s.tenant_id FROM user_sessions s
		JOIN users u ON u.id = s.user_id AND u.application_id = $1
		WHERE s.application_id = $1 AND s.organization_id IS NULL AND s.revoked_at IS NULL
	`, appRowID))
}

// sessionOrganization re-validates the organisation of an existing session
// without minting, for the refresh grace window: the request it authorises
// must see the same organisation a rotation would, or none at all.
func (s *AuthService) sessionOrganization(ctx context.Context, userID, tenantID, sessionID int64) (*mintOrganization, error) {
	var appID *int64
	if err := s.pool.QueryRow(ctx, `SELECT application_id FROM user_sessions WHERE id = $1`, sessionID).Scan(&appID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrInvalidRefreshToken
		}
		return nil, fmt.Errorf("load session application: %w", err)
	}
	var appRowID int64
	if appID != nil {
		appRowID = *appID
	}
	return s.resolveRotationOrganization(ctx, userID, tenantID, appRowID, sessionID)
}
