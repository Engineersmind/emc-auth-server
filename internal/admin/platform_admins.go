package admin

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// ---------------------------------------------------------------------------
// Cross-tenant administrator directory (issue #97 follow-on).
//
// The per-tenant listing (ListTenantAdmins) answers "who administers THIS
// tenant?". This answers the platform question — "who administers anything?" —
// which is the one a platform admin actually has: they oversee every tenant and
// cannot open forty tenant pages to find the one owner who never accepted an
// invitation.
//
// Restricted to tenant:manage. It deliberately spans tenants, so it is the one
// listing in the system that is not tenant-bounded.
// ---------------------------------------------------------------------------

// PlatformAdminResult is one administrator anywhere in the system.
//
// Richer than TenantAdminResult because the reader has no other context: they
// are looking at a name they may not recognise, in a tenant they may not have
// opened, so the tenant, sign-in history and second-factor state have to be on
// the row itself.
type PlatformAdminResult struct {
	// ID is the tenant_admins row, which is what the per-tenant management
	// endpoints take. UserID is the account behind it, for the user-detail and
	// session endpoints.
	ID     string `json:"id"`
	UserID string `json:"user_id"`

	TenantID   string `json:"tenant_id"`
	TenantName string `json:"tenant_name"`
	TenantSlug string `json:"tenant_slug"`

	Email string `json:"email"`
	Name  string `json:"name"`
	// Role is "owner" or "co_owner".
	Role string `json:"role"`
	// Applications names the applications a co-owner administers. Empty for an
	// owner, who administers every application in their tenant — the two empties
	// mean opposite things, so read this with Role.
	Applications []string `json:"applications"`
	IsPrimary    bool     `json:"is_primary"`

	// Status is "active", "pending_invitation" (granted but never accepted), or
	// "blocked". Distinguishing the last matters: a blocked administrator still
	// holds their grant and regains it the moment the block is lifted.
	Status        string     `json:"status"`
	EmailVerified bool       `json:"email_verified"`
	MFAEnabled    bool       `json:"mfa_enabled"`
	LastLoginAt   *time.Time `json:"last_login_at"`
	LoginsCount   int        `json:"logins_count"`
	CreatedAt     time.Time  `json:"created_at"`
}

// PlatformAdminFilter narrows the directory.
type PlatformAdminFilter struct {
	Search string // ILIKE over email, name, tenant name and slug
	Role   string // "owner", "co_owner", or "" for both
	Status string // "active", "pending_invitation", "blocked", or "" for all
	Page   int
	Limit  int
}

// PlatformAdminsPage wraps a paginated directory listing.
type PlatformAdminsPage struct {
	Data       []PlatformAdminResult `json:"data"`
	Total      int                   `json:"total"`
	Page       int                   `json:"page"`
	TotalPages int                   `json:"total_pages"`
	PerPage    int                   `json:"per_page"`
}

// PlatformAdminStats is the directory summary, so the platform admin sees the
// shape of the estate before filtering it.
//
// PendingInvitations and NoMFA are the two numbers worth acting on: the first is
// tenants nobody has taken ownership of, the second is privileged accounts
// protected by a password alone.
type PlatformAdminStats struct {
	TotalAdmins         int `json:"total_admins"`
	Owners              int `json:"owners"`
	CoOwners            int `json:"co_owners"`
	PendingInvitations  int `json:"pending_invitations"`
	NoMFA               int `json:"no_mfa"`
	TenantsWithoutOwner int `json:"tenants_without_owner"`
}

// platformAdminSelect projects one directory row. The per-row subqueries are
// index-backed and bounded by the page size, matching userEnrichmentColumns'
// approach rather than joining and grouping across every tenant.
const platformAdminSelect = `
	SELECT ta.id, ta.user_id, ta.tenant_id,
	       COALESCE(NULLIF(t.display_name, ''), t.name), t.slug,
	       u.email, TRIM(CONCAT(u.first_name, ' ', u.last_name)), ta.admin_role,
	       COALESCE((
	           SELECT array_agg(oc.name ORDER BY oc.name)
	           FROM tenant_admin_app_scopes sc
	           JOIN oauth_clients oc ON oc.id = sc.application_id
	           WHERE sc.admin_id = ta.id
	       ), '{}'),
	       (t.primary_admin_id = ta.id),
	       ta.activated_at IS NOT NULL,
	       u.blocked_at IS NOT NULL,
	       u.is_active,
	       u.email_verified,
	       EXISTS (SELECT 1 FROM totp_secrets ts WHERE ts.user_id = u.id AND ts.is_active)
	         OR EXISTS (SELECT 1 FROM email_mfa_settings em WHERE em.user_id = u.id AND em.is_active),
	       -- GREATEST over both sources: refresh_tokens is finer but is now reaped
	       -- once sessions die, so on its own it would report NULL for a dormant
	       -- administrator and show them as having never signed in. audit_logs is
	       -- the durable half. Same reasoning as userEnrichmentColumns — see there.
	       GREATEST(
	           (SELECT MAX(COALESCE(rt.last_used_at, rt.created_at))
	            FROM refresh_tokens rt WHERE rt.user_id = u.id AND rt.tenant_id = u.tenant_id),
	           (SELECT MAX(al.created_at) FROM audit_logs al
	            WHERE al.user_id = u.id AND al.tenant_id = u.tenant_id
	              AND al.action IN (
	                  'auth.login', 'auth.google_login', 'auth.github_login',
	                  'auth.magic_link_requested', 'auth.register'))
	       ),
	       -- Served by idx_audit_logs_user_action_created
	       -- (user_id, action, created_at DESC) WHERE user_id IS NOT NULL, from
	       -- migration 00055: the leading two columns match this predicate
	       -- exactly. tenant_id is a residual check over rows that are already
	       -- only this user's logins, so it does not widen the scan. Bounded by
	       -- the page size, like every other subquery here.
	       (SELECT COUNT(*) FROM audit_logs al
	        WHERE al.user_id = u.id AND al.tenant_id = u.tenant_id AND al.action = 'auth.login'),
	       ta.created_at
	FROM tenant_admins ta
	JOIN users u   ON u.id = ta.user_id
	JOIN tenants t ON t.id = ta.tenant_id
`

// platformAdminWhere is shared by the count and the page so the total can never
// describe a different set from the rows.
const platformAdminWhere = `
	WHERE ta.deleted_at IS NULL
	  AND u.deleted_at IS NULL
	  AND ($1 = '%%' OR u.email ILIKE $1 OR u.first_name ILIKE $1 OR u.last_name ILIKE $1
	       OR t.name ILIKE $1 OR t.slug ILIKE $1)
	  AND ($2 = '' OR ta.admin_role = $2)
	  AND ($3 = '' OR
	       ($3 = 'blocked'            AND u.blocked_at IS NOT NULL) OR
	       ($3 = 'pending_invitation' AND ta.activated_at IS NULL AND u.blocked_at IS NULL) OR
	       ($3 = 'active'             AND ta.activated_at IS NOT NULL AND u.blocked_at IS NULL AND u.is_active))
`

// ListPlatformAdministrators returns every administrator across every tenant.
func (s *Service) ListPlatformAdministrators(ctx context.Context, f PlatformAdminFilter) (*PlatformAdminsPage, error) {
	if f.Page < 1 {
		f.Page = 1
	}
	if f.Limit < 1 {
		f.Limit = 25
	}
	if f.Limit > 100 {
		f.Limit = 100
	}
	if f.Role != "" && f.Role != auth.AdminRoleOwner && f.Role != auth.AdminRoleCoOwner {
		return nil, fmt.Errorf("role must be %q or %q", auth.AdminRoleOwner, auth.AdminRoleCoOwner)
	}
	switch f.Status {
	case "", "active", "pending_invitation", "blocked":
	default:
		return nil, fmt.Errorf(`status must be "active", "pending_invitation", "blocked", or empty`)
	}

	search := "%" + f.Search + "%"

	var total int
	if err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM tenant_admins ta
		JOIN users u   ON u.id = ta.user_id
		JOIN tenants t ON t.id = ta.tenant_id
	`+platformAdminWhere, search, f.Role, f.Status).Scan(&total); err != nil {
		return nil, fmt.Errorf("count platform administrators: %w", err)
	}

	rows, err := s.pool.Query(ctx, platformAdminSelect+platformAdminWhere+`
		-- Newest grant first.
		--
		-- Not by tenant name, which is what this was: grouping by tenant scattered
		-- one administrator across the list, so a person holding three tenants
		-- appeared under three separate headings. Tenant is a column on the row and
		-- a filter — it does not need to be the sort.
		--
		-- Recency is the right default for a directory an operator opens after
		-- acting: the administrator they just invited is the one they came to check,
		-- and it belongs at the top. Same reasoning as the tenant table
		-- (admin.ListOwnedTenants). Finding a KNOWN address is served by the search
		-- filter above, which is the tool for that job — a sort cannot do both.
		--
		-- ta.id DESC as the tie-break, and it is required rather than cosmetic. This
		-- listing is PAGINATED, so the sort has to be total: created_at is not
		-- unique — a tenant's seeded owner and every grant written in the same
		-- transaction share a timestamp to the microsecond — and equal values may
		-- come back in any order, which lets a row repeat on one page and vanish
		-- from another. ta.id is monotonic, so DESC on it preserves the
		-- newest-first intent inside a timestamp collision rather than fighting it.
		ORDER BY ta.created_at DESC, ta.id DESC
		LIMIT $4 OFFSET $5
	`, search, f.Role, f.Status, f.Limit, (f.Page-1)*f.Limit)
	if err != nil {
		return nil, fmt.Errorf("list platform administrators: %w", err)
	}
	defer rows.Close()

	out := []PlatformAdminResult{}
	for rows.Next() {
		var r PlatformAdminResult
		var id, userID, tenantID int64
		var isPrimary *bool
		var activated, blocked, isActive bool
		if err := rows.Scan(
			&id, &userID, &tenantID,
			&r.TenantName, &r.TenantSlug,
			&r.Email, &r.Name, &r.Role,
			&r.Applications, &isPrimary,
			&activated, &blocked, &isActive, &r.EmailVerified, &r.MFAEnabled,
			&r.LastLoginAt, &r.LoginsCount, &r.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan platform administrator: %w", err)
		}
		r.ID = strconv.FormatInt(id, 10)
		r.UserID = strconv.FormatInt(userID, 10)
		r.TenantID = strconv.FormatInt(tenantID, 10)
		r.IsPrimary = isPrimary != nil && *isPrimary
		r.Status = platformAdminStatus(activated, blocked, isActive)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate platform administrators: %w", err)
	}

	totalPages := (total + f.Limit - 1) / f.Limit
	return &PlatformAdminsPage{
		Data: out, Total: total, Page: f.Page, TotalPages: totalPages, PerPage: f.Limit,
	}, nil
}

// platformAdminStatus collapses three independent flags into one label.
//
// Order matters: a blocked administrator whose grant was never activated is
// reported as blocked, because that is the condition an operator must clear
// first — telling them the invitation is pending would send them to resend a
// link that cannot be accepted.
func platformAdminStatus(activated, blocked, isActive bool) string {
	switch {
	case blocked || !isActive:
		return "blocked"
	case !activated:
		return "pending_invitation"
	default:
		return "active"
	}
}

// PlatformAdminSummary counts the estate.
func (s *Service) PlatformAdminSummary(ctx context.Context) (*PlatformAdminStats, error) {
	var st PlatformAdminStats
	err := s.pool.QueryRow(ctx, `
		SELECT
			COUNT(*),
			COUNT(*) FILTER (WHERE ta.admin_role = 'owner'),
			COUNT(*) FILTER (WHERE ta.admin_role = 'co_owner'),
			COUNT(*) FILTER (WHERE ta.activated_at IS NULL),
			COUNT(*) FILTER (WHERE NOT (
				EXISTS (SELECT 1 FROM totp_secrets ts WHERE ts.user_id = u.id AND ts.is_active)
				OR EXISTS (SELECT 1 FROM email_mfa_settings em WHERE em.user_id = u.id AND em.is_active)
			))
		FROM tenant_admins ta
		JOIN users u ON u.id = ta.user_id
		WHERE ta.deleted_at IS NULL AND u.deleted_at IS NULL
	`).Scan(&st.TotalAdmins, &st.Owners, &st.CoOwners, &st.PendingInvitations, &st.NoMFA)
	if err != nil {
		return nil, fmt.Errorf("summarise platform administrators: %w", err)
	}

	// Tenants with nobody who can actually administer them. Counted separately
	// because it is about tenants, not administrators, and it is the number that
	// signals a tenant nobody has taken ownership of — an owner who never
	// accepted does not count.
	if err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM tenants t
		WHERE t.deleted_at IS NULL
		  AND NOT EXISTS (
		      SELECT 1 FROM tenant_admins ta
		      JOIN users u ON u.id = ta.user_id
		      WHERE ta.tenant_id = t.id
		        AND ta.admin_role = 'owner'
		        AND ta.deleted_at IS NULL
		        AND ta.activated_at IS NOT NULL
		        AND u.deleted_at IS NULL
		        AND u.is_active
		        AND u.blocked_at IS NULL
		  )
	`).Scan(&st.TenantsWithoutOwner); err != nil {
		return nil, fmt.Errorf("count tenants without an owner: %w", err)
	}
	return &st, nil
}
