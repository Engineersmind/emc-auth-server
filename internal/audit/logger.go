// Package audit provides structured audit logging for all auth and admin events.
// Every security-relevant action writes a row to the audit_logs table.
// Two query surfaces are exposed:
//   - Tenant-scoped: admin sees only their own tenant's events
//   - System-wide:   super_admin sees events across all tenants
package audit

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
)

// ---------------------------------------------------------------------------
// Action constants — every loggable event has a namespaced string key.
// Format: <domain>.<event>
// ---------------------------------------------------------------------------

const (
	// Auth events
	ActionAuthRegister            = "auth.register"
	ActionAuthLogin               = "auth.login"
	ActionAuthLoginFailed         = "auth.login_failed"
	ActionAuthLogout              = "auth.logout"
	ActionAuthTokenRefresh        = "auth.token_refresh"
	ActionAuthPasswordResetReq    = "auth.password_reset_requested"
	ActionAuthPasswordResetDone   = "auth.password_reset_completed"

	// Admin — tenant management
	ActionAdminTenantCreated     = "admin.tenant_created"
	ActionAdminTenantUpdated     = "admin.tenant_updated"
	ActionAdminTenantDeactivated = "admin.tenant_deactivated"

	// Admin — permission management
	ActionAdminPermissionCreated = "admin.permission_created"
	ActionAdminPermissionDeleted = "admin.permission_deleted"

	// Admin — role management
	ActionAdminRoleCreated          = "admin.role_created"
	ActionAdminRolePermissionsUpdated = "admin.role_permissions_updated"
	ActionAdminRoleDeleted          = "admin.role_deleted"

	// Admin — user pool management
	ActionAdminUserCreated          = "admin.user_created"
	ActionAdminUserUpdated          = "admin.user_updated"
	ActionAdminUserDeleted          = "admin.user_deleted"
	ActionAdminUserRoleAssigned     = "admin.user_role_assigned"
	ActionAdminForcePasswordReset   = "admin.force_password_reset"

	// Admin — per-app rate limit management (08-02)
	ActionAdminAppLimitCreated = "admin.app_limit_created"
	ActionAdminAppLimitUpdated = "admin.app_limit_updated"
	ActionAdminAppLimitDeleted = "admin.app_limit_deleted"

	// Admin — tenant CORS configuration
	ActionAdminCORSUpdated = "admin.cors_origins_updated"
)

// ---------------------------------------------------------------------------
// Event — input to Logger.Log()
// ---------------------------------------------------------------------------

// Event describes a single auditable action.
type Event struct {
	// TenantID is the tenant the action occurred in. Nil for system-level events.
	TenantID *uuid.UUID
	// UserID is the user who performed the action. Nil for unauthenticated events.
	UserID *uuid.UUID
	// AgentID is the agent that performed the action. Nil for human-initiated events (08-03).
	AgentID *uuid.UUID
	// ActorEmail is the email of the actor (denormalized at log time).
	ActorEmail string
	// Action is one of the Action* constants above.
	Action string
	// ResourceType is the kind of resource affected (tenant, user, role, permission).
	ResourceType string
	// ResourceID is the UUID (as string) of the affected resource.
	ResourceID string
	// IPAddress is the caller's remote IP.
	IPAddress string
	// UserAgent is the caller's User-Agent header.
	UserAgent string
}

// ---------------------------------------------------------------------------
// Query result types
// ---------------------------------------------------------------------------

// LogEntry is a single audit log row returned by the query endpoints.
type LogEntry struct {
	ID           string    `json:"id"`
	TenantID     *string   `json:"tenant_id"`
	TenantSlug   *string   `json:"tenant_slug"`
	UserID       *string   `json:"user_id"`
	AgentID      *string   `json:"agent_id,omitempty"`
	ActorEmail   string    `json:"actor_email"`
	Action       string    `json:"action"`
	ResourceType string    `json:"resource_type"`
	ResourceID   string    `json:"resource_id"`
	IPAddress    string    `json:"ip_address"`
	CreatedAt    time.Time `json:"created_at"`
}

// LogsPage wraps a paginated audit log result.
type LogsPage struct {
	Logs       []LogEntry `json:"logs"`
	Total      int        `json:"total"`
	Page       int        `json:"page"`
	TotalPages int        `json:"total_pages"`
}

// QueryParams are the filter options for both query endpoints.
type QueryParams struct {
	// TenantID restricts results to one tenant (used for tenant-scoped endpoint).
	// Nil means no restriction (system-wide endpoint).
	TenantID *uuid.UUID
	Action   string
	UserID   string
	AgentID  string // optional UUID string; filters to events by a specific agent (08-03)
	From     *time.Time
	To       *time.Time
	Page     int
	Limit    int
}

// ---------------------------------------------------------------------------
// Logger
// ---------------------------------------------------------------------------

// Logger writes audit events to the audit_logs table.
type Logger struct {
	pool   *pgxpool.Pool
	logger zerolog.Logger
}

// New creates an audit Logger.
func New(pool *pgxpool.Pool, logger zerolog.Logger) *Logger {
	return &Logger{pool: pool, logger: logger}
}

// Log writes an audit event. Errors are logged but never propagated to callers —
// an audit failure must never block an auth operation.
func (l *Logger) Log(ctx context.Context, e Event) {
	_, err := l.pool.Exec(ctx, `
		INSERT INTO audit_logs
		  (id, tenant_id, user_id, agent_id, actor_email, action, resource_type, resource_id, ip_address, user_agent)
		VALUES
		  (gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, e.TenantID, e.UserID, e.AgentID, e.ActorEmail, e.Action,
		e.ResourceType, e.ResourceID, e.IPAddress, e.UserAgent)
	if err != nil {
		l.logger.Error().Err(err).Str("action", e.Action).Msg("audit: failed to write log entry")
	}
}

// ---------------------------------------------------------------------------
// Query — tenant-scoped (admin:access) and system-wide (tenant:manage)
// ---------------------------------------------------------------------------

// Query returns a paginated, filtered list of audit log entries.
// When p.TenantID is set, results are scoped to that tenant only.
// When p.TenantID is nil, results span all tenants (system-wide view).
func (l *Logger) Query(ctx context.Context, p QueryParams) (*LogsPage, error) {
	if p.Page < 1 {
		p.Page = 1
	}
	if p.Limit < 1 {
		p.Limit = 50
	}
	if p.Limit > 200 {
		p.Limit = 200
	}
	offset := (p.Page - 1) * p.Limit

	// Build dynamic WHERE clause.
	// We use positional args to avoid SQL injection.
	args := []any{}
	where := "WHERE 1=1"

	if p.TenantID != nil {
		args = append(args, *p.TenantID)
		where += fmt.Sprintf(" AND al.tenant_id = $%d", len(args))
	}
	if p.Action != "" {
		args = append(args, p.Action)
		where += fmt.Sprintf(" AND al.action = $%d", len(args))
	}
	if p.UserID != "" {
		uid, err := uuid.Parse(p.UserID)
		if err == nil {
			args = append(args, uid)
			where += fmt.Sprintf(" AND al.user_id = $%d", len(args))
		}
	}
	if p.AgentID != "" {
		aid, err := uuid.Parse(p.AgentID)
		if err == nil {
			args = append(args, aid)
			where += fmt.Sprintf(" AND al.agent_id = $%d", len(args))
		}
	}
	if p.From != nil {
		args = append(args, *p.From)
		where += fmt.Sprintf(" AND al.created_at >= $%d", len(args))
	}
	if p.To != nil {
		args = append(args, *p.To)
		where += fmt.Sprintf(" AND al.created_at <= $%d", len(args))
	}

	// Count total.
	var total int
	countSQL := fmt.Sprintf(`
		SELECT COUNT(*) FROM audit_logs al %s
	`, where)
	if err := l.pool.QueryRow(ctx, countSQL, args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("audit count: %w", err)
	}

	// Fetch page — JOIN tenants for slug (left join so system events with NULL tenant_id still appear).
	args = append(args, p.Limit, offset)
	limitArg := len(args) - 1
	offsetArg := len(args)

	querySQL := fmt.Sprintf(`
		SELECT al.id, al.tenant_id, t.slug, al.user_id, al.agent_id,
		       al.actor_email, al.action, al.resource_type,
		       al.resource_id, al.ip_address, al.created_at
		FROM audit_logs al
		LEFT JOIN tenants t ON t.id = al.tenant_id
		%s
		ORDER BY al.created_at DESC
		LIMIT $%d OFFSET $%d
	`, where, limitArg, offsetArg)

	rows, err := l.pool.Query(ctx, querySQL, args...)
	if err != nil {
		return nil, fmt.Errorf("audit query: %w", err)
	}
	defer rows.Close()

	var logs []LogEntry
	for rows.Next() {
		var e LogEntry
		var tenantID *uuid.UUID
		var userID *uuid.UUID
		var agentID *uuid.UUID
		var tenantSlug *string
		if err := rows.Scan(
			&e.ID, &tenantID, &tenantSlug, &userID, &agentID,
			&e.ActorEmail, &e.Action, &e.ResourceType,
			&e.ResourceID, &e.IPAddress, &e.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("audit scan: %w", err)
		}
		if tenantID != nil {
			s := tenantID.String()
			e.TenantID = &s
		}
		if userID != nil {
			s := userID.String()
			e.UserID = &s
		}
		if agentID != nil {
			s := agentID.String()
			e.AgentID = &s
		}
		e.TenantSlug = tenantSlug
		logs = append(logs, e)
	}
	if logs == nil {
		logs = []LogEntry{}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	totalPages := (total + p.Limit - 1) / p.Limit
	if totalPages == 0 {
		totalPages = 1
	}
	return &LogsPage{
		Logs:       logs,
		Total:      total,
		Page:       p.Page,
		TotalPages: totalPages,
	}, nil
}
