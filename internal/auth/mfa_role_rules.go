package auth

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
)

// ---------------------------------------------------------------------------
// Role-based MFA rules (#195, stage 2 of #189)
//
// An application can list some of its own roles; a user holding any of them is
// treated as if the application's mode were 'required', whatever the mode says.
// Rules apply only while the master switch is on and the mode is not
// 'disabled'. Roles are read from the database at login (users.role_id and
// user_roles), never from a token.
// ---------------------------------------------------------------------------

// MaxMFARoleRules caps one application's rule list. A role rule names a whole
// population of users; a list longer than this is a configuration mistake, and
// the cap bounds the size of the audit row that records it.
const MaxMFARoleRules = 100

// ErrMFARoleRulesInactive refuses writing a role rule while it could not apply:
// the application's MFA switch is off or its mode is 'disabled'. Accepting it
// would report success for a rule that enforces nothing. Clearing the list is
// always allowed.
var ErrMFARoleRulesInactive = errors.New("MFA role rules can only be set while the application's MFA switch is on and its mode is not disabled")

// ErrMFARoleRuleInvalidRole refuses a rule naming a role that is not a live
// role of this application (another application's, a tenant-level role, a
// deleted one, or no role at all).
var ErrMFARoleRuleInvalidRole = errors.New("every MFA role rule must name a live role of this application")

// ErrTooManyMFARoleRules refuses a rule list longer than MaxMFARoleRules.
var ErrTooManyMFARoleRules = errors.New("too many MFA role rules for one application")

// MFARoleRule is one role whose holders must use MFA on the application.
type MFARoleRule struct {
	RoleID    string    `json:"role_id"`
	RoleName  string    `json:"role_name"`
	CreatedAt time.Time `json:"created_at"`
	// CreatedBy is the users.id of the administrator who added the rule; empty
	// for a service token or an account since deleted.
	CreatedBy string `json:"created_by,omitempty"`
}

// MFARoleRulesUpdate reports the rule list before and after a PUT, so the
// caller audits only a real change.
type MFARoleRulesUpdate struct {
	Old []MFARoleRule
	New []MFARoleRule
}

// Changed reports whether the set of roles differs.
func (u MFARoleRulesUpdate) Changed() bool {
	if len(u.Old) != len(u.New) {
		return true
	}
	for i := range u.Old {
		if u.Old[i].RoleID != u.New[i].RoleID {
			return true
		}
	}
	return false
}

// RoleIDs returns the role ids of rules, in order.
func RoleIDs(rules []MFARoleRule) []string {
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		out = append(out, r.RoleID)
	}
	return out
}

// ListAppMFARoleRules returns the application's role rules, ordered by role id.
// The caller must have verified that appRowID belongs to tenantID; tenant_id is
// still pinned in the query.
func (s *TOTPService) ListAppMFARoleRules(ctx context.Context, tenantID, appRowID int64) ([]MFARoleRule, error) {
	return listAppMFARoleRules(ctx, s.pool, tenantID, appRowID)
}

type mfaRuleQuerier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

func listAppMFARoleRules(ctx context.Context, q mfaRuleQuerier, tenantID, appRowID int64) ([]MFARoleRule, error) {
	rows, err := q.Query(ctx, `
		SELECT rr.role_id, r.name, rr.created_at, rr.created_by
		FROM application_mfa_role_rules rr
		JOIN roles r ON r.id = rr.role_id
		WHERE rr.application_id = $1 AND rr.tenant_id = $2
		ORDER BY rr.role_id
	`, appRowID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list MFA role rules: %w", err)
	}
	defer rows.Close()
	out := []MFARoleRule{}
	for rows.Next() {
		var roleID int64
		var createdBy *int64
		var r MFARoleRule
		if err := rows.Scan(&roleID, &r.RoleName, &r.CreatedAt, &createdBy); err != nil {
			return nil, fmt.Errorf("scan MFA role rule: %w", err)
		}
		r.RoleID = strconv.FormatInt(roleID, 10)
		if createdBy != nil {
			r.CreatedBy = strconv.FormatInt(*createdBy, 10)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate MFA role rules: %w", err)
	}
	return out, nil
}

// SetAppMFARoleRules replaces the application's whole rule list in ONE
// transaction. An empty list clears it and is accepted in any state; a
// non-empty one requires the switch on and the mode not 'disabled'
// (ErrMFARoleRulesInactive) and every role to be a live role of this
// application (ErrMFARoleRuleInvalidRole). Rules kept across the replacement
// keep their original created_at / created_by.
//
// The application row is locked FOR NO KEY UPDATE first, the same lock
// UpdateAppMFASettings takes, so the switch/mode read here cannot be overtaken
// by a concurrent settings change. The named roles are locked FOR SHARE so a
// concurrent DeleteRole either waits for this commit (and then sees the rule
// and refuses) or commits first (and the role fails validation here).
func (s *TOTPService) SetAppMFARoleRules(ctx context.Context, tenantID, appRowID int64, roleIDs []int64, createdBy *int64) (MFARoleRulesUpdate, error) {
	var res MFARoleRulesUpdate
	// Never nil: a nil slice would be sent as SQL NULL, and NOT (role_id = ANY(NULL))
	// matches no row, so clearing the list would silently keep every rule.
	ids := append(make([]int64, 0, len(roleIDs)), roleIDs...)
	slices.Sort(ids)
	ids = slices.Compact(ids)
	if len(ids) > MaxMFARoleRules {
		return res, ErrTooManyMFARoleRules
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return res, fmt.Errorf("begin MFA role rules update: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var one int
	if err = tx.QueryRow(ctx, `
		SELECT 1 FROM oauth_clients WHERE id = $1 AND tenant_id = $2 FOR NO KEY UPDATE
	`, appRowID, tenantID).Scan(&one); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return res, ErrAppNotFound
		}
		return res, fmt.Errorf("lock application for MFA role rules: %w", err)
	}

	if len(ids) > 0 {
		cfg, cfgErr := loadAppMFAConfig(ctx, tx, appRowID)
		if cfgErr != nil {
			return res, cfgErr
		}
		if !cfg.Enabled || cfg.Mode == MFAModeDisabled {
			return res, ErrMFARoleRulesInactive
		}
		rows, qErr := tx.Query(ctx, `
			SELECT id FROM roles
			WHERE id = ANY($1) AND tenant_id = $2 AND application_id = $3 AND deleted_at IS NULL
			FOR SHARE
		`, ids, tenantID, appRowID)
		if qErr != nil {
			return res, fmt.Errorf("validate MFA rule roles: %w", qErr)
		}
		found := 0
		for rows.Next() {
			found++
		}
		rows.Close()
		if err = rows.Err(); err != nil {
			return res, fmt.Errorf("validate MFA rule roles: %w", err)
		}
		if found != len(ids) {
			return res, ErrMFARoleRuleInvalidRole
		}
	}

	if res.Old, err = listAppMFARoleRules(ctx, tx, tenantID, appRowID); err != nil {
		return res, err
	}

	if _, err = tx.Exec(ctx, `
		DELETE FROM application_mfa_role_rules
		WHERE application_id = $1 AND tenant_id = $2 AND NOT (role_id = ANY($3))
	`, appRowID, tenantID, ids); err != nil {
		return res, fmt.Errorf("remove MFA role rules: %w", err)
	}
	if len(ids) > 0 {
		if _, err = tx.Exec(ctx, `
			INSERT INTO application_mfa_role_rules (application_id, role_id, tenant_id, created_by)
			SELECT $1, rid, $2, $4 FROM unnest($3::BIGINT[]) AS rid
			ON CONFLICT (application_id, role_id) DO NOTHING
		`, appRowID, tenantID, ids, createdBy); err != nil {
			return res, fmt.Errorf("insert MFA role rules: %w", err)
		}
	}

	if res.New, err = listAppMFARoleRules(ctx, tx, tenantID, appRowID); err != nil {
		return res, err
	}
	if err = tx.Commit(ctx); err != nil {
		return res, fmt.Errorf("commit MFA role rules: %w", err)
	}
	return res, nil
}

// mfaRuleRoleFor returns the name of a role the user holds that the
// application's MFA role rules list, or "" when none does. Both role sources
// are read — the primary users.role_id and every user_roles grant — straight
// from the database: a token's role claims are what the user was given at the
// last sign-in, not what they hold now, and a session narrowed to some of its
// roles still belongs to a user who holds the rest. Deleted roles never match.
// Deterministic (lowest name) so status and audit say the same thing each time.
func mfaRuleRoleFor(ctx context.Context, q mfaSettingsQuerier, userID, tenantID, appRowID int64) (string, error) {
	var name string
	err := q.QueryRow(ctx, `
		SELECT r.name
		FROM application_mfa_role_rules rr
		JOIN roles r ON r.id = rr.role_id AND r.deleted_at IS NULL
		WHERE rr.application_id = $1 AND rr.tenant_id = $3
		  AND (EXISTS (SELECT 1 FROM users u
		               WHERE u.id = $2 AND u.tenant_id = $3 AND u.role_id = rr.role_id)
		       OR EXISTS (SELECT 1 FROM user_roles ur
		                  WHERE ur.user_id = $2 AND ur.tenant_id = $3 AND ur.role_id = rr.role_id))
		ORDER BY r.name
		LIMIT 1
	`, appRowID, userID, tenantID).Scan(&name)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("load MFA role rules for user: %w", err)
	}
	return name, nil
}
