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
//
// A rule may also restrict which methods satisfy it (#199): allowed_methods
// NULL means the application's own list; a non-NULL list must be a non-empty
// subset of it when written. A user covered by several rules is held to the
// narrowest set — the application's list intersected with every covering
// rule's list. If the application's list later shrinks so that the
// intersection is empty, the user is refused (ErrAppMFAUnavailable) rather
// than let through with any method.
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

// ErrMFARoleRuleInvalidMethods refuses a rule whose allowed_methods is empty,
// names an unknown method, or names a method the application itself does not
// allow (#199).
var ErrMFARoleRuleInvalidMethods = errors.New("a role rule's allowed_methods must be a non-empty subset of the application's allowed_methods")

// ErrTooManyMFARoleRules refuses a rule list longer than MaxMFARoleRules.
var ErrTooManyMFARoleRules = errors.New("too many MFA role rules for one application")

// ErrMFARoleRulesPasswordlessConflict refuses a non-empty rule list that
// leaves covered users email as their only MFA method — the application allows
// only email, or a rule's own allowed_methods (#199) narrows to email alone —
// while passwordless email-code sign-in is on for the application. Every
// covered user is treated as 'required', and an email-code sign-in cannot
// satisfy an email-only second factor (the same inbox twice), so each of their
// email-code logins would fail with ErrPasswordlessMFAConflict — locking out
// users who have no password. It is the role-rule twin of the check
// setAppMFAPolicy makes for mode 'required'.
var ErrMFARoleRulesPasswordlessConflict = errors.New("MFA role rules cannot leave email as the only MFA method while passwordless email-code sign-in is on")

// MFARoleRule is one role whose holders must use MFA on the application.
type MFARoleRule struct {
	RoleID   string `json:"role_id"`
	RoleName string `json:"role_name"`
	// AllowedMethods restricts which methods satisfy this rule (#199). null =
	// the application's allowed_methods.
	AllowedMethods []string  `json:"allowed_methods"`
	CreatedAt      time.Time `json:"created_at"`
	// CreatedBy is the users.id of the administrator who added the rule; empty
	// for a service token or an account since deleted.
	CreatedBy string `json:"created_by,omitempty"`
}

// MFARoleRuleSpec is one rule of a PUT: the role and, optionally, the methods
// that satisfy it (nil = the application's list).
type MFARoleRuleSpec struct {
	RoleID         int64
	AllowedMethods []string
}

// MFARoleRulesUpdate reports the rule list before and after a PUT, so the
// caller audits only a real change.
type MFARoleRulesUpdate struct {
	Old []MFARoleRule
	New []MFARoleRule
}

// Changed reports whether the set of roles, or any rule's methods, differs.
func (u MFARoleRulesUpdate) Changed() bool {
	if len(u.Old) != len(u.New) {
		return true
	}
	for i := range u.Old {
		if u.Old[i].RoleID != u.New[i].RoleID {
			return true
		}
		if (u.Old[i].AllowedMethods == nil) != (u.New[i].AllowedMethods == nil) ||
			!slices.Equal(u.Old[i].AllowedMethods, u.New[i].AllowedMethods) {
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
		SELECT rr.role_id, r.name, rr.allowed_methods, rr.created_at, rr.created_by
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
		if err := rows.Scan(&roleID, &r.RoleName, &r.AllowedMethods, &r.CreatedAt, &createdBy); err != nil {
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

// SetAppMFARoleRules replaces the application's whole rule list with rules that
// use the application's own methods. See SetAppMFARoleRuleSpecs.
func (s *TOTPService) SetAppMFARoleRules(ctx context.Context, tenantID, appRowID int64, roleIDs []int64, createdBy *int64) (MFARoleRulesUpdate, error) {
	specs := make([]MFARoleRuleSpec, 0, len(roleIDs))
	for _, id := range roleIDs {
		specs = append(specs, MFARoleRuleSpec{RoleID: id})
	}
	return s.SetAppMFARoleRuleSpecs(ctx, tenantID, appRowID, specs, createdBy)
}

// SetAppMFARoleRuleSpecs replaces the application's whole rule list in ONE
// transaction. An empty list clears it and is accepted in any state; a
// non-empty one requires the switch on and the mode not 'disabled'
// (ErrMFARoleRulesInactive), every role to be a live role of this application
// (ErrMFARoleRuleInvalidRole), and every non-nil method list to be a non-empty
// subset of the application's allowed_methods (ErrMFARoleRuleInvalidMethods,
// #199). Rules kept across the replacement keep their original created_at /
// created_by; their methods are replaced. A role listed twice keeps its last
// entry.
//
// The application row is locked FOR NO KEY UPDATE first, the same lock
// UpdateAppMFASettings takes, so the switch/mode/methods read here cannot be
// overtaken by a concurrent settings change. The named roles are locked FOR
// SHARE so a concurrent DeleteRole either waits for this commit (and then sees
// the rule and refuses) or commits first (and the role fails validation here).
func (s *TOTPService) SetAppMFARoleRuleSpecs(ctx context.Context, tenantID, appRowID int64, rules []MFARoleRuleSpec, createdBy *int64) (MFARoleRulesUpdate, error) {
	var res MFARoleRulesUpdate
	byRole := make(map[int64][]string, len(rules))
	for _, r := range rules {
		byRole[r.RoleID] = r.AllowedMethods
	}
	// Never nil: a nil slice would be sent as SQL NULL, and NOT (role_id = ANY(NULL))
	// matches no row, so clearing the list would silently keep every rule.
	ids := make([]int64, 0, len(byRole))
	for id := range byRole {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	if len(ids) > MaxMFARoleRules {
		return res, ErrTooManyMFARoleRules
	}
	for _, m := range byRole {
		if m != nil && !ValidMFAMethods(m) {
			return res, ErrMFARoleRuleInvalidMethods
		}
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
		// Normalise each method list to the application's order, and refuse a
		// method the application does not allow.
		for id, m := range byRole {
			if m == nil {
				continue
			}
			norm := intersectMethods(cfg.Methods, m)
			for _, want := range m {
				if !methodAllowed(norm, want) {
					return res, ErrMFARoleRuleInvalidMethods
				}
			}
			byRole[id] = norm
		}
		// Rules make covered users 'required'; refuse them exactly where
		// setAppMFAPolicy refuses mode 'required' (email-only methods while
		// email codes are on), so neither path reaches the locked-out state.
		// A rule's own method list (#199) counts: a rule narrowed to email
		// alone conflicts even when the application allows more.
		if s.emailCodeEnabled != nil {
			emailOnly := false
			for _, id := range ids {
				eff := cfg.Methods
				if byRole[id] != nil {
					eff = byRole[id]
				}
				if emailOnlyMFAMethods(eff) {
					emailOnly = true
					break
				}
			}
			if emailOnly && s.emailCodeEnabled(ctx, tenantID, appRowID) {
				return res, ErrMFARoleRulesPasswordlessConflict
			}
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
	// One statement per rule (at most MaxMFARoleRules): each carries its own
	// method array, which unnest cannot pair with a role id.
	for _, id := range ids {
		if _, err = tx.Exec(ctx, `
			INSERT INTO application_mfa_role_rules (application_id, role_id, tenant_id, created_by, allowed_methods)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (application_id, role_id) DO UPDATE
			SET allowed_methods = EXCLUDED.allowed_methods
		`, appRowID, id, tenantID, createdBy, byRole[id]); err != nil {
			return res, fmt.Errorf("upsert MFA role rule: %w", err)
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

// emailOnlyMFAMethods reports whether email is the application's only allowed
// MFA method — the method set an email-code sign-in cannot satisfy.
func emailOnlyMFAMethods(methods []string) bool {
	return len(methods) == 1 && methods[0] == MFAMethodEmail
}

// mfaRuleEmailOnly summarises an application's role rules for the
// passwordless-conflict checks.
type mfaRuleEmailOnly struct {
	// any is true when at least one rule names a live role.
	any bool
	// emailOnly is true when some rule leaves its covered users email as the
	// only method: its own allowed_methods (#199), or the application's when it
	// has none, intersected with the application's methods.
	emailOnly bool
}

// loadMFARuleEmailOnly reads the application's live role rules and reports
// whether any exists and whether any leaves email as the only method, given
// the application's methods appMethods (the proposed list, on a policy write).
// Each rule is judged on its own: with two methods, an email-only intersection
// of several rules implies one of them is email-only already.
func loadMFARuleEmailOnly(ctx context.Context, q mfaRuleQuerier, appRowID int64, appMethods []string) (mfaRuleEmailOnly, error) {
	var out mfaRuleEmailOnly
	rows, err := q.Query(ctx, `
		SELECT rr.allowed_methods
		FROM application_mfa_role_rules rr
		JOIN roles r ON r.id = rr.role_id AND r.deleted_at IS NULL
		WHERE rr.application_id = $1
	`, appRowID)
	if err != nil {
		return out, fmt.Errorf("check MFA role rules: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var methods []string
		if err := rows.Scan(&methods); err != nil {
			return out, fmt.Errorf("scan MFA role rule: %w", err)
		}
		out.any = true
		eff := appMethods
		if methods != nil {
			eff = intersectMethods(appMethods, methods)
		}
		if emailOnlyMFAMethods(eff) {
			out.emailOnly = true
		}
	}
	if err := rows.Err(); err != nil {
		return out, fmt.Errorf("iterate MFA role rules: %w", err)
	}
	return out, nil
}

// EffectiveAppMFAModeForConflict returns the application's MFA mode and allowed
// methods as the passwordless-conflict checks must see them. Role rules make
// covered users 'required' (#195) and may narrow their methods (#199), so:
//   - a rule that leaves its users email as the only method is reported as
//     'required' with methods [email], whatever the mode and the application's
//     own list;
//   - otherwise an 'optional' application with rules is reported as
//     'required' with its own methods.
//
// The passwordless policy write path uses this, so turning email-code sign-in
// on is refused wherever some users would be held to email-only MFA — the
// reciprocal of ErrMFARoleRulesPasswordlessConflict.
func (s *TOTPService) EffectiveAppMFAModeForConflict(ctx context.Context, appRowID int64) (string, []string, error) {
	cfg, err := s.GetAppMFAConfig(ctx, appRowID)
	if err != nil {
		return "", nil, err
	}
	if cfg.Mode == MFAModeDisabled {
		return cfg.Mode, cfg.Methods, nil
	}
	rules, rErr := loadMFARuleEmailOnly(ctx, s.pool, appRowID, cfg.Methods)
	if rErr != nil {
		return "", nil, rErr
	}
	if rules.emailOnly {
		return MFAModeRequired, []string{MFAMethodEmail}, nil
	}
	if rules.any && cfg.Mode == MFAModeOptional {
		return MFAModeRequired, cfg.Methods, nil
	}
	return cfg.Mode, cfg.Methods, nil
}

// intersectMethods returns the methods of base that also appear in other, in
// base's order. Never nil.
func intersectMethods(base, other []string) []string {
	out := make([]string, 0, len(base))
	for _, m := range base {
		if methodAllowed(other, m) && !methodAllowed(out, m) {
			out = append(out, m)
		}
	}
	return out
}

// mfaRuleCoverage is what the application's MFA role rules say about one user.
type mfaRuleCoverage struct {
	// role is the lowest-named rule role the user holds, "" when no rule
	// covers them.
	role string
	// methods is the intersection of the method lists of every covering rule
	// that restricts methods (#199); nil when none does (the application's
	// list applies). May be empty: the restrictions exclude each other.
	methods []string
}

// effectiveMethods applies the coverage's restriction to the application's
// methods: the narrowest set the user may use. Empty means no method can
// satisfy every rule covering the user — the caller must fail closed.
func (c mfaRuleCoverage) effectiveMethods(appMethods []string) []string {
	if c.role == "" || c.methods == nil {
		return appMethods
	}
	return intersectMethods(appMethods, c.methods)
}

// loadMFARuleCoverage reads every rule of the application that covers the
// user. Both role sources are read — the primary users.role_id and every
// user_roles grant — straight from the database: a token's role claims are
// what the user was given at the last sign-in, not what they hold now, and a
// session narrowed to some of its roles still belongs to a user who holds the
// rest. Deleted roles never match. The reported role is deterministic (lowest
// name) so status and audit say the same thing each time.
func loadMFARuleCoverage(ctx context.Context, q mfaRuleQuerier, userID, tenantID, appRowID int64) (mfaRuleCoverage, error) {
	var cov mfaRuleCoverage
	rows, err := q.Query(ctx, `
		SELECT r.name, rr.allowed_methods
		FROM application_mfa_role_rules rr
		JOIN roles r ON r.id = rr.role_id AND r.deleted_at IS NULL
		WHERE rr.application_id = $1 AND rr.tenant_id = $3
		  AND (EXISTS (SELECT 1 FROM users u
		               WHERE u.id = $2 AND u.tenant_id = $3 AND u.role_id = rr.role_id)
		       OR EXISTS (SELECT 1 FROM user_roles ur
		                  WHERE ur.user_id = $2 AND ur.tenant_id = $3 AND ur.role_id = rr.role_id))
		ORDER BY r.name
	`, appRowID, userID, tenantID)
	if err != nil {
		return cov, fmt.Errorf("load MFA role rules for user: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		var methods []string
		if err := rows.Scan(&name, &methods); err != nil {
			return mfaRuleCoverage{}, fmt.Errorf("scan MFA role rule for user: %w", err)
		}
		if cov.role == "" {
			cov.role = name
		}
		if methods == nil {
			continue
		}
		if cov.methods == nil {
			cov.methods = append([]string{}, methods...)
		} else {
			cov.methods = intersectMethods(cov.methods, methods)
		}
	}
	if err := rows.Err(); err != nil {
		return mfaRuleCoverage{}, fmt.Errorf("iterate MFA role rules for user: %w", err)
	}
	return cov, nil
}
