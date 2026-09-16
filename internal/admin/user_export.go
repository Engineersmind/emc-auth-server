// user_export.go — streaming CSV export of a tenant's user directory.
//
// Modelled on internal/audit/export.go: one bounded query streamed straight
// into the writer, so a large tenant never buffers its whole directory in
// memory. The shapes are deliberately identical — same row cap, same
// maintenance rate limiter on the route, same "headers are already sent"
// failure posture in the handler.
//
// # What is deliberately absent
//
// Credentials. Not the password hash, not the TOTP secret, not a WebAuthn
// public key — no credential material of any kind appears in an export, and
// no filter or flag can add it.
//
// An export is a file that leaves the building: it lands in a browser's
// download folder, an email attachment, a shared drive. A hash corpus in a
// spreadsheet is an offline cracking target with no compensating control, and
// every managed IdP takes the same position — Auth0's user export omits
// password hashes outright and releases them only under a separate support
// process. Exporting a second factor is worse still: a TOTP secret in a CSV is
// no longer a second factor.
//
// The asymmetry with import is intentional and matches the industry: foreign
// hashes are accepted IN (the import path relies on password.Verify accepting
// bcrypt and NeedsRehash upgrading opportunistically) and no hash ever goes OUT.
package admin

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strconv"

	"time"

	"github.com/jackc/pgx/v5"
)

// maxUserExportRows caps a single export so a broad request cannot stream
// unbounded data or hold a database connection indefinitely. Matches the audit
// export's cap for the same reason.
const maxUserExportRows = 50000

// userExportHeader is the CSV column order.
//
// Names match the import document's fields, but a CSV cannot be re-imported —
// the importer takes JSON, because a credential and a federated identity are
// nested and CSV can only carry them by inventing column conventions nobody
// else reads. ExportUsersJSON is the round-trippable form; this one is for
// opening in a spreadsheet.
//
// last_login_at and login_count have no import counterpart at all. They are
// here because an export is also read by people reconciling licences and
// dormancy, which is most of what an export is actually used for.
var userExportHeader = []string{
	"email", "first_name", "last_name", "role", "application",
	"is_active", "email_verified", "created_at", "last_login_at", "login_count",
}

// UserExportParams narrows an export. Both fields are resolved by the handler
// from the caller's own claims and path, never from client-supplied ids.
type UserExportParams struct {
	TenantID      int64
	ApplicationID *int64
}

// csvSafe neutralises spreadsheet formula injection.
//
// Excel, LibreOffice and Google Sheets treat a leading =, +, -, @, tab or
// carriage return as the start of a formula, so a user whose display name is
// stored as "=HYPERLINK(...)" becomes a live payload the moment an operator
// opens the export — the classic CSV injection. The value is user-controlled
// (anyone can register with a crafted first_name), the reader is an
// administrator, and nothing downstream of this function can undo it.
//
// Prefixing with an apostrophe is the OWASP-recommended defence: spreadsheets
// read it as "treat the rest as literal text" and strip it on display, while
// plain CSV parsers see one extra character rather than an executable cell.
func csvSafe(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}

// queryExportRows is the one query both serialisers read.
//
// Shared rather than duplicated because the exclusions are the point: no
// credential columns, no soft-deleted users, and the application scope applied
// exactly once. A second copy is how one format comes to leak what the other
// withholds.
func (s *Service) queryExportRows(ctx context.Context, p UserExportParams) (pgx.Rows, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT u.email, u.first_name, u.last_name,
		       COALESCE(r.name, ''), COALESCE(oc.name, ''),
		       u.is_active, u.email_verified, u.created_at,
		       (SELECT MAX(rt.created_at) FROM refresh_tokens rt
		         WHERE rt.user_id = u.id AND rt.tenant_id = u.tenant_id),
		       (SELECT COUNT(*) FROM audit_logs al
		         WHERE al.user_id = u.id AND al.tenant_id = u.tenant_id
		           AND al.action = 'login' AND al.status = 'success')
		FROM users u
		LEFT JOIN roles r          ON r.id = u.role_id
		LEFT JOIN oauth_clients oc ON oc.id = u.application_id
		WHERE u.tenant_id = $1
		  AND u.deleted_at IS NULL
		  AND ($2::BIGINT IS NULL OR u.application_id = $2)
		ORDER BY u.created_at DESC
		LIMIT $3
	`, p.TenantID, p.ApplicationID, maxUserExportRows)
	if err != nil {
		return nil, fmt.Errorf("user export query: %w", err)
	}
	return rows, nil
}

// scanExportRow reads one row into the shape both formats serialise from.
func scanExportRow(rows pgx.Rows) (ExportedUser, error) {
	var u ExportedUser
	if err := rows.Scan(&u.Email, &u.FirstName, &u.LastName, &u.Role, &u.Application,
		&u.IsActive, &u.EmailVerified, &u.CreatedAt, &u.LastLoginAt, &u.LoginCount); err != nil {
		return u, fmt.Errorf("user export scan: %w", err)
	}
	u.CreatedAt = u.CreatedAt.UTC()
	if u.LastLoginAt != nil {
		t := u.LastLoginAt.UTC()
		u.LastLoginAt = &t
	}
	return u, nil
}

// ExportUsersCSV writes the tenant's users as CSV to w, newest first, honoring
// the optional application scope. Bounded by maxUserExportRows.
//
// Soft-deleted users are excluded: an export describes the directory as it
// stands, and a deleted account is not part of it.
func (s *Service) ExportUsersCSV(ctx context.Context, p UserExportParams, w io.Writer) error {
	rows, err := s.queryExportRows(ctx, p)
	if err != nil {
		return err
	}
	defer rows.Close()

	cw := csv.NewWriter(w)
	if err := cw.Write(userExportHeader); err != nil {
		return err
	}

	for rows.Next() {
		u, err := scanExportRow(rows)
		if err != nil {
			return err
		}
		lastLogin := ""
		if u.LastLoginAt != nil {
			lastLogin = u.LastLoginAt.Format(time.RFC3339)
		}
		if err := cw.Write([]string{
			csvSafe(u.Email), csvSafe(u.FirstName), csvSafe(u.LastName),
			csvSafe(u.Role), csvSafe(u.Application),
			strconv.FormatBool(u.IsActive), strconv.FormatBool(u.EmailVerified),
			u.CreatedAt.Format(time.RFC3339), lastLogin,
			strconv.FormatInt(u.LoginCount, 10),
		}); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	cw.Flush()
	return cw.Error()
}

// --- JSON export ---------------------------------------------------------

// ExportedUser is one row of a JSON export.
//
// Field names deliberately match ImportUser, so an export can be edited and fed
// straight back to the importer — the use case CSV cannot serve, since the
// importer takes JSON. The fields an import does not accept (last_login_at,
// login_count) are still present: an export is also read by people
// reconciling licences and dormancy, and the importer ignores what it cannot
// use rather than refusing the file.
//
// There is no password field of any kind, and there is no flag that adds one.
// See the package comment for why.
type ExportedUser struct {
	Email         string     `json:"email"`
	FirstName     string     `json:"first_name,omitempty"`
	LastName      string     `json:"last_name,omitempty"`
	Role          string     `json:"role,omitempty"`
	Application   string     `json:"application,omitempty"`
	IsActive      bool       `json:"is_active"`
	EmailVerified bool       `json:"email_verified"`
	CreatedAt     time.Time  `json:"created_at"`
	LastLoginAt   *time.Time `json:"last_login_at,omitempty"`
	LoginCount    int64      `json:"login_count"`
}

// ExportedDocument wraps the rows in the same envelope the importer expects, so
// a round trip needs no reshaping — only credentials added.
type ExportedDocument struct {
	Users []ExportedUser `json:"users"`
}

// ExportUsersJSON writes the tenant's users as a JSON document.
//
// Encoded row by row into the writer rather than marshalled from a slice: at
// maxUserExportRows a buffered document is tens of megabytes held in memory for
// the length of the request, and the CSV path beside it already streams.
func (s *Service) ExportUsersJSON(ctx context.Context, p UserExportParams, w io.Writer) error {
	rows, err := s.queryExportRows(ctx, p)
	if err != nil {
		return err
	}
	defer rows.Close()

	if _, err := io.WriteString(w, "{\n  \"users\": [\n"); err != nil {
		return err
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("    ", "  ")

	first := true
	for rows.Next() {
		u, err := scanExportRow(rows)
		if err != nil {
			return err
		}
		if !first {
			if _, err := io.WriteString(w, ",\n"); err != nil {
				return err
			}
		}
		first = false
		if _, err := io.WriteString(w, "    "); err != nil {
			return err
		}
		if err := enc.Encode(u); err != nil {
			return fmt.Errorf("user export encode: %w", err)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	_, err = io.WriteString(w, "  ]\n}\n")
	return err
}
