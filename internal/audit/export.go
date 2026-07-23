// export.go — streaming CSV export of the audit trail for compliance/evidence.
// Streams straight from a single bounded query into the writer, so it never
// buffers the whole result set in memory.

package audit

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"strconv"
	"time"
)

// maxExportRows caps a single export so a broad filter cannot stream unbounded
// data or hold a DB connection indefinitely.
const maxExportRows = 50000

var exportHeader = []string{
	"id", "created_at", "action", "status", "http_status", "auth_method",
	"actor_email", "user_id", "ip_address", "tenant", "application", "request_id",
}

// ExportCSV writes matching audit rows as CSV to w, newest first, honoring the
// same filters as Query (tenant scope, action, status, auth_method, from/to).
// Bounded by maxExportRows.
func (l *Logger) ExportCSV(ctx context.Context, p QueryParams, w io.Writer) error {
	args := []any{}
	where := "WHERE 1=1"
	add := func(cond string, val any) {
		args = append(args, val)
		where += fmt.Sprintf(" AND %s $%d", cond, len(args))
	}
	if p.TenantID != nil {
		add("al.tenant_id =", *p.TenantID)
	}
	if p.Action != "" {
		add("al.action =", p.Action)
	}
	if p.Status != "" {
		add("al.status =", p.Status)
	}
	if p.AuthMethod != "" {
		add("al.auth_method =", p.AuthMethod)
	}
	if p.From != nil {
		add("al.created_at >=", *p.From)
	}
	if p.To != nil {
		add("al.created_at <=", *p.To)
	}

	query := fmt.Sprintf(`
		SELECT al.id, al.created_at, al.action, al.status, al.http_status, al.auth_method,
		       al.actor_email, al.user_id, COALESCE(host(al.ip_address), ''),
		       COALESCE(t.slug, ''), COALESCE(oc.name, ''), al.request_id
		FROM audit_logs al
		LEFT JOIN tenants t ON t.id = al.tenant_id
		LEFT JOIN oauth_clients oc ON oc.id = al.application_id
		%s
		ORDER BY al.created_at DESC
		LIMIT %d
	`, where, maxExportRows)

	rows, err := l.pool.Query(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("audit export query: %w", err)
	}
	defer rows.Close()

	cw := csv.NewWriter(w)
	if err := cw.Write(exportHeader); err != nil {
		return err
	}

	for rows.Next() {
		var id int64
		var createdAt time.Time
		var action, status, authMethod, actorEmail, ip, tenant, app, requestID string
		var httpStatus *int16
		var userID *int64
		if err := rows.Scan(&id, &createdAt, &action, &status, &httpStatus, &authMethod,
			&actorEmail, &userID, &ip, &tenant, &app, &requestID); err != nil {
			return fmt.Errorf("audit export scan: %w", err)
		}
		hs := ""
		if httpStatus != nil {
			hs = strconv.Itoa(int(*httpStatus))
		}
		uid := ""
		if userID != nil {
			uid = strconv.FormatInt(*userID, 10)
		}
		if err := cw.Write([]string{
			strconv.FormatInt(id, 10), createdAt.UTC().Format(time.RFC3339), action, status,
			hs, authMethod, actorEmail, uid, ip, tenant, app, requestID,
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
