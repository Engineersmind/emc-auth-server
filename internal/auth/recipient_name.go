package auth

import (
	"context"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// recipientLookupTimeout bounds the optional name lookup. It runs on the path of
// emails a person is waiting for (a reset link, a sign-in code), so a slow
// database must cost the greeting, never the email.
const recipientLookupTimeout = 750 * time.Millisecond

// firstNameByID returns the user's first name for an email greeting, or "".
//
// Best-effort by design: a missing user, an empty column or any error yields "",
// and a template renders without a name rather than failing. Never used for
// anything but display.
func firstNameByID(ctx context.Context, pool *pgxpool.Pool, userID int64) string {
	if pool == nil || userID == 0 {
		return ""
	}
	ctx, cancel := context.WithTimeout(ctx, recipientLookupTimeout)
	defer cancel()
	var name string
	if err := pool.QueryRow(ctx, `SELECT first_name FROM users WHERE id = $1`, userID).Scan(&name); err != nil {
		return ""
	}
	return strings.TrimSpace(name)
}

// firstNameByEmail is firstNameByID for flows that hold the address and scope but
// not the user id (emailed sign-in codes). A sign-up has no user yet, so it
// returns "" and the greeting simply has no name.
func firstNameByEmail(ctx context.Context, pool *pgxpool.Pool, tenantID int64, appRowID *int64, email string) string {
	if pool == nil || email == "" {
		return ""
	}
	ctx, cancel := context.WithTimeout(ctx, recipientLookupTimeout)
	defer cancel()
	var name string
	err := pool.QueryRow(ctx, `
		SELECT first_name FROM users
		WHERE tenant_id = $1 AND email = $2 AND application_id IS NOT DISTINCT FROM $3
		  AND deleted_at IS NULL
		LIMIT 1
	`, tenantID, strings.ToLower(strings.TrimSpace(email)), appRowID).Scan(&name)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(name)
}
