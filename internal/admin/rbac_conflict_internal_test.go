package admin

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// A permission deleted between the read and the grant insert is a foreign-key
// violation, not a unique one. It must surface as the documented 409 conflict
// rather than an unmapped 500.
func TestRBACWriteErr_MapsConflictsAndWrapsTheRest(t *testing.T) {
	for code, wantConflict := range map[string]bool{
		"23505": true,  // unique: a name was created concurrently
		"23503": true,  // foreign key: a permission was deleted concurrently
		"22021": false, // invalid byte sequence: not a conflict
	} {
		err := rbacWriteErr("op", &pgconn.PgError{Code: code})
		if got := errors.Is(err, ErrRBACConflict); got != wantConflict {
			t.Errorf("code %s: errors.Is(ErrRBACConflict) = %v, want %v", code, got, wantConflict)
		}
	}
}

func TestHasControlChars(t *testing.T) {
	cases := []struct {
		in          string
		allowLayout bool
		want        bool
	}{
		{"plain", false, false},
		{"nul\x00role", false, true},
		{"nul\x00role", true, true},
		{"tab\there", false, true},
		{"tab\there", true, false},
		{"line\nbreak", true, false},
		{"bell\a", true, true},
		{"unicode é 日本", false, false},
	}
	for _, c := range cases {
		if got := hasControlChars(c.in, c.allowLayout); got != c.want {
			t.Errorf("hasControlChars(%q, %v) = %v, want %v", c.in, c.allowLayout, got, c.want)
		}
	}
}
