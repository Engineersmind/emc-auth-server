// Package emailaddr holds the single definition of an email address's
// canonical form.
//
// Every address that enters the system — registration, login, invitation,
// password reset, magic link, admin grant, SSO assertion — must pass through
// Normalize before it is stored or used in a lookup. The domain part of an
// address is case-insensitive by RFC 5321, and no mail provider we support
// treats the local part as case-sensitive, so users reasonably expect
// Subham.D@example.com and subham.d@example.com to be one account (issue: an
// owner invited with mixed case could not log in with lowercase).
//
// The database enforces the same rule: users.email carries a CHECK constraint
// requiring email = lower(email), so a write that skips Normalize fails loudly
// instead of creating a second, unreachable account.
package emailaddr

import "strings"

// Normalize returns the canonical form of an email address: surrounding
// whitespace removed and folded to lowercase.
//
// It deliberately does no further canonicalization — dots and +tags in the
// local part are left alone, because whether those are equivalent is the mail
// provider's decision, not ours.
func Normalize(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// Equal reports whether two addresses refer to the same account.
func Equal(a, b string) bool {
	return Normalize(a) == Normalize(b)
}
