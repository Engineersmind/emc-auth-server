// apierror.go — the response shape for a failed request.
//
// # Why two fields
//
// An error has two audiences and they want different things. A client needs a
// stable token it can branch on; a person needs a sentence telling them what to
// do next. Serving one string to both means either the client parses prose —
// which breaks the moment anybody improves the wording — or the person reads a
// token.
//
// So a failure carries both:
//
//	{ "error": "invalid_credentials",
//	  "message": "That email or password didn't match. Check them and try again." }
//
// `error` is the contract: lower_snake_case, stable, safe to switch on. `message`
// is prose, may be reworded at any time, and must never be parsed. Stripe, Auth0
// and GitHub all split the two this way for the same reason.
//
// # Compatibility
//
// `error` keeps carrying what the handler already sent, so every existing client
// and test continues to work. `message` is additive.
//
// # What a message may say
//
// The message is written for the person who hit the wall, and answers "what do I
// do now?" — not "what did the server's control flow do?".
//
//   - It never confirms whether an account, email or tenant exists. Sign-in,
//     password reset and magic-link failures all read identically whether the
//     address is real or not; anything else turns the login form into an account
//     enumeration oracle.
//   - It never names an internal component, table, or Go error. "failed to query
//     activity" tells the reader nothing they can act on and tells an attacker
//     something about the shape of the system.
//   - It offers the next step where one exists: reset the password, check the
//     authenticator's clock, contact an administrator.
//   - It uses the words a person would use. Not "TOTP" but "authenticator app";
//     not "principal" but "account".
package handlers

import "github.com/labstack/echo/v4"

// APIError is the body of every failed response.
type APIError struct {
	// Error is the stable machine code. Clients switch on this.
	Error string `json:"error"`
	// Message is prose for the person who hit the failure. Never parse it.
	Message string `json:"message,omitempty"`
}

// fail writes a coded error with the human message registered for that code.
//
// A code with no registered message still sends `error` alone, so a handler that
// has not been migrated degrades to today's behaviour rather than shipping an
// empty `message`.
func fail(c echo.Context, status int, code string) error {
	return c.JSON(status, APIError{Error: code, Message: userMessage(code)})
}

// userMessage returns the sentence shown for a code, or "" when none is
// registered.
func userMessage(code string) string { return errorMessages[code] }

// UserMessage is userMessage for callers outside this package.
//
// Exists because the social sign-in flow cannot answer with a body at all: it
// redirects to the application's own page carrying ?error=<code>, so the page
// renders the sentence. Exporting the map keeps that page and this server
// saying the same thing, instead of every client inventing its own wording for
// account_conflict.
func UserMessage(code string) string { return errorMessages[code] }

// ErrorCatalog returns every code and its message.
//
// Served so a client can render failures it was not built against — a login
// page written today still has a sentence for a code added next year, rather
// than falling back to "something went wrong".
func ErrorCatalog() map[string]string {
	out := make(map[string]string, len(errorMessages))
	for k, v := range errorMessages {
		out[k] = v
	}
	return out
}

// errorMessages maps a machine code to the sentence a person reads.
//
// Grouped by the surface the failure comes from. Deliberately flat and explicit
// rather than composed from fragments: every one of these is read by a human
// under some pressure, and a message assembled at runtime is a message nobody
// ever reads end to end before shipping it.
var errorMessages = map[string]string{

	// --- Sign-in ---------------------------------------------------------
	//
	// Every failure here is deliberately indistinguishable. A message that
	// distinguished "no such account" from "wrong password" would let anyone
	// test an address list against the login form.
	"invalid_credentials": "That email or password didn't match. Check them and try again, or reset your password.",
	"login_failed":        "We couldn't sign you in. Check your details and try again.",
	"account_blocked":     "This account has been blocked. Contact your administrator to restore access.",
	"account_locked":      "Too many failed sign-in attempts. Try again shortly, or reset your password to unlock the account now.",
	"session_terminated":  "Your session was ended for security reasons. Sign in again to continue.",

	// --- Multi-factor ----------------------------------------------------
	"mfa_code_invalid":     "That code wasn't right. Check your authenticator app and enter the current code.",
	"mfa_code_expired":     "That code has expired. Request a new one and enter it within a few minutes.",
	"mfa_session_expired":  "This sign-in took too long to complete. Start again from the sign-in page.",
	"mfa_not_enrolled":     "Two-factor authentication isn't set up on this account yet.",
	"mfa_already_enrolled": "Two-factor authentication is already set up on this account.",
	"mfa_unavailable":      "Two-factor authentication isn't available on this server. Contact your administrator.",
	"backup_code_invalid":  "That backup code wasn't recognised. Each code works only once — try a different one.",

	// Administrator MFA (migration 00094): mandatory, so every dead end names
	// the way forward — sign in again, pick another method, or ask an owner.
	"mfa_step_up_required":   "Sign in again with two-factor authentication to open this organization.",
	"mfa_method_not_allowed": "Your organization doesn't allow that sign-in method for administrators. Choose another method.",
	"mfa_required_by_policy": "Two-factor authentication is required for administrators. Add another method before removing this one.",
	"mfa_reset_forbidden":    "You can't reset two-factor authentication for this administrator. Ask an owner or a platform administrator.",

	// --- Passwords -------------------------------------------------------
	"password_too_short":    "Choose a password of at least 8 characters.",
	"password_incorrect":    "That isn't your current password.",
	"password_reset_failed": "We couldn't reset your password. Request a new reset link and try again.",
	"reset_link_invalid":    "This password reset link is no longer valid. Links expire after a short time — request a new one.",

	// --- Email verification and change ------------------------------------
	"verification_link_invalid": "This verification link is no longer valid. Request a new one from the sign-in page.",
	"email_already_registered":  "An account already exists for that email address.",
	"email_unchanged":           "That is already your email address.",
	"email_taken":               "That email address is already in use.",
	"email_change_failed":       "We couldn't change your email address. Start again from your account settings.",
	"verification_unavailable":  "Email verification isn't configured on this server. Contact your administrator.",

	// --- Invitations and magic links --------------------------------------
	"invitation_invalid":   "This invitation link is no longer valid. Ask whoever invited you to send a new one.",
	"invitation_failed":    "We couldn't complete your invitation. Ask your administrator for a new invitation link.",
	"magic_link_invalid":   "This sign-in link is no longer valid. Links expire after a short time — request a new one.",
	"magic_link_send_fail": "We couldn't send your sign-in link. Try again in a moment.",
	"magic_link_disabled":  "Sign-in links aren't available on this server. Use your password instead.",

	// --- Social sign-in ---------------------------------------------------
	//
	// account_conflict is the one an imported user meets: the server can see an
	// account with this email but cannot safely attach the social identity to
	// it. Naming the password path matters — it is the route that works.
	"account_conflict":          "We couldn't connect that account. If you already have an account with this email, sign in with your password or use “Forgot password” to set one.",
	"provider_email_unverified": "Your provider hasn't verified this email address. Verify it with them, then try again.",
	"provider_unavailable":      "That sign-in method isn't available right now. Try another way to sign in.",
	"consent_denied":            "Sign-in was cancelled. You can try again whenever you're ready.",

	// --- Passkeys ---------------------------------------------------------
	"passkey_invalid":     "That passkey couldn't be verified. Try again, or sign in with your password.",
	"passkey_unavailable": "Passkeys aren't available on this server. Sign in with your password instead.",
	"passkey_not_found":   "No passkey is registered for this account on this device.",

	// --- Sessions and tokens ----------------------------------------------
	"session_expired":       "Your session has expired. Sign in again to continue.",
	"refresh_token_invalid": "Your session is no longer valid. Sign in again to continue.",
	"refresh_in_progress":   "Your session is being renewed. Try that again in a moment.",

	// --- Authorisation ----------------------------------------------------
	"unauthorized": "You need to sign in to do that.",
	"forbidden":    "You don't have permission to do that. Contact your administrator if you think you should.",

	// --- Rate limiting and availability -----------------------------------
	"rate_limited":        "Too many attempts. Wait a moment and try again.",
	"service_unavailable": "That service is temporarily unavailable. Try again shortly.",
	"internal_error":      "Something went wrong on our side. Try again — if it keeps happening, contact your administrator.",

	// --- Request shape ----------------------------------------------------
	//
	// These reach a developer far more often than an end user, so they stay
	// precise rather than becoming soothing.
	"invalid_request":   "That request couldn't be read. Check the fields and try again.",
	"missing_field":     "Some required information is missing.",
	"not_found":         "We couldn't find that.",
	"conflict":          "That conflicts with something that already exists.",
	"payload_too_large": "That file is too large. Split it into smaller batches and try again.",

	// --- Bulk import ------------------------------------------------------
	"import_too_large":   "That import is larger than this server accepts. Split it into smaller files.",
	"import_invalid":     "That import file couldn't be read. Check it is valid JSON in the expected format.",
	"import_job_missing": "We couldn't find that import. It may have finished and been cleared.",
	"import_job_invalid": "That import reference isn't valid.",
	"import_failed":      "We couldn't run that import. Try again — if it keeps happening, contact your administrator.",
}
