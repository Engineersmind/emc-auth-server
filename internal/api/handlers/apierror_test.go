package handlers

import (
	"strings"
	"testing"
)

// Every registered code must carry a message. A code with none sends `error`
// alone, which is the state this layer exists to replace.
func TestErrorMessages_AllCodesHaveText(t *testing.T) {
	for code, msg := range errorMessages {
		if strings.TrimSpace(msg) == "" {
			t.Errorf("code %q has no message", code)
		}
	}
}

// The sign-in failures must be indistinguishable from one another.
//
// This is the property the whole surface rests on: if "no such account" reads
// differently from "wrong password", the login form becomes a way to test an
// address list. The soft-lock case matters most — a message that said "locked"
// would confirm to an attacker that their guess was correct.
func TestErrorMessages_SignInDoesNotLeakAccountExistence(t *testing.T) {
	msg := errorMessages["invalid_credentials"]

	for _, leak := range []string{
		"no account", "not found", "does not exist", "unknown user",
		"unregistered", "locked", "too many", "wrong password",
	} {
		if strings.Contains(strings.ToLower(msg), leak) {
			t.Errorf("invalid_credentials names %q, which distinguishes why sign-in failed: %q", leak, msg)
		}
	}
}

// A message is read by someone who wants to get on with something. Where a next
// step exists it should be named, rather than leaving the reader at a dead end.
func TestErrorMessages_DeadEndsOfferARoute(t *testing.T) {
	// Codes whose whole problem is "I cannot get in" — each must point
	// somewhere: a different sign-in method, a reset, or an administrator.
	routed := []string{
		"invalid_credentials",
		"account_blocked",
		"account_locked",
		"account_conflict",
		"reset_link_invalid",
		"magic_link_invalid",
		"invitation_invalid",
		"verification_link_invalid",
	}
	for _, code := range routed {
		msg := strings.ToLower(errorMessages[code])
		if msg == "" {
			t.Errorf("%s has no message", code)
			continue
		}
		hasRoute := strings.Contains(msg, "try") ||
			strings.Contains(msg, "request") ||
			strings.Contains(msg, "contact") ||
			strings.Contains(msg, "sign in") ||
			strings.Contains(msg, "reset") ||
			strings.Contains(msg, "ask")
		if !hasRoute {
			t.Errorf("%s leaves the reader with nowhere to go: %q", code, errorMessages[code])
		}
	}
}

// Internal vocabulary belongs in logs, not in something a person reads.
func TestErrorMessages_AvoidInternalVocabulary(t *testing.T) {
	banned := []string{
		"totp", "principal", "claim", "tenant_id", "nil", "sql",
		"goroutine", "pgx", "constraint", "foreign key", "500",
	}
	for code, msg := range errorMessages {
		lower := strings.ToLower(msg)
		for _, word := range banned {
			if strings.Contains(lower, word) {
				t.Errorf("code %q uses internal vocabulary %q: %q", code, word, msg)
			}
		}
	}
}

// Codes are the contract clients switch on, so they must be stable, lowercase,
// and free of the spacing that makes a string awkward to compare.
func TestErrorMessages_CodesAreMachineReadable(t *testing.T) {
	for code := range errorMessages {
		if code != strings.ToLower(code) {
			t.Errorf("code %q is not lowercase", code)
		}
		if strings.ContainsAny(code, " -.") {
			t.Errorf("code %q contains spacing or punctuation; use lower_snake_case", code)
		}
	}
}

// A message is a sentence somebody reads under pressure. Anything much longer
// than a couple of lines is not read at all.
func TestErrorMessages_AreReadableLength(t *testing.T) {
	for code, msg := range errorMessages {
		if len(msg) > 200 {
			t.Errorf("code %q is %d characters — too long to be read: %q", code, len(msg), msg)
		}
		if !strings.HasSuffix(strings.TrimSpace(msg), ".") &&
			!strings.HasSuffix(strings.TrimSpace(msg), "?") {
			t.Errorf("code %q does not end as a sentence: %q", code, msg)
		}
	}
}

// UserMessage is what the social sign-in page resolves its ?error= code
// against, so it must agree with what the JSON surfaces send.
func TestUserMessage_MatchesTheCatalog(t *testing.T) {
	if UserMessage("account_conflict") != errorMessages["account_conflict"] {
		t.Error("UserMessage disagrees with the catalog")
	}
	if UserMessage("no_such_code") != "" {
		t.Error("an unregistered code should resolve to empty, not to a guess")
	}
}

func TestErrorCatalog_IsACopy(t *testing.T) {
	c := ErrorCatalog()
	c["invalid_credentials"] = "tampered"
	if errorMessages["invalid_credentials"] == "tampered" {
		t.Error("ErrorCatalog handed out the live map; a caller can rewrite every message")
	}
}
