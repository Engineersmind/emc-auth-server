// Package requestctx carries the calling browser's network identity — client IP
// and User-Agent — from the HTTP edge down to the service layer through
// context.Context.
//
// It exists because session rows must record the device that created them, and
// the only place that knows the device is the HTTP handler, while the only place
// that writes the row is deep inside AuthService.issueTokenPair. There are eight
// call sites between the two (password login, register, MFA completion, magic
// link, OAuth/SAML callbacks, and both refresh paths), so threading two extra
// string parameters through all of them would mean every future token-minting
// flow has to remember to pass them — and a flow that forgets writes a session
// nobody can identify, silently.
//
// This is a leaf package on purpose: internal/auth cannot import
// internal/api/middleware (middleware already imports auth), so the shared
// carrier has to live somewhere neither owns.
//
// The values are descriptive metadata, never authority. Client IP is derived
// from proxy headers by echo's RealIP and User-Agent is attacker-controlled
// text; nothing may authorize on either. They exist so an operator — or the user
// themselves — can look at a session list and recognise which entry is which.
package requestctx

import "context"

// maxUserAgentLen bounds what is stored. Real User-Agent strings top out around
// 200 bytes; the column is TEXT, so an unbounded header would let any caller
// write megabytes per login into a table with one row per token rotation.
const maxUserAgentLen = 512

// RequestInfo is the calling client's network identity.
type RequestInfo struct {
	// IPAddress is the client address as resolved by the HTTP edge (echo's
	// RealIP, driven by middleware.ClientIPExtractor, which believes
	// X-Forwarded-For only from TRUSTED_PROXIES hops). Empty when the
	// request did not come through HTTP — a background job, a test, a cron task.
	IPAddress string
	// UserAgent is the raw User-Agent header, truncated to maxUserAgentLen.
	UserAgent string
	// Timezone is the end user's IANA timezone ("Asia/Kolkata") when a trusted
	// backend forwarded it. Empty otherwise. Validated by the caller that sets it.
	Timezone string
	// Trusted reports that IPAddress and UserAgent describe the END USER's
	// device: either a trusted backend forwarded them, or the request came
	// straight from the user's own client.
	//
	// It is false for a request an application's backend made on its own behalf
	// without forwarding the user's identity. In that case IPAddress and
	// UserAgent are the BACKEND's, and anything that would present them to a
	// person as "your device" or "your location" — the security emails — must
	// not. It is zero-valued (false) outside HTTP, so a background job never
	// claims an identity.
	Trusted bool
	// UserAgentTrusted reports that UserAgent is the END USER's browser. It can be
	// false while Trusted is true: a backend that forwards the user's IP but not a
	// (valid) User-Agent leaves UserAgent as the backend's own HTTP client, which
	// is kept for session attribution but must never be shown as "your browser".
	UserAgentTrusted bool
}

// ctxKey is the private context key type. Unexported so no other package can
// write this slot: the only way in is WithRequestInfo.
type ctxKey struct{}

// WithRequestInfo returns ctx carrying the given client identity.
//
// The User-Agent is truncated here rather than at the database, so every reader
// of a RequestInfo — including future ones that do not write to refresh_tokens —
// sees the same bounded value.
func WithRequestInfo(ctx context.Context, ip, userAgent string) context.Context {
	return WithClientIdentity(ctx, ip, userAgent, "", false, false)
}

// WithClientIdentity is WithRequestInfo plus the end user's timezone and whether
// the address and the User-Agent may each be shown to that user. See
// RequestInfo.Trusted and RequestInfo.UserAgentTrusted.
func WithClientIdentity(ctx context.Context, ip, userAgent, timezone string, trusted, userAgentTrusted bool) context.Context {
	if len(userAgent) > maxUserAgentLen {
		userAgent = userAgent[:maxUserAgentLen]
	}
	return context.WithValue(ctx, ctxKey{}, RequestInfo{
		IPAddress: ip, UserAgent: userAgent, Timezone: timezone, Trusted: trusted, UserAgentTrusted: userAgentTrusted,
	})
}

type noClientContextKey struct{}

// WithoutClientContext marks ctx so that emails sent under it do not describe
// the requester's device or location. Use it where the person making the request
// is not the person receiving the email — an administrator acting on a user.
func WithoutClientContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, noClientContextKey{}, true)
}

// ClientContextSuppressed reports whether WithoutClientContext was applied.
func ClientContextSuppressed(ctx context.Context) bool {
	v, _ := ctx.Value(noClientContextKey{}).(bool)
	return v
}

// FromContext returns the client identity carried by ctx, or the zero
// RequestInfo when none was attached.
//
// The zero value is a valid, expected result — not an error. Token issuance runs
// outside HTTP in tests and could in future run from a background job, and those
// paths must keep working; they simply produce a session row with no device
// attribution rather than failing to log the user in.
func FromContext(ctx context.Context) RequestInfo {
	info, _ := ctx.Value(ctxKey{}).(RequestInfo)
	return info
}
