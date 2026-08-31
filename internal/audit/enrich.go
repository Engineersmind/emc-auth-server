// enrich.go — request-context enrichment applied in the async pipeline, from
// data already carried on the Event (UserAgent, IPAddress). Two enrichers:
//
//   - User-Agent parsing (built-in, always on): raw UA → browser / os / device
//     / is_mobile, so the log shows "Chrome 120 / Mac OS X" not a 200-char
//     string. Auth0's parsed user_agent + is_mobile.
//   - GeoIP (optional, injected via WithGeoIP): IP → coarse location. Disabled
//     when no resolver is configured (empty GEOIP_DATABASE_PATH). Auth0's
//     location_info.
//
// Both run on the background worker (see writer.go): they need only fields
// already on the Event, so keeping them out of the handler layer avoids
// threading parsers through every handler constructor. Results are merged into
// the event's metadata JSONB, never override a caller-supplied key, and are
// redacted + size-capped by buildMetadata like any other metadata.
package audit

import (
	"context"
	"net/netip"
	"time"

	"github.com/mssola/useragent"

	"github.com/engineersmind/emc-auth-server/internal/metrics"
)

// GeoInfo is a coarse, non-PII location derived from an IP address.
type GeoInfo struct {
	CountryCode string  `json:"country_code,omitempty"`
	Country     string  `json:"country,omitempty"`
	City        string  `json:"city,omitempty"`
	TimeZone    string  `json:"time_zone,omitempty"`
	Latitude    float64 `json:"latitude,omitempty"`
	Longitude   float64 `json:"longitude,omitempty"`
}

// GeoResolver maps an IP string to a location. Implementations wrap a GeoIP
// database (e.g. MaxMind GeoLite2-City); the concrete type lives outside the
// audit package so this package need not depend on the geoip library. Lookup
// returns ok=false for private/invalid IPs or a miss.
type GeoResolver interface {
	Lookup(ip string) (GeoInfo, bool)
}

// RiskInput is the context a RiskAssessor needs to score a login-type event.
// Geo is the already-resolved location (may be nil when geo is disabled/missed).
type RiskInput struct {
	UserID    *int64
	TenantID  *int64
	Action    string
	IPAddress string
	UserAgent string
	Geo       *GeoInfo
}

// RiskAssessor evaluates security signals (new device, impossible travel,
// untrusted IP) for a login-type event, using audit history + the current
// context. It returns a metadata-ready map (nil/empty when nothing to add).
// Implementations must be best-effort and never block: a slow/failed query
// returns an empty result rather than an error. The concrete type lives
// outside the audit package (it needs DB history) and is injected via
// WithRiskAssessor.
type RiskAssessor interface {
	Assess(ctx context.Context, in RiskInput) map[string]any
}

// parseUA turns a raw User-Agent into browser/os/device facets. Returns a map
// ready to merge into metadata; empty when the UA is blank or unparseable.
func parseUA(raw string) map[string]any {
	if raw == "" {
		return nil
	}
	ua := useragent.New(raw)
	if ua == nil {
		return nil
	}
	name, version := ua.Browser()
	out := map[string]any{}
	if name != "" {
		out["browser"] = name
	}
	if version != "" {
		out["browser_version"] = version
	}
	if os := ua.OS(); os != "" {
		out["os"] = os
	}
	out["is_mobile"] = ua.Mobile()
	out["device_type"] = deviceType(ua)
	return out
}

func deviceType(ua *useragent.UserAgent) string {
	switch {
	case ua.Bot():
		return "bot"
	case ua.Mobile():
		return "mobile"
	default:
		return "desktop"
	}
}

// enrichedMetadata returns a copy of the event's metadata augmented with the
// parsed UA facets and (when a resolver is configured) the geo location. It
// never overwrites a key the caller already set, so an explicit value always
// wins. Returns the original map untouched when there is nothing to add.
func (l *Logger) enrichedMetadata(e Event) map[string]any {
	uaFields := parseUA(e.UserAgent)
	var geo *GeoInfo
	if l.geo != nil {
		if info, ok := l.geo.Lookup(e.IPAddress); ok {
			geo = &info
		}
	}
	if uaFields == nil && geo == nil {
		return e.Metadata
	}

	out := make(map[string]any, len(e.Metadata)+len(uaFields)+1)
	for k, v := range e.Metadata {
		out[k] = v
	}
	for k, v := range uaFields {
		if _, exists := out[k]; !exists {
			out[k] = v
		}
	}
	if geo != nil {
		if _, exists := out["location"]; !exists {
			out["location"] = geo
		}
	}
	return out
}

// riskActions are the events worth a security assessment — the credential
// verification points where new-device / impossible-travel / untrusted-IP
// matter. Assessing every audit row would add needless history queries.
// Deliberately excludes machine-to-machine events (client_credentials, API-key,
// agent): new-device / impossible-travel / untrusted-IP are human-session
// signals and would be misleading noise for a non-interactive service caller.
var riskActions = map[string]bool{
	ActionAuthLogin:              true,
	ActionAuthLoginFailed:        true,
	ActionAuthGoogleLogin:        true,
	ActionAuthGoogleLoginFailed:  true,
	ActionAuthReplayDetected:     true,
	ActionAuthMFALockedOut:       true,
	ActionAuthTokenRefreshFailed: true,

	// Lockout tiers (issue #72). Each one is a credential-verification outcome
	// where the geo/device signals are exactly what tells a locked-out traveller
	// apart from a distributed guessing attack.
	ActionAuthAccountSoftLocked:    true,
	ActionAuthLoginFailedThreshold: true,
	ActionAuthAccountBlocked:       true,
	ActionAuthTenantLockoutSpike:   true,
}

// assessRisk merges security signals into the metadata for login-type events
// when a RiskAssessor is configured. Best-effort: a nil assessor, a non-risk
// action, or an empty result leaves metadata untouched. The current location
// (if any) is threaded in from the geo enrichment already merged into meta.
func (l *Logger) assessRisk(ctx context.Context, e Event, meta map[string]any) map[string]any {
	if l.risk == nil || !riskActions[e.Action] {
		return meta
	}
	in := RiskInput{
		UserID:    e.UserID,
		TenantID:  e.TenantID,
		Action:    e.Action,
		IPAddress: e.IPAddress,
		UserAgent: e.UserAgent,
	}
	if meta != nil {
		if g, ok := meta["location"].(*GeoInfo); ok {
			in.Geo = g
		}
	}
	signals := l.risk.Assess(ctx, in)
	if len(signals) == 0 {
		return meta
	}
	out := make(map[string]any, len(meta)+1)
	for k, v := range meta {
		out[k] = v
	}
	if _, exists := out["risk"]; !exists {
		out["risk"] = signals
	}
	return out
}

// backfillApplication attributes an event to the application its user belongs
// to, when the call site didn't already set one. Application-scoped users
// (users.application_id) carry their app across every event — login, logout,
// MFA enrollment, etc. — not just the ones that happen to decode it from a JWT.
// Tenant-level users (application_id NULL, e.g. platform admins) stay app-less.
// PK lookup on users; skipped for events that already have an application or no
// user. Runs on the worker, off the request path.
func (l *Logger) backfillApplication(ctx context.Context, e *Event) {
	if e.UserID == nil || e.ApplicationID != nil {
		return
	}
	var appID *int64
	if err := l.pool.QueryRow(ctx,
		`SELECT application_id FROM users WHERE id = $1`, *e.UserID,
	).Scan(&appID); err != nil {
		return
	}
	if appID != nil {
		e.ApplicationID = appID
	}
}

// recordLoginStats bumps the user's login counter and snapshots it into the
// event metadata (Auth0's stats.loginsCount). It runs only for successful
// auth.login events with a known user — every successful login flows through
// exactly one such audit event, so this is the natural single chokepoint and
// needs no per-handler wiring. Best-effort: a failed update leaves metadata
// untouched and never blocks the flush.
//
// The CTE returns the NEW count (including this login, matching Auth0) plus the
// PREVIOUS last_login_at, so a login row can show "47th login, last seen 18h ago".
func (l *Logger) recordLoginStats(ctx context.Context, e Event, meta map[string]any) map[string]any {
	if e.Action != ActionAuthLogin || e.UserID == nil {
		return meta
	}
	// Atomic in-SQL increment — no explicit FOR UPDATE. The `login_count + 1`
	// runs under the UPDATE's own brief row lock, so concurrent logins for the
	// same user still count correctly without holding a lock across a read. The
	// prev CTE captures the prior last_login_at for display (cosmetic; a rare
	// concurrent race only affects the "previous login" hint, never the count).
	var newCount int64
	var prevAt *time.Time
	err := l.pool.QueryRow(ctx, `
		WITH prev AS (
			SELECT last_login_at FROM users WHERE id = $1
		)
		UPDATE users u
		SET login_count = u.login_count + 1, last_login_at = $2
		FROM prev
		WHERE u.id = $1
		RETURNING u.login_count, prev.last_login_at
	`, *e.UserID, e.createdAt).Scan(&newCount, &prevAt)
	if err != nil {
		metrics.AuditEnrichmentErrors.WithLabelValues("stats").Inc()
		return meta
	}

	stats := map[string]any{
		"logins_count":  newCount,
		"last_login_at": e.createdAt,
	}
	if prevAt != nil {
		stats["previous_login_at"] = *prevAt
	}
	out := make(map[string]any, len(meta)+1)
	for k, v := range meta {
		out[k] = v
	}
	if _, exists := out["stats"]; !exists {
		out["stats"] = stats
	}
	return out
}

// privateOrInvalid reports whether an IP should be skipped for geo lookup —
// exported for reuse by GeoResolver implementations that want the same guard.
func PrivateOrInvalidIP(s string) bool {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return true
	}
	return addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsUnspecified()
}
