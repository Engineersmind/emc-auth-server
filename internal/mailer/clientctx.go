package mailer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/mssola/useragent"

	"github.com/engineersmind/emc-auth-server/internal/requestctx"
)

// GeoPlace is a coarse location for an IP address.
type GeoPlace struct {
	City     string
	Country  string
	TimeZone string // IANA name, may be empty
}

// GeoLookup resolves an IP to a place. ok=false for a private address or a miss.
// A function type rather than an interface so the mailer does not depend on the
// GeoIP library or on the audit package that already wraps it.
type GeoLookup func(ip string) (GeoPlace, bool)

// userContextTypes are the templates whose recipient is the person who made the
// request that triggered the email, so "this came from Chrome on Windows near
// Pune" is a statement about THEM. This is the signal Auth0 and Okta put in
// their security emails: it lets a recipient spot a request that was not theirs.
//
// Deliberately absent:
//
//	user_invitation       sent on an administrator's request
//	tenant_lockout_alert  an aggregate with no single request
//	admin_activity,       operator emails written by the notification pipeline,
//	access_changed        which has no request of its own (admin_activity already
//	                      carries the actor's IPAddress)
//	provider_test         a diagnostic
var userContextTypes = map[TemplateType]bool{
	TemplateEmailVerification: true,
	TemplatePasswordReset:     true,
	TemplateWelcome:           true,
	TemplateMFACode:           true,
	TemplateMagicLink:         true,
	TemplatePasswordChanged:   true,
	TemplateChangeEmail:       true,
	TemplateBlockedAccount:    true,
	TemplatePasswordBreach:    true,
	TemplatePasswordlessCode:  true,
}

// applyCentralFields fills every field of data that can be derived without help
// from the calling flow: the end user's device, place and local time, the
// expiry clock time, the masked address and the support address. Values a caller
// already set are kept.
//
// Best-effort by construction. It runs on the send path of password-reset and
// verification emails, so it must never fail or delay one: every lookup that
// misses simply leaves its field empty, and a panic is contained.
func (m *mailerImpl) applyCentralFields(ctx context.Context, sender *SMTPConfig, tt TemplateType, to string, data *TemplateData) {
	loc := time.UTC
	func() {
		defer func() {
			if r := recover(); r != nil {
				m.logger.Error().Interface("panic", r).Str("type", string(tt)).
					Msg("mailer: client-context enrichment panicked — sending without it")
				loc = time.UTC
			}
		}()
		loc = m.applyClientContext(ctx, tt, data)
	}()

	now := time.Now().In(loc)
	if data.OccurredAt == "" {
		data.OccurredAt = now.Format("2 Jan 2006, 15:04")
	}
	if data.Timezone == "" {
		data.Timezone = zoneLabel(now)
	}
	if data.ExpiryTime == "" && data.TTLMinutes > 0 {
		data.ExpiryTime = now.Add(time.Duration(data.TTLMinutes) * time.Minute).Format("15:04")
	}
	if data.MaskedEmail == "" {
		data.MaskedEmail = maskEmail(to)
	}
	if data.SupportEmail == "" {
		switch {
		case sender != nil && sender.ReplyTo != "":
			data.SupportEmail = sender.ReplyTo
		case sender != nil && sender.From != "":
			data.SupportEmail = sender.From
		case m.global.ReplyTo != "":
			data.SupportEmail = m.global.ReplyTo
		default:
			data.SupportEmail = m.global.From
		}
	}
}

// applyClientContext fills Browser, OS, City, Country and Location from the
// request identity carried by ctx, and returns the zone to display times in.
//
// Nothing is filled unless ALL of these hold: the template describes the
// recipient's own request; the send has not been marked as made on someone else's
// behalf; and the identity is trusted. The last is the one that matters most
// behind a proxy: when an application's backend calls this server for its users
// without forwarding theirs, the IP and User-Agent on the request are the
// backend's, and presenting them as "your device, your location" would be wrong
// in a security email — worse than saying nothing.
func (m *mailerImpl) applyClientContext(ctx context.Context, tt TemplateType, data *TemplateData) *time.Location {
	if !userContextTypes[tt] || requestctx.ClientContextSuppressed(ctx) {
		return time.UTC
	}
	// An administrator disabling an account is not the account holder's request.
	if tt == TemplateBlockedAccount && data.Reason == BlockReasonAdmin {
		return time.UTC
	}
	ri := requestctx.FromContext(ctx)
	if !ri.Trusted {
		return time.UTC
	}

	if ri.UserAgent != "" && data.Browser == "" && data.OS == "" {
		if ua := useragent.New(ri.UserAgent); ua != nil {
			data.Browser, _ = ua.Browser()
			data.OS = ua.OS()
		}
	}

	var geoZone string
	if m.geo != nil && ri.IPAddress != "" && data.Location == "" {
		if g, ok := m.geo(ri.IPAddress); ok {
			data.City, data.Country = g.City, g.Country
			switch {
			case g.City != "" && g.Country != "":
				data.Location = g.City + ", " + g.Country
			case g.Country != "":
				data.Location = g.Country
			default:
				data.Location = g.City
			}
			geoZone = g.TimeZone
		}
	}

	// The user's own timezone beats one inferred from their IP.
	for _, name := range []string{ri.Timezone, geoZone} {
		if name == "" {
			continue
		}
		if l, err := time.LoadLocation(name); err == nil {
			return l
		}
	}
	return time.UTC
}

// zoneLabel names the zone of t for display: its abbreviation ("IST"), or
// "UTC+05:30" for zones whose abbreviation is just a numeric offset.
func zoneLabel(t time.Time) string {
	abbr, offset := t.Zone()
	if abbr != "" && abbr[0] != '+' && abbr[0] != '-' {
		return abbr
	}
	if offset == 0 {
		return "UTC"
	}
	sign := '+'
	if offset < 0 {
		sign = '-'
		offset = -offset
	}
	h, mi := offset/3600, (offset%3600)/60
	if mi == 0 {
		return fmt.Sprintf("UTC%c%d", sign, h)
	}
	return fmt.Sprintf("UTC%c%d:%02d", sign, h, mi)
}

// maskEmail hides the local part of an address: "alex@acme.com" → "a***@acme.com".
// A malformed address is returned unchanged rather than mangled.
func maskEmail(addr string) string {
	at := strings.LastIndex(addr, "@")
	if at < 1 {
		return addr
	}
	return addr[:1] + "***" + addr[at:]
}
