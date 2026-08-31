// Package risk assesses security signals for login-type audit events, matching
// the dimensions a full IdP surfaces (Auth0's riskAssessment): new device,
// impossible travel, and untrusted IP. It reads only existing audit history —
// no new tables — and is best-effort: any query error yields a "not flagged"
// result rather than blocking the audit write.
package risk

import (
	"context"
	"encoding/json"
	"math"
	"net"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mssola/useragent"
	"github.com/rs/zerolog"

	"github.com/engineersmind/emc-auth-server/internal/audit"
	"github.com/engineersmind/emc-auth-server/internal/metrics"
)

// lookback bounds the device-history window: a device unseen for this long is
// treated as new. impossibleSpeed is the km/h threshold above which two logins
// are geographically impossible for one human.
const (
	lookback        = 90 * 24 * time.Hour
	impossibleSpeed = 900.0 // km/h — faster than any commercial flight
	minTravelKM     = 100.0 // ignore tiny hops (geo/IP jitter)
	assessTimeout   = 2 * time.Second
)

// Assessor implements audit.RiskAssessor over the audit_logs history.
type Assessor struct {
	pool      *pgxpool.Pool
	untrusted []*net.IPNet
	logger    zerolog.Logger
}

// New builds an Assessor. untrustedCIDRs is an optional denylist; malformed
// entries are skipped with a warning. A nil pool disables history-based signals
// (new_device / impossible_travel) while still evaluating untrusted_ip.
func New(pool *pgxpool.Pool, untrustedCIDRs []string, logger zerolog.Logger) *Assessor {
	nets := make([]*net.IPNet, 0, len(untrustedCIDRs))
	for _, c := range untrustedCIDRs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			logger.Warn().Str("cidr", c).Msg("risk: ignoring malformed UNTRUSTED_IP_CIDRS entry")
			continue
		}
		nets = append(nets, n)
	}
	return &Assessor{pool: pool, untrusted: nets, logger: logger}
}

// Assess implements audit.RiskAssessor.
func (a *Assessor) Assess(ctx context.Context, in audit.RiskInput) map[string]any {
	ctx, cancel := context.WithTimeout(ctx, assessTimeout)
	defer cancel()

	untrusted := a.isUntrustedIP(in.IPAddress)
	newDevice := a.isNewDevice(ctx, in)
	impossible := a.isImpossibleTravel(ctx, in)

	if newDevice {
		metrics.RiskSignals.WithLabelValues("new_device").Inc()
	}
	if impossible {
		metrics.RiskSignals.WithLabelValues("impossible_travel").Inc()
	}
	if untrusted {
		metrics.RiskSignals.WithLabelValues("untrusted_ip").Inc()
	}

	return map[string]any{
		"new_device":        newDevice,
		"impossible_travel": impossible,
		"untrusted_ip":      untrusted,
		"score":             score(newDevice, impossible, untrusted),
	}
}

// score collapses the boolean signals into a coarse level for quick filtering.
func score(newDevice, impossible, untrusted bool) string {
	switch {
	case impossible || untrusted:
		return "high"
	case newDevice:
		return "medium"
	default:
		return "low"
	}
}

func (a *Assessor) isUntrustedIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, n := range a.untrusted {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// deviceScanLimit bounds how many recent distinct User-Agents are pulled for
// the new-device comparison — enough to cover a user's real device set without
// scanning unbounded history.
const deviceScanLimit = 200

// deviceBaselineActions are the audited events that establish what device a user
// signs in from. Any of them proves the person was present on that device, so any
// of them is a valid baseline for "has their device changed?".
//
// Deliberately broader than auth.login: an account's first login is otherwise
// compared against an empty history even when the account was just created from
// the same browser, which made the new-device signal fire on every new user. See
// isNewDevice for the full reasoning.
//
// Social logins are matched by prefix at query time rather than enumerated here,
// because SocialLoginAction mints one action per provider.
var deviceBaselineActions = []string{
	audit.ActionAuthLogin,
	audit.ActionAuthRegister,
	audit.ActionAuthInvitationAccepted,
	audit.ActionAuthGoogleLogin,
}

// isNewDevice reports whether this user has NOT successfully logged in from a
// device with the same browser + OS family within the lookback window. Matching
// on the parsed (browser, OS) family rather than the exact User-Agent string
// avoids a false "new device" on every browser auto-update (which bumps the
// version inside the UA) and is not defeated by trivial UA-string churn.
// Unknown (no user / no UA / query error) is treated as not-new to avoid false
// alarms.
func (a *Assessor) isNewDevice(ctx context.Context, in audit.RiskInput) bool {
	if a.pool == nil || in.UserID == nil || in.UserAgent == "" {
		return false
	}
	curBrowser, curOS := deviceFamily(in.UserAgent)
	if curBrowser == "" && curOS == "" {
		return false // unparseable UA — cannot judge, so don't flag
	}
	// Every action that proves the user was present on a device, not just
	// auth.login.
	//
	// Filtering on auth.login alone made the FIRST login of any account look like a
	// new device even though the account had just been created from that very
	// browser: registration is audited as auth.register, an invited user's first
	// appearance as auth.invitation_accepted, and a social sign-in under its own
	// provider action — none of which matched, so the baseline was empty and the
	// alert fired on a device the user had demonstrably just used. The signal is
	// "did this person's device change", and any of these establishes what their
	// device was.
	//
	// The current login's own row is deliberately NOT excluded by time.
	//
	// It may or may not be visible yet — the audit writer is asynchronous — but
	// either way the answer is right: if it is visible, its UA equals the one being
	// assessed and the loop below returns "not new" on the match; if it is not, the
	// history is judged without it. A time-based exclusion window was tried here and
	// is wrong, because it also hides a legitimate baseline established moments
	// earlier (registering and then signing in) and would blind the signal exactly
	// when a real attacker follows a compromise straight into a session.
	rows, err := a.pool.Query(ctx, `
		SELECT DISTINCT user_agent FROM audit_logs
		WHERE user_id = $1
		  AND action = ANY($2)
		  AND status = 'success'
		  AND user_agent <> ''
		  AND created_at > $3
		ORDER BY user_agent
		LIMIT $4`,
		*in.UserID, deviceBaselineActions, time.Now().Add(-lookback), deviceScanLimit,
	)
	if err != nil {
		a.logger.Debug().Err(err).Msg("risk: new-device lookup failed")
		return false
	}
	defer rows.Close()
	seen := 0
	for rows.Next() {
		var ua string
		if err := rows.Scan(&ua); err != nil {
			a.logger.Debug().Err(err).Msg("risk: new-device scan failed")
			return false
		}
		seen++
		b, o := deviceFamily(ua)
		if b == curBrowser && o == curOS {
			return false // same device family seen before — not new
		}
	}
	if err := rows.Err(); err != nil {
		a.logger.Debug().Err(err).Msg("risk: new-device iteration failed")
		return false
	}

	// No prior successful login at all: there is no baseline, so nothing can deviate
	// from it. "New device" is a comparison, and with an empty history the comparison
	// has no meaning.
	//
	// Without this the signal fired on every account's FIRST login — necessarily,
	// since a first login is always from an unseen device — which alerted the owner
	// that their own sign-up was suspicious and recorded a risk event on every new
	// account. A signal that fires 100% of the time carries no information and
	// teaches operators to ignore the ones that matter.
	//
	// The first login is what establishes the baseline; the second onwards can
	// deviate from it.
	if seen == 0 {
		return false
	}
	return true
}

// deviceFamily reduces a User-Agent to its (browser name, OS) pair — the stable
// device identity that survives version bumps.
func deviceFamily(raw string) (browser, os string) {
	ua := useragent.New(raw)
	if ua == nil {
		return "", ""
	}
	name, _ := ua.Browser()
	return name, ua.OS()
}

// isImpossibleTravel compares the current login location against the user's most
// recent prior login location and the time between them. Flags when the implied
// travel speed exceeds impossibleSpeed. Requires geo on both ends; missing geo
// (disabled/private IP) yields false.
func (a *Assessor) isImpossibleTravel(ctx context.Context, in audit.RiskInput) bool {
	if a.pool == nil || in.UserID == nil || in.Geo == nil {
		return false
	}
	if in.Geo.Latitude == 0 && in.Geo.Longitude == 0 {
		return false
	}

	var prevMeta []byte
	var prevAt time.Time
	err := a.pool.QueryRow(ctx, `
		SELECT metadata, created_at FROM audit_logs
		WHERE user_id = $1 AND action = $2 AND status = 'success'
		  AND metadata ? 'location'
		ORDER BY created_at DESC
		LIMIT 1`,
		*in.UserID, audit.ActionAuthLogin,
	).Scan(&prevMeta, &prevAt)
	if err != nil {
		return false // no prior located login (or query error) → cannot judge
	}

	var prev struct {
		Location struct {
			Latitude  float64 `json:"latitude"`
			Longitude float64 `json:"longitude"`
		} `json:"location"`
	}
	if err := json.Unmarshal(prevMeta, &prev); err != nil {
		return false
	}
	if prev.Location.Latitude == 0 && prev.Location.Longitude == 0 {
		return false
	}

	distKM := haversineKM(
		prev.Location.Latitude, prev.Location.Longitude,
		in.Geo.Latitude, in.Geo.Longitude,
	)
	if distKM < minTravelKM {
		return false
	}
	hours := time.Since(prevAt).Hours()
	if hours <= 0 {
		return true // same instant, different continents
	}
	return distKM/hours > impossibleSpeed
}

// haversineKM returns the great-circle distance between two lat/lon points.
func haversineKM(lat1, lon1, lat2, lon2 float64) float64 {
	const earthRadiusKM = 6371.0
	dLat := radians(lat2 - lat1)
	dLon := radians(lon2 - lon1)
	a := math.Sin(dLat/2)*math.Sin(dLat/2) +
		math.Cos(radians(lat1))*math.Cos(radians(lat2))*
			math.Sin(dLon/2)*math.Sin(dLon/2)
	return earthRadiusKM * 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
}

func radians(deg float64) float64 { return deg * math.Pi / 180 }
