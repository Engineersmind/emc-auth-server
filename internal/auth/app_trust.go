package auth

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
)

// Server-to-server trust for application backends.
//
// A product backend signs in, registers and resets every one of its users by
// calling /auth/apps/* from a handful of egress addresses with one client_id.
// Without this, the server cannot tell that backend apart from one very busy
// attacker, and keys its IP limits and captcha counter on an address that every
// user of the product shares.
//
// Two per-application settings, both off by default:
//
//   - Server IPs: the backend's egress addresses. A request from one of them, for
//     that application, skips the per-IP flood guard. The application quota and
//     the per-user limits still apply, so this is not an exemption from limiting,
//     only from counting a whole product as one address.
//   - Trust forwarded IP: the backend may report the end user's address in
//     X-EMC-Forwarded-For. The middleware honours it only for a request whose
//     client secret verified AND that came from one of the registered server
//     IPs, so forwarding needs at least one. This is the model Auth0 ("Trust
//     Token Endpoint IP Header"), Okta (trusted applications with network
//     zones) and Cognito (ContextData) use, with the address requirement
//     added so a leaked secret alone cannot be used to invent user addresses.
//
// The request path reads an in-memory snapshot rather than the database. The
// lookup happens BEFORE the per-IP guard (it decides whether that guard applies),
// so a database read here would let an unauthenticated flood of made-up
// client_ids drive queries at full speed. The snapshot holds only applications
// that have configured something, which is a small set, and is refreshed every
// AppTrustRefreshInterval; a change made through this service is visible on the
// instance that made it immediately and on the others within one interval.

// ErrInvalidServerIP is returned by SetServerTrust for an address or range that
// cannot be registered. The wrapped message says which entry and why.
var ErrInvalidServerIP = errors.New("invalid server ip")

const (
	// MaxAppServerIPs bounds the allowlist per application. Real egress sets are
	// a handful of NAT addresses; a list in the hundreds is a sign someone is
	// pasting a cloud provider's whole range, which defeats the purpose.
	MaxAppServerIPs = 50

	// Narrowest acceptable ranges. Anything wider covers networks the
	// application does not own, and a /0 would exempt the internet from the
	// per-IP guard for this application's client_id.
	minServerIPv4Prefix = 24
	minServerIPv6Prefix = 48

	maxServerIPDescriptionLen = 200

	// AppTrustRefreshInterval is how often each instance reloads the snapshot.
	AppTrustRefreshInterval = 30 * time.Second
)

// AppServerIP is one registered egress address or range.
type AppServerIP struct {
	CIDR        string    `json:"cidr"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
}

// AppServerIPInput is one entry of a SetServerTrust request.
type AppServerIPInput struct {
	CIDR        string `json:"cidr"`
	Description string `json:"description"`
}

// AppServerTrust is an application's server-to-server settings, as the admin API
// reads and writes them.
type AppServerTrust struct {
	ApplicationID    int64         `json:"application_id"`
	TenantID         int64         `json:"tenant_id"`
	TrustForwardedIP bool          `json:"trust_forwarded_ip"`
	ServerIPs        []AppServerIP `json:"server_ips"`
}

// ServerTrust is the request-path view of one application's settings.
type ServerTrust struct {
	TenantID         int64
	ApplicationID    int64
	TrustForwardedIP bool
	Prefixes         []netip.Prefix
}

// HasServerIPs reports whether the application registered any egress address.
func (t ServerTrust) HasServerIPs() bool { return len(t.Prefixes) > 0 }

// AllowsIP reports whether ip is one of the application's registered egress
// addresses. An unparseable ip is never allowed.
func (t ServerTrust) AllowsIP(ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	for _, p := range t.Prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// AppTrustService manages application server IPs and the forwarded-IP flag.
type AppTrustService struct {
	pool   *pgxpool.Pool
	logger zerolog.Logger
	// snapshot maps client_id → settings for every active application that has
	// configured either setting. Swapped whole on reload, so readers never lock.
	snapshot atomic.Pointer[map[string]ServerTrust]
}

// NewAppTrustService creates an AppTrustService with an empty snapshot. Call
// Start to load it and keep it fresh.
func NewAppTrustService(pool *pgxpool.Pool, logger zerolog.Logger) *AppTrustService {
	s := &AppTrustService{pool: pool, logger: logger}
	empty := map[string]ServerTrust{}
	s.snapshot.Store(&empty)
	return s
}

// Lookup returns the settings for clientID from the in-memory snapshot. It never
// touches the database, which is what makes it safe ahead of the per-IP guard.
func (s *AppTrustService) Lookup(clientID string) (ServerTrust, bool) {
	if s == nil || clientID == "" {
		return ServerTrust{}, false
	}
	m := s.snapshot.Load()
	if m == nil {
		return ServerTrust{}, false
	}
	t, ok := (*m)[clientID]
	return t, ok
}

// Start loads the snapshot and refreshes it every AppTrustRefreshInterval until
// the returned stop function is called. A failed load keeps the previous
// snapshot: losing trust settings on a database blip would throttle every
// registered backend at once.
func (s *AppTrustService) Start(ctx context.Context) (stop func()) {
	ctx, cancel := context.WithCancel(ctx)
	if err := s.Reload(ctx); err != nil {
		s.logger.Warn().Err(err).Msg("app trust: initial load failed — server IPs and forwarding are inactive until the next refresh")
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(AppTrustRefreshInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := s.Reload(ctx); err != nil && ctx.Err() == nil {
					s.logger.Warn().Err(err).Msg("app trust: refresh failed — keeping the previous snapshot")
				}
			}
		}
	}()
	return func() {
		cancel()
		<-done
	}
}

// Reload rebuilds the snapshot from the database.
//
// Suspended and deleted applications are left out, so a suspended backend loses
// its exemptions within one refresh even though its rows remain.
func (s *AppTrustService) Reload(ctx context.Context) error {
	rows, err := s.pool.Query(ctx, `
		SELECT c.client_id, c.id, c.tenant_id, c.trust_forwarded_ip,
		       COALESCE(array_agg(s.cidr::text ORDER BY s.id) FILTER (WHERE s.id IS NOT NULL), '{}')
		FROM oauth_clients c
		LEFT JOIN app_server_ips s ON s.application_id = c.id
		WHERE c.deleted_at IS NULL AND c.is_active
		  AND (c.trust_forwarded_ip OR s.id IS NOT NULL)
		GROUP BY c.id, c.client_id, c.tenant_id, c.trust_forwarded_ip
	`)
	if err != nil {
		return fmt.Errorf("load app trust: %w", err)
	}
	defer rows.Close()

	next := map[string]ServerTrust{}
	for rows.Next() {
		var (
			clientID string
			t        ServerTrust
			cidrs    []string
		)
		if err := rows.Scan(&clientID, &t.ApplicationID, &t.TenantID, &t.TrustForwardedIP, &cidrs); err != nil {
			return fmt.Errorf("scan app trust: %w", err)
		}
		for _, raw := range cidrs {
			p, err := netip.ParsePrefix(raw)
			if err != nil {
				// The column type is CIDR, so this cannot happen short of a
				// driver change. Skip the entry rather than the application.
				s.logger.Warn().Err(err).Str("cidr", raw).Int64("application_id", t.ApplicationID).
					Msg("app trust: unparseable server ip skipped")
				continue
			}
			t.Prefixes = append(t.Prefixes, p.Masked())
		}
		next[clientID] = t
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read app trust: %w", err)
	}
	s.snapshot.Store(&next)
	return nil
}

// GetServerTrust returns the application's settings. ErrAppNotFound when the
// application does not exist in the tenant.
func (s *AppTrustService) GetServerTrust(ctx context.Context, tenantID, applicationID int64) (*AppServerTrust, error) {
	out := &AppServerTrust{ApplicationID: applicationID, TenantID: tenantID, ServerIPs: []AppServerIP{}}
	err := s.pool.QueryRow(ctx, `
		SELECT trust_forwarded_ip FROM oauth_clients
		WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL
	`, applicationID, tenantID).Scan(&out.TrustForwardedIP)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrAppNotFound
		}
		return nil, fmt.Errorf("get app trust: %w", err)
	}

	rows, err := s.pool.Query(ctx, `
		SELECT cidr::text, description, created_at FROM app_server_ips
		WHERE application_id = $1 AND tenant_id = $2
		ORDER BY id
	`, applicationID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list app server ips: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var ip AppServerIP
		if err := rows.Scan(&ip.CIDR, &ip.Description, &ip.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan app server ip: %w", err)
		}
		out.ServerIPs = append(out.ServerIPs, ip)
	}
	return out, rows.Err()
}

// SetServerTrust replaces the application's settings. A nil argument keeps that
// setting as it is, so a caller changing only the flag cannot wipe the list by
// omission.
func (s *AppTrustService) SetServerTrust(
	ctx context.Context,
	tenantID, applicationID int64,
	trustForwardedIP *bool,
	serverIPs *[]AppServerIPInput,
) (*AppServerTrust, error) {
	var normalized []AppServerIPInput
	if serverIPs != nil {
		var err error
		if normalized, err = NormalizeServerIPs(*serverIPs); err != nil {
			return nil, err
		}
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin app trust update: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// Ownership check and flag update in one statement. Locks the row, so two
	// concurrent replacements of the list serialise instead of interleaving.
	tag, err := tx.Exec(ctx, `
		UPDATE oauth_clients
		SET trust_forwarded_ip = COALESCE($3, trust_forwarded_ip), updated_at = NOW()
		WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL
	`, applicationID, tenantID, trustForwardedIP)
	if err != nil {
		return nil, fmt.Errorf("update app trust flag: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrAppNotFound
	}

	if serverIPs != nil {
		if _, err := tx.Exec(ctx, `DELETE FROM app_server_ips WHERE application_id = $1 AND tenant_id = $2`,
			applicationID, tenantID); err != nil {
			return nil, fmt.Errorf("clear app server ips: %w", err)
		}
		for _, ip := range normalized {
			if _, err := tx.Exec(ctx, `
				INSERT INTO app_server_ips (tenant_id, application_id, cidr, description)
				VALUES ($1, $2, $3::cidr, $4)
			`, tenantID, applicationID, ip.CIDR, ip.Description); err != nil {
				return nil, fmt.Errorf("insert app server ip: %w", err)
			}
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit app trust update: %w", err)
	}

	// Apply on this instance now; the others pick it up on their next refresh.
	if err := s.Reload(ctx); err != nil {
		s.logger.Warn().Err(err).Msg("app trust: reload after update failed — change applies at the next refresh")
	}
	return s.GetServerTrust(ctx, tenantID, applicationID)
}

// NormalizeServerIPs validates and canonicalises an allowlist: bare addresses
// become single-host ranges, host bits are masked off, duplicates are dropped
// (the first description wins), and the rules in NormalizeServerIP apply to
// every entry.
func NormalizeServerIPs(in []AppServerIPInput) ([]AppServerIPInput, error) {
	out := make([]AppServerIPInput, 0, len(in))
	seen := map[netip.Prefix]bool{}
	for i, entry := range in {
		p, err := NormalizeServerIP(entry.CIDR)
		if err != nil {
			return nil, fmt.Errorf("%w: entry %d (%q): %s", ErrInvalidServerIP, i+1, entry.CIDR, err.Error())
		}
		desc := strings.TrimSpace(entry.Description)
		if len(desc) > maxServerIPDescriptionLen {
			return nil, fmt.Errorf("%w: entry %d: description is longer than %d characters",
				ErrInvalidServerIP, i+1, maxServerIPDescriptionLen)
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, AppServerIPInput{CIDR: p.String(), Description: desc})
	}
	if len(out) > MaxAppServerIPs {
		return nil, fmt.Errorf("%w: at most %d server ips per application", ErrInvalidServerIP, MaxAppServerIPs)
	}
	return out, nil
}

// NormalizeServerIP parses one address ("203.0.113.10") or range
// ("203.0.113.0/28") and returns it as a masked prefix.
//
// Refused: unspecified and multicast addresses, IPv6 zones, and ranges wider
// than /24 (IPv4) or /48 (IPv6). Private ranges are accepted because a backend
// in the same VPC as this server legitimately arrives from one.
func NormalizeServerIP(raw string) (netip.Prefix, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return netip.Prefix{}, errors.New("address is empty")
	}

	var p netip.Prefix
	if strings.Contains(raw, "/") {
		parsed, err := netip.ParsePrefix(raw)
		if err != nil {
			return netip.Prefix{}, errors.New("not a valid address or CIDR range")
		}
		p = parsed
	} else {
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			return netip.Prefix{}, errors.New("not a valid address or CIDR range")
		}
		if addr.Zone() != "" {
			return netip.Prefix{}, errors.New("IPv6 zones are not accepted")
		}
		addr = addr.Unmap()
		p = netip.PrefixFrom(addr, addr.BitLen())
	}

	addr := p.Addr()
	if addr.Is4In6() {
		// "::ffff:203.0.113.0/120" — store it as the IPv4 range it means.
		bits := p.Bits() - 96
		if bits < 0 {
			return netip.Prefix{}, errors.New("range is too wide")
		}
		p = netip.PrefixFrom(addr.Unmap(), bits)
		addr = p.Addr()
	}
	if addr.IsUnspecified() || addr.IsMulticast() {
		return netip.Prefix{}, errors.New("unspecified and multicast addresses are not accepted")
	}
	if addr.Is4() && p.Bits() < minServerIPv4Prefix {
		return netip.Prefix{}, fmt.Errorf("IPv4 ranges must be /%d or narrower", minServerIPv4Prefix)
	}
	if addr.Is6() && p.Bits() < minServerIPv6Prefix {
		return netip.Prefix{}, fmt.Errorf("IPv6 ranges must be /%d or narrower", minServerIPv6Prefix)
	}
	return p.Masked(), nil
}
