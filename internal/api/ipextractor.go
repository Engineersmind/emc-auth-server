package api

import (
	"net"

	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog"
)

// NewIPExtractor builds the Echo IPExtractor that backs c.RealIP() for every
// rate-limit, CAPTCHA, and audit/risk decision in the service.
//
// trustedProxies is the operator-configured list of CIDRs (or bare IPs) whose
// X-Forwarded-For header may be believed. When it is empty the
// extractor is ExtractIPDirect: the connection address is the client IP and
// forwarded headers are ignored entirely. That is the only safe default —
// Echo's built-in RealIP honours XFF unconditionally, which lets any client
// spoof an IP to bypass rate limits or poison risk/audit data.
//
// When proxies are configured, the RFC6890 defaults are switched off so the
// operator's list is the whole trust set — a proxy at a public address would
// otherwise be silently untrusted while an attacker on a private range was
// believed.
func NewIPExtractor(trustedProxies []string, logger zerolog.Logger) echo.IPExtractor {
	if len(trustedProxies) == 0 {
		return echo.ExtractIPDirect()
	}

	opts := []echo.TrustOption{
		echo.TrustLoopback(false),
		echo.TrustLinkLocal(false),
		echo.TrustPrivateNet(false),
	}
	for _, entry := range trustedProxies {
		if _, ipNet, err := net.ParseCIDR(entry); err == nil {
			opts = append(opts, echo.TrustIPRange(ipNet))
			continue
		}
		if ip := net.ParseIP(entry); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			opts = append(opts, echo.TrustIPRange(&net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}))
			continue
		}
		logger.Warn().Str("cidr", entry).Msg("TRUSTED_PROXIES: ignoring malformed entry")
	}
	logger.Info().Strs("trusted_proxies", trustedProxies).Msg("forwarded-IP headers trusted from configured proxies only")
	return echo.ExtractIPFromXFFHeader(opts...)
}
