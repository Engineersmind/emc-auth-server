package middleware

import (
	"net"

	"github.com/labstack/echo/v4"
)

// ClientIPExtractor resolves the caller's IP for c.RealIP(), which keys every
// per-IP rate limiter, the adaptive CAPTCHA, audit rows and the risk engine.
//
// X-Forwarded-For is walked right to left and the first hop that is not a
// trusted proxy is the client; a direct peer that is not trusted has its header
// ignored entirely, and an entry that does not parse as an IP falls back to the
// direct peer. Without an extractor, Echo returns the LEFTMOST entry — the one
// the client wrote (GHSA-3rxg-g9v9-4gh8).
//
// Private ranges are deliberately NOT trusted wholesale: the Docker network the
// app runs on also holds Redis, Prometheus and Grafana, and none of them is a
// proxy. Only the ranges named in TRUSTED_PROXIES are.
func ClientIPExtractor(trusted []*net.IPNet) echo.IPExtractor {
	opts := []echo.TrustOption{
		echo.TrustLoopback(true),
		echo.TrustLinkLocal(false),
		echo.TrustPrivateNet(false),
	}
	for _, n := range trusted {
		opts = append(opts, echo.TrustIPRange(n))
	}
	return echo.ExtractIPFromXFFHeader(opts...)
}
