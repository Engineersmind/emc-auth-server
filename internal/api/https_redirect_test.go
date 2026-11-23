package api

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
)

// proxyNet is the TLS-terminating proxy's range, as TRUSTED_PROXIES names it.
func proxyNet(t *testing.T) []*net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR("172.18.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	return []*net.IPNet{n}
}

func serveHTTPSRedirect(t *testing.T, env, remote, proto string, viaTLS bool) *httptest.ResponseRecorder {
	t.Helper()
	e := echo.New()
	e.Use(httpsRedirect(env, proxyNet(t)))
	e.GET("/x", func(c echo.Context) error { return c.NoContent(http.StatusOK) })

	req := httptest.NewRequest(http.MethodGet, "/x?a=1", nil)
	req.Host = "auth.example.test"
	req.RemoteAddr = remote
	if proto != "" {
		req.Header.Set("X-Forwarded-Proto", proto)
	}
	if viaTLS {
		req.TLS = &tls.ConnectionState{}
	}
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}

func TestHTTPSRedirect(t *testing.T) {
	const (
		proxy    = "172.18.0.1:5000"
		direct   = "198.51.100.5:5000"
		loopback = "127.0.0.1:5000"
	)
	cases := []struct {
		name         string
		env          string
		remote       string
		proto        string
		viaTLS       bool
		wantRedirect bool
	}{
		// why: #216 — the header is client-supplied unless the peer is the proxy.
		{"direct peer claiming https is redirected", "production", direct, "https", false, true},
		// why: #216 — traffic behind the real proxy is unchanged.
		{"trusted proxy forwarding https passes", "production", proxy, "https", false, false},
		// why: #216
		{"trusted proxy forwarding http is redirected", "production", proxy, "http", false, true},
		// why: #216 — loopback is trusted exactly as ClientIPExtractor trusts it.
		{"loopback proxy forwarding https passes", "production", loopback, "https", false, false},
		{"other private range is not a proxy", "production", "10.0.0.5:5000", "https", false, true},
		{"direct peer without header is redirected", "production", direct, "", false, true},
		{"real TLS connection passes", "production", direct, "", true, false},
		{"development never redirects", "development", direct, "", false, false},
		{"development ignores a spoofed header too", "development", direct, "http", false, false},
		{"staging never redirects", "staging", direct, "", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := serveHTTPSRedirect(t, tc.env, tc.remote, tc.proto, tc.viaTLS)
			if tc.wantRedirect {
				if rec.Code != http.StatusMovedPermanently {
					t.Fatalf("status = %d, want 301", rec.Code)
				}
				if got, want := rec.Header().Get("Location"), "https://auth.example.test/x?a=1"; got != want {
					t.Fatalf("Location = %q, want %q", got, want)
				}
				return
			}
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (Location %q)", rec.Code, rec.Header().Get("Location"))
			}
		})
	}
}
