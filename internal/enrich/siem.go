// SIEM streaming sink — posts each persisted audit batch as JSON to a webhook
// (Datadog/Splunk/S3-proxy/generic). Fully decoupled from the audit writer: its
// own buffered channel + worker goroutine, drop-on-full, bounded HTTP timeout.
// A downstream outage can only lose stream entries (counted), never slow the
// audit writer or the auth path.
package enrich

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"syscall"
	"time"

	"github.com/rs/zerolog"

	"github.com/engineersmind/emc-auth-server/internal/audit"
	"github.com/engineersmind/emc-auth-server/internal/metrics"
)

const (
	siemQueueSize = 256
	siemTimeout   = 5 * time.Second
)

// WebhookSink implements audit.Sink by POSTing batches to an HTTP endpoint.
type WebhookSink struct {
	url    string
	secret string
	client *http.Client
	ch     chan []audit.Event
	done   chan struct{}
	closed chan struct{}
	logger zerolog.Logger
}

// NewWebhookSink starts the streaming worker. Returns nil when url is empty
// (streaming disabled) so callers can pass the result straight to
// audit.WithSink without a nil check tripping the option.
//
// The URL is validated at startup: it must be https and must not resolve to a
// private/loopback/link-local address (SSRF guard against metadata endpoints
// and internal admin ports). An invalid URL disables streaming (returns nil)
// with a warning rather than starting a worker that can never deliver. When
// secret is set, every payload is signed with HMAC-SHA256 so the receiver can
// authenticate the stream; an unsigned stream is warned about at startup.
func NewWebhookSink(rawURL, secret string, logger zerolog.Logger) *WebhookSink {
	if rawURL == "" {
		return nil
	}
	if err := validateWebhookURL(rawURL); err != nil {
		logger.Error().Err(err).Msg("audit siem: AUDIT_SIEM_WEBHOOK_URL rejected — streaming disabled")
		return nil
	}
	if secret == "" {
		logger.Warn().Msg("audit siem: AUDIT_SIEM_WEBHOOK_SECRET is empty — outbound stream is unsigned")
	}
	s := &WebhookSink{
		url:    rawURL,
		secret: secret,
		client: &http.Client{Timeout: siemTimeout, Transport: ssrfSafeTransport()},
		ch:     make(chan []audit.Event, siemQueueSize),
		done:   make(chan struct{}),
		closed: make(chan struct{}),
		logger: logger,
	}
	go s.run()
	return s
}

// validateWebhookURL enforces https and rejects a URL whose host resolves to a
// non-public address, blocking SSRF to metadata/loopback/internal targets.
func validateWebhookURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("unparseable URL: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("scheme must be https, got %q", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("missing host")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return fmt.Errorf("cannot resolve host %q: %w", host, err)
	}
	for _, ip := range ips {
		if isBlockedIP(ip.IP) {
			return fmt.Errorf("host %q resolves to a non-public address %s", host, ip.IP)
		}
	}
	return nil
}

// isBlockedIP reports whether an IP is one no outbound webhook should reach.
func isBlockedIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified()
}

// ssrfSafeTransport returns an http.Transport whose dialer rejects any
// connection to a blocked address. The Control hook runs after DNS resolution
// with the concrete remote IP, so it also defeats DNS-rebinding (a host that
// passed the startup check but later resolves to 169.254.169.254).
func ssrfSafeTransport() *http.Transport {
	d := &net.Dialer{
		Timeout: 10 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip := net.ParseIP(host)
			if ip == nil || isBlockedIP(ip) {
				return fmt.Errorf("audit siem: blocked connection to non-public address %s", address)
			}
			return nil
		},
	}
	return &http.Transport{DialContext: d.DialContext}
}

// Emit enqueues a batch for streaming; drops (and counts) when the buffer is
// full so it never blocks the audit worker.
func (s *WebhookSink) Emit(events []audit.Event) {
	if s == nil || len(events) == 0 {
		return
	}
	select {
	case s.ch <- events:
	default:
		metrics.AuditEnrichmentErrors.WithLabelValues("siem_drop").Inc()
	}
}

// Close stops the worker after draining what is already buffered.
func (s *WebhookSink) Close() {
	if s == nil {
		return
	}
	close(s.done)
	<-s.closed
}

func (s *WebhookSink) run() {
	defer close(s.closed)
	for {
		select {
		case batch := <-s.ch:
			s.post(batch)
		case <-s.done:
			// Drain remaining buffered batches, then exit.
			for {
				select {
				case batch := <-s.ch:
					s.post(batch)
				default:
					return
				}
			}
		}
	}
}

func (s *WebhookSink) post(events []audit.Event) {
	payload := make([]map[string]any, 0, len(events))
	for _, e := range events {
		payload = append(payload, map[string]any{
			"action":      e.Action,
			"auth_method": e.AuthMethod,
			"status":      e.Status,
			"http_status": e.HTTPStatus,
			"actor_email": e.ActorEmail,
			"ip_address":  e.IPAddress,
			"user_agent":  e.UserAgent,
			"request_id":  e.RequestID,
			"resource":    e.ResourceType,
			"resource_id": e.ResourceID,
			"metadata":    e.Metadata,
			"created_at":  e.CreatedAt().UTC().Format(time.RFC3339Nano),
		})
	}
	body, err := json.Marshal(map[string]any{"events": payload})
	if err != nil {
		metrics.AuditEnrichmentErrors.WithLabelValues("siem_marshal").Inc()
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), siemTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		metrics.AuditEnrichmentErrors.WithLabelValues("siem_req").Inc()
		return
	}
	req.Header.Set("Content-Type", "application/json")
	// Authenticate the stream: HMAC-SHA256 over the exact bytes sent, so the
	// receiver can verify the payload originated from us and was not tampered.
	if s.secret != "" {
		mac := hmac.New(sha256.New, []byte(s.secret))
		mac.Write(body)
		req.Header.Set("X-EMC-Audit-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	// URL is operator-configured (AUDIT_SIEM_WEBHOOK_URL), validated https at
	// startup, and the transport's dialer rejects any private/loopback target
	// on every dial (defeating DNS-rebinding) — so the SSRF surface is closed.
	//nolint:gosec // G704: destination is https-validated + dialer blocks non-public IPs per connection.
	resp, err := s.client.Do(req)
	if err != nil {
		metrics.AuditEnrichmentErrors.WithLabelValues("siem_post").Inc()
		s.logger.Debug().Err(err).Msg("audit siem: stream POST failed")
		return
	}
	_ = resp.Body.Close()
	if resp.StatusCode >= 300 {
		metrics.AuditEnrichmentErrors.WithLabelValues("siem_status").Inc()
	}
}
