// SIEM streaming sink — posts each persisted audit batch as JSON to a webhook
// (Datadog/Splunk/S3-proxy/generic). Fully decoupled from the audit writer: its
// own buffered channel + worker goroutine, drop-on-full, bounded HTTP timeout.
// A downstream outage can only lose stream entries (counted), never slow the
// audit writer or the auth path.
package enrich

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
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
	client *http.Client
	ch     chan []audit.Event
	done   chan struct{}
	closed chan struct{}
	logger zerolog.Logger
}

// NewWebhookSink starts the streaming worker. Returns nil when url is empty
// (streaming disabled) so callers can pass the result straight to
// audit.WithSink without a nil check tripping the option.
func NewWebhookSink(url string, logger zerolog.Logger) *WebhookSink {
	if url == "" {
		return nil
	}
	s := &WebhookSink{
		url:    url,
		client: &http.Client{Timeout: siemTimeout},
		ch:     make(chan []audit.Event, siemQueueSize),
		done:   make(chan struct{}),
		closed: make(chan struct{}),
		logger: logger,
	}
	go s.run()
	return s
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
