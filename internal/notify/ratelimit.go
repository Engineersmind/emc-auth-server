package notify

import (
	"strings"
	"time"

	"github.com/engineersmind/emc-auth-server/internal/metrics"
)

// allow reports whether another email may go to this address in the current
// hour, and counts it when it may.
//
// Collapsing folds repeats of the SAME action; it does nothing for twenty
// different ones in a busy tenant. Without a ceiling the channel becomes a
// firehose, and a firehose gets a filter rule — at which point the alerts that
// matter are lost along with the noise.
//
// Called only from the worker goroutine, so the counters need no lock. Keeping
// it that way is why this is a method on the sink rather than a shared helper.
func (s *EmailSink) allow(addr string) bool {
	key := strings.ToLower(addr)
	now := time.Now()

	if s.sentCounts == nil {
		s.sentCounts = map[string]*hourCount{}
	}
	c, ok := s.sentCounts[key]
	if !ok || now.Sub(c.windowStart) >= time.Hour {
		s.sentCounts[key] = &hourCount{windowStart: now, n: 1}
		s.pruneCounts(now)
		return true
	}
	if c.n >= perRecipientHourlyCap {
		metrics.AuditEnrichmentErrors.WithLabelValues("notify_rate_limited").Inc()
		s.logger.Warn().Str("to", addr).Int("cap", perRecipientHourlyCap).
			Msg("notify: hourly cap reached — further notifications suppressed for this recipient")
		return false
	}
	c.n++
	return true
}

// hourCount is one recipient's tally within a rolling window.
type hourCount struct {
	windowStart time.Time
	n           int
}

// pruneCounts drops windows that have expired. Without it the map grows for the
// life of the process, one entry per address ever notified — small per entry,
// but unbounded, and this runs on a long-lived server.
func (s *EmailSink) pruneCounts(now time.Time) {
	for k, c := range s.sentCounts {
		if now.Sub(c.windowStart) >= time.Hour {
			delete(s.sentCounts, k)
		}
	}
}
