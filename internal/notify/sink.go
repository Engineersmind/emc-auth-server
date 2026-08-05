package notify

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	"github.com/engineersmind/emc-auth-server/internal/audit"
	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/mailer"
	"github.com/engineersmind/emc-auth-server/internal/metrics"
)

const (
	// queueSize buffers whole batches, not events. Full means drop: see Emit.
	queueSize = 256

	// defaultCollapseWindow is how long identical actions are gathered into one
	// email.
	//
	// It is the delay every notification pays. Kept short because the point of
	// this channel is that a surprising change is seen while it still matters —
	// but not zero, because an admin adjusting grants four times in a minute made
	// one decision, and the first three emails would each describe a state that
	// no longer exists by the time they are read.
	defaultCollapseWindow = 15 * time.Second

	// defaultFlushTick is how often due notices are swept. Finer than the window
	// so the effective delay stays close to it.
	defaultFlushTick = 3 * time.Second

	// perRecipientHourlyCap bounds one address's mail. Collapsing folds repeats
	// of the SAME action; it does nothing for twenty different ones, and an
	// unbounded channel is one that gets filtered to junk.
	perRecipientHourlyCap = 20

	// sendTimeout bounds one delivery so a hung SMTP server cannot wedge the
	// worker and stall every later notification behind it.
	sendTimeout = 20 * time.Second
)

// EmailSink turns persisted audit events into notification emails.
//
// It implements audit.Sink. Emit runs on the audit writer's goroutine, so it
// copies and returns; everything else happens on this type's own worker.
type EmailSink struct {
	pool           *pgxpool.Pool
	notifier       auth.EmailNotifier
	mailer         mailer.Mailer
	consoleBaseURL string
	platformEmails []string
	logger         zerolog.Logger

	// collapseWindow and flushTick are fields rather than constants so tests can
	// shorten them; production always gets the defaults below.
	collapseWindow time.Duration
	flushTick      time.Duration

	// auditLog records deliveries. Attached after construction because the audit
	// logger does not exist until this sink has been handed to it — see
	// WithAudit.
	auditLog *audit.Logger

	ch        chan []audit.Event
	done      chan struct{}
	closed    chan struct{}
	closeOnce sync.Once

	// sentCounts is the per-recipient hourly tally. Touched only by the worker
	// goroutine, so it needs no lock — keep it that way.
	sentCounts map[string]*hourCount
}

// notice is one pending email: an event plus how many identical ones it stands
// for, and when the first arrived.
type notice struct {
	ev    audit.Event
	count int
	first time.Time
}

// NewEmailSink creates the sink and starts its worker.
//
// senderSvc is deliberately absent: notifications go out via the GLOBAL sender,
// not the tenant's white-label one. An administrative notice is platform
// correspondence — a platform admin overseeing many tenants should not receive
// mail branded as each tenant in turn, and an owner being told what a co-owner
// did is not customer-facing mail from their own product. Per-scope TEMPLATE
// overrides and the disable switch still apply, so a tenant retains control of
// the wording and can turn the type off.
func NewEmailSink(
	pool *pgxpool.Pool,
	m mailer.Mailer,
	tmplSvc *auth.EmailTemplateService,
	consoleBaseURL string,
	platformEmails []string,
	logger zerolog.Logger,
) *EmailSink {
	s := &EmailSink{
		pool:           pool,
		notifier:       auth.NewEmailNotifier(m, logger).WithTemplates(tmplSvc),
		mailer:         m,
		consoleBaseURL: strings.TrimRight(consoleBaseURL, "/"),
		platformEmails: platformEmails,
		logger:         logger,
		collapseWindow: defaultCollapseWindow,
		flushTick:      defaultFlushTick,
		ch:             make(chan []audit.Event, queueSize),
		done:           make(chan struct{}),
		closed:         make(chan struct{}),
	}
	go s.run()
	return s
}

// WithAudit attaches the audit logger so deliveries are recorded.
//
// Separate from the constructor because of an ordering knot: the sink is passed
// to audit.New, so the logger does not exist yet. Call this immediately after
// constructing the logger and before the server starts serving — no events flow
// until then, so there is nothing to race with.
func (s *EmailSink) WithAudit(a *audit.Logger) *EmailSink {
	if s != nil {
		s.auditLog = a
	}
	return s
}

// Emit takes a persisted batch. It must return promptly: it runs on the audit
// writer's goroutine, so blocking here stalls the writer and audit events start
// dropping as queue_full. Losing a notification is strictly better than losing
// the log entry it describes.
func (s *EmailSink) Emit(events []audit.Event) {
	if s == nil || len(events) == 0 {
		return
	}

	// Filter before copying: most batches are logins and token refreshes, and
	// there is no reason to copy events nobody will be told about.
	var keep []audit.Event
	for _, e := range events {
		if _, ok := label(e.Action); !ok {
			continue
		}
		// Status is the raw value the caller set; the writer's "" → success
		// normalisation happens on the copy bound for the database. An attempt
		// that changed nothing is not news — except for the actions whose
		// failure IS the news, such as a refused privileged request.
		if e.Status != "" && e.Status != audit.StatusSuccess && !notifyOnFailure[e.Action] {
			continue
		}
		keep = append(keep, e)
	}
	if len(keep) == 0 {
		return
	}

	// keep is already a fresh slice, so the writer reusing its backing array
	// cannot alter it. Copying is not optional here: audit.Logger reuses one
	// buffer across flushes.
	select {
	case s.ch <- keep:
	default:
		metrics.AuditEnrichmentErrors.WithLabelValues("notify_drop").Add(float64(len(keep)))
		s.logger.Warn().Int("events", len(keep)).
			Msg("notify: queue full — notifications dropped (audit log is unaffected)")
	}
}

// Close stops the worker, flushing everything still pending. Called by main.go
// during shutdown, after the audit logger has drained.
//
// Idempotent, and blocks until the worker has finished. Shutdown paths overlap
// — a defer plus an explicit call is easy to end up with — and a second close of
// an unguarded channel panics, which is a poor way to discover the duplication
// during a production shutdown.
func (s *EmailSink) Close() {
	if s == nil {
		return
	}
	s.closeOnce.Do(func() { close(s.done) })
	<-s.closed
}

func (s *EmailSink) run() {
	defer close(s.closed)

	pending := map[string]*notice{}
	ticker := time.NewTicker(s.flushTick)
	defer ticker.Stop()

	for {
		select {
		case batch := <-s.ch:
			s.accumulate(pending, batch)
		case <-ticker.C:
			s.flush(pending, time.Now(), false)
		case <-s.done:
			// Drain whatever is queued, then send everything regardless of the
			// collapse window — shutdown must not swallow a pending notice.
			for {
				select {
				case batch := <-s.ch:
					s.accumulate(pending, batch)
					continue
				default:
				}
				break
			}
			s.flush(pending, time.Now(), true)
			return
		}
	}
}

// accumulate folds a batch into the pending set, collapsing repeats.
func (s *EmailSink) accumulate(pending map[string]*notice, batch []audit.Event) {
	now := time.Now()
	for _, e := range batch {
		k := collapseKey(e)
		if n, ok := pending[k]; ok {
			n.count++
			continue
		}
		pending[k] = &notice{ev: e, count: 1, first: now}
	}
}

// collapseKey groups events that describe one decision: the same actor doing the
// same thing to the same resource in the same tenant.
//
// The resource is part of the key on purpose — rotating the secrets of two
// different applications is two decisions and deserves two emails, even though
// the actor and action match.
func collapseKey(e audit.Event) string {
	tenant := int64(0)
	if e.TenantID != nil {
		tenant = *e.TenantID
	}
	return strconv.FormatInt(tenant, 10) + "|" + e.ActorEmail + "|" + e.Action + "|" +
		e.ResourceType + "|" + e.ResourceID
}

// flush sends every notice whose collapse window has elapsed. force ignores the
// window, for shutdown.
func (s *EmailSink) flush(pending map[string]*notice, now time.Time, force bool) {
	for k, n := range pending {
		if !force && now.Sub(n.first) < s.collapseWindow {
			continue
		}
		delete(pending, k)
		s.deliver(n)
	}
}

// deliver resolves the audience and sends one notice. Every failure is logged
// and counted rather than returned: there is nobody above this to handle it, and
// the audit row it describes is already safely written.
func (s *EmailSink) deliver(n *notice) {
	ctx, cancel := context.WithTimeout(context.Background(), sendTimeout)
	defer cancel()

	if n.ev.TenantID == nil {
		return // a cross-tenant event has no owner tier to notify
	}
	tenantID := *n.ev.TenantID

	aud, err := s.resolveAudience(ctx, tenantID, n.ev.UserID, n.ev.ActorEmail, n.ev.Action)
	if err != nil {
		metrics.AuditEnrichmentErrors.WithLabelValues("notify_recipients").Inc()
		s.logger.Error().Err(err).Str("action", n.ev.Action).Msg("notify: could not resolve recipients")
		return
	}
	if len(aud.to) == 0 {
		return
	}

	phrase, _ := label(n.ev.Action)
	appName := s.applicationName(ctx, n.ev.ApplicationID, n.ev.ResourceType, n.ev.ResourceID)
	msg := mailer.AdminActivityEmail{
		ActorEmail:   n.ev.ActorEmail,
		ActorRole:    aud.actorRole,
		ActionLabel:  phrase,
		TenantName:   s.tenantName(ctx, tenantID),
		ResourceName: appName,
		OccurredAt:   n.ev.CreatedAt().UTC().Format("2 Jan 2006, 15:04 MST"),
		IPAddress:    n.ev.IPAddress,
		Link:         s.monitoringLink(tenantID),
		Count:        n.count,
	}

	// The person the change was made TO, when it was an access change. They are
	// not in the tier-up audience — that reports upward — and without this they
	// would learn of it only by being refused something they could do yesterday.
	s.notifySubject(ctx, n, tenantID, aud.actorRole, msg.TenantName)

	for _, addr := range aud.to {
		if !s.allow(addr) {
			s.recordSuppressed(ctx, tenantID, addr, n.ev.Action, "hourly_cap")
			continue
		}
		msg.To = addr
		sent, err := s.notifier.Send(ctx, tenantID, nil, mailer.TemplateAdminActivity,
			func(sender *mailer.SMTPConfig, tmpl *mailer.Template) error {
				return s.mailer.SendAdminActivity(ctx, sender, tmpl, msg)
			})
		switch {
		case err != nil:
			metrics.AuditEnrichmentErrors.WithLabelValues("notify_send").Inc()
			s.logger.Error().Err(err).Str("to", addr).Str("action", n.ev.Action).
				Msg("notify: admin-activity email failed")
		case !sent:
			// Suppressed by template configuration — a deliberate choice, so it
			// is recorded rather than logged as a fault.
			s.recordSuppressed(ctx, tenantID, addr, n.ev.Action, "template_disabled")
		default:
			s.recordSent(ctx, tenantID, addr, n.ev.Action, n.count)
		}
	}
}

// notifySubject tells somebody their own administrative access changed.
//
// A no-op for every action that is not an access change, which is most of them.
// The actor is never the subject here: somebody adjusting their own grants
// already knows, and they get the actor copy anyway.
func (s *EmailSink) notifySubject(ctx context.Context, n *notice, tenantID int64, actorRole, tenantName string) {
	phrase, ok := subjectLabel(n.ev.Action)
	if !ok {
		return
	}
	to, apps := s.accessChangeSubject(ctx, tenantID, n.ev.ResourceType, n.ev.ResourceID)
	if to == "" || strings.EqualFold(to, n.ev.ActorEmail) {
		return
	}
	if !s.allow(to) {
		s.recordSuppressed(ctx, tenantID, to, n.ev.Action, "hourly_cap")
		return
	}

	msg := mailer.AccessChangedEmail{
		To:           to,
		ActionLabel:  phrase,
		ActorEmail:   n.ev.ActorEmail,
		ActorRole:    actorRole,
		TenantName:   tenantName,
		ResourceName: apps,
		OccurredAt:   n.ev.CreatedAt().UTC().Format("2 Jan 2006, 15:04 MST"),
	}
	sent, err := s.notifier.Send(ctx, tenantID, nil, mailer.TemplateAccessChanged,
		func(sender *mailer.SMTPConfig, tmpl *mailer.Template) error {
			return s.mailer.SendAccessChanged(ctx, sender, tmpl, msg)
		})
	switch {
	case err != nil:
		metrics.AuditEnrichmentErrors.WithLabelValues("notify_send").Inc()
		s.logger.Error().Err(err).Str("to", to).Msg("notify: access-changed notice failed")
	case !sent:
		s.recordSuppressed(ctx, tenantID, to, n.ev.Action, "template_disabled")
	default:
		s.recordSent(ctx, tenantID, to, n.ev.Action, 1)
	}
}

// monitoringLink deep-links the console's monitoring view for the tenant. Empty
// when no console origin is configured, and the template omits the line.
func (s *EmailSink) monitoringLink(tenantID int64) string {
	if s.consoleBaseURL == "" {
		return ""
	}
	return fmt.Sprintf("%s/dashboard/tenants/%d/logs", s.consoleBaseURL, tenantID)
}

func (s *EmailSink) recordSent(ctx context.Context, tenantID int64, to, action string, count int) {
	s.record(ctx, audit.ActionNotificationSent, tenantID, to, action, map[string]any{
		"notified_action": action,
		"occurrences":     count,
	})
}

func (s *EmailSink) recordSuppressed(ctx context.Context, tenantID int64, to, action, reason string) {
	s.record(ctx, audit.ActionNotificationSuppressed, tenantID, to, action, map[string]any{
		"notified_action": action,
		"reason":          reason,
	})
}

// record writes the delivery outcome to the audit trail, so "was the owner
// actually told?" is answerable. Recipient addresses are the point of the
// record, so they are stored; nothing else here is sensitive.
func (s *EmailSink) record(ctx context.Context, action string, tenantID int64, to, subject string, meta map[string]any) {
	if s.auditLog == nil {
		return
	}
	s.auditLog.Log(ctx, audit.Event{
		TenantID:     &tenantID,
		ActorEmail:   to,
		Action:       action,
		ResourceType: "notification",
		ResourceID:   subject,
		Metadata:     meta,
	})
}

func isNoRows(err error) bool { return errors.Is(err, pgx.ErrNoRows) }
