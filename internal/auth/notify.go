package auth

import (
	"context"
	"strconv"

	"github.com/rs/zerolog"

	"github.com/engineersmind/emc-auth-server/internal/audit"
	"github.com/engineersmind/emc-auth-server/internal/mailer"
)

// ---------------------------------------------------------------------------
// Shared transactional-send pipeline.
//
// Every transactional email follows the same five steps: honour the per-scope
// disable flag (auditing the suppression), resolve the white-label sender
// (application → tenant → global), resolve the template override, send, and
// retry once via the global sender if a tenant's own sender fails. EmailNotifier
// factors those steps out so each flow only supplies the payload.
//
// It is exported because the notification sink (internal/notify) sends on the
// same terms — per-scope suppression, white-label sender, template override,
// global-sender retry. Duplicating that there would mean two implementations of
// the retry rule, and the second one drifting is exactly how a tenant with a
// broken SMTP server silently stops receiving one class of email.
// ---------------------------------------------------------------------------

// EmailNotifier carries the dependencies a transactional send needs. All are
// optional: a nil mailer disables sending, a nil tmplSvc means "no override,
// nothing suppressed", a nil senderSvc means "always the global sender".
//
// Construct with NewEmailNotifier and the With* builders from outside the
// package; inside it, a struct literal is equivalent.
type EmailNotifier struct {
	mailer    mailer.Mailer
	senderSvc *EmailSenderService
	tmplSvc   *EmailTemplateService
	audit     *audit.Logger
	logger    zerolog.Logger
}

// NewEmailNotifier creates a notifier that sends via the global sender and the
// built-in templates. Layer on the rest with the With* builders.
func NewEmailNotifier(m mailer.Mailer, logger zerolog.Logger) EmailNotifier {
	return EmailNotifier{mailer: m, logger: logger}
}

// WithSenders wires white-label sender resolution (application → tenant → global).
func (n EmailNotifier) WithSenders(s *EmailSenderService) EmailNotifier {
	n.senderSvc = s
	return n
}

// WithTemplates wires per-scope template overrides and the disable flag.
func (n EmailNotifier) WithTemplates(t *EmailTemplateService) EmailNotifier {
	n.tmplSvc = t
	return n
}

// WithAudit records suppressed sends, so a disabled template leaves a trace
// rather than looking like a delivery that never happened.
func (n EmailNotifier) WithAudit(a *audit.Logger) EmailNotifier {
	n.audit = a
	return n
}

// auditUserEvent records a security event these flows raise on their own (a
// lockout, an unblock, a breach hit) rather than in response to a request, so
// there is no handler to attribute it. Nil-safe and non-blocking.
func (n EmailNotifier) auditUserEvent(ctx context.Context, action string, tenantID int64, appRowID *int64, userID int64, meta map[string]any) {
	if n.audit == nil {
		return
	}
	n.audit.Log(ctx, audit.Event{
		TenantID:      &tenantID,
		ApplicationID: appRowID,
		UserID:        &userID,
		Action:        action,
		ResourceType:  "user",
		Metadata:      meta,
	})
}

// auditTenantEvent records a security event that belongs to a TENANT rather than
// to one account — a lockout spike being the case it exists for, where the event
// is precisely that many separate accounts were affected and naming any single one
// of them would misrepresent it. Nil-safe and non-blocking.
func (n EmailNotifier) auditTenantEvent(ctx context.Context, action string, tenantID int64, appRowID *int64, meta map[string]any) {
	if n.audit == nil {
		return
	}
	n.audit.Log(ctx, audit.Event{
		TenantID:      &tenantID,
		ApplicationID: appRowID,
		Action:        action,
		ResourceType:  "tenant",
		ResourceID:    strconv.FormatInt(tenantID, 10),
		Metadata:      meta,
	})
}

// resolveSender resolves the white-label sender chain, degrading to the global
// sender (nil) on any error — a broken tenant sender must never block a send.
func (n EmailNotifier) resolveSender(ctx context.Context, tenantID int64, appRowID *int64) *mailer.SMTPConfig {
	if n.senderSvc == nil {
		return nil
	}
	sender, err := n.senderSvc.Resolve(ctx, tenantID, appRowID)
	if err != nil {
		n.logger.Warn().Err(err).Int64("tenant_id", tenantID).Msg("notify: sender resolution failed — using global sender")
		return nil
	}
	return sender
}

// Send runs the shared pipeline for one email. deliver receives the resolved
// sender (nil = global) and template override (nil = built-in default) and calls
// the matching mailer method.
//
// It reports whether the message was handed to a transport. A suppressed type
// returns (false, nil) — not an error, since suppression is a configured choice.
func (n EmailNotifier) Send(
	ctx context.Context,
	tenantID int64,
	appRowID *int64,
	tt mailer.TemplateType,
	deliver func(sender *mailer.SMTPConfig, tmpl *mailer.Template) error,
) (bool, error) {
	if n.mailer == nil {
		return false, nil
	}
	if !n.tmplSvc.IsTypeEnabled(ctx, tenantID, appRowID, tt) {
		n.logger.Info().Int64("tenant_id", tenantID).Str("type", string(tt)).Msg("notify: template disabled at this scope — not sending")
		auditEmailSuppressed(ctx, n.audit, tenantID, appRowID, tt)
		return false, nil
	}

	sender := n.resolveSender(ctx, tenantID, appRowID)
	tmpl := n.tmplSvc.ResolveTemplate(ctx, tenantID, appRowID, tt)

	err := deliver(sender, tmpl)
	if err != nil && sender != nil {
		n.logger.Warn().Err(err).Str("type", string(tt)).Msg("notify: white-label sender failed — retrying via global sender")
		err = deliver(nil, tmpl)
	}
	if err != nil {
		return false, err
	}
	return true, nil
}
