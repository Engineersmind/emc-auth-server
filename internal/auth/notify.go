package auth

import (
	"context"

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
// retry once via the global sender if a tenant's own sender fails. emailNotifier
// factors those steps out so each flow only supplies the payload.
// ---------------------------------------------------------------------------

// emailNotifier carries the dependencies a transactional send needs. All fields
// are optional: a nil mailer disables sending, a nil tmplSvc means "no override,
// nothing suppressed", a nil senderSvc means "always the global sender".
type emailNotifier struct {
	mailer    mailer.Mailer
	senderSvc *EmailSenderService
	tmplSvc   *EmailTemplateService
	audit     *audit.Logger
	logger    zerolog.Logger
}

// auditUserEvent records a security event these flows raise on their own (a
// lockout, an unblock, a breach hit) rather than in response to a request, so
// there is no handler to attribute it. Nil-safe and non-blocking.
func (n emailNotifier) auditUserEvent(ctx context.Context, action string, tenantID int64, appRowID *int64, userID int64, meta map[string]any) {
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

// resolveSender resolves the white-label sender chain, degrading to the global
// sender (nil) on any error — a broken tenant sender must never block a send.
func (n emailNotifier) resolveSender(ctx context.Context, tenantID int64, appRowID *int64) *mailer.SMTPConfig {
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

// send runs the shared pipeline for one email. deliver receives the resolved
// sender (nil = global) and template override (nil = built-in default) and calls
// the matching mailer method.
//
// It reports whether the message was handed to a transport. A suppressed type
// returns (false, nil) — not an error, since suppression is a configured choice.
func (n emailNotifier) send(
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
