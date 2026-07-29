package mailer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/rs/zerolog"
	mail "github.com/wneessen/go-mail"
)

// Provider names. A per-scope sender or the global config selects one of these
// transports; an unknown/empty value defaults to SMTP for backward compatibility.
const (
	ProviderSMTP     = "smtp"
	ProviderSendGrid = "sendgrid"
)

// outMessage is the transport-neutral, fully-rendered message handed to a
// Provider. Rendering (templates, branding) happens before this struct exists.
type outMessage struct {
	From     string
	FromName string
	ReplyTo  string
	To       string
	Subject  string
	HTML     string
	Text     string
}

// transport delivers a fully-rendered message. Implementations: smtpTransport
// (go-mail relay), sendGridTransport (SendGrid Web API v3), devTransport (log).
type transport interface {
	send(ctx context.Context, msg outMessage) error
}

// pickTransport chooses the transport for a resolved sender. A nil sender means
// "use the global default transport" (already wired into the mailer). This is
// only called with a non-nil per-scope override.
//
// Credentials are trimmed at every transport boundary. A key or password
// pasted into a form or a .env line very often carries a trailing newline or
// space; sent verbatim it produces an indistinguishable 401, which reads as
// "wrong key" and sends people hunting in the provider console for a problem
// that is in their clipboard. Whitespace is never significant in any of these
// values, so trimming cannot break a valid credential.
func pickTransport(sender *SMTPConfig, logger zerolog.Logger) transport {
	switch strings.ToLower(strings.TrimSpace(sender.Provider)) {
	case ProviderSendGrid:
		return &sendGridTransport{apiKey: strings.TrimSpace(sender.APIKey), logger: logger}
	default:
		return &smtpTransport{
			host:     strings.TrimSpace(sender.Host),
			port:     sender.Port,
			username: strings.TrimSpace(sender.Username),
			password: strings.TrimSpace(sender.Password),
			tlsMode:  sender.TLSMode,
			logger:   logger,
		}
	}
}

// ---------------------------------------------------------------------------
// SMTP transport (go-mail).
// ---------------------------------------------------------------------------

type smtpTransport struct {
	host, tlsMode      string
	port               int
	username, password string
	logger             zerolog.Logger
}

func (t *smtpTransport) send(ctx context.Context, m outMessage) error {
	msg := mail.NewMsg()
	if m.FromName != "" {
		if err := msg.FromFormat(m.FromName, m.From); err != nil {
			return fmt.Errorf("invalid from address %q: %w", m.From, err)
		}
	} else if err := msg.From(m.From); err != nil {
		return fmt.Errorf("invalid from address %q: %w", m.From, err)
	}
	if err := msg.To(m.To); err != nil {
		return fmt.Errorf("invalid recipient %q: %w", m.To, err)
	}
	if m.ReplyTo != "" {
		if err := msg.ReplyTo(m.ReplyTo); err != nil {
			return fmt.Errorf("invalid reply-to %q: %w", m.ReplyTo, err)
		}
	}
	msg.Subject(m.Subject)
	msg.SetBodyString(mail.TypeTextPlain, m.Text)
	msg.AddAlternativeString(mail.TypeTextHTML, m.HTML)

	opts := []mail.Option{
		mail.WithPort(t.port),
		mail.WithTimeout(smtpSendTimeout),
	}
	if useSSL, policy := tlsFor(t.port, t.tlsMode); useSSL {
		opts = append(opts, mail.WithSSL())
	} else {
		opts = append(opts, mail.WithTLSPolicy(policy))
	}
	if t.username != "" {
		opts = append(opts,
			mail.WithSMTPAuth(mail.SMTPAuthAutoDiscover),
			mail.WithUsername(t.username),
			mail.WithPassword(t.password),
		)
	} else {
		opts = append(opts, mail.WithSMTPAuth(mail.SMTPAuthNoAuth))
	}

	client, err := mail.NewClient(t.host, opts...)
	if err != nil {
		return fmt.Errorf("smtp client: %w", err)
	}
	if err := client.DialAndSendWithContext(ctx, msg); err != nil {
		t.logger.Error().Err(err).Str("to", m.To).Str("from", m.From).Msg("smtp send failed")
		// SMTP has no structured error code here, so classification is by the
		// 535/534 auth codes and the standard "authentication failed" wording
		// relays use. A miss only costs a less specific message, never a wrong
		// send, so matching loosely is the right trade.
		if isSMTPAuthFailure(err) {
			return fmt.Errorf("%w: the SMTP relay rejected the username/password", ErrProviderAuth)
		}
		return fmt.Errorf("smtp send: %w", err)
	}
	return nil
}

// isSMTPAuthFailure reports whether a go-mail send error looks like credential
// rejection rather than a connection or content problem.
// The numeric codes are anchored with a trailing space and paired with the
// enhanced status code, because a bare "535" also matches byte counts, port
// numbers and message IDs that happen to contain it.
//
// The residual risk is a false positive, and it is bounded to UX rather than
// security: the phrase matches are generic English ("authentication failed"
// could plausibly appear in a future go-mail wrapping of a content rejection),
// so a miss sends the admin to check credentials that were actually fine. It
// never changes what is sent, to whom, or with which sender — misclassification
// only ever swaps one 502 message for another. That is why matching loosely is
// the right trade here; if it were reachable from a send decision it would not be.
func isSMTPAuthFailure(err error) bool {
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "535 ") || // "535 authentication credentials invalid"
		strings.Contains(s, "534 ") || // "534 authentication mechanism too weak"
		strings.Contains(s, "5.7.8") || // enhanced status code for bad credentials
		strings.Contains(s, "authentication failed") ||
		strings.Contains(s, "auth failed") ||
		strings.Contains(s, "invalid credentials") ||
		strings.Contains(s, "username and password not accepted")
}

// ErrProviderAuth reports that the provider rejected our CREDENTIALS, as
// opposed to rejecting the message or being unreachable. It is the difference
// between "your API key is wrong" and "something went wrong" — an admin can act
// on the first immediately, so the distinction is worth carrying up to the API
// rather than collapsing every failure into one opaque message.
var ErrProviderAuth = errors.New("the email provider rejected the configured credentials")

// ErrProviderSender reports that the provider accepted our credentials but
// refused the From address — almost always an unverified sender identity or
// unauthenticated domain, which is a completely different fix from a bad key.
var ErrProviderSender = errors.New("the email provider rejected the From address")

// ---------------------------------------------------------------------------
// SendGrid Web API v3 transport.
// ---------------------------------------------------------------------------

const sendGridEndpoint = "https://api.sendgrid.com/v3/mail/send"

type sendGridTransport struct {
	apiKey     string
	endpoint   string // overridable in tests; empty = sendGridEndpoint
	httpClient *http.Client
	logger     zerolog.Logger
}

// sgMail is the subset of the SendGrid v3 /mail/send schema we populate.
type sgMail struct {
	Personalizations []sgPersonalization `json:"personalizations"`
	From             sgAddr              `json:"from"`
	ReplyTo          *sgAddr             `json:"reply_to,omitempty"`
	Subject          string              `json:"subject"`
	Content          []sgContent         `json:"content"`
}

type sgPersonalization struct {
	To []sgAddr `json:"to"`
}

type sgAddr struct {
	Email string `json:"email"`
	Name  string `json:"name,omitempty"`
}

type sgContent struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

func (t *sendGridTransport) send(ctx context.Context, m outMessage) error {
	if t.apiKey == "" {
		return fmt.Errorf("sendgrid: no API key configured")
	}
	body := sgMail{
		Personalizations: []sgPersonalization{{To: []sgAddr{{Email: m.To}}}},
		From:             sgAddr{Email: m.From, Name: m.FromName},
		Subject:          m.Subject,
		// SendGrid requires text/plain before text/html when both are present.
		Content: []sgContent{
			{Type: "text/plain", Value: m.Text},
			{Type: "text/html", Value: m.HTML},
		},
	}
	if m.ReplyTo != "" {
		body.ReplyTo = &sgAddr{Email: m.ReplyTo}
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("sendgrid: marshal: %w", err)
	}

	endpoint := t.endpoint
	if endpoint == "" {
		endpoint = sendGridEndpoint
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("sendgrid: new request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+t.apiKey)
	req.Header.Set("Content-Type", "application/json")

	client := t.httpClient
	if client == nil {
		client = &http.Client{Timeout: smtpSendTimeout}
	}
	//nolint:gosec // G704: endpoint is the fixed SendGrid API URL constant (only overridden in tests), never user input.
	resp, err := client.Do(req)
	if err != nil {
		t.logger.Error().Err(err).Str("to", m.To).Msg("sendgrid send failed")
		return fmt.Errorf("sendgrid: send: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	t.logger.Error().Int("status", resp.StatusCode).Str("to", m.To).
		Str("response", string(snippet)).Msg("sendgrid rejected message")

	// Classify the two failures an admin can actually fix, so the API can say
	// which one it is instead of echoing a raw upstream body.
	//
	// 401 is an invalid/revoked key. 403 is ambiguous at SendGrid: it covers
	// both an under-scoped key (no Mail Send permission) and an unverified
	// sender identity, and the only way to tell them apart is the body text.
	respBody := strings.TrimSpace(string(snippet))
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return fmt.Errorf("%w: sendgrid rejected the API key (status 401)", ErrProviderAuth)
	case resp.StatusCode == http.StatusForbidden && strings.Contains(strings.ToLower(respBody), "verified sender"):
		return fmt.Errorf("%w: sendgrid does not recognise %q as a verified sender", ErrProviderSender, m.From)
	case resp.StatusCode == http.StatusForbidden:
		return fmt.Errorf("%w: sendgrid returned 403 — the API key may lack Mail Send permission", ErrProviderAuth)
	}
	return fmt.Errorf("sendgrid: status %d: %s", resp.StatusCode, respBody)
}

// ---------------------------------------------------------------------------
// Dev transport (log-only).
// ---------------------------------------------------------------------------

type devTransport struct {
	logger zerolog.Logger
}

func (t *devTransport) send(_ context.Context, m outMessage) error {
	t.logger.Info().
		Str("to", m.To).Str("from", m.From).Str("subject", m.Subject).
		Msg("[DEV] email (not sent — log only)")
	return nil
}
