package mailer

import (
	"bytes"
	"context"
	"encoding/json"
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
func pickTransport(sender *SMTPConfig, logger zerolog.Logger) transport {
	switch strings.ToLower(sender.Provider) {
	case ProviderSendGrid:
		return &sendGridTransport{apiKey: sender.APIKey, logger: logger}
	default:
		return &smtpTransport{
			host:     sender.Host,
			port:     sender.Port,
			username: sender.Username,
			password: sender.Password,
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
		return fmt.Errorf("smtp send: %w", err)
	}
	return nil
}

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
	return fmt.Errorf("sendgrid: status %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
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
