// audit_capture.go — captures the actual HTTP response (status + body) the
// server sent and attaches it to that request's audit events, mirroring Auth0's
// details.error/response detail.
//
// Timing problem it solves: handlers emit audit events *before* the response is
// written (audit is logged at the decision point, then c.JSON runs). So the
// real status code and body are not known when Log() would fire. This middleware
// inverts that: handler audit events are *staged* on the request context, the
// response body is buffered as it is written, and once the handler returns the
// staged events are enriched with the real status + redacted body and only then
// handed to the async audit logger.
//
// Safety: the body is JSON-parsed and run through audit.Redact before storage,
// so a success response's access_token/refresh_token become "[REDACTED]" — the
// audit trail records the *shape* of what was served, never live credentials.
// Non-JSON bodies (redirects, HTML, binary) are summarised, not stored raw, and
// the whole payload is size-capped.
package middleware

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"

	"github.com/engineersmind/emc-auth-server/internal/audit"
)

const (
	// maxResponseCapture caps the buffered response body. Bodies beyond this are
	// recorded as a truncation marker rather than stored.
	maxResponseCapture = 8 * 1024

	captureActiveKey = "audit_capture_active"
	stagedEventsKey  = "audit_staged_events"
)

// bodyCaptureWriter tees written bytes into a capped buffer while passing them
// through to the real writer. Status is tracked by echo.Response itself, so this
// only needs to observe the body.
type bodyCaptureWriter struct {
	http.ResponseWriter
	buf *bytes.Buffer
}

func (w *bodyCaptureWriter) Write(b []byte) (int, error) {
	if remain := maxResponseCapture - w.buf.Len(); remain > 0 {
		if len(b) <= remain {
			w.buf.Write(b)
		} else {
			w.buf.Write(b[:remain])
		}
	}
	return w.ResponseWriter.Write(b)
}

// Flush/Hijack pass-through keep SSE/websocket-style writers working.
func (w *bodyCaptureWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// StageAuditEvent records an already-enriched event to be logged once the
// response is known. Returns true when capture is active (event staged); false
// when it is not, so the caller falls back to logging immediately.
func StageAuditEvent(c echo.Context, e audit.Event) bool {
	if active, _ := c.Get(captureActiveKey).(bool); !active {
		return false
	}
	staged, _ := c.Get(stagedEventsKey).([]audit.Event)
	c.Set(stagedEventsKey, append(staged, e))
	return true
}

// Response-body capture modes (config AUDIT_CAPTURE_RESPONSE_BODY).
const (
	CaptureOff      = "off"      // never store the response body
	CaptureFailures = "failures" // store only on 4xx/5xx (error envelopes; no PII)
	CaptureAll      = "all"      // store on every response (redacted)
)

// AuditCapture buffers the response body and, after the handler completes,
// enriches every staged audit event with the real HTTP status and — subject to
// `mode` — a redacted, size-capped copy of the response body before handing
// them to auditLog. The body is always run through secret + PII redaction, and
// the default mode ("failures") never stores success-response bodies (which can
// carry user PII).
func AuditCapture(auditLog *audit.Logger, mode string) echo.MiddlewareFunc {
	if mode == "" {
		mode = CaptureFailures
	}
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			cw := &bodyCaptureWriter{ResponseWriter: c.Response().Writer, buf: new(bytes.Buffer)}
			c.Response().Writer = cw
			c.Set(captureActiveKey, true)

			err := next(c)

			staged, _ := c.Get(stagedEventsKey).([]audit.Event)
			if len(staged) == 0 {
				return err
			}
			status := c.Response().Status
			var body any
			if shouldCaptureBody(mode, status) {
				body = safeResponseBody(cw.buf.Bytes(), c.Response().Header().Get(echo.HeaderContentType))
			}
			for _, e := range staged {
				if status != 0 {
					e.HTTPStatus = status // the real code served wins over any heuristic
				}
				if body != nil {
					if e.Metadata == nil {
						e.Metadata = map[string]any{}
					}
					if _, ok := e.Metadata["response_body"]; !ok {
						e.Metadata["response_body"] = body
					}
				}
				auditLog.Log(c.Request().Context(), e)
			}
			return err
		}
	}
}

func shouldCaptureBody(mode string, status int) bool {
	switch mode {
	case CaptureAll:
		return true
	case CaptureFailures:
		return status >= 400
	default: // CaptureOff or unknown
		return false
	}
}

// safeResponseBody turns a raw response body into a redacted, storable value.
// JSON objects are parsed and scrubbed of secret-looking keys; non-JSON or
// oversized bodies are summarised rather than stored raw. Returns nil when there
// is nothing worth recording.
func safeResponseBody(raw []byte, contentType string) any {
	if len(raw) == 0 {
		return nil
	}
	if !strings.Contains(contentType, "application/json") {
		return map[string]any{"_content_type": firstToken(contentType), "_bytes": len(raw)}
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		// Truncated (hit the cap) or malformed — record the fact, not the bytes.
		return map[string]any{"_truncated": true, "_bytes": len(raw)}
	}
	// Two passes: secret redaction (shared audit rules) then PII redaction so a
	// stored response body never leaks credentials or personal data.
	return redactPII(audit.Redact(v))
}

// piiKeyParts flags response-body keys whose values are personal data and must
// not be persisted in the audit trail. Case-insensitive substring match.
var piiKeyParts = []string{
	"email", "phone", "mobile", "first_name", "last_name", "full_name",
	"given_name", "family_name", "address", "dob", "birth", "ssn",
	"national_id", "tax_id", "postal", "zip",
	// OIDC standard claims that carry personal data (relevant when
	// AUDIT_CAPTURE_RESPONSE_BODY=all captures an id-token/userinfo body).
	"picture", "locale", "profile", "birthdate",
}

// piiKeyExact matches OIDC claim keys too short/ambiguous for a substring rule
// ("sub" would hit "subject"/"subscription"; "name" would hit "app_name").
var piiKeyExact = map[string]bool{
	"sub":  true,
	"name": true,
}

func isPIIKey(key string) bool {
	k := strings.ToLower(key)
	if piiKeyExact[k] {
		return true
	}
	for _, part := range piiKeyParts {
		if strings.Contains(k, part) {
			return true
		}
	}
	return false
}

// redactPII deep-walks a decoded JSON value and replaces PII field values with
// "[PII]". Mirrors audit.Redact's shape but for personal-data keys.
func redactPII(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			if isPIIKey(k) {
				out[k] = "[PII]"
			} else {
				out[k] = redactPII(val)
			}
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = redactPII(val)
		}
		return out
	default:
		return v
	}
}

func firstToken(contentType string) string {
	if i := strings.IndexByte(contentType, ';'); i >= 0 {
		return strings.TrimSpace(contentType[:i])
	}
	return strings.TrimSpace(contentType)
}
