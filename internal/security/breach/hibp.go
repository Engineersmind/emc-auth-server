// Package breach checks whether a password appears in a known third-party data
// breach, using the Have I Been Pwned "Pwned Passwords" range API.
//
// The check is k-anonymous: only the first five hex characters of the password's
// SHA-1 hash leave this server. The API answers with every known hash suffix
// sharing that prefix (~800 on average) and the match is made locally, so the
// password — and even its full hash — is never transmitted. This is the same
// protocol Chrome, 1Password, and Auth0 use for breached-credential detection.
//
// SHA-1 is not a security choice here: it is the hash the Pwned Passwords corpus
// is indexed by, and it is used purely as a lookup key, never to protect a
// secret. Password storage is argon2id (see internal/password).
package breach

import (
	"bufio"
	"context"
	// #nosec G505 -- SHA-1 is the index of the Pwned Passwords corpus, used here
	// only as a lookup key. Nothing is protected by it; password storage is argon2id
	// (see internal/password).
	"crypto/sha1" //nolint:gosec // G505: see the #nosec justification above
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

// rangeEndpoint is the fixed Pwned Passwords range API base. It is a constant so
// no caller-supplied value can redirect the lookup elsewhere.
const rangeEndpoint = "https://api.pwnedpasswords.com/range/"

// checkTimeout bounds one lookup. The check is advisory — a slow or unreachable
// API must never delay a sign-in — so this is deliberately short.
const checkTimeout = 3 * time.Second

// maxRangeResponseBytes caps how much of a range response is read. Real padded
// responses are ~40–65 KB, so this is generous while keeping a hostile or
// hijacked endpoint from streaming an unbounded body into memory.
const maxRangeResponseBytes = 512 * 1024

// Checker queries the Pwned Passwords range API.
type Checker struct {
	client *http.Client
	// endpoint is overridable in tests only; production always uses rangeEndpoint.
	endpoint string
	logger   zerolog.Logger
}

// New returns a Checker, or nil when the feature is disabled. A nil *Checker is
// safe to call: Count reports "not breached", so callers need no branch.
func New(enabled bool, logger zerolog.Logger) *Checker {
	if !enabled {
		return nil
	}
	return &Checker{
		client:   &http.Client{Timeout: checkTimeout},
		endpoint: rangeEndpoint,
		logger:   logger,
	}
}

// NewForTest returns a Checker pointed at a stub range API. It exists so tests
// can exercise the parsing and matching logic without reaching the real service;
// production code always uses New, which pins rangeEndpoint.
func NewForTest(endpoint string, logger zerolog.Logger) *Checker {
	return &Checker{client: &http.Client{Timeout: checkTimeout}, endpoint: endpoint, logger: logger}
}

// HashSuffixForTest returns the SHA-1 hash suffix (everything after the 5-char
// prefix) that a stub range API must serve for this password to register as
// breached. Test support only.
func HashSuffixForTest(password string) string {
	sum := sha1.Sum([]byte(password)) //nolint:gosec // G401: lookup key only, see package doc
	return strings.ToUpper(hex.EncodeToString(sum[:]))[5:]
}

// Count returns how many times the password appears in the breach corpus (0 when
// absent). A nil Checker, an empty password, or any transport/parse failure
// returns 0 — the check is advisory and must fail open, never blocking or
// delaying authentication.
func (c *Checker) Count(ctx context.Context, password string) int {
	if c == nil || password == "" {
		return 0
	}

	sum := sha1.Sum([]byte(password)) //nolint:gosec // G401: lookup key only, see package doc
	full := strings.ToUpper(hex.EncodeToString(sum[:]))
	prefix, suffix := full[:5], full[5:]

	ctx, cancel := context.WithTimeout(ctx, checkTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint+prefix, nil)
	if err != nil {
		c.logger.Debug().Err(err).Msg("breach: building range request failed")
		return 0
	}
	// Add-Padding makes every response a uniform size, so an observer cannot
	// infer the queried prefix from the response length.
	req.Header.Set("Add-Padding", "true")
	req.Header.Set("User-Agent", "emc-auth-server")

	//nolint:gosec // G704: endpoint is the fixed rangeEndpoint constant (only overridden in tests) and the path suffix is a hex hash prefix we computed, never user input.
	resp, err := c.client.Do(req)
	if err != nil {
		c.logger.Debug().Err(err).Msg("breach: range lookup failed — treating password as not breached")
		return 0
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		c.logger.Debug().Int("status", resp.StatusCode).Msg("breach: unexpected range API status")
		return 0
	}

	// Each line is "SUFFIX:COUNT". Padding entries carry a count of 0 and are
	// therefore indistinguishable from a genuine miss, which is the point.
	//
	// The read is byte-bounded as well as time-bounded: checkTimeout caps how long
	// a response may take, but not how much it may send, so a hijacked or
	// misbehaving endpoint could otherwise drip an unbounded body into memory
	// while staying inside the deadline. A padded range response is ~40–65 KB.
	scanner := bufio.NewScanner(io.LimitReader(resp.Body, maxRangeResponseBytes))
	for scanner.Scan() {
		line := scanner.Text()
		sep := strings.IndexByte(line, ':')
		if sep != len(suffix) || !strings.EqualFold(line[:sep], suffix) {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(line[sep+1:]))
		if err != nil {
			return 0
		}
		return n
	}
	if err := scanner.Err(); err != nil {
		c.logger.Debug().Err(err).Msg("breach: reading range response failed")
	}
	return 0
}

// Describe renders a breach count for logs and audit metadata.
func Describe(count int) string {
	if count <= 0 {
		return "not found in breach corpus"
	}
	return fmt.Sprintf("found in breach corpus %d time(s)", count)
}
