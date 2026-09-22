package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"

	"github.com/engineersmind/emc-auth-server/internal/metrics"
)

// ---------------------------------------------------------------------------
// CAPTCHA service (issue #145).
//
// Three operations, and the whole feature is these three:
//
//	Issue          mint a challenge and return its image
//	Check          decide whether this request needs one, and verify it if so
//	RecordFailure  count a failed attempt so the next one may need a challenge
//
// Deliberately NOT part of AuthService. The gate belongs in the HTTP handler,
// where the client address is already in hand and where the failure branch
// already exists — putting it in the service would mean threading an IP through
// LoginInput and reordering authentication logic to accommodate a speed bump.
// Nothing in service.go changes because of this file.
//
// State lives entirely in Redis. Challenges are short-lived and single-use, and
// a Postgres table for them would be a write on every unauthenticated request
// for rows whose maximum useful lifetime is two minutes.
// ---------------------------------------------------------------------------

var (
	// ErrCaptchaRequired means the caller must obtain and solve a challenge
	// before this request can be evaluated. It is returned BEFORE any credential
	// check, so the password is never even read.
	ErrCaptchaRequired = errors.New("captcha required")

	// ErrCaptchaInvalid covers every way an answer can fail: wrong, expired,
	// already spent, issued for a different purpose, or issued to a different
	// client.
	//
	// One error for all of them on purpose. Telling a caller that their
	// challenge expired rather than that their answer was wrong changes nothing
	// they can act on — the next step is "get a new challenge" either way — and
	// distinguishing the cases hands an automated solver a free signal about
	// which part of its pipeline failed.
	ErrCaptchaInvalid = errors.New("captcha invalid")

	// ErrCaptchaDisabled is returned by Issue when policy does not enable
	// captchas for the requested scope. Distinguishable from a failure because a
	// client asking for a challenge it will never need is a client bug worth
	// surfacing, not an authentication event.
	ErrCaptchaDisabled = errors.New("captcha is not enabled for this application")
)

// Redis key namespaces. Separate prefixes so an operator can count live
// challenges without also matching failure counters.
const (
	captchaChallengePrefix = "captcha:ch:"
	captchaFailurePrefix   = "captcha:fail:"
)

// captchaIDBytes is the length of a challenge id before encoding. 16 bytes is
// 128 bits — the id is a bearer reference to a Redis key, so it must not be
// guessable by anyone who wants to burn somebody else's outstanding challenge.
const captchaIDBytes = 16

// captchaRecord is what a challenge stores. The answer is present only as an
// HMAC.
type captchaRecord struct {
	// AnswerHMAC is HMAC-SHA256 of the normalised answer, hex-encoded.
	//
	// Keyed rather than a bare hash because the answer space is small — 28^6 is
	// ~4.8e8, which is seconds of GPU time. A plain SHA-256 here would mean
	// anyone who can read Redis can read every outstanding answer; the HMAC key
	// makes a precomputed table useless and costs one function call.
	AnswerHMAC string `json:"a"`
	// Purpose binds the challenge to one flow, so a challenge minted on the
	// cheap unauthenticated register path cannot be spent on login.
	Purpose string `json:"p"`
	// ClientID binds the challenge to one application.
	ClientID string `json:"c"`
	// TenantID is recorded for audit context only; it is not part of the
	// verification decision, which is made on purpose and client alone.
	TenantID int64 `json:"t"`
	// Attempts counts answers already submitted against this challenge.
	Attempts int `json:"n"`
	// MaxAttempts is copied from the policy at issue time rather than re-read at
	// verify time. A policy edit between issue and verify must not change the
	// rules a challenge already in flight is being judged by.
	MaxAttempts int `json:"m"`
	// CaseSensitive is likewise captured at issue time, because it determines
	// how the stored HMAC was computed.
	CaseSensitive bool `json:"s"`
}

// CaptchaChallenge is what Issue returns to a caller.
type CaptchaChallenge struct {
	ID        string    `json:"challenge_id"`
	Image     string    `json:"image"`
	ExpiresAt time.Time `json:"expires_at"`
	Width     int       `json:"width"`
	Height    int       `json:"height"`
	// CaseSensitive tells the client whether the answer must match case, so a
	// sign-in page can set autocapitalize and its help text from the policy
	// rather than hardcoding an assumption that may be wrong for this tenant.
	CaseSensitive bool `json:"case_sensitive"`
}

// CaptchaService issues and verifies challenges and owns the failure counter.
type CaptchaService struct {
	redis   *redis.Client
	policy  *CaptchaPolicyService
	logger  zerolog.Logger
	hmacKey []byte

	// enabled is the deployment-level switch (CAPTCHA_ENABLED). It gates the
	// whole feature ahead of policy: a deployment that has not configured a
	// signing key must not be able to have captchas turned on underneath it by a
	// tenant editing a policy row.
	enabled bool

	// defaultTTL applies when a resolved policy carries none, which happens only
	// on the degraded path where the policy table could not be read.
	defaultTTL time.Duration
}

// NewCaptchaService wires a captcha service.
//
// Returns an error when enabled is true and the HMAC key is missing or too
// short. Failing at construction rather than degrading to an unkeyed hash is
// deliberate: the quiet version of this mistake is a server that looks like it
// has captchas and stores recoverable answers, which is worse than a server that
// refuses to boot.
func NewCaptchaService(
	redisCli *redis.Client,
	policy *CaptchaPolicyService,
	hmacKey string,
	defaultTTL time.Duration,
	enabled bool,
	logger zerolog.Logger,
) (*CaptchaService, error) {
	if enabled {
		if len(hmacKey) < 32 {
			return nil, fmt.Errorf("CAPTCHA_HMAC_KEY must be at least 32 characters when CAPTCHA_ENABLED=true (got %d)", len(hmacKey))
		}
		if redisCli == nil {
			return nil, errors.New("captcha requires Redis; set REDIS_URL or CAPTCHA_ENABLED=false")
		}
	}
	if defaultTTL <= 0 {
		defaultTTL = DefaultCaptchaPolicy.TTL
	}
	return &CaptchaService{
		redis:      redisCli,
		policy:     policy,
		logger:     logger,
		hmacKey:    []byte(hmacKey),
		enabled:    enabled,
		defaultTTL: defaultTTL,
	}, nil
}

// Enabled reports whether the deployment-level switch is on. Handlers use it to
// short-circuit before resolving policy.
func (s *CaptchaService) Enabled() bool {
	return s != nil && s.enabled && s.redis != nil
}

// Policy exposes the resolver so the admin write path can invalidate its cache.
func (s *CaptchaService) Policy() *CaptchaPolicyService {
	if s == nil {
		return nil
	}
	return s.policy
}

// ---------------------------------------------------------------------------
// Issue
// ---------------------------------------------------------------------------

// Issue mints a challenge for the given scope and flow.
//
// previousID, when non-empty, is burned first. That is what makes the "I can't
// read it" button safe: without it, a caller could hold a hundred outstanding
// challenges and work through them at leisure, which is exactly the position a
// solver farm wants to be in.
func (s *CaptchaService) Issue(
	ctx context.Context,
	tenantID int64,
	applicationID *int64,
	clientID string,
	flow CaptchaFlow,
	previousID string,
) (*CaptchaChallenge, error) {
	if !s.Enabled() {
		return nil, ErrCaptchaDisabled
	}

	policy := s.policy.Resolve(ctx, tenantID, applicationID)
	if !policy.Protects(flow) {
		return nil, ErrCaptchaDisabled
	}

	if previousID != "" {
		// Best-effort: a failed burn must not stop the caller getting a readable
		// challenge, and the old one expires on its own within the TTL anyway.
		if err := s.redis.Del(ctx, captchaChallengePrefix+previousID).Err(); err != nil {
			s.logger.Debug().Err(err).Msg("captcha: could not burn previous challenge")
		}
	}

	code, err := generateCaptchaCode(policy.CodeLength, policy.CaseSensitive)
	if err != nil {
		return nil, err
	}

	img, err := renderCaptcha(code, policy.NoiseLevel)
	if err != nil {
		return nil, err
	}

	idBytes := make([]byte, captchaIDBytes)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, fmt.Errorf("generate captcha id: %w", err)
	}
	id := base64.RawURLEncoding.EncodeToString(idBytes)

	ttl := policy.TTL
	if ttl <= 0 {
		ttl = s.defaultTTL
	}

	rec := captchaRecord{
		AnswerHMAC:    s.answerHMAC(code, policy.CaseSensitive),
		Purpose:       string(flow),
		ClientID:      clientID,
		TenantID:      tenantID,
		Attempts:      0,
		MaxAttempts:   policy.MaxAttemptsPerChallenge,
		CaseSensitive: policy.CaseSensitive,
	}
	payload, err := json.Marshal(rec)
	if err != nil {
		return nil, fmt.Errorf("marshal captcha record: %w", err)
	}

	if err := s.redis.Set(ctx, captchaChallengePrefix+id, payload, ttl).Err(); err != nil {
		return nil, fmt.Errorf("store captcha challenge: %w", err)
	}

	metrics.CaptchaChallengesIssued.WithLabelValues(string(flow)).Inc()

	return &CaptchaChallenge{
		ID:            id,
		Image:         img.DataURI,
		ExpiresAt:     time.Now().Add(ttl),
		Width:         img.Width,
		Height:        img.Height,
		CaseSensitive: policy.CaseSensitive,
	}, nil
}

// ---------------------------------------------------------------------------
// Check — the gate
// ---------------------------------------------------------------------------

// CaptchaRequest is what a handler hands the gate.
type CaptchaRequest struct {
	TenantID      int64
	ApplicationID *int64
	ClientID      string
	Flow          CaptchaFlow
	// IP is the client address, from echo's RealIP.
	IP string
	// ChallengeID and Answer are the optional fields on the request body.
	ChallengeID string
	Answer      string
}

// Check decides whether this request needs a captcha, and verifies one if it
// does.
//
// Returns nil when the request may proceed — which is the overwhelmingly common
// case, and the one that must stay cheap. With the feature off it is a single
// boolean test; with it on and the caller under the threshold it is one cached
// policy read and one Redis GET.
//
// Returns ErrCaptchaRequired when a challenge is needed and none was supplied,
// and ErrCaptchaInvalid when one was supplied and did not verify. Both are
// returned before any credential is examined.
func (s *CaptchaService) Check(ctx context.Context, req CaptchaRequest) error {
	if !s.Enabled() {
		return nil
	}

	policy := s.policy.Resolve(ctx, req.TenantID, req.ApplicationID)
	if !policy.Protects(req.Flow) {
		return nil
	}

	if !s.gateArmed(ctx, policy, req) {
		return nil
	}

	if req.ChallengeID == "" || req.Answer == "" {
		metrics.CaptchaRequired.WithLabelValues(string(req.Flow)).Inc()
		return ErrCaptchaRequired
	}
	return s.verify(ctx, req)
}

// gateArmed reports whether a challenge is demanded for this request.
//
// In 'always' mode, yes. In adaptive mode, only once the origin has accumulated
// enough recent failures.
//
// A Redis error here answers "not armed" — it fails OPEN. That is the right call
// for a speed bump: the alternative is that a Redis blip demands captchas from
// every user while the endpoint that issues them is equally broken, turning a
// cache outage into a total login outage. The lockout ladder and the rate
// limiters are the tiers that must fail closed, and they do.
func (s *CaptchaService) gateArmed(ctx context.Context, policy CaptchaPolicy, req CaptchaRequest) bool {
	if policy.Mode == CaptchaModeAlways {
		return true
	}
	if req.IP == "" {
		// No usable origin means the adaptive counter has nothing to key on.
		// Treating that as "not armed" rather than "armed" keeps the behaviour
		// of a misconfigured proxy identical to today's.
		return false
	}

	n, err := s.redis.Get(ctx, s.failureKey(req.ClientID, req.IP)).Int()
	if err != nil {
		if !errors.Is(err, redis.Nil) {
			s.logger.Warn().Err(err).Msg("captcha: failure counter unreadable, gate open")
		}
		return false
	}
	return n >= policy.TriggerAfterFailures
}

// verify checks a submitted answer and burns the challenge.
//
// GETDEL rather than GET-then-DEL: it is one round trip, and more importantly it
// is atomic. Two concurrent replays of the same solved id cannot both succeed,
// because only one of them receives the value — with a read-then-delete, both
// would read it before either deleted it.
//
// The consequence is that a challenge is consumed by the FIRST answer even when
// that answer is wrong. Where the policy allows more than one attempt, the
// record is written back with an incremented counter; this is why MaxAttempts is
// stored on the record rather than re-read from policy.
func (s *CaptchaService) verify(ctx context.Context, req CaptchaRequest) error {
	key := captchaChallengePrefix + req.ChallengeID

	raw, err := s.redis.GetDel(ctx, key).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			// Expired, never existed, or already spent. All three are the same
			// answer to the CALLER — but not to an operator, so the metric
			// separates them even though the response does not. A spike in
			// `expired` is a TTL that is too short for real people; a spike in
			// `invalid` is images nobody can read.
			metrics.CaptchaVerifications.WithLabelValues(string(req.Flow), "expired").Inc()
			return ErrCaptchaInvalid
		}
		s.logger.Warn().Err(err).Msg("captcha: challenge lookup failed")
		metrics.CaptchaVerifications.WithLabelValues(string(req.Flow), "invalid").Inc()
		return ErrCaptchaInvalid
	}

	var rec captchaRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		s.logger.Warn().Err(err).Msg("captcha: malformed challenge record")
		metrics.CaptchaVerifications.WithLabelValues(string(req.Flow), "invalid").Inc()
		return ErrCaptchaInvalid
	}

	// Binding checks before the answer comparison, and with the same error, so a
	// caller cannot probe which binding it violated.
	if rec.Purpose != string(req.Flow) || rec.ClientID != req.ClientID {
		// Counted as `reused` rather than `invalid`: a challenge presented on
		// the wrong flow or the wrong client is almost never a person typing
		// badly, it is a client replaying a challenge it should not have.
		metrics.CaptchaVerifications.WithLabelValues(string(req.Flow), "reused").Inc()
		return ErrCaptchaInvalid
	}

	want, err := hex.DecodeString(rec.AnswerHMAC)
	if err != nil {
		s.logger.Warn().Err(err).Msg("captcha: unreadable stored answer")
		metrics.CaptchaVerifications.WithLabelValues(string(req.Flow), "invalid").Inc()
		return ErrCaptchaInvalid
	}
	got, err := hex.DecodeString(s.answerHMAC(req.Answer, rec.CaseSensitive))
	if err != nil {
		return ErrCaptchaInvalid
	}

	if hmac.Equal(want, got) {
		metrics.CaptchaVerifications.WithLabelValues(string(req.Flow), "ok").Inc()
		return nil
	}
	metrics.CaptchaVerifications.WithLabelValues(string(req.Flow), "invalid").Inc()

	// Wrong answer. Restore the challenge if the policy allows another attempt,
	// with the remaining TTL rather than a fresh one — an attacker must not be
	// able to extend a challenge's life by answering it wrongly.
	rec.Attempts++
	if rec.Attempts < rec.MaxAttempts {
		if payload, mErr := json.Marshal(rec); mErr == nil {
			if sErr := s.redis.Set(ctx, key, payload, captchaRetryGrace).Err(); sErr != nil {
				s.logger.Debug().Err(sErr).Msg("captcha: could not restore challenge for retry")
			}
		}
	}
	return ErrCaptchaInvalid
}

// captchaRetryGrace is how long a challenge is restored for when the policy
// allows more than one attempt.
//
// A fixed short grace rather than the challenge's remaining TTL, for two
// reasons. GETDEL has already removed the key, so the original expiry is no
// longer readable — and re-setting the full TTL would let an attacker extend a
// challenge's life indefinitely by answering it wrongly.
//
// Thirty seconds is enough for somebody who mistyped to look again and retype.
// It is not enough to matter to anything automated.
const captchaRetryGrace = 30 * time.Second

// ---------------------------------------------------------------------------
// Failure counter
// ---------------------------------------------------------------------------

// RecordFailure counts a failed attempt against the caller's origin.
//
// Keyed by IP and client_id, NEVER by email. That is the invariant the whole
// adaptive design is shaped around: the existing lockout counter
// (users.failed_login_attempts) is keyed by user id, so a captcha driven by it
// would appear only for addresses that belong to a real account — an
// enumeration oracle — and would do nothing at all on register, where no account
// exists yet.
//
// Best-effort and never returns an error: it is called from the failure branch
// of a login handler, where a bookkeeping problem must not change what the
// caller is told.
func (s *CaptchaService) RecordFailure(ctx context.Context, tenantID int64, applicationID *int64, clientID, ip string) {
	if !s.Enabled() || ip == "" {
		return
	}
	policy := s.policy.Resolve(ctx, tenantID, applicationID)
	if !policy.Enabled || policy.Mode != CaptchaModeAdaptive {
		return
	}

	key := s.failureKey(clientID, ip)
	pipe := s.redis.TxPipeline()
	incr := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, policy.FailureWindow)
	if _, err := pipe.Exec(ctx); err != nil {
		s.logger.Debug().Err(err).Msg("captcha: could not record failure")
		return
	}

	// The EXPIRE above is unconditional, so the window slides with activity
	// rather than expiring a fixed time after the first failure. That is the
	// behaviour wanted here: somebody attempting continuously should stay gated,
	// and somebody who failed twice an hour ago should not.
	_ = incr
}

// ClearFailures drops the counter for an origin. Called after a successful
// authentication so one good sign-in releases a shared address — an office NAT
// must not stay gated because one person fumbled their password this morning.
func (s *CaptchaService) ClearFailures(ctx context.Context, clientID, ip string) {
	if !s.Enabled() || ip == "" {
		return
	}
	if err := s.redis.Del(ctx, s.failureKey(clientID, ip)).Err(); err != nil {
		s.logger.Debug().Err(err).Msg("captcha: could not clear failure counter")
	}
}

// failureKey namespaces the counter by application and origin.
//
// The IP is hashed rather than stored in the clear. It is not a secret — it is
// in the access log — but a Redis instance shared with other workloads should
// not carry a browsable list of the addresses currently failing to sign in, and
// nothing here ever needs to read the address back.
func (s *CaptchaService) failureKey(clientID, ip string) string {
	sum := sha256.Sum256([]byte(ip))
	app := clientID
	if app == "" {
		app = "-"
	}
	return captchaFailurePrefix + app + ":" + hex.EncodeToString(sum[:8])
}

// answerHMAC normalises and keys an answer.
//
// Normalisation is trim plus, unless the policy says otherwise, upper-casing.
// Case-insensitive by default because the glyphs are rotated and warped: the
// case of a rendered letter is frequently not recoverable by a human even when
// the letter plainly is.
func (s *CaptchaService) answerHMAC(answer string, caseSensitive bool) string {
	normalised := strings.TrimSpace(answer)
	if !caseSensitive {
		normalised = strings.ToUpper(normalised)
	}
	mac := hmac.New(sha256.New, s.hmacKey)
	mac.Write([]byte(normalised))
	return hex.EncodeToString(mac.Sum(nil))
}
