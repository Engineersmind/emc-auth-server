package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/mail"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"

	"github.com/engineersmind/emc-auth-server/internal/audit"
	"github.com/engineersmind/emc-auth-server/internal/emailaddr"
	"github.com/engineersmind/emc-auth-server/internal/mailer"
	"github.com/engineersmind/emc-auth-server/internal/metrics"
)

// ---------------------------------------------------------------------------
// Passwordless sign-in and sign-up by emailed one-time code (issue #203,
// docs/plans/passwordless-email-otp.md).
//
// Two calls cover both registration and login, so a caller never has to know
// whether an address is registered, which is also what makes the flow safe
// against account enumeration:
//
//	Start   emails a code (or, for an address that must not receive one, stores a
//	        decoy and sends nothing) and answers identically either way.
//	Verify  proves the code, then signs the user in, or creates the account and
//	        signs in. Nothing durable is written at Start.
//
// This file is deliberately separate from Login, VerifyMagicLink and Register,
// which are not edited. completePasswordlessLogin repeats the steps password
// Login performs after its credential check, in the same order, by calling the
// same helpers; passwordless_parity_test.go keeps the two from drifting.
// ---------------------------------------------------------------------------

// Errors returned by the passwordless flow. ErrPasswordlessInvalidCode is the
// one uniform failure for a wrong, expired, unknown, burned or refused code: a
// caller cannot tell which, so none of them is an oracle.
var (
	ErrPasswordlessDisabled       = errors.New("passwordless sign-in is not enabled for this application")
	ErrPasswordlessInvalidCode    = errors.New("invalid_or_expired_code")
	ErrPasswordlessInvalidEmail   = errors.New("a valid email address is required")
	ErrPasswordlessTooManyResends = errors.New("too_many_resends")
	// ErrPasswordlessUnavailable means the challenge store is unreachable. It is
	// the same for every address, so it reveals nothing about any of them.
	ErrPasswordlessUnavailable = errors.New("passwordless sign-in is temporarily unavailable")
)

// PasswordlessCooldownError is returned by Resend inside the cooldown window.
type PasswordlessCooldownError struct{ RetryAfter time.Duration }

func (e *PasswordlessCooldownError) Error() string {
	return fmt.Sprintf("resend_cooldown: retry in %d seconds", int(e.RetryAfter.Seconds())+1)
}

const (
	// PasswordlessCodeLength is the number of digits in a code.
	PasswordlessCodeLength = EmailOTPLength

	// passwordlessFailBudget is how many failed verifications one address may
	// accumulate per hour, across ALL its challenges, before verification is
	// refused for it for passwordlessBlockFor. It is what stops an attacker
	// minting many challenges to multiply the per-challenge guesses.
	passwordlessFailBudget = 10
	passwordlessBlockFor   = 15 * time.Minute

	// passwordlessStartFloor is the minimum wall-clock time Start takes, so a
	// real challenge and a decoy are not told apart by latency.
	passwordlessStartFloor = 150 * time.Millisecond

	passwordlessSendTimeout  = 30 * time.Second
	passwordlessSendAttempts = 3
	passwordlessSendWorkers  = 32
)

// passwordlessRuntime is the wiring the flow needs beyond AuthService.
type passwordlessRuntime struct {
	policy  *PasswordlessPolicyService
	key     []byte
	audit   *audit.Logger
	sendSem chan struct{}
}

// WithPasswordless enables the passwordless flow on the service. policy and key
// are required; a nil audit logger just skips the service-side audit events.
func (s *AuthService) WithPasswordless(policy *PasswordlessPolicyService, key []byte, a *audit.Logger) *AuthService {
	s.pwless = &passwordlessRuntime{
		policy:  policy,
		key:     key,
		audit:   a,
		sendSem: make(chan struct{}, passwordlessSendWorkers),
	}
	return s
}

// PasswordlessSettingsFor returns the resolved passwordless settings for an
// application, or the password-only default when the feature is not wired.
// Used by the password endpoints to enforce password_enabled=false.
func (s *AuthService) PasswordlessSettingsFor(ctx context.Context, tenantID int64, appRowID *int64) PasswordlessSettings {
	if s == nil || s.pwless == nil {
		return DefaultPasswordlessSettings()
	}
	return s.pwless.policy.Resolve(ctx, tenantID, appRowID)
}

// PasswordlessKeyFromConfig decodes PASSWORDLESS_CODE_HMAC_KEY. Outside
// production an unset key falls back to a fixed development key so the feature
// can be tried locally; config.Validate already refuses an unset key in
// production and staging when the feature is on.
func PasswordlessKeyFromConfig(env, hexKey string) ([]byte, error) {
	if hexKey == "" {
		if env == "production" || env == "staging" {
			return nil, errors.New("PASSWORDLESS_CODE_HMAC_KEY is required")
		}
		sum := sha256.Sum256([]byte("emc-auth passwordless development key"))
		return sum[:], nil
	}
	k, err := hex.DecodeString(hexKey)
	if err != nil || len(k) < 32 {
		return nil, errors.New("PASSWORDLESS_CODE_HMAC_KEY must be at least 64 hex characters")
	}
	return k, nil
}

// ---------------------------------------------------------------------------
// Redis keys and scripts
// ---------------------------------------------------------------------------

func pwlessChallengeKey(id string) string { return "pwless:ch:" + id }

func pwlessEmailHash(email string) string {
	sum := sha256.Sum256([]byte(email))
	return hex.EncodeToString(sum[:16])
}

func pwlessScoped(kind string, appRowID int64, email string) string {
	return fmt.Sprintf("pwless:%s:%d:%s", kind, appRowID, pwlessEmailHash(email))
}

// pwlessMAC is HMAC-SHA-256(key, challenge_id || 0x00 || code). A plain hash of
// a 6-digit code is a 10^6 space and recoverable instantly from a Redis read;
// the key is what prevents that. Binding the challenge id means a code is only
// ever valid for the challenge it was issued under.
func pwlessMAC(key []byte, challengeID, code string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(challengeID))
	m.Write([]byte{0})
	m.Write([]byte(code))
	return hex.EncodeToString(m.Sum(nil))
}

// incrWithTTL increments KEYS[1] and sets its TTL (ARGV[1] seconds) on creation,
// atomically, so a counter can never be left without an expiry.
var pwlessIncr = redis.NewScript(`
local n = redis.call("INCR", KEYS[1])
if n == 1 then redis.call("EXPIRE", KEYS[1], tonumber(ARGV[1])) end
return n
`)

// pwlessVerifyScript loads the challenge, spends one attempt, and consumes it on
// a match, all atomically, so a code is single-use even under concurrent
// verification.
//
//	KEYS[1] challenge   ARGV[1] candidate MAC   ARGV[2] app id   ARGV[3] tenant id
//
// Returns {0} for every failure (missing, wrong, burned, other application) so
// the caller cannot distinguish them, or {1, email, persistent, first, last}.
// The MAC comparison is an equality check, not constant-time: both sides are
// HMACs under a key the caller does not have, so a timing difference leaks
// nothing an attacker can use to build a matching value.
var pwlessVerifyScript = redis.NewScript(`
local f = redis.call("HMGET", KEYS[1], "mac", "attempts", "max", "app", "tenant", "decoy")
if not f[1] then return {0} end
local attempts = redis.call("HINCRBY", KEYS[1], "attempts", 1)
local max = tonumber(f[3])
if attempts > max then redis.call("DEL", KEYS[1]); return {0} end
local ok = (f[6] ~= "1") and (f[4] == ARGV[2]) and (f[5] == ARGV[3]) and (f[1] == ARGV[1])
if ok then
  local p = redis.call("HMGET", KEYS[1], "email", "persistent", "first", "last")
  redis.call("DEL", KEYS[1])
  return {1, p[1] or "", p[2] or "0", p[3] or "", p[4] or ""}
end
if attempts >= max then redis.call("DEL", KEYS[1]) end
return {0}
`)

// pwlessResendScript rotates the code on the same challenge when the cooldown
// and resend budget allow. The old code dies with the swap. Attempts are NOT
// reset, so resends cannot be used to multiply guesses.
//
//	KEYS[1] challenge  ARGV[1] new MAC  ARGV[2] now (unix s)  ARGV[3] app id  ARGV[4] tenant id
//
// Returns {-1} unknown or other application, {-2} out of resends,
// {-3, seconds} cooling down, or {1, resends_left, email, decoy}.
var pwlessResendScript = redis.NewScript(`
local f = redis.call("HMGET", KEYS[1], "resends", "max_resends", "cooldown", "sent_at", "email", "decoy", "app", "tenant")
if not f[1] then return {-1} end
if f[7] ~= ARGV[3] or f[8] ~= ARGV[4] then return {-1} end
local resends = tonumber(f[1]); local max = tonumber(f[2])
if resends >= max then return {-2} end
local wait = tonumber(f[4]) + tonumber(f[3]) - tonumber(ARGV[2])
if wait > 0 then return {-3, wait} end
redis.call("HSET", KEYS[1], "mac", ARGV[1], "sent_at", ARGV[2])
redis.call("HINCRBY", KEYS[1], "resends", 1)
return {1, max - resends - 1, f[5], f[6]}
`)

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

// PasswordlessStartInput is the payload for Start.
type PasswordlessStartInput struct {
	ClientID, ClientSecret string
	Email                  string
	FirstName, LastName    string
	Persistent             bool
	IP, UserAgent          string
}

// PasswordlessStartResult is the response to Start, identical for every address.
type PasswordlessStartResult struct {
	ChallengeID string `json:"challenge_id"`
	ExpiresIn   int    `json:"expires_in"`
	ResendAfter int    `json:"resend_after"`
	CodeLength  int    `json:"code_length"`
}

// PasswordlessStartMeta describes what Start actually did, for the handler's
// audit event. It is never returned to the caller: the outcome (real, decoy,
// throttled) is exactly what must not be observable.
type PasswordlessStartMeta struct {
	TenantID, AppRowID int64
	Outcome            string // sent | decoy | throttled | suppressed
}

func (s *AuthService) pwlessReady() error {
	if s.pwless == nil || s.redisCli == nil || s.appSvc == nil || s.emailSvc == nil {
		return ErrPasswordlessUnavailable
	}
	return nil
}

func normalisePasswordlessEmail(raw string) (string, error) {
	e := emailaddr.Normalize(raw)
	if e == "" || len(e) > 254 {
		return "", ErrPasswordlessInvalidEmail
	}
	for i := 0; i < len(e); i++ {
		if e[i] >= 0x80 || e[i] <= 0x20 { // ASCII only, no whitespace: plan T13
			return "", ErrPasswordlessInvalidEmail
		}
	}
	addr, err := mail.ParseAddress(e)
	if err != nil || addr.Address != e || strings.Count(e, "@") != 1 {
		return "", ErrPasswordlessInvalidEmail
	}
	return e, nil
}

// Start requests a sign-in or sign-up code for an address. It answers
// identically for every address; whether a real code was issued is not
// observable from the response, its timing, or its failure modes.
func (s *AuthService) PasswordlessStart(ctx context.Context, in PasswordlessStartInput) (*PasswordlessStartResult, *PasswordlessStartMeta, error) {
	began := time.Now()
	if err := s.pwlessReady(); err != nil {
		return nil, nil, err
	}
	tenantID, appRowID, err := s.authenticateApp(ctx, in.ClientID, in.ClientSecret)
	if err != nil {
		return nil, nil, err
	}
	settings := s.pwless.policy.Resolve(ctx, tenantID, &appRowID)
	if !settings.EmailOTPEnabled {
		return nil, nil, ErrPasswordlessDisabled
	}
	email, err := normalisePasswordlessEmail(in.Email)
	if err != nil {
		metrics.PasswordlessStarts.WithLabelValues("invalid").Inc()
		return nil, nil, err
	}
	meta := &PasswordlessStartMeta{TenantID: tenantID, AppRowID: appRowID}
	defer func() { settlePasswordlessStart(ctx, began) }()

	// Throttles key on the SUBMITTED address and the application, never on
	// whether the address exists, so being throttled is not an oracle either.
	// A throttled request is answered exactly like a decoy.
	throttled := false
	startKey := pwlessScoped("start", appRowID, email)
	if n, err := pwlessIncr.Run(ctx, s.redisCli, []string{startKey}, 3600).Int(); err != nil {
		return nil, nil, ErrPasswordlessUnavailable
	} else if n > settings.StartsPerHour {
		throttled = true
		metrics.PasswordlessThrottled.WithLabelValues("start_email").Inc()
	}
	if !throttled && settings.DailyEmailBudget > 0 {
		budgetKey := fmt.Sprintf("pwless:budget:%d:%s", appRowID, time.Now().UTC().Format("20060102"))
		if n, err := pwlessIncr.Run(ctx, s.redisCli, []string{budgetKey}, 90000).Int(); err == nil && n > settings.DailyEmailBudget {
			throttled = true
			metrics.PasswordlessThrottled.WithLabelValues("start_budget").Inc()
		}
	}

	real, verifyWording := false, false
	if !throttled {
		real, verifyWording = s.pwlessMayReceiveCode(ctx, tenantID, appRowID, email, settings)
	}

	// Sending is skipped, with the response unchanged, when the template is off.
	suppressed := false
	if real && !s.emailSvc.tmplSvc.IsTypeEnabled(ctx, tenantID, &appRowID, mailer.TemplatePasswordlessCode) {
		real, suppressed = false, true
		auditEmailSuppressed(ctx, s.pwless.audit, tenantID, &appRowID, mailer.TemplatePasswordlessCode)
	}

	challengeID, code, err := s.pwlessStoreChallenge(ctx, tenantID, appRowID, email, in, settings, !real)
	if err != nil {
		return nil, nil, err
	}
	switch {
	case real:
		meta.Outcome = "sent"
		s.pwlessSendAsync(ctx, tenantID, appRowID, email, code, verifyWording, in.IP)
	case throttled:
		meta.Outcome = "throttled"
	case suppressed:
		meta.Outcome = "suppressed"
	default:
		meta.Outcome = "decoy"
	}
	metrics.PasswordlessStarts.WithLabelValues(meta.Outcome).Inc()

	return &PasswordlessStartResult{
		ChallengeID: challengeID,
		ExpiresIn:   settings.CodeTTLSeconds,
		ResendAfter: settings.ResendCooldownSecs,
		CodeLength:  PasswordlessCodeLength,
	}, meta, nil
}

// settlePasswordlessStart pads Start to a fixed floor so a real challenge and a
// decoy cannot be told apart by latency.
func settlePasswordlessStart(ctx context.Context, began time.Time) {
	remaining := passwordlessStartFloor - time.Since(began)
	if remaining <= 0 {
		return
	}
	t := time.NewTimer(remaining)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}

// pwlessMayReceiveCode decides whether a real code should be mailed to email.
// verifyWording is true when the mail should ask the reader to confirm the
// address (new sign-up, or an account whose address was never verified).
//
// A false answer means a decoy challenge: unknown address with sign-up off or the
// domain refused, an inactive or blocked account, a soft-locked account, a tenant
// that is switched off.
func (s *AuthService) pwlessMayReceiveCode(ctx context.Context, tenantID, appRowID int64, email string, settings PasswordlessSettings) (real, verifyWording bool) {
	var userID int64
	var active, verified bool
	err := s.pool.QueryRow(ctx, `
		SELECT u.id, u.is_active, u.email_verified
		FROM users u JOIN tenants t ON t.id = u.tenant_id
		WHERE u.email = $1 AND u.tenant_id = $2 AND u.application_id = $3
		  AND u.deleted_at IS NULL AND t.is_active = true
	`, email, tenantID, appRowID).Scan(&userID, &active, &verified)
	switch {
	case err == nil:
		if !active {
			return false, false
		}
		if s.blockSvc != nil {
			if _, locked := s.blockSvc.SoftLockedFor(ctx, tenantID, userID); locked {
				return false, false
			}
		}
		return true, !verified
	case errors.Is(err, pgx.ErrNoRows):
		if settings.SignupEnabled && settings.DomainPermitted(email) {
			return true, true
		}
		return false, false
	default:
		// A read error must not make real and decoy differ visibly. Treat as a
		// decoy: the worst case is one missed email, and the user can ask again.
		s.logger.Warn().Err(err).Msg("passwordless start: user lookup failed, issuing a decoy")
		return false, false
	}
}

// pwlessStoreChallenge writes the challenge, superseding any earlier one for the
// same application and address. A decoy has the same shape and attempt budget but
// a MAC that can never match.
func (s *AuthService) pwlessStoreChallenge(ctx context.Context, tenantID, appRowID int64, email string, in PasswordlessStartInput, st PasswordlessSettings, decoy bool) (id, code string, err error) {
	raw := make([]byte, 32)
	if _, err = rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("generate challenge id: %w", err)
	}
	id = hex.EncodeToString(raw) // 256 bits, opaque, not derived from the address

	mac := ""
	if decoy {
		d := make([]byte, 32)
		if _, err = rand.Read(d); err != nil {
			return "", "", err
		}
		mac = hex.EncodeToString(d) // never equals an HMAC of any code
	} else {
		if code, err = generateEmailOTP(); err != nil {
			return "", "", err
		}
		mac = pwlessMAC(s.pwless.key, id, code)
	}

	ttl := time.Duration(st.CodeTTLSeconds) * time.Second
	now := time.Now().Unix()
	persistent := "0"
	if in.Persistent && st.AllowPersistent {
		persistent = "1"
	}
	decoyFlag := "0"
	if decoy {
		decoyFlag = "1"
	}
	chKey := pwlessChallengeKey(id)
	curKey := pwlessScoped("cur", appRowID, email)

	// Latest start wins: the previous challenge for this application and address
	// is destroyed, so an old, possibly forwarded code stops working.
	if prev, gErr := s.redisCli.Get(ctx, curKey).Result(); gErr == nil && prev != "" {
		s.redisCli.Del(ctx, pwlessChallengeKey(prev)) //nolint:errcheck
	}
	pipe := s.redisCli.TxPipeline()
	pipe.HSet(ctx, chKey, map[string]any{
		"email": email, "tenant": strconv.FormatInt(tenantID, 10), "app": strconv.FormatInt(appRowID, 10),
		"mac": mac, "attempts": 0, "max": st.MaxAttempts, "resends": 0, "max_resends": st.MaxResends,
		"cooldown": st.ResendCooldownSecs, "sent_at": now, "persistent": persistent,
		"first": in.FirstName, "last": in.LastName, "decoy": decoyFlag,
	})
	pipe.Expire(ctx, chKey, ttl)
	pipe.Set(ctx, curKey, id, ttl)
	if _, err = pipe.Exec(ctx); err != nil {
		return "", "", ErrPasswordlessUnavailable
	}
	return id, code, nil
}

// pwlessSendAsync mails the code without holding up the response, so SMTP latency
// or failure can never separate a known address from an unknown one. Bounded
// concurrency and bounded retry; a restart can lose a pending email and the user
// can resend. The failure is visible only in the metric and the log.
func (s *AuthService) pwlessSendAsync(ctx context.Context, tenantID, appRowID int64, email, code string, verify bool, ip string) {
	bg := context.WithoutCancel(ctx)
	s.bgSends.Add(1)
	go func() {
		defer s.bgSends.Done()
		select {
		case s.pwless.sendSem <- struct{}{}:
			defer func() { <-s.pwless.sendSem }()
		case <-time.After(passwordlessSendTimeout):
			metrics.PasswordlessEmailSendFailures.Inc()
			return
		}
		ctx, cancel := context.WithTimeout(bg, passwordlessSendTimeout)
		defer cancel()
		if err := s.pwlessSend(ctx, tenantID, appRowID, email, code, verify, ip); err != nil {
			metrics.PasswordlessEmailSendFailures.Inc()
			s.logger.Warn().Err(err).Int64("tenant_id", tenantID).Int64("app", appRowID).
				Msg("passwordless: code email failed after retries — the user can ask for a new code")
		}
	}()
}

func (s *AuthService) pwlessSend(ctx context.Context, tenantID, appRowID int64, email, code string, verify bool, ip string) error {
	msg := mailer.PasswordlessCodeEmail{
		To:         email,
		Code:       code,
		AppName:    s.appNameByID(ctx, strconv.FormatInt(appRowID, 10)),
		TTLMinutes: s.pwlessTTLMinutes(ctx, tenantID, appRowID),
		Verify:     verify,
		Origin:     ip,
		Name:       firstNameByEmail(ctx, s.pool, tenantID, &appRowID, email),
	}
	sender := s.resolveEmailSender(ctx, tenantID, &appRowID)
	tmpl := s.emailSvc.tmplSvc.ResolveTemplate(ctx, tenantID, &appRowID, mailer.TemplatePasswordlessCode)
	var err error
	for attempt := 0; attempt < passwordlessSendAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(time.Duration(attempt*attempt) * 500 * time.Millisecond):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		if err = s.emailSvc.mailer.SendPasswordlessCode(ctx, sender, tmpl, msg); err == nil {
			return nil
		}
		// A broken white-label relay must never lock users out: fall back to the
		// global sender, as email MFA and the magic link do.
		if sender != nil {
			if err = s.emailSvc.mailer.SendPasswordlessCode(ctx, nil, tmpl, msg); err == nil {
				return nil
			}
		}
	}
	return err
}

func (s *AuthService) pwlessTTLMinutes(ctx context.Context, tenantID, appRowID int64) int {
	st := s.pwless.policy.Resolve(ctx, tenantID, &appRowID)
	if m := st.CodeTTLSeconds / 60; m > 0 {
		return m
	}
	return 5
}

// ---------------------------------------------------------------------------
// Resend
// ---------------------------------------------------------------------------

// PasswordlessResendResult is the response to Resend.
type PasswordlessResendResult struct {
	ResendAfter int `json:"resend_after"`
	ResendsLeft int `json:"resends_left"`
}

// PasswordlessResend rotates the code on an existing challenge. Decoy
// challenges answer identically and send nothing.
func (s *AuthService) PasswordlessResend(ctx context.Context, clientID, clientSecret, challengeID string) (*PasswordlessResendResult, error) {
	if err := s.pwlessReady(); err != nil {
		return nil, err
	}
	tenantID, appRowID, err := s.authenticateApp(ctx, clientID, clientSecret)
	if err != nil {
		return nil, err
	}
	settings := s.pwless.policy.Resolve(ctx, tenantID, &appRowID)
	if !settings.EmailOTPEnabled {
		return nil, ErrPasswordlessDisabled
	}
	if len(challengeID) != 64 {
		return nil, ErrPasswordlessInvalidCode
	}

	code, err := generateEmailOTP()
	if err != nil {
		return nil, err
	}
	res, err := pwlessResendScript.Run(ctx, s.redisCli, []string{pwlessChallengeKey(challengeID)},
		pwlessMAC(s.pwless.key, challengeID, code), time.Now().Unix(),
		strconv.FormatInt(appRowID, 10), strconv.FormatInt(tenantID, 10)).Slice()
	if err != nil {
		return nil, ErrPasswordlessUnavailable
	}
	code0, _ := res[0].(int64)
	switch code0 {
	case -2:
		return nil, ErrPasswordlessTooManyResends
	case -3:
		wait, _ := res[1].(int64)
		return nil, &PasswordlessCooldownError{RetryAfter: time.Duration(wait) * time.Second}
	case 1:
	default:
		return nil, ErrPasswordlessInvalidCode
	}
	left, _ := res[1].(int64)
	email, _ := res[2].(string)
	decoy, _ := res[3].(string)
	if decoy != "1" {
		// Whether the address needs the verify wording is re-derived, not stored.
		_, verify := s.pwlessMayReceiveCode(ctx, tenantID, appRowID, email, settings)
		s.pwlessSendAsync(ctx, tenantID, appRowID, email, code, verify, "")
	}
	return &PasswordlessResendResult{ResendAfter: settings.ResendCooldownSecs, ResendsLeft: int(left)}, nil
}

// ---------------------------------------------------------------------------
// Verify
// ---------------------------------------------------------------------------

// PasswordlessVerifyInput is the payload for Verify.
type PasswordlessVerifyInput struct {
	ClientID, ClientSecret string
	ChallengeID, Code      string
	Organization           string
	Roles                  []string
	IP, UserAgent          string
}

// PasswordlessVerifyMeta describes a verification for the handler's audit event.
type PasswordlessVerifyMeta struct {
	UserID, TenantID, AppRowID int64
	Email                      string
	Created                    bool
}

// PasswordlessVerify proves a code and completes the sign-in (or sign-up). The
// result is tokens, an OTP challenge or an enrolment challenge, exactly as for a
// password login. Every refusal is ErrPasswordlessInvalidCode.
func (s *AuthService) PasswordlessVerify(ctx context.Context, in PasswordlessVerifyInput) (*LoginResult, *PasswordlessVerifyMeta, error) {
	if err := s.pwlessReady(); err != nil {
		return nil, nil, err
	}
	tenantID, appRowID, err := s.authenticateApp(ctx, in.ClientID, in.ClientSecret)
	if err != nil {
		return nil, nil, err
	}
	settings := s.pwless.policy.Resolve(ctx, tenantID, &appRowID)
	if !settings.EmailOTPEnabled {
		metrics.PasswordlessVerifies.WithLabelValues("refused").Inc()
		return nil, nil, ErrPasswordlessInvalidCode
	}
	code := strings.TrimSpace(in.Code)
	if len(in.ChallengeID) != 64 || len(code) != PasswordlessCodeLength || !allDigits(code) {
		metrics.PasswordlessVerifies.WithLabelValues("invalid").Inc()
		return nil, nil, ErrPasswordlessInvalidCode
	}

	chKey := pwlessChallengeKey(in.ChallengeID)
	// The address is read first only to apply the per-address failure block. It is
	// not a secret to whoever holds the challenge.
	email, hErr := s.redisCli.HGet(ctx, chKey, "email").Result()
	if hErr != nil {
		if errors.Is(hErr, redis.Nil) {
			metrics.PasswordlessVerifies.WithLabelValues("invalid").Inc()
			return nil, nil, ErrPasswordlessInvalidCode
		}
		return nil, nil, ErrPasswordlessUnavailable
	}
	blockKey := pwlessScoped("block", appRowID, email)
	if n, bErr := s.redisCli.Exists(ctx, blockKey).Result(); bErr == nil && n > 0 {
		metrics.PasswordlessVerifies.WithLabelValues("blocked").Inc()
		metrics.PasswordlessThrottled.WithLabelValues("verify_email").Inc()
		return nil, nil, ErrPasswordlessInvalidCode
	}

	res, err := pwlessVerifyScript.Run(ctx, s.redisCli, []string{chKey},
		pwlessMAC(s.pwless.key, in.ChallengeID, code),
		strconv.FormatInt(appRowID, 10), strconv.FormatInt(tenantID, 10)).Slice()
	if err != nil {
		return nil, nil, ErrPasswordlessUnavailable
	}
	if ok, _ := res[0].(int64); ok != 1 {
		s.pwlessRecordFailure(ctx, appRowID, email)
		metrics.PasswordlessVerifies.WithLabelValues("invalid").Inc()
		return nil, &PasswordlessVerifyMeta{TenantID: tenantID, AppRowID: appRowID, Email: email}, ErrPasswordlessInvalidCode
	}
	persistent, _ := res[2].(string)
	first, _ := res[3].(string)
	last, _ := res[4].(string)

	meta := &PasswordlessVerifyMeta{TenantID: tenantID, AppRowID: appRowID, Email: email}
	result, err := s.pwlessResolveAndComplete(ctx, meta, settings, first, last, persistent == "1", in)
	if err != nil {
		if errors.Is(err, ErrPasswordlessInvalidCode) {
			metrics.PasswordlessVerifies.WithLabelValues("refused").Inc()
		} else {
			metrics.PasswordlessVerifies.WithLabelValues("error").Inc()
		}
		return nil, meta, err
	}
	// A correct code clears the address's failure count.
	s.redisCli.Del(ctx, pwlessScoped("fail", appRowID, email)) //nolint:errcheck
	metrics.PasswordlessVerifies.WithLabelValues("success").Inc()
	return result, meta, nil
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// pwlessRecordFailure counts a failed verification against the address, across
// all its challenges, and blocks verification for it once the budget is spent.
func (s *AuthService) pwlessRecordFailure(ctx context.Context, appRowID int64, email string) {
	n, err := pwlessIncr.Run(ctx, s.redisCli, []string{pwlessScoped("fail", appRowID, email)}, 3600).Int()
	if err != nil {
		return
	}
	if n >= passwordlessFailBudget {
		s.redisCli.Set(ctx, pwlessScoped("block", appRowID, email), "1", passwordlessBlockFor) //nolint:errcheck
	}
}

// ClearPasswordlessThrottle lifts the verify block and failure count for an
// address. An administrator action (plan C5).
func (s *AuthService) ClearPasswordlessThrottle(ctx context.Context, appRowID int64, email string) error {
	if s.redisCli == nil {
		return ErrPasswordlessUnavailable
	}
	email = emailaddr.Normalize(email)
	return s.redisCli.Del(ctx, pwlessScoped("block", appRowID, email), pwlessScoped("fail", appRowID, email)).Err()
}

// pwlessUser is the fresh read of a user at verify time.
type pwlessUser struct {
	id            int64
	roleName      string
	isActive      bool
	emailVerified bool
	hasPassword   bool
	blockReason   *string
}

func (s *AuthService) pwlessLoadUser(ctx context.Context, tenantID, appRowID int64, email string) (*pwlessUser, error) {
	var u pwlessUser
	err := s.pool.QueryRow(ctx, `
		SELECT u.id, COALESCE(r.name, ''), u.is_active, u.email_verified,
		       EXISTS (SELECT 1 FROM user_credentials uc WHERE uc.user_id = u.id),
		       u.block_reason
		FROM users u
		JOIN tenants t ON t.id = u.tenant_id
		LEFT JOIN roles r ON r.id = u.role_id AND r.deleted_at IS NULL
		WHERE u.email = $1 AND u.tenant_id = $2 AND u.application_id = $3
		  AND u.deleted_at IS NULL AND t.is_active = true
	`, email, tenantID, appRowID).Scan(&u.id, &u.roleName, &u.isActive, &u.emailVerified, &u.hasPassword, &u.blockReason)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load passwordless user: %w", err)
	}
	return &u, nil
}

// pwlessResolveAndComplete applies plan section 4.4 after a correct code: sign in
// an existing user, secure an unverified account, or create one.
func (s *AuthService) pwlessResolveAndComplete(ctx context.Context, meta *PasswordlessVerifyMeta, st PasswordlessSettings, first, last string, persistent bool, in PasswordlessVerifyInput) (*LoginResult, error) {
	tenantID, appRowID, email := meta.TenantID, meta.AppRowID, meta.Email

	u, err := s.pwlessLoadUser(ctx, tenantID, appRowID, email)
	if err != nil {
		return nil, err
	}
	if u == nil {
		if !st.SignupEnabled || !st.DomainPermitted(email) {
			return nil, ErrPasswordlessInvalidCode
		}
		id, role, created, cErr := s.pwlessCreateUser(ctx, tenantID, appRowID, email, first, last)
		if cErr != nil {
			return nil, cErr
		}
		meta.Created = created
		if created {
			metrics.PasswordlessCreated.WithLabelValues("created").Inc()
			s.pwlessAudit(ctx, audit.Event{
				TenantID: &tenantID, ApplicationID: &appRowID, UserID: &id,
				Action: audit.ActionUserCreatedPasswordless, ResourceType: "user", ResourceID: strconv.FormatInt(id, 10),
				AuthMethod: audit.AuthMethodEmailOTP, IPAddress: in.IP, UserAgent: in.UserAgent,
				Metadata: map[string]any{"email_domain": emailDomain(email)},
			})
			if st.WelcomeEmailEnabled {
				s.pwlessWelcome(ctx, tenantID, appRowID, email)
			}
		} else {
			metrics.PasswordlessCreated.WithLabelValues("raced").Inc()
		}
		u = &pwlessUser{id: id, roleName: role, isActive: true, emailVerified: true}
	}
	meta.UserID = u.id

	if !u.emailVerified {
		if err := s.pwlessSecureUnverified(ctx, tenantID, appRowID, u, email, in); err != nil {
			return nil, err
		}
	}
	return s.completePasswordlessLogin(ctx, tenantID, appRowID, u, email, persistent && st.AllowPersistent, in)
}

func emailDomain(email string) string {
	if i := strings.LastIndexByte(email, '@'); i >= 0 {
		return email[i+1:]
	}
	return ""
}

// pwlessCreateUser creates an application user with the default role in one
// transaction, verified, with NO credential row. Register is not edited; this is
// its own small helper. A concurrent verify that creates the same address loses
// the INSERT ... ON CONFLICT and reads the winner's row instead.
func (s *AuthService) pwlessCreateUser(ctx context.Context, tenantID, appRowID int64, email, first, last string) (id int64, role string, created bool, err error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, "", false, fmt.Errorf("begin passwordless sign-up: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// Only the application's own default, non-system role is ever assigned, so
	// sign-up cannot escalate (plan T14). Read inside the transaction with the
	// INSERT that consumes it, as Register does.
	var roleID *int64
	err = tx.QueryRow(ctx, `
		SELECT id, name FROM roles
		WHERE tenant_id = $1 AND application_id = $2 AND is_default = true
		  AND is_system = false AND deleted_at IS NULL
		FOR SHARE`, tenantID, appRowID).Scan(&roleID, &role)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return 0, "", false, fmt.Errorf("fetch default role: %w", err)
	}

	err = tx.QueryRow(ctx, `
		INSERT INTO users (tenant_id, email, first_name, last_name, role_id, application_id, is_active, email_verified)
		VALUES ($1, $2, $3, $4, $5, $6, true, true)
		ON CONFLICT (tenant_id, application_id, email) WHERE application_id IS NOT NULL AND deleted_at IS NULL
		DO NOTHING
		RETURNING id`, tenantID, email, first, last, roleID, appRowID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		// Lost the race: someone created it between our read and our insert.
		u, lErr := s.pwlessLoadUser(ctx, tenantID, appRowID, email)
		if lErr != nil || u == nil {
			return 0, "", false, ErrPasswordlessInvalidCode
		}
		return u.id, u.roleName, false, nil
	}
	if err != nil {
		return 0, "", false, fmt.Errorf("insert passwordless user: %w", err)
	}
	if roleID != nil {
		if _, err = tx.Exec(ctx, `
			INSERT INTO user_roles (user_id, role_id, tenant_id, granted_by)
			VALUES ($1, $2, $3, NULL) ON CONFLICT (user_id, role_id) DO NOTHING`, id, *roleID, tenantID); err != nil {
			return 0, "", false, fmt.Errorf("record default role grant: %w", err)
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return 0, "", false, fmt.Errorf("commit passwordless sign-up: %w", err)
	}
	return id, role, true, nil
}

// pwlessSecureUnverified is the pre-hijack safeguard (plan T3). The first time
// the real owner proves control of the inbox on an account that was never
// verified, any session an earlier registrant opened is ended and the address is
// marked verified. A stored password is KEPT, never deleted or changed: in a
// passwordless-only application the password flow is closed so it is harmless,
// and in "both" mode the owner can reset it through the existing flow (residual
// risk accepted in the plan, and equal to today's).
func (s *AuthService) pwlessSecureUnverified(ctx context.Context, tenantID, appRowID int64, u *pwlessUser, email string, in PasswordlessVerifyInput) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin verify-address: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if u.hasPassword {
		if err := RevokeAllSessionsTx(ctx, tx, u.id, tenantID, "preverification_neutralized"); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE users SET email_verified = true, token_version = token_version + 1, updated_at = NOW() WHERE id = $1`, u.id); err != nil {
			return fmt.Errorf("verify address: %w", err)
		}
	} else if _, err := tx.Exec(ctx, `UPDATE users SET email_verified = true, updated_at = NOW() WHERE id = $1`, u.id); err != nil {
		return fmt.Errorf("verify address: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit verify-address: %w", err)
	}
	u.emailVerified = true

	if u.hasPassword {
		DenyAccountSessions(ctx, s.logger, u.id, tenantID)
		metrics.PasswordlessPreverification.Inc()
		s.pwlessAudit(ctx, audit.Event{
			TenantID: &tenantID, ApplicationID: &appRowID, UserID: &u.id,
			Action: audit.ActionAuthPreverificationNeutralized, ResourceType: "user", ResourceID: strconv.FormatInt(u.id, 10),
			AuthMethod: audit.AuthMethodEmailOTP, IPAddress: in.IP, UserAgent: in.UserAgent,
			Metadata: map[string]any{"email_domain": emailDomain(email), "password_kept": true},
		})
	}
	return nil
}

func (s *AuthService) pwlessAudit(ctx context.Context, e audit.Event) {
	if s.pwless != nil && s.pwless.audit != nil {
		s.pwless.audit.Log(ctx, e)
	}
}

// pwlessWelcome sends the welcome email best-effort, as email verification does.
func (s *AuthService) pwlessWelcome(ctx context.Context, tenantID, appRowID int64, email string) {
	bg := context.WithoutCancel(ctx)
	s.bgSends.Add(1)
	go func() {
		defer s.bgSends.Done()
		ctx, cancel := context.WithTimeout(bg, passwordlessSendTimeout)
		defer cancel()
		if !s.emailSvc.tmplSvc.IsTypeEnabled(ctx, tenantID, &appRowID, mailer.TemplateWelcome) {
			auditEmailSuppressed(ctx, s.pwless.audit, tenantID, &appRowID, mailer.TemplateWelcome)
			return
		}
		sender := s.resolveEmailSender(ctx, tenantID, &appRowID)
		tmpl := s.emailSvc.tmplSvc.ResolveTemplate(ctx, tenantID, &appRowID, mailer.TemplateWelcome)
		msg := mailer.WelcomeEmail{
			To: email, AppName: s.appNameByID(ctx, strconv.FormatInt(appRowID, 10)),
			Name: firstNameByEmail(ctx, s.pool, tenantID, &appRowID, email),
		}
		if err := s.emailSvc.mailer.SendWelcome(ctx, sender, tmpl, msg); err != nil && sender != nil {
			_ = s.emailSvc.mailer.SendWelcome(ctx, nil, tmpl, msg)
		}
	}()
}

// ---------------------------------------------------------------------------
// completePasswordlessLogin
// ---------------------------------------------------------------------------

// completePasswordlessLogin performs the steps password Login performs after its
// credential check, in the same order, by calling the same helpers: hard-lock
// expiry, soft-lock check, failed-login reset, role scoping, permission load,
// organization intent, MFA gate, token issue. Login itself is not edited.
//
// The one difference is the MFA gate: the first factor here was proof of the
// inbox, so the email method is not offered as a second factor (inboxFirstFactor).
//
// Every refusal is ErrPasswordlessInvalidCode, never a distinct error, so a
// refusal does not say why.
func (s *AuthService) completePasswordlessLogin(ctx context.Context, tenantID, appRowID int64, u *pwlessUser, email string, persistent bool, in PasswordlessVerifyInput) (*LoginResult, error) {
	lockoutScope := &appRowID
	lockoutPolicy := s.lockoutSvc.Resolve(ctx, tenantID, lockoutScope)

	// A hard-locked account whose lock has run its course is lifted here, the way
	// Login lifts it, and refused otherwise. The unlock re-validates the elapsed
	// time in SQL against the tenant's real policy.
	if !u.isActive {
		expired := u.blockReason != nil && *u.blockReason == "failed_attempts" && lockoutPolicy.HardLockDuration > 0
		if !expired || s.blockSvc == nil || !s.blockSvc.ExpireHardLock(ctx, tenantID, u.id, lockoutPolicy.HardLockDuration) {
			return nil, ErrPasswordlessInvalidCode
		}
	}
	if s.blockSvc != nil {
		if _, locked := s.blockSvc.SoftLockedFor(ctx, tenantID, u.id); locked {
			return nil, ErrPasswordlessInvalidCode
		}
		s.blockSvc.ResetFailedLogins(ctx, tenantID, u.id)
	}

	// A requested session scope the account does not hold is refused outright,
	// with the same uniform error, before any token is minted.
	var activeRoles []string
	if len(in.Roles) > 0 {
		held, err := s.loadRoles(ctx, u.id, tenantID)
		if err != nil {
			return nil, fmt.Errorf("resolve session roles: %w", err)
		}
		activeRoles, err = resolveActiveRoles(in.Roles, held)
		if err != nil {
			s.logger.Warn().Int64("user_id", u.id).Strs("requested", in.Roles).
				Msg("passwordless: refused a session scoped to roles the account does not hold")
			return nil, ErrPasswordlessInvalidCode
		}
	}

	perms, err := s.loadPermissionsScoped(ctx, u.id, tenantID, activeRoles)
	if err != nil {
		s.logger.Warn().Err(err).Msg("passwordless: failed to load permissions, continuing with empty set")
		perms = []string{}
	}

	orgReq := orgSessionRequest{requested: strings.TrimSpace(in.Organization)}
	appID := strconv.FormatInt(appRowID, 10)

	if gate, err := s.mfaGateWith(ctx, mfaGateOptions{inboxFirstFactor: true},
		u.id, tenantID, appRowID, appID, email, u.roleName, perms, persistent, activeRoles, orgReq); err != nil {
		return nil, err
	} else if gate != nil {
		return gate, nil
	}

	tokens, err := s.issueTokenPair(ctx, u.id, tenantID, email, u.roleName, perms,
		sessionContext{
			persistent:  persistent,
			amr:         []string{AMREmailOTP},
			grant:       GrantEmailOTP,
			activeRoles: activeRoles,
			org:         orgReq,
		}, appID)
	if err != nil {
		return nil, err
	}
	return &LoginResult{Token: tokens}, nil
}

// ---------------------------------------------------------------------------
// password_enabled enforcement (plan section 4.9 and 4.11)
// ---------------------------------------------------------------------------

// ErrPasswordAuthDisabled is returned by the password endpoints (login,
// register, forgot-password, reset) for an application whose resolved policy has
// password_enabled=false. It is returned BEFORE any user lookup, hash or
// comparison, so a refused attempt is not counted toward lockout and costs
// nothing. It is per-application configuration, so it is safe to reveal.
//
// The stored password hashes are never read, changed or deleted by this: the
// flow is closed, not erased, and re-enabling passwords makes them work again.
var ErrPasswordAuthDisabled = errors.New("password_auth_disabled")

// PasswordFlowClosed reports whether the password flow is closed for an
// application. False whenever passwordless is not wired (the feature flag is off)
// or no policy applies, which is every deployment and application today.
func (s *AuthService) PasswordFlowClosed(ctx context.Context, tenantID int64, appRowID *int64) bool {
	if s == nil || s.pwless == nil || appRowID == nil || *appRowID == 0 {
		return false
	}
	return !s.pwless.policy.Resolve(ctx, tenantID, appRowID).PasswordEnabled
}
