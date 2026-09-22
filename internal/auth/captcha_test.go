package auth

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// ---------------------------------------------------------------------------
// Captcha service tests (issue #145, phases 3 and 4).
//
// These need Redis (REDIS_URL) and skip without it. They deliberately do NOT
// need Postgres: the policy is injected directly, because what is under test
// here is the challenge lifecycle and the gate, not policy resolution — that is
// covered by the admin tests and by the SQL-level checks on the migration.
// ---------------------------------------------------------------------------

const testHMACKey = "0123456789abcdef0123456789abcdef0123456789abcdef"

// stubPolicyService returns a CaptchaPolicyService whose resolver always answers
// with the given policy.
//
// The cache is pre-seeded and the pool left nil. Resolve consults the cache
// before it touches the pool, so this exercises exactly the read path a warm
// resolver takes in production, without needing a database.
func stubPolicyService(p CaptchaPolicy) *CaptchaPolicyService {
	s := &CaptchaPolicyService{
		cache: make(map[captchaPolicyKey]cachedCaptchaPolicy),
		ttl:   time.Hour,
	}
	// Seeded for every scope the tests use. Resolve consults the cache before
	// the pool, so a nil pool never reaches a query.
	for _, tenant := range []int64{0, 1} {
		s.cache[captchaPolicyKey{tenantID: tenant}] = cachedCaptchaPolicy{policy: p, cachedAt: time.Now()}
	}
	return s
}

// enabledPolicy is the platform default with the feature switched on.
func enabledPolicy() CaptchaPolicy {
	p := DefaultCaptchaPolicy
	p.Enabled = true
	p.Source = "platform"
	return p
}

func newTestCaptchaService(t *testing.T, policy CaptchaPolicy) (*CaptchaService, *redis.Client) {
	t.Helper()
	rdb := testhelper.NewTestRedis(t)
	svc, err := NewCaptchaService(rdb, stubPolicyService(policy), testHMACKey,
		2*time.Minute, true, testhelper.TestLogger())
	if err != nil {
		t.Fatalf("NewCaptchaService: %v", err)
	}
	return svc, rdb
}

// solve reads the answer back out of Redis for a challenge the test just issued.
//
// Tests cannot know the code — that is the point of the feature — so this
// reverses it the only way available: by brute-forcing the stored HMAC against
// the alphabet. Kept to length 4 so it stays fast.
func solve(t *testing.T, svc *CaptchaService, rdb *redis.Client, id string, length int) string {
	t.Helper()
	raw, err := rdb.Get(context.Background(), captchaChallengePrefix+id).Bytes()
	if err != nil {
		t.Fatalf("read challenge: %v", err)
	}
	var rec captchaRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatalf("unmarshal challenge: %v", err)
	}

	var walk func(prefix string) string
	walk = func(prefix string) string {
		if len(prefix) == length {
			if svc.answerHMAC(prefix, rec.CaseSensitive) == rec.AnswerHMAC {
				return prefix
			}
			return ""
		}
		for _, r := range CaptchaAlphabet {
			if got := walk(prefix + string(r)); got != "" {
				return got
			}
		}
		return ""
	}
	answer := walk("")
	if answer == "" {
		t.Fatal("could not recover the challenge answer")
	}
	return answer
}

// shortCodePolicy keeps solve() tractable.
func shortCodePolicy() CaptchaPolicy {
	p := enabledPolicy()
	p.CodeLength = 4
	return p
}

func TestCaptcha_PlaintextAnswerIsNeverStored(t *testing.T) {
	svc, rdb := newTestCaptchaService(t, shortCodePolicy())
	ctx := context.Background()

	ch, err := svc.Issue(ctx, 1, nil, "client-a", CaptchaFlowLogin, "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	answer := solve(t, svc, rdb, ch.ID, 4)

	raw, err := rdb.Get(ctx, captchaChallengePrefix+ch.ID).Result()
	if err != nil {
		t.Fatalf("read challenge: %v", err)
	}
	// The acceptance criterion, asserted rather than assumed: the stored record
	// must not contain the code in any form a reader could use.
	if strings.Contains(strings.ToUpper(raw), answer) {
		t.Fatalf("plaintext answer %q found in the stored record: %s", answer, raw)
	}
}

func TestCaptcha_SingleUse(t *testing.T) {
	svc, rdb := newTestCaptchaService(t, shortCodePolicy())
	ctx := context.Background()

	ch, err := svc.Issue(ctx, 1, nil, "client-a", CaptchaFlowLogin, "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	answer := solve(t, svc, rdb, ch.ID, 4)

	req := CaptchaRequest{ClientID: "client-a", Flow: CaptchaFlowLogin, IP: "203.0.113.9",
		ChallengeID: ch.ID, Answer: answer}

	if err := svc.verify(ctx, req); err != nil {
		t.Fatalf("first verify should succeed: %v", err)
	}
	if err := svc.verify(ctx, req); err == nil {
		t.Fatal("replay of a solved challenge must be refused")
	}
}

func TestCaptcha_PurposeAndClientBinding(t *testing.T) {
	svc, rdb := newTestCaptchaService(t, shortCodePolicy())
	ctx := context.Background()

	t.Run("wrong purpose", func(t *testing.T) {
		ch, err := svc.Issue(ctx, 1, nil, "client-a", CaptchaFlowRegister, "")
		if err != nil {
			t.Fatalf("Issue: %v", err)
		}
		answer := solve(t, svc, rdb, ch.ID, 4)
		err = svc.verify(ctx, CaptchaRequest{ClientID: "client-a", Flow: CaptchaFlowLogin,
			ChallengeID: ch.ID, Answer: answer})
		if err == nil {
			t.Fatal("a register challenge must not be spendable on login")
		}
	})

	t.Run("wrong client", func(t *testing.T) {
		ch, err := svc.Issue(ctx, 1, nil, "client-a", CaptchaFlowLogin, "")
		if err != nil {
			t.Fatalf("Issue: %v", err)
		}
		answer := solve(t, svc, rdb, ch.ID, 4)
		err = svc.verify(ctx, CaptchaRequest{ClientID: "client-b", Flow: CaptchaFlowLogin,
			ChallengeID: ch.ID, Answer: answer})
		if err == nil {
			t.Fatal("a challenge issued to client-a must not be spendable by client-b")
		}
	})
}

func TestCaptcha_UnknownChallengeIsInvalidNotAnError(t *testing.T) {
	svc, _ := newTestCaptchaService(t, shortCodePolicy())

	err := svc.verify(context.Background(), CaptchaRequest{
		ClientID: "client-a", Flow: CaptchaFlowLogin,
		ChallengeID: "definitely-not-a-real-id", Answer: "ABCD",
	})
	if err == nil {
		t.Fatal("unknown challenge must be refused")
	}
	// Expired and never-existed must be indistinguishable from a wrong answer.
	if err.Error() != ErrCaptchaInvalid.Error() {
		t.Fatalf("expected %v, got %v", ErrCaptchaInvalid, err)
	}
}

func TestCaptcha_PreviousChallengeIsBurned(t *testing.T) {
	svc, rdb := newTestCaptchaService(t, shortCodePolicy())
	ctx := context.Background()

	first, err := svc.Issue(ctx, 1, nil, "client-a", CaptchaFlowLogin, "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	answer := solve(t, svc, rdb, first.ID, 4)

	if _, err := svc.Issue(ctx, 1, nil, "client-a", CaptchaFlowLogin, first.ID); err != nil {
		t.Fatalf("Issue (refresh): %v", err)
	}

	// The refresh button must not leave a stack of solvable challenges behind.
	if err := svc.verify(ctx, CaptchaRequest{ClientID: "client-a", Flow: CaptchaFlowLogin,
		ChallengeID: first.ID, Answer: answer}); err == nil {
		t.Fatal("the previous challenge should have been burned")
	}
}

func TestCaptcha_CaseInsensitiveByDefault(t *testing.T) {
	svc, rdb := newTestCaptchaService(t, shortCodePolicy())
	ctx := context.Background()

	ch, err := svc.Issue(ctx, 1, nil, "client-a", CaptchaFlowLogin, "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	answer := solve(t, svc, rdb, ch.ID, 4)

	// Lower-cased and padded — what a real person types.
	if err := svc.verify(ctx, CaptchaRequest{ClientID: "client-a", Flow: CaptchaFlowLogin,
		ChallengeID: ch.ID, Answer: "  " + strings.ToLower(answer) + " "}); err != nil {
		t.Fatalf("a lower-cased, padded answer must be accepted: %v", err)
	}
}

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

func TestCaptchaGate_DisabledPolicyIsAlwaysOpen(t *testing.T) {
	rdb := testhelper.NewTestRedis(t)
	svc, err := NewCaptchaService(rdb, stubPolicyService(DefaultCaptchaPolicy), testHMACKey,
		2*time.Minute, true, testhelper.TestLogger())
	if err != nil {
		t.Fatalf("NewCaptchaService: %v", err)
	}
	ctx := context.Background()

	// Even after enough failures to arm an enabled policy many times over.
	for i := 0; i < 20; i++ {
		svc.RecordFailure(ctx, 0, nil, "client-a", "203.0.113.20")
	}
	if err := svc.Check(ctx, CaptchaRequest{ClientID: "client-a", Flow: CaptchaFlowLogin, IP: "203.0.113.20"}); err != nil {
		t.Fatalf("a disabled policy must never demand a captcha: %v", err)
	}
}

func TestCaptchaGate_AdaptiveArmsAtThreshold(t *testing.T) {
	policy := shortCodePolicy()
	policy.TriggerAfterFailures = 2
	svc, rdb := newTestCaptchaService(t, policy)
	ctx := context.Background()
	const ip = "203.0.113.31"
	t.Cleanup(func() { rdb.Del(ctx, svc.failureKey("client-a", ip)) })

	req := CaptchaRequest{ClientID: "client-a", Flow: CaptchaFlowLogin, IP: ip}

	if err := svc.Check(ctx, req); err != nil {
		t.Fatalf("no failures yet: %v", err)
	}
	svc.RecordFailure(ctx, 0, nil, "client-a", ip)
	if err := svc.Check(ctx, req); err != nil {
		t.Fatalf("one failure is below the threshold: %v", err)
	}
	svc.RecordFailure(ctx, 0, nil, "client-a", ip)
	if err := svc.Check(ctx, req); err == nil {
		t.Fatal("the second failure should have armed the gate")
	} else if err.Error() != ErrCaptchaRequired.Error() {
		t.Fatalf("expected %v, got %v", ErrCaptchaRequired, err)
	}

	// A successful sign-in releases the origin — otherwise a shared address
	// stays gated because one person mistyped.
	svc.ClearFailures(ctx, "client-a", ip)
	if err := svc.Check(ctx, req); err != nil {
		t.Fatalf("a cleared counter must reopen the gate: %v", err)
	}
}

func TestCaptchaGate_AlwaysModeDemandsImmediately(t *testing.T) {
	policy := shortCodePolicy()
	policy.Mode = CaptchaModeAlways
	svc, _ := newTestCaptchaService(t, policy)

	err := svc.Check(context.Background(), CaptchaRequest{
		ClientID: "client-a", Flow: CaptchaFlowLogin, IP: "203.0.113.41",
	})
	if err == nil {
		t.Fatal("always mode must demand a captcha on the first attempt")
	}
}

func TestCaptchaGate_UnprotectedFlowIsOpen(t *testing.T) {
	policy := shortCodePolicy()
	policy.ProtectedFlows = []string{string(CaptchaFlowRegister)}
	policy.Mode = CaptchaModeAlways
	svc, _ := newTestCaptchaService(t, policy)
	ctx := context.Background()

	if err := svc.Check(ctx, CaptchaRequest{ClientID: "c", Flow: CaptchaFlowLogin, IP: "203.0.113.51"}); err != nil {
		t.Fatalf("login is not in protected_flows: %v", err)
	}
	if err := svc.Check(ctx, CaptchaRequest{ClientID: "c", Flow: CaptchaFlowRegister, IP: "203.0.113.51"}); err == nil {
		t.Fatal("register IS in protected_flows and should be gated")
	}
}

// TestCaptchaGate_DemandDoesNotVaryByEmail is the enumeration assertion.
//
// It is the reason the adaptive counter is keyed by IP and client_id rather than
// reusing users.failed_login_attempts, which is keyed by user id: a captcha that
// appeared only for addresses belonging to real accounts would tell an attacker
// which addresses those are, breaking non-negotiable #6.
//
// The service never sees an email at all — which is exactly what makes this
// property hold — so the test asserts the shape that guarantees it: identical
// inputs apart from who is signing in produce identical decisions, and
// CaptchaRequest has no field an email could travel in.
func TestCaptchaGate_DemandDoesNotVaryByEmail(t *testing.T) {
	policy := shortCodePolicy()
	policy.TriggerAfterFailures = 2
	svc, rdb := newTestCaptchaService(t, policy)
	ctx := context.Background()
	const ip = "203.0.113.61"
	t.Cleanup(func() { rdb.Del(ctx, svc.failureKey("client-a", ip)) })

	// Two failures from one origin: in real use one against an account that
	// exists and one against an address that does not. RecordFailure cannot tell
	// them apart, because it is not given anything that would let it.
	svc.RecordFailure(ctx, 0, nil, "client-a", ip)
	svc.RecordFailure(ctx, 0, nil, "client-a", ip)

	req := CaptchaRequest{ClientID: "client-a", Flow: CaptchaFlowLogin, IP: ip}
	first := svc.Check(ctx, req)
	second := svc.Check(ctx, req)

	if first == nil || second == nil {
		t.Fatal("the gate should be armed after two failures")
	}
	if first.Error() != second.Error() {
		t.Fatalf("the decision differed between two identical requests: %v vs %v", first, second)
	}
}

// TestCaptchaGate_FailsOpenWhenCounterUnreadable pins the deliberate choice that
// a Redis problem opens the gate rather than closing it.
//
// Closing it would mean a Redis blip demands captchas from every user while the
// endpoint that issues them is equally broken — a cache outage turned into a
// total login outage. The lockout ladder and the rate limiters are the tiers
// that fail closed; this one is a speed bump and must not.
func TestCaptchaGate_FailsOpenWhenCounterUnreadable(t *testing.T) {
	policy := shortCodePolicy()
	// A client pointed at a port nothing is listening on.
	dead := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", DialTimeout: 200 * time.Millisecond})
	t.Cleanup(func() { _ = dead.Close() })

	svc, err := NewCaptchaService(dead, stubPolicyService(policy), testHMACKey,
		2*time.Minute, true, testhelper.TestLogger())
	if err != nil {
		t.Fatalf("NewCaptchaService: %v", err)
	}

	if err := svc.Check(context.Background(), CaptchaRequest{
		ClientID: "client-a", Flow: CaptchaFlowLogin, IP: "203.0.113.71",
	}); err != nil {
		t.Fatalf("an unreadable counter must leave the gate open, got %v", err)
	}
}

// TestNewCaptchaService_RefusesWeakKey pins the boot-time refusal. The quiet
// version of this mistake is a server that looks like it has captchas and stores
// recoverable answers.
func TestNewCaptchaService_RefusesWeakKey(t *testing.T) {
	rdb := testhelper.NewTestRedis(t)

	if _, err := NewCaptchaService(rdb, stubPolicyService(DefaultCaptchaPolicy), "tooshort",
		2*time.Minute, true, testhelper.TestLogger()); err == nil {
		t.Fatal("a short HMAC key must be refused when the feature is enabled")
	}
	// Disabled, the key is irrelevant and the server must still start.
	if _, err := NewCaptchaService(rdb, stubPolicyService(DefaultCaptchaPolicy), "",
		2*time.Minute, false, testhelper.TestLogger()); err != nil {
		t.Fatalf("a disabled service must not need a key: %v", err)
	}
}

// TestDefaultCaptchaPolicyMatchesSeed pins the compiled-in fallback against the
// row migration 00090 seeds. They are read by different code paths — the
// resolver's degraded path and the admin API's fallback view — and drift between
// them would make the API describe a policy the server is not applying.
func TestDefaultCaptchaPolicyMatchesSeed(t *testing.T) {
	d := DefaultCaptchaPolicy
	switch {
	case d.Enabled:
		t.Error("the seeded platform default is enabled=false")
	case d.Mode != CaptchaModeAdaptive:
		t.Errorf("mode = %q, seed is 'adaptive'", d.Mode)
	case d.TriggerAfterFailures != 2:
		t.Errorf("trigger_after_failures = %d, seed is 2", d.TriggerAfterFailures)
	case d.FailureWindowSeconds != 900:
		t.Errorf("failure_window_seconds = %d, seed is 900", d.FailureWindowSeconds)
	case d.CodeLength != 6:
		t.Errorf("code_length = %d, seed is 6", d.CodeLength)
	case d.TTLSeconds != 120:
		t.Errorf("ttl_seconds = %d, seed is 120", d.TTLSeconds)
	case d.MaxAttemptsPerChallenge != 1:
		t.Errorf("max_attempts_per_challenge = %d, seed is 1", d.MaxAttemptsPerChallenge)
	case d.NoiseLevel != CaptchaNoiseMedium:
		t.Errorf("noise_level = %q, seed is 'medium'", d.NoiseLevel)
	case len(d.ProtectedFlows) != 5:
		t.Errorf("protected_flows has %d entries, seed has 5", len(d.ProtectedFlows))
	}
	for _, f := range d.ProtectedFlows {
		if !IsValidCaptchaFlow(f) {
			t.Errorf("default protected_flows contains unknown flow %q", f)
		}
	}
}
