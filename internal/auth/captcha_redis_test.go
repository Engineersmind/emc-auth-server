package auth

import (
	"context"
	"testing"

	"github.com/redis/go-redis/v9"

	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// Pins the 'always'-mode fail-open fixed after Copilot's review of PR #147.
//
// gateArmed used to return an unconditional true in 'always' mode. Nothing else
// on that path touches Redis, so with Redis down the gate armed, Issue could not
// store a challenge, verify could not consume one, and every protected request
// answered 428 with no way for any caller to satisfy it — a total login outage
// for the scope, which is exactly what the fail-open design elsewhere in this
// file exists to prevent. Adaptive mode never had it, because its Redis GET
// already failed open.
func alwaysOnPolicyForRedisTest() CaptchaPolicy {
	p := DefaultCaptchaPolicy
	p.Enabled = true
	p.Mode = CaptchaModeAlways
	return p
}

// Redis pointed at a closed port: reachable code path, unreachable server.
func newUnreachableRedisCaptcha(t *testing.T) *CaptchaService {
	t.Helper()
	// Port 1 is reserved and nothing listens on it, so every command errors
	// promptly rather than hanging.
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	t.Cleanup(func() { _ = rdb.Close() })

	svc, err := NewCaptchaService(
		rdb,
		NewStaticCaptchaPolicyService(alwaysOnPolicyForRedisTest()),
		"test-hmac-key-at-least-32-characters-long",
		0, true, testhelper.TestLogger(),
	)
	if err != nil {
		t.Fatalf("NewCaptchaService: %v", err)
	}
	return svc
}

func TestCaptchaGate_AlwaysModeFailsOpenWhenRedisIsDown(t *testing.T) {
	svc := newUnreachableRedisCaptcha(t)

	err := svc.Check(context.Background(), CaptchaRequest{
		Flow: CaptchaFlowLogin,
		IP:   "203.0.113.7",
	})
	if err != nil {
		t.Fatalf("always mode demanded a captcha with Redis unreachable: %v", err)
	}
}

// With Redis up, always mode must still demand one on the very first request —
// the fail-open must not become a fail-always-open.
func TestCaptchaGate_AlwaysModeStillDemandsWhenRedisIsUp(t *testing.T) {
	rdb := testhelper.NewTestRedis(t)
	svc, err := NewCaptchaService(
		rdb,
		NewStaticCaptchaPolicyService(alwaysOnPolicyForRedisTest()),
		"test-hmac-key-at-least-32-characters-long",
		0, true, testhelper.TestLogger(),
	)
	if err != nil {
		t.Fatalf("NewCaptchaService: %v", err)
	}

	checkErr := svc.Check(context.Background(), CaptchaRequest{
		Flow: CaptchaFlowLogin,
		IP:   "203.0.113.8",
	})
	if checkErr == nil {
		t.Fatal("always mode let a request through with no challenge and Redis up")
	}
}
