package middleware_test

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog"

	"github.com/engineersmind/emc-auth-server/internal/api/middleware"
	"github.com/engineersmind/emc-auth-server/internal/auth"
)

// Regression tests for the second review round.

// slowWrongClients answers every check as a wrong secret, slowly, so that a
// burst of concurrent requests are all in flight together — the condition a
// check-then-spend budget fails under.
type slowWrongClients struct {
	calls   atomic.Int32
	release chan struct{}
}

func (f *slowWrongClients) AuthenticateClient(context.Context, string, string) (int64, int64, error) {
	f.calls.Add(1)
	<-f.release
	return 0, 0, auth.ErrInvalidClient
}

// Re-review 1: concurrent guesses from one address must not all reach the
// credential check. The attempt budget is spent before the check, atomically.
func TestRereview_ConcurrentGuessesAreBounded(t *testing.T) {
	middleware.ResetStoresForTest()
	clients := &slowWrongClients{release: make(chan struct{})}
	s := middleware.NewAppS2S(middleware.AppS2SConfig{}, nil, clients, zerolog.Nop())
	chain := loginChain(s)

	const burst = 60
	var wg sync.WaitGroup
	wg.Add(burst)
	for i := 0; i < burst; i++ {
		go func(i int) {
			defer wg.Done()
			runS2S(t, chain, s2sReq{remote: strangerIP, clientID: appClient, secret: fmt.Sprintf("guess-%d", i), body: emailBody("a@x.com")})
		}(i)
	}
	// Let the in-flight checks finish once the burst has been dispatched.
	go func() {
		for clients.calls.Load() < 1 {
		}
		close(clients.release)
	}()
	wg.Wait()

	if n := clients.calls.Load(); n > 10 {
		t.Fatalf("%d concurrent guesses reached the credential check; at most 10 may", n)
	}
}

// Re-review A: on /oauth/token, once the legacy per-client bucket is spent,
// the right secret from an address that is not known good must get the same
// answer as a wrong one — no verification, legacy 429.
func TestRereview_NoOAuthOracleAfterLegacyBucket(t *testing.T) {
	middleware.ResetStoresForTest()
	clients := &fakeClients{}
	s := middleware.NewAppS2S(middleware.AppS2SConfig{}, nil, clients, zerolog.Nop())
	chain := []echo.MiddlewareFunc{
		s.ResolveOAuthClient(middleware.SurfaceOAuth, middleware.OAuthTokenLegacyExhausted),
		s.OAuthTokenLimit(),
	}
	// Spend the legacy per-client bucket with wrong secrets from many IPs.
	for i := 0; i < middleware.OAuthTokenPerClientRate; i++ {
		runS2S(t, chain, s2sReq{remote: fmt.Sprintf("10.9.%d.%d", i/250, i%250+1), clientID: appClient, secret: "guess"})
	}
	before := clients.calls.Load()
	right := runS2S(t, chain, s2sReq{remote: "10.8.0.1", clientID: appClient, secret: appSecret})
	wrong := runS2S(t, chain, s2sReq{remote: "10.8.0.2", clientID: appClient, secret: "guess"})
	if right.code != http.StatusTooManyRequests || wrong.code != http.StatusTooManyRequests {
		t.Fatalf("after the legacy bucket: right %d, wrong %d — both must be 429", right.code, wrong.code)
	}
	if clients.calls.Load() != before {
		t.Fatal("no credential check may happen once the legacy bucket is spent")
	}
}

var _ middleware.ClientAuthenticator = (*slowWrongClients)(nil)

// burstChecks fires `ips` addresses x `perIP` concurrent requests with wrong
// secrets through chain, holding every credential check open until all have
// been dispatched, and returns how many checks happened.
func burstChecks(t *testing.T, chain func(*middleware.AppS2S) []echo.MiddlewareFunc, trust middleware.ServerTrustLookup, ips, perIP int, ipFor func(int) string) int32 {
	t.Helper()
	middleware.ResetStoresForTest()
	clients := &slowWrongClients{release: make(chan struct{})}
	s := middleware.NewAppS2S(middleware.AppS2SConfig{}, trust, clients, zerolog.Nop())
	ch := chain(s)
	var wg sync.WaitGroup
	for ip := 0; ip < ips; ip++ {
		for j := 0; j < perIP; j++ {
			wg.Add(1)
			go func(ip, j int) {
				defer wg.Done()
				runS2S(t, ch, s2sReq{remote: ipFor(ip), clientID: appClient, secret: fmt.Sprintf("g-%d-%d", ip, j), body: emailBody("a@x.com")})
			}(ip, j)
		}
	}
	go func() {
		for clients.calls.Load() < 1 {
		}
		close(clients.release)
	}()
	wg.Wait()
	return clients.calls.Load()
}

// Many addresses bursting at once against one client_id: bounded per client,
// atomically (the old limiter's 10/min per client), not 10 per address.
func TestRereview_ConcurrentGuessesAcrossIPsBoundedPerClient(t *testing.T) {
	n := burstChecks(t, loginChain, nil, 20, 10, func(i int) string { return fmt.Sprintf("198.51.100.%d", 10+i) })
	if n > int32(middleware.DefaultBadCredentialsPerClientRate) {
		t.Fatalf("%d checks across 20 addresses; at most %d may happen per client", n, middleware.DefaultBadCredentialsPerClientRate)
	}
}

// Someone sharing a trusted address (a registered server IP here) cannot burst
// unlimited checks through it: uncached checks there have their own budget.
func TestRereview_ConcurrentGuessesFromTrustedAddressBounded(t *testing.T) {
	n := burstChecks(t, loginChain, trustWith([]string{backendIP + "/32"}, false), 1, 100, func(int) string { return backendIP })
	if n > 30 {
		t.Fatalf("%d checks from one trusted address; at most 30 may happen", n)
	}
}

// OAuth: guesses across addresses are bounded per client at the legacy rate,
// atomically.
func TestRereview_OAuthGuessesAcrossIPsBoundedPerClient(t *testing.T) {
	oauth := func(s *middleware.AppS2S) []echo.MiddlewareFunc {
		return []echo.MiddlewareFunc{
			s.ResolveOAuthClient(middleware.SurfaceOAuth, middleware.OAuthTokenLegacyExhausted),
			s.OAuthTokenLimit(),
		}
	}
	n := burstChecks(t, oauth, nil, 40, 10, func(i int) string { return fmt.Sprintf("10.7.%d.1", i) })
	if n > int32(middleware.OAuthTokenPerClientRate) {
		t.Fatalf("%d checks across 40 addresses; at most %d may happen per client", n, middleware.OAuthTokenPerClientRate)
	}
}

// Spend-first must not cost legitimate traffic: the real backend arriving from
// many new addresses (autoscaling, rotating egress) is refunded on every
// correct secret, so the per-client budget never runs out for it.
func TestRereview_LegitFirstContactsFromManyIPsAreRefunded(t *testing.T) {
	s, _ := newS2S(middleware.AppS2SConfig{}, nil)
	chain := loginChain(s)
	for i := 0; i < 60; i++ {
		res := runS2S(t, chain, s2sReq{remote: fmt.Sprintf("10.20.%d.1", i), clientID: appClient, secret: appSecret, body: emailBody(fmt.Sprintf("u%d@x.com", i))})
		if res.code != http.StatusOK {
			t.Fatalf("legit first contact %d from a new address: got %d %v, want 200", i+1, res.code, res.body)
		}
	}
	// Wrong secrets are NOT refunded: the bound still holds for guesses.
	for i := 0; i < middleware.DefaultBadCredentialsPerClientRate; i++ {
		runS2S(t, chain, s2sReq{remote: fmt.Sprintf("10.30.%d.1", i), clientID: appClient, secret: "guess", body: emailBody("a@x.com")})
	}
	if res := runS2S(t, chain, s2sReq{remote: "10.40.0.1", clientID: appClient, secret: "guess", body: emailBody("a@x.com")}); res.code != http.StatusTooManyRequests {
		t.Fatalf("guess past the per-client budget: got %d, want 429", res.code)
	}
}
