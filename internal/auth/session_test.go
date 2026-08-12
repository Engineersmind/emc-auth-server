package auth_test

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/requestctx"
	"github.com/engineersmind/emc-auth-server/internal/store"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// sessionEnv is the fixture for session-lifecycle tests: a real database with the
// "emc" tenant seeded, Redis wired (the rotation lock and the revocation denylist
// both need it), and a registered user to own the sessions.
type sessionEnv struct {
	pool     *pgxpool.Pool
	svc      *auth.AuthService
	ctx      context.Context
	tenantID int64
	userID   int64
	email    string
}

func newSessionEnv(t *testing.T) sessionEnv {
	t.Helper()
	pool := testhelper.NewTestDB(t)
	rdb := testhelper.NewTestRedis(t)
	logger := testhelper.TestLogger()
	ctx := context.Background()

	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}
	t.Cleanup(func() { testhelper.CleanupTables(t, pool) })

	jwtSvc := newTestJWTService(t, pool, "https://auth.emc.local")
	svc := auth.NewAuthService(pool, jwtSvc, logger).WithTOTP(nil, rdb)

	var tenantID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM tenants WHERE slug = 'emc'`).Scan(&tenantID); err != nil {
		t.Fatalf("tenant id: %v", err)
	}

	email := uniqueEmail("session")
	if _, err := svc.Register(ctx, auth.RegisterInput{
		TenantSlug: "emc", Email: email, Password: "Password123!",
		FirstName: "Session", LastName: "User",
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	var userID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM users WHERE email = $1`, email).Scan(&userID); err != nil {
		t.Fatalf("user id: %v", err)
	}

	// Register auto-logs the new user in, so it leaves a live session behind.
	// Clear it: every test here counts sessions, and starting from one instead of
	// zero would make each assertion carry an unexplained +1 that reads as an
	// off-by-one bug in the code under test rather than a fixture artefact.
	if _, err := svc.RevokeOtherSessions(ctx, userID, tenantID, ""); err != nil {
		t.Fatalf("clear registration session: %v", err)
	}

	return sessionEnv{pool: pool, svc: svc, ctx: ctx, tenantID: tenantID, userID: userID, email: email}
}

// login performs a password login and returns the token pair.
func (e sessionEnv) login(t *testing.T, persistent bool) *auth.AuthResult {
	t.Helper()
	res, err := e.svc.Login(e.ctx, auth.LoginInput{
		Email: e.email, Password: "Password123!", Persistent: persistent,
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if res.Token == nil {
		t.Fatalf("Login returned no token pair")
	}
	return res.Token
}

// liveFamilies counts the user's live session families using the same predicate
// the production reads use.
func (e sessionEnv) liveFamilies(t *testing.T) int {
	t.Helper()
	var n int
	if err := e.pool.QueryRow(e.ctx, `
		SELECT COUNT(*) FROM user_sessions
		WHERE user_id = $1 AND tenant_id = $2 AND `+auth.LiveSessionWhere(""),
		e.userID, e.tenantID).Scan(&n); err != nil {
		t.Fatalf("count live families: %v", err)
	}
	return n
}

// sidOf extracts the "sid" claim without verifying the signature — the claim's
// presence and value are what is under test, not the signing.
func sidOf(t *testing.T, accessToken string) string {
	t.Helper()
	var claims jwt.MapClaims
	if _, _, err := jwt.NewParser().ParseUnverified(accessToken, &claims); err != nil {
		t.Fatalf("parse access token: %v", err)
	}
	sid, _ := claims["sid"].(string)
	return sid
}

// Every login must produce a session that is identifiable in the access token and
// resolvable to a real row. Without the sid claim, single-session revocation has
// nothing to key on and falls back to the account-wide token_version counter.
func TestIssueTokenPair_StampsSessionIDAndDeadlines(t *testing.T) {
	e := newSessionEnv(t)
	tokens := e.login(t, false)

	sid := sidOf(t, tokens.AccessToken)
	if sid == "" {
		t.Fatal(`access token carries no "sid" claim`)
	}

	var familyID int64
	var idleExpires, absoluteExpires *time.Time
	var isPersistent bool
	var amr []string
	if err := e.pool.QueryRow(e.ctx, `
		SELECT id, idle_expires_at, absolute_expires_at, is_persistent, amr
		FROM user_sessions WHERE user_id = $1 ORDER BY id DESC LIMIT 1
	`, e.userID).Scan(&familyID, &idleExpires, &absoluteExpires, &isPersistent, &amr); err != nil {
		t.Fatalf("read session row: %v", err)
	}

	if fmt.Sprint(familyID) != sid {
		t.Errorf("sid = %q, session_family_id = %d — the claim must name the session row", sid, familyID)
	}
	if idleExpires == nil || absoluteExpires == nil {
		t.Fatal("idle/absolute deadlines not written; the session has no lifetime bound")
	}
	if !idleExpires.Before(*absoluteExpires) {
		t.Errorf("idle deadline %v is not before absolute %v — an idle clock at or past the cap can never fire",
			idleExpires, absoluteExpires)
	}
	if isPersistent {
		t.Error("is_persistent = true for a login that did not ask to be remembered")
	}
	if len(amr) == 0 {
		t.Error("amr is empty; the authentication method was not recorded")
	}
}

// A "remember me" login must get the longer idle clock. This is the whole
// mechanism by which the two clocks differ, so if it silently collapses to one
// value the distinction exists only in the schema.
func TestIssueTokenPair_PersistentGetsLongerIdleClock(t *testing.T) {
	e := newSessionEnv(t)

	e.login(t, false)
	shortIdle := lastIdleExpiry(t, e)

	e.login(t, true)
	longIdle := lastIdleExpiry(t, e)

	if !longIdle.After(shortIdle) {
		t.Errorf("persistent idle deadline %v is not later than non-persistent %v", longIdle, shortIdle)
	}
}

func lastIdleExpiry(t *testing.T, e sessionEnv) time.Time {
	t.Helper()
	var idle time.Time
	if err := e.pool.QueryRow(e.ctx, `
		SELECT idle_expires_at FROM user_sessions WHERE user_id = $1 ORDER BY id DESC LIMIT 1
	`, e.userID).Scan(&idle); err != nil {
		t.Fatalf("read idle expiry: %v", err)
	}
	return idle
}

// The absolute deadline is measured from first authentication and must survive
// rotation untouched. If a rotation recomputed it from "now", a session refreshing
// on any interval shorter than the cap would live forever — the sliding-window bug
// that makes an absolute cap decorative.
func TestRefresh_DoesNotSlideAbsoluteDeadline(t *testing.T) {
	e := newSessionEnv(t)
	tokens := e.login(t, false)

	before := lastAbsoluteExpiry(t, e)

	rotated, err := e.svc.Refresh(e.ctx, tokens.RefreshToken)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	after := lastAbsoluteExpiry(t, e)

	if !after.Equal(before) {
		t.Errorf("absolute deadline moved from %v to %v across a rotation", before, after)
	}
	// The session identity must also survive, or every refresh would look like a
	// new device in the session list.
	if sidOf(t, rotated.AccessToken) != sidOf(t, tokens.AccessToken) {
		t.Error("sid changed across rotation; the rotation started a new session instead of continuing one")
	}
	if got := e.liveFamilies(t); got != 1 {
		t.Errorf("live families after rotation = %d, want 1", got)
	}
}

func lastAbsoluteExpiry(t *testing.T, e sessionEnv) time.Time {
	t.Helper()
	var abs time.Time
	if err := e.pool.QueryRow(e.ctx, `
		SELECT absolute_expires_at FROM user_sessions WHERE user_id = $1 ORDER BY id DESC LIMIT 1
	`, e.userID).Scan(&abs); err != nil {
		t.Fatalf("read absolute expiry: %v", err)
	}
	return abs
}

// An idle-expired token must be refused, and refused as an ordinary invalid token
// rather than as a replay: the user did nothing wrong, and misreporting it would
// flood the replay metric that operators alert on.
func TestRefresh_IdleExpiredIsRejectedNotTreatedAsReplay(t *testing.T) {
	e := newSessionEnv(t)
	tokens := e.login(t, false)

	if _, err := e.pool.Exec(e.ctx, `
		UPDATE user_sessions SET idle_expires_at = NOW() - INTERVAL '1 second' WHERE user_id = $1
	`, e.userID); err != nil {
		t.Fatalf("expire idle clock: %v", err)
	}

	_, err := e.svc.Refresh(e.ctx, tokens.RefreshToken)
	if !errors.Is(err, auth.ErrInvalidRefreshToken) {
		t.Fatalf("Refresh(idle-expired) error = %v, want ErrInvalidRefreshToken", err)
	}
	if errors.Is(err, auth.ErrTokenReplay) {
		t.Error("idle expiry reported as a replay; that is a security alert for a benign event")
	}
	if got := e.liveFamilies(t); got != 0 {
		t.Errorf("live families = %d, want 0 — an idle-expired session must not be listed as active", got)
	}
}

// Logout must end the whole session, not just the token presented. A client that
// logs out holding an already-rotated token — a stale tab, a retried request, an app
// resuming from a background refresh — would otherwise be told it signed out while
// the live successor token kept working.
func TestLogoutSession_RevokesWholeFamilyFromStaleToken(t *testing.T) {
	e := newSessionEnv(t)
	first := e.login(t, false)

	// Rotate once, so `first` is now a stale token and a live successor exists.
	if _, err := e.svc.Refresh(e.ctx, first.RefreshToken); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if got := e.liveFamilies(t); got != 1 {
		t.Fatalf("live families before logout = %d, want 1", got)
	}

	revoked, err := e.svc.LogoutSession(e.ctx, first.RefreshToken)
	if err != nil {
		t.Fatalf("LogoutSession(stale token): %v", err)
	}
	if revoked == 0 {
		t.Error("logout with a stale token revoked nothing; the live successor would still work")
	}
	if got := e.liveFamilies(t); got != 0 {
		t.Errorf("live families after logout = %d, want 0", got)
	}
}

// Logout with a token that was never issued must not report an error: for the
// caller, "unrecognised credential" and "you are signed out" are the same outcome,
// and distinguishing them turns logout into an oracle for whether a token value
// ever existed.
func TestLogoutSession_UnknownTokenSucceedsSilently(t *testing.T) {
	e := newSessionEnv(t)

	revoked, err := e.svc.LogoutSession(e.ctx, "not-a-token-that-was-ever-issued")
	if err != nil {
		t.Fatalf("LogoutSession(unknown) error = %v, want nil", err)
	}
	if revoked != 0 {
		t.Errorf("revoked = %d, want 0", revoked)
	}
}

// The concurrent-session cap must hold. This is the backstop that keeps a session
// list usable even if an idle-clock regression ships, so it has to bound the count
// on its own.
func TestSessionCap_EvictsOldestBeyondLimit(t *testing.T) {
	e := newSessionEnv(t)

	if _, err := e.pool.Exec(e.ctx, `
		INSERT INTO session_policies (tenant_id, application_id, idle_ttl_seconds,
		    non_persistent_idle_ttl_seconds, absolute_ttl_seconds, max_concurrent_sessions, allow_persistent)
		VALUES ($1, NULL, 3600, 3600, 7200, 2, true)
	`, e.tenantID); err != nil {
		t.Fatalf("seed tenant policy: %v", err)
	}
	// Writing the row is not enough: the resolver caches for a minute, and the
	// fixture's Register/Login already populated that cache with the platform
	// default. The admin API drops the cache on every policy write for exactly this
	// reason, so doing it here mirrors production rather than working around it.
	//
	// Without this the test passed for the wrong reason — the policy table used to be
	// empty in the test database, resolution failed, and the failure path returns
	// defaults WITHOUT caching, so every login happened to re-read the table.
	e.svc.SessionPolicy().InvalidateCache()

	for i := 0; i < 4; i++ {
		e.login(t, false)
	}

	if got := e.liveFamilies(t); got != 2 {
		t.Errorf("live families = %d, want 2 (the tenant's cap)", got)
	}

	var evicted int
	if err := e.pool.QueryRow(e.ctx, `
		SELECT COUNT(*) FROM user_sessions
		WHERE user_id = $1 AND revoked_reason = $2
	`, e.userID, auth.RevokeReasonCapEvicted).Scan(&evicted); err != nil {
		t.Fatalf("count evictions: %v", err)
	}
	if evicted == 0 {
		t.Error("no rows recorded as cap_evicted; the cause of the revocation is not queryable")
	}
}

// "Sign out everywhere else" must spare the caller's own session. Ending it too
// would sign the user out of the page they are using to secure their account.
func TestRevokeOtherSessions_KeepsCallersOwnSession(t *testing.T) {
	e := newSessionEnv(t)

	keep := e.login(t, false)
	e.login(t, false)
	e.login(t, false)
	if got := e.liveFamilies(t); got != 3 {
		t.Fatalf("live families = %d, want 3", got)
	}

	keepSID := sidOf(t, keep.AccessToken)
	revoked, err := e.svc.RevokeOtherSessions(e.ctx, e.userID, e.tenantID, keepSID)
	if err != nil {
		t.Fatalf("RevokeOtherSessions: %v", err)
	}
	if revoked == 0 {
		t.Error("revoked nothing")
	}
	if got := e.liveFamilies(t); got != 1 {
		t.Fatalf("live families after revoke = %d, want 1", got)
	}

	// The surviving session must be the one that was kept, and it must still work.
	if _, err := e.svc.Refresh(e.ctx, keep.RefreshToken); err != nil {
		t.Errorf("kept session can no longer refresh: %v", err)
	}
}

// A revoked session's outstanding access tokens must be refused immediately rather
// than remaining valid until they expire. The denylist is what closes that window.
func TestRevokeSession_DeniesOutstandingAccessToken(t *testing.T) {
	e := newSessionEnv(t)
	tokens := e.login(t, false)
	sid := sidOf(t, tokens.AccessToken)

	uid := strconv.FormatInt(e.userID, 10)
	tid := strconv.FormatInt(e.tenantID, 10)

	if e.svc.SessionDenied(e.ctx, sid, uid, tid, time.Now().UTC().Unix()) {
		t.Fatal("session denied before any revocation")
	}

	famID := int64(0)
	if _, err := fmt.Sscan(sid, &famID); err != nil {
		t.Fatalf("parse sid: %v", err)
	}
	if _, err := e.svc.RevokeSession(e.ctx, e.userID, e.tenantID, famID, auth.RevokeReasonAdmin); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}

	if !e.svc.SessionDenied(e.ctx, sid, uid, tid, time.Now().UTC().Unix()) {
		t.Error("revoked session not on the denylist; its access token stays valid until expiry")
	}
}

/*
 * An account-wide revocation must deny tokens that carry no session id, and must
 * deny sessions the caller never enumerated.
 *
 * This is the case that shipped broken. "Revoke all sessions" wrote the refresh-row
 * revocation and bumped users.token_version, then reported success — and because
 * nothing verifies token_version and no denylist entry was written, the user stayed
 * signed in until their access token expired. The per-session denylist could not
 * have caught it: revoke-all does not know which sessions exist.
 */
func TestDenyUserSessions_DeniesEveryTokenForTheAccount(t *testing.T) {
	e := newSessionEnv(t)
	first := e.login(t, false)
	second := e.login(t, false)

	uid := strconv.FormatInt(e.userID, 10)
	tid := strconv.FormatInt(e.tenantID, 10)
	firstSID := sidOf(t, first.AccessToken)
	secondSID := sidOf(t, second.AccessToken)
	// The tokens' own issue times, not time.Now(): the check compares iat against the
	// revocation instant, so passing "now" would describe a token minted after the
	// revocation and correctly not be denied.
	firstIssued := issuedAtOf(t, first.AccessToken)
	secondIssued := issuedAtOf(t, second.AccessToken)

	if e.svc.SessionDenied(e.ctx, firstSID, uid, tid, firstIssued) {
		t.Fatal("denied before any revocation")
	}

	// The revocation must land in a strictly later second than the logins, because a
	// token issued in the same second is deliberately allowed through — see
	// revokedBefore. Real revocations are minutes or days after the login; only the
	// test compresses them into the same instant.
	time.Sleep(1100 * time.Millisecond)
	e.svc.DenyUserSessions(e.ctx, e.userID, e.tenantID)

	if !e.svc.SessionDenied(e.ctx, firstSID, uid, tid, firstIssued) {
		t.Error("first session not denied after an account-wide revocation")
	}
	if !e.svc.SessionDenied(e.ctx, secondSID, uid, tid, secondIssued) {
		t.Error("second session not denied after an account-wide revocation")
	}
	// A token with no sid — one minted before the claim existed — must still be
	// caught by the account key, or an account-wide revocation would silently spare
	// exactly the oldest tokens.
	if !e.svc.SessionDenied(e.ctx, "", uid, tid, firstIssued) {
		t.Error("sid-less token not denied; the account key is not being consulted")
	}
}

// The account key must not reach across tenants: user ids are only unique within
// one, so keying on the user alone would let a revocation in one tenant sign out an
// unrelated account in another.
func TestDenyUserSessions_IsScopedToTheTenant(t *testing.T) {
	e := newSessionEnv(t)
	e.login(t, false)

	uid := strconv.FormatInt(e.userID, 10)
	e.svc.DenyUserSessions(e.ctx, e.userID, e.tenantID)

	otherTenant := strconv.FormatInt(e.tenantID+1, 10)
	if e.svc.SessionDenied(e.ctx, "", uid, otherTenant, time.Now().UTC().Unix()) {
		t.Error("revocation leaked to the same user id in another tenant")
	}
}

/*
 * An account-wide revocation must not lock the user out of signing back in.
 *
 * The account key applies to the ACCOUNT rather than to one session, so a naive
 * "deny everything" marker also refuses the tokens the user receives on their next
 * login — leaving them unable to sign in for the key's full fifteen-minute lifetime
 * immediately after being signed out. That is worse than the bug the denylist was
 * added to fix, and it is what the first version of this did.
 *
 * The entry stores the revocation instant instead, so it means "deny tokens issued
 * before this".
 */
func TestDenyUserSessions_DoesNotBlockLaterLogins(t *testing.T) {
	e := newSessionEnv(t)
	old := e.login(t, false)
	oldIssued := issuedAtOf(t, old.AccessToken)

	uid := strconv.FormatInt(e.userID, 10)
	tid := strconv.FormatInt(e.tenantID, 10)

	time.Sleep(1100 * time.Millisecond)
	e.svc.DenyUserSessions(e.ctx, e.userID, e.tenantID)

	if !e.svc.SessionDenied(e.ctx, sidOf(t, old.AccessToken), uid, tid, oldIssued) {
		t.Fatal("the token in circulation at revocation time was not denied")
	}

	// A token minted after the revocation must be accepted. Its iat is at least the
	// revocation second, and the same-second case is deliberately allowed — see
	// revokedBefore for why that trade is the right way round.
	future := time.Now().UTC().Add(2 * time.Second).Unix()
	if e.svc.SessionDenied(e.ctx, "999999", uid, tid, future) {
		t.Error("a token issued after the revocation was denied; the user cannot sign back in")
	}
}

// issuedAtOf reads the "iat" claim without verifying the signature.
func issuedAtOf(t *testing.T, accessToken string) int64 {
	t.Helper()
	var claims jwt.MapClaims
	if _, _, err := jwt.NewParser().ParseUnverified(accessToken, &claims); err != nil {
		t.Fatalf("parse access token: %v", err)
	}
	iat, ok := claims["iat"].(float64)
	if !ok {
		t.Fatal(`access token carries no "iat" claim`)
	}
	return int64(iat)
}

// Session rows must record the device that created them. Without this the session
// list is a column of blanks and neither an operator nor the user can tell which
// entry is which — which is what made a four-hundred-entry list unusable.
func TestIssueTokenPair_RecordsDeviceFromRequestContext(t *testing.T) {
	e := newSessionEnv(t)

	ctx := requestctx.WithRequestInfo(e.ctx, "203.0.113.7", "TestBrowser/1.0")
	if _, err := e.svc.Login(ctx, auth.LoginInput{Email: e.email, Password: "Password123!"}); err != nil {
		t.Fatalf("Login: %v", err)
	}

	var ua string
	var ip *string
	if err := e.pool.QueryRow(e.ctx, `
		SELECT user_agent, host(ip_address) FROM user_sessions
		WHERE user_id = $1 ORDER BY id DESC LIMIT 1
	`, e.userID).Scan(&ua, &ip); err != nil {
		t.Fatalf("read device columns: %v", err)
	}
	if ua != "TestBrowser/1.0" {
		t.Errorf("user_agent = %q, want TestBrowser/1.0", ua)
	}
	if ip == nil || *ip != "203.0.113.7" {
		t.Errorf("ip_address = %v, want 203.0.113.7", ip)
	}
}

// The reaper must delete only rows that can never be presented again, and only
// after the retention margin. A reaper that removes live sessions is worse than no
// reaper at all.
func TestSessionReaper_DeletesOnlyLongDeadRows(t *testing.T) {
	e := newSessionEnv(t)
	live := e.login(t, false)

	// A row revoked long ago (past retention) and one revoked just now.
	seedDeadToken(t, e, "old-dead", -30*24*time.Hour)
	seedDeadToken(t, e, "fresh-dead", -time.Minute)

	reaper := auth.NewSessionReaper(e.pool, testhelper.TestLogger())
	if err := reaper.RunOnce(e.ctx); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}

	if exists(t, e, "old-dead") {
		t.Error("row revoked 30 days ago was not reaped")
	}
	if !exists(t, e, "fresh-dead") {
		t.Error("row revoked a minute ago was reaped; the forensic retention margin was not honoured")
	}
	// The live session must be untouched and still usable.
	if _, err := e.svc.Refresh(e.ctx, live.RefreshToken); err != nil {
		t.Errorf("live session broken by the reaper: %v", err)
	}
}

// seedDeadToken creates a revoked session with one token, revoked revokedAgo ago.
//
// A session plus a token rather than a bare token, because the reaper now deletes
// the session and relies on ON DELETE CASCADE to take the tokens with it — a
// parentless token would never be swept by that path and the test would assert
// nothing.
func seedDeadToken(t *testing.T, e sessionEnv, hash string, revokedAgo time.Duration) {
	t.Helper()
	revokedAt := fmt.Sprintf("%f seconds", revokedAgo.Seconds())

	var sessionID int64
	if err := e.pool.QueryRow(e.ctx, `
		INSERT INTO user_sessions
		    (user_id, tenant_id, idle_expires_at, absolute_expires_at, revoked_at, revoked_reason)
		VALUES ($1, $2, NOW() + INTERVAL '1 day', NOW() + INTERVAL '1 day',
		        NOW() + $3::interval, 'logout')
		RETURNING id
	`, e.userID, e.tenantID, revokedAt).Scan(&sessionID); err != nil {
		t.Fatalf("seed dead session for %s: %v", hash, err)
	}

	if _, err := e.pool.Exec(e.ctx, `
		INSERT INTO refresh_tokens
		    (user_id, tenant_id, token_hash, expires_at, session_id, session_family_id,
		     revoked_at, revoked_reason)
		VALUES ($1, $2, $3, NOW() + INTERVAL '1 day', $4, $4,
		        NOW() + $5::interval, 'logout')
	`, e.userID, e.tenantID, hash, sessionID, revokedAt); err != nil {
		t.Fatalf("seed dead token %s: %v", hash, err)
	}
}

func exists(t *testing.T, e sessionEnv, hash string) bool {
	t.Helper()
	var n int
	if err := e.pool.QueryRow(e.ctx,
		`SELECT COUNT(*) FROM refresh_tokens WHERE token_hash = $1`, hash).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", hash, err)
	}
	return n > 0
}
