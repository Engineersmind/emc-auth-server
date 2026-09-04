package auth

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"

	"github.com/engineersmind/emc-auth-server/internal/metrics"
)

// ---------------------------------------------------------------------------
// Session liveness
// ---------------------------------------------------------------------------

// LiveSessionWhere is the single definition of "this session is still usable",
// expressed over user_sessions columns.
//
// One definition because the predicate is checked in six places — the refresh path,
// the grace-window lookup, the admin session list, the active-session count, the
// concurrent-session cap, and the reaper. Hand-maintaining six copies is how the
// listing and the refresh path come to disagree about what is alive, and that
// disagreement presents to an operator as "I revoked that session and it still
// works": the worst possible way to learn about a drifted WHERE clause.
//
// No NULL-tolerance here, unlike the refresh_tokens version this replaces: both
// clocks are NOT NULL on user_sessions, and migration 00069 derives a value for
// every backfilled row, so "unknown deadline" is not a state a session can be in.
//
// Takes a table alias rather than being a bare constant, because both predicates
// name columns that exist on BOTH tables — `revoked_at` and `expires_at` most
// importantly. An unqualified fragment inside a join is not merely ambiguous to
// Postgres; it is the kind of ambiguity that could resolve to the wrong table and
// check the wrong thing. Pass "" for a single-table query, "s." for a join.
func LiveSessionWhere(alias string) string {
	return fmt.Sprintf(
		`%[1]srevoked_at IS NULL AND %[1]sidle_expires_at > NOW() AND %[1]sabsolute_expires_at > NOW()`,
		alias,
	)
}

// LiveTokenWhere is the credential half: whether this particular refresh token may
// still be presented. Over refresh_tokens columns.
//
// Kept separate from LiveSessionWhere because they answer different questions and
// both must hold. A token is single-use and dies at rotation; the session outlives
// every token it issues. Conflating the two is what made session state a property of
// a credential in the first place.
func LiveTokenWhere(alias string) string {
	return fmt.Sprintf(
		`%[1]srevoked_at IS NULL AND %[1]sdeleted_at IS NULL AND %[1]sexpires_at > NOW()`,
		alias,
	)
}

// ---------------------------------------------------------------------------
// Revocation reasons
// ---------------------------------------------------------------------------

// Revocation reasons written to refresh_tokens.revoked_reason.
//
// Recorded so "which sessions did policy terminate, and why?" is a query rather
// than an inference from timestamps — the question a compliance reviewer asks,
// and the question an operator asks first during an incident.
const (
	// RevokeReasonRotated is the ordinary single-use rotation: this token was
	// exchanged for its successor. By far the most common value, and the one to
	// exclude when looking for sessions that ended unusually.
	RevokeReasonRotated = "rotated"
	// RevokeReasonLogout — the user signed out deliberately.
	RevokeReasonLogout = "logout"
	// RevokeReasonUserRevoked — the user ended this session from their own
	// device list.
	RevokeReasonUserRevoked = "user_revoked"
	// RevokeReasonAdmin — an administrator ended this one session.
	RevokeReasonAdmin = "admin_revoked"
	// RevokeReasonAdminAll — an administrator signed the account out everywhere.
	RevokeReasonAdminAll = "admin_revoked_all"
	// RevokeReasonReplay — a rotated token was presented again, so the whole
	// family was terminated. A security event, not hygiene.
	RevokeReasonReplay = "replay_detected"
	// RevokeReasonCapEvicted — a new login exceeded the concurrent-session cap
	// and this, the least recently active session, was evicted to make room.
	RevokeReasonCapEvicted = "cap_evicted"
	// RevokeReasonCredentialChange — a password reset, email change, or role
	// change invalidated every existing session.
	RevokeReasonCredentialChange = "credential_change"
	// RevokeReasonPasskeyCloned — an assertion showed evidence that a passkey's
	// private key exists in more than one place, so every session the account
	// had was ended. Distinct from replay_detected: that one says a token was
	// reused, this one says a hardware-backed key was copied, and the second is
	// the more serious finding of the two.
	RevokeReasonPasskeyCloned = "passkey_cloned"
	// RevokeReasonSessionRejected — tokens were minted and then the request that
	// minted them was refused, so the session was never handed to anybody. The
	// cookie-session endpoints refusing an application-scoped identity are the
	// case that motivated it (issue #116).
	//
	// Worth its own reason precisely because the alternative was reading as
	// cap_evicted: the orphan held the freshest last_seen_at, survived the cap,
	// and pushed genuine sessions out under a reason that looks like ordinary
	// session pressure. An operator debugging "why was I signed out of my other
	// devices" must be able to see this instead.
	RevokeReasonSessionRejected = "session_rejected"
)

// ---------------------------------------------------------------------------
// Authentication methods (OIDC "amr")
// ---------------------------------------------------------------------------

// Authentication method references recorded on the session, following the OIDC
// "amr" claim and the RFC 8176 vocabulary where it has a suitable value.
//
// Recorded per session so a relying party — or a future step-up check — can ask
// "how strongly was this session authenticated?" rather than assuming. A session
// established by a magic link alone is not the same as one established by password
// plus TOTP, and once the session exists there is no other record of which it was.
// RFC 8176 has no distinct value for an authenticator app versus an emailed
// code — both are "otp" — so AMROTP covers TOTP and email OTP alike. The factor
// actually used is already recorded per-event in the audit trail
// (audit.AuthMethodTOTP / AuthMethodEmailOTP); duplicating that distinction here
// under a non-standard value would make the claim less interoperable, not more
// informative.
const (
	AMRPassword  = "pwd"  // password
	AMROTP       = "otp"  // one-time password: authenticator app or emailed code
	AMRMFA       = "mfa"  // multiple factors were used
	AMRMagicLink = "link" // emailed sign-in link (no registered RFC 8176 value)
	AMRFederated = "fed"  // federated / external identity provider
	// AMRWebAuthn is RFC 8176 "hwk": proof of possession of a hardware-backed
	// key. Covers every passkey — platform authenticators (Windows Hello, Touch
	// ID) and roaming security keys alike, since the distinction is not one the
	// relying party can verify.
	AMRWebAuthn = "hwk"
	// AMRUserVerif is RFC 8176 "user": the authenticator performed user
	// verification (biometric or PIN). Emitted only when the ASSERTION says so —
	// never because we asked for it — because it is what justifies also claiming
	// AMRMFA on a passwordless sign-in.
	AMRUserVerif = "user"
)

// ---------------------------------------------------------------------------
// Session revocation
// ---------------------------------------------------------------------------

// revokeSession ends one session.
//
// A single write to the session row, which is the whole point of the parent-table
// shape: the session's tokens are dead by relationship, so there is no multi-row
// predicate to get wrong. The previous version had to match family AND user AND
// tenant across every token row, and getting that predicate wrong is how a
// replayed token could once have revoked family 0 across every tenant.
//
// user_id and tenant_id remain in the WHERE clause as an authorization check
// rather than a correctness one: the caller has asserted whose session this is,
// and the query refuses to act if that assertion is wrong.
//
// Returns 1 when a live session was ended, 0 when there was nothing to end —
// callers distinguish "revoked" from "not found" on that.
func (s *AuthService) revokeSession(ctx context.Context, userID, tenantID, sessionID int64, reason string) (int64, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin revoke session: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	ct, err := tx.Exec(ctx, `
		UPDATE user_sessions
		SET revoked_at = NOW(), revoked_reason = $4, updated_at = NOW()
		WHERE id = $1 AND user_id = $2 AND tenant_id = $3 AND revoked_at IS NULL
	`, sessionID, userID, tenantID, reason)
	if err != nil {
		return 0, fmt.Errorf("revoke session: %w", err)
	}
	n := ct.RowsAffected()
	if n == 0 {
		return 0, nil
	}

	// The tokens are already unusable — the refresh path requires a live session —
	// so this is bookkeeping, not enforcement: it stops a revoked session's tokens
	// lingering as apparently-live rows for the reaper and for anyone reading the
	// table directly.
	if _, err := tx.Exec(ctx, `
		UPDATE refresh_tokens
		SET revoked_at = NOW(), revoked_reason = $2, updated_at = NOW()
		WHERE session_id = $1 AND revoked_at IS NULL
	`, sessionID, reason); err != nil {
		return 0, fmt.Errorf("revoke session tokens: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit revoke session: %w", err)
	}

	metrics.SessionRevocations.WithLabelValues(reason).Add(float64(n))
	// After the commit: a Redis entry cannot be rolled back, so denying a session
	// the transaction then failed to revoke would sign a user out on the strength
	// of a write that never landed.
	s.denySession(ctx, sessionID)
	return n, nil
}

// RevokeSession ends one session and returns how many tokens were revoked.
//
// The exported entry point for callers outside this package — the admin API and
// the end-user device list. Both must go through here rather than issuing their
// own UPDATE, because "revoke a session" is three things, not one: revoke the
// rows, record the reason, and deny the session's outstanding access tokens. A
// caller that writes the UPDATE itself silently skips the third, and the symptom
// is a session that keeps working for fifteen minutes after the API said it was
// gone.
func (s *AuthService) RevokeSession(ctx context.Context, userID, tenantID, sessionID int64, reason string) (int64, error) {
	return s.revokeSession(ctx, userID, tenantID, sessionID, reason)
}

// RevokeOtherSessions ends every session belonging to the user EXCEPT the one
// identified by keepFamilyID, returning how many tokens were revoked.
//
// Backs the user-facing "sign out everywhere else" action. Keeping the caller's own
// session is the point: the alternative signs them out of the page they are using
// to secure their account, on a device they have just been told may be compromised.
//
// keepFamilyID is the caller's "sid" claim, so it is a value the server minted and
// verified, not client input. An empty or unparseable value revokes everything,
// which is the safe direction — a caller whose token carries no session identity
// gets the stronger action rather than a silent no-op.
//
// Deliberately does NOT bump users.token_version, even though it revokes many
// sessions: the bump is account-global and would invalidate the caller's own access
// token along with the rest, which is exactly what this function exists to avoid.
// The revoked sessions' access tokens are handled by the denylist instead.
// keepNoSession is the "spare nothing" sentinel for RevokeOtherSessions.
//
// -1, not 0: session ids are positive, so `id <> -1` matches every row. 0 was
// wrong because it spared any legacy row whose family id was 0 — the exact
// opposite of the documented behaviour, and silently so. Named rather than
// written inline so a copy-paste carries the reasoning with it.
const keepNoSession = int64(-1)

func (s *AuthService) RevokeOtherSessions(ctx context.Context, userID, tenantID int64, keepFamilyID string) (int64, error) {
	keep := keepNoSession
	if keepFamilyID != "" {
		if parsed, err := strconv.ParseInt(keepFamilyID, 10, 64); err == nil {
			keep = parsed
		}
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin revoke other sessions: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// RETURNING the ids rather than just a count: each has to go on the denylist
	// individually, and re-querying afterwards would race with anything else
	// revoking in between.
	rows, err := tx.Query(ctx, `
		UPDATE user_sessions
		SET revoked_at = NOW(), revoked_reason = $4, updated_at = NOW()
		WHERE user_id = $1 AND tenant_id = $2 AND id <> $3 AND revoked_at IS NULL
		RETURNING id
	`, userID, tenantID, keep, RevokeReasonUserRevoked)
	if err != nil {
		return 0, fmt.Errorf("revoke other sessions: %w", err)
	}

	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan revoked session: %w", err)
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("revoke other sessions: %w", err)
	}

	if len(ids) > 0 {
		if _, err := tx.Exec(ctx, `
			UPDATE refresh_tokens
			SET revoked_at = NOW(), revoked_reason = $2, updated_at = NOW()
			WHERE session_id = ANY($1) AND revoked_at IS NULL
		`, ids, RevokeReasonUserRevoked); err != nil {
			return 0, fmt.Errorf("revoke other session tokens: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit revoke other sessions: %w", err)
	}

	revoked := int64(len(ids))
	if revoked > 0 {
		metrics.SessionRevocations.WithLabelValues(RevokeReasonUserRevoked).Add(float64(revoked))
	}
	for _, id := range ids {
		s.denySession(ctx, id)
	}
	return revoked, nil
}

// ---------------------------------------------------------------------------
// Revoked-session denylist
// ---------------------------------------------------------------------------

// sessionDenyKeyPrefix namespaces the revoked-session denylist in Redis.
const sessionDenyKeyPrefix = "session:revoked:"

// userDenyKeyPrefix namespaces the account-wide variant.
const userDenyKeyPrefix = "session:revoked:user:"

// sessionDenyKey is the denylist key for one session.
func sessionDenyKey(sessionID int64) string {
	return sessionDenyKeyPrefix + strconv.FormatInt(sessionID, 10)
}

// userDenyKey is the denylist key for every session an account holds.
//
// Scoped by tenant as well as user because user ids are only unique within a
// tenant; keying on the user id alone would let a revocation in one tenant sign
// out an unrelated account in another.
func userDenyKey(userID, tenantID int64) string {
	return userDenyKeyPrefix + strconv.FormatInt(tenantID, 10) + ":" + strconv.FormatInt(userID, 10)
}

// denySession records a revoked session so its already-issued access tokens stop
// being accepted immediately, instead of remaining valid until they expire.
//
// Without this, revoking one session cannot touch its access token at all: the
// JWT is stateless and the only account-wide kill switch (users.token_version) is
// global, so using it to end ONE session would sign out every other session too
// — the opposite of what a single-session revoke means. The denylist closes that
// gap for the access token's remaining lifetime and no longer.
//
// The entry expires after AccessTokenTTL because that is exactly how long a
// revoked session's access token can still be presented. This bounds the key
// space to "sessions revoked in the last 15 minutes" with no cleanup job.
//
// Best-effort by design: a Redis failure is logged and swallowed. The durable
// guarantee is the revoked refresh-token row, which stops renewal regardless;
// the denylist only shortens the window from 15 minutes to zero. Failing the
// revoke because Redis blinked would leave the caller believing the session is
// still live when the database says otherwise — strictly worse.
//
// NOTE: this denylist is the ONLY mechanism that invalidates an already-issued
// access token. users.token_version is written by several revocation paths and
// reads like a second, Redis-independent kill switch, but nothing verifies that
// counter anywhere in the codebase — it has never had any effect on token
// validity. Do not rely on it; if Redis is down, revocation genuinely does take
// until the access token's natural expiry.
func (s *AuthService) denySession(ctx context.Context, sessionID int64) {
	if s.redisCli == nil {
		return
	}
	if err := s.redisCli.Set(ctx, sessionDenyKey(sessionID), "1", AccessTokenTTL).Err(); err != nil {
		metrics.SessionDenylistErrors.WithLabelValues("write").Inc()
		s.logger.Warn().Err(err).Int64("session_id", sessionID).
			Msg("session denylist: write failed; revocation still enforced at refresh")
	}
}

// pkgDenier is the process-wide Redis handle used by DenyAccountSessions.
//
// Package-level because the account-wide revocations are spread across five
// services in this package — AccountBlockService, ResetService, EmailChangeService,
// InvitationService, and the tenant-admin grant path — none of which share a
// funnel, and each of which writes its own UPDATE. Threading a Redis client into
// all five (and into every future one) is exactly how a path comes to skip the
// denylist and report a revocation that never took effect. That is not a
// hypothetical: every one of these five did precisely that until this existed,
// because they relied on users.token_version, which nothing verifies.
//
// nil disables the account-wide denylist, which degrades to the old behaviour
// (revocation effective at the access token's natural expiry) rather than failing.
var pkgDenier *redis.Client

// RegisterSessionDenier installs the Redis handle used for account-wide session
// revocation. Called once during wiring, before the server accepts traffic.
func RegisterSessionDenier(client *redis.Client) { pkgDenier = client }

// DenyAccountSessions is the package-level form of DenyUserSessions, for the
// revocation paths that do not hold an *AuthService.
//
// logger may be the zero value; failures are logged at warn and swallowed, on the
// same reasoning as denySession — a credential change must not fail because Redis
// blinked, and the refresh-token revocation beside it is the durable part.
func DenyAccountSessions(ctx context.Context, logger zerolog.Logger, userID, tenantID int64) {
	if pkgDenier == nil {
		return
	}
	if err := pkgDenier.Set(ctx, userDenyKey(userID, tenantID), "1", AccessTokenTTL).Err(); err != nil {
		metrics.SessionDenylistErrors.WithLabelValues("write_user").Inc()
		logger.Warn().Err(err).Int64("user_id", userID).Int64("tenant_id", tenantID).
			Msg("session denylist: account-wide write failed; revocation only enforced at refresh")
	}
}

// DenyUserSessions marks every session an account holds as revoked, so all of its
// outstanding access tokens are refused immediately.
//
// Needed because the per-session denylist cannot express an account-wide
// revocation efficiently: "revoke all" and a password reset do not know, and
// should not have to enumerate, which sessions exist — and the sessions being
// revoked may outnumber the sessions the caller can see. One key per account is
// bounded and costs the middleware a single extra lookup.
//
// This is what makes RevokeAllUserSessions, an operator block, a password reset,
// and an email change take effect NOW rather than within fifteen minutes. Before
// it existed those paths bumped users.token_version and returned success, and
// because nothing verifies that counter the user simply stayed signed in — the
// exact symptom this fixes.
//
// Same TTL and same fail-open posture as denySession: the entry only has to
// outlive the access tokens it invalidates.
func (s *AuthService) DenyUserSessions(ctx context.Context, userID, tenantID int64) {
	if s.redisCli == nil {
		return
	}
	if err := s.redisCli.Set(ctx, userDenyKey(userID, tenantID), revocationStamp(), AccessTokenTTL).Err(); err != nil {
		metrics.SessionDenylistErrors.WithLabelValues("write_user").Inc()
		s.logger.Warn().Err(err).
			Int64("user_id", userID).Int64("tenant_id", tenantID).
			Msg("session denylist: account-wide write failed; revocation only enforced at refresh")
	}
}

// revocationStamp is the value stored under an account-wide deny key: the instant
// the revocation happened, as unix seconds.
//
// The key cannot be a bare marker. An account-wide entry applies to the ACCOUNT,
// not to a particular session, so a plain "deny everything" value also denies the
// tokens the user gets when they sign back in — locking them out for the key's full
// fifteen-minute lifetime immediately after being signed out. That is worse than the
// bug this denylist was added to fix, and it is exactly what the first version did.
//
// Storing the timestamp turns the entry into "deny tokens issued before this", which
// is the actual intent: it invalidates everything in circulation at the moment of
// revocation and nothing minted afterwards.
func revocationStamp() string {
	return strconv.FormatInt(time.Now().UTC().Unix(), 10)
}

// SessionDenied reports whether a session family has been revoked recently
// enough that its access tokens must be refused.
//
// Fails OPEN on a Redis error — the opposite of RefreshWithLock's distributed
// lock, which fails closed. The difference is what each protects: the lock
// guards the single-use rotation invariant, where proceeding blind risks mass
// logout, whereas this only accelerates a revocation the refresh path already
// enforces. Failing closed here would turn a Redis blip into a total auth
// outage, rejecting every request from every healthy session, to avoid a
// 15-minute window on a handful of just-revoked ones. The error is counted so
// the trade is visible rather than silent.
// Both the session key and the account key are checked, in one round trip. The
// account key is what catches a "revoke all", a block, or a credential change,
// none of which know the caller's session id; the session key catches a
// single-session revoke. Missing either check would leave one of the two
// revocation shapes silently ineffective, which is how this function's first
// version shipped.
//
// userID/tenantID may be empty for tokens that have no account behind them
// (client-credentials, agent); the account lookup is then skipped.
// issuedAt is the token's "iat" in unix seconds; pass 0 when unknown, which skips
// the account-wide comparison rather than guessing.
func (s *AuthService) SessionDenied(ctx context.Context, sessionID, userID, tenantID string, issuedAt int64) bool {
	if s.redisCli == nil {
		return false
	}

	// The session key is a bare existence check and needs no timestamp: a family
	// that has been revoked can never rotate again, so no token minted after the
	// revocation can carry this sid. A fresh login gets a new family and a new sid.
	sessionKey := ""
	if sessionID != "" {
		if id, err := strconv.ParseInt(sessionID, 10, 64); err == nil {
			sessionKey = sessionDenyKey(id)
		}
	}

	accountKey := ""
	uid, uidErr := strconv.ParseInt(userID, 10, 64)
	tid, tidErr := strconv.ParseInt(tenantID, 10, 64)
	if uidErr == nil && tidErr == nil {
		accountKey = userDenyKey(uid, tid)
	}

	switch {
	case sessionKey != "" && accountKey != "":
		// One round trip for both. MGet returns nil for a missing key, so a present
		// session key is decisive and the account value is only interpreted if set.
		vals, err := s.redisCli.MGet(ctx, sessionKey, accountKey).Result()
		if err != nil {
			return s.denylistReadFailed(err)
		}
		if vals[0] != nil {
			return true
		}
		return revokedBefore(vals[1], issuedAt)
	case sessionKey != "":
		n, err := s.redisCli.Exists(ctx, sessionKey).Result()
		if err != nil {
			return s.denylistReadFailed(err)
		}
		return n > 0
	case accountKey != "":
		val, err := s.redisCli.Get(ctx, accountKey).Result()
		if err != nil {
			if errors.Is(err, redis.Nil) {
				return false
			}
			return s.denylistReadFailed(err)
		}
		return revokedBefore(val, issuedAt)
	default:
		return false
	}
}

// denylistReadFailed centralises the fail-open decision so both branches above
// cannot drift apart on it.
func (s *AuthService) denylistReadFailed(err error) bool {
	metrics.SessionDenylistErrors.WithLabelValues("read").Inc()
	s.logger.Warn().Err(err).Msg("session denylist: read failed; allowing request")
	return false
}

// revocationSkewAllowance widens the account-wide comparison to absorb clock drift
// between replicas.
//
// The revocation timestamp comes from whichever instance handled the revoke; "iat"
// came from whichever instance signed the token. Without an allowance, a revoking
// server whose clock is a few seconds BEHIND would record a timestamp earlier than
// tokens that already existed, and those tokens would escape denial entirely — a
// silent failure of the security control, visible only under multi-replica drift.
//
// Two seconds errs toward denying. The cost of being slightly too aggressive is
// bounded and self-correcting: a user signing in within two seconds of a revocation
// may need one retry. The cost of being too lenient is a session that should be
// dead staying alive for fifteen minutes.
const revocationSkewAllowance = 2

// revokedBefore reports whether a token issued at issuedAt predates the
// account-wide revocation recorded in raw.
//
// The comparison is issuedAt < revokedAt + skew rather than a bare <, so tokens
// issued around the revocation instant are denied rather than allowed. That is the
// opposite of the same-second choice the first version made, and the reversal is
// deliberate: it turned out to be a security-versus-convenience trade, and on
// reflection the convenience it bought (a signed-out user re-signing in within the
// same second) is worth far less than the guarantee it gave up.
func revokedBefore(raw any, issuedAt int64) bool {
	if raw == nil || issuedAt == 0 {
		return false
	}
	str, ok := raw.(string)
	if !ok {
		return false
	}
	revokedAt, err := strconv.ParseInt(str, 10, 64)
	if err != nil {
		// A value written by an older build, or corrupt. Treat the entry as a plain
		// marker and deny: an unparseable revocation record is still a record that a
		// revocation happened.
		return true
	}
	return issuedAt < revokedAt+revocationSkewAllowance
}

// ---------------------------------------------------------------------------
// Logout
// ---------------------------------------------------------------------------

// LogoutSession ends the session the presented refresh token belongs to and
// returns how many tokens were revoked.
//
// Revokes the whole FAMILY, not just the presented token. The previous
// single-token behaviour was the main reason session lists grew without bound: a
// rotation chain's older tokens are already revoked, so revoking only the newest
// one does end the session in practice — but it is fragile in a way that matters.
// A client that logs out with a token it has already rotated away (a stale tab, a
// retried request, a mobile app resuming from a background refresh) revokes an
// already-revoked row, reports success, and leaves the live successor token
// working. The user is told they signed out and did not. Revoking by family makes
// logout idempotent and total, whichever token in the chain the client happens to
// still be holding.
func (s *AuthService) LogoutSession(ctx context.Context, rawRefreshToken string) (int64, error) {
	return s.revokeSessionByRefreshToken(ctx, rawRefreshToken, RevokeReasonLogout)
}

// RevokeIssuedSession ends a session that was just minted and then refused
// before its tokens reached the caller.
//
// Exists for the cookie-session endpoints (issue #116). Those mint through
// Login/LoginWebAuthn/Refresh and only afterwards discover the identity may not
// have cookies; the tokens are then dropped on the floor, leaving a live session
// no client holds. Nothing enforces its absence — the session is perfectly
// valid, just unreachable — so it lingers until idle expiry, and while it
// lingers it counts against the concurrent-session cap.
//
// A distinct reason rather than reusing logout, because the whole cost of this
// bug was misattribution: an operator reading revoked_reason needs to see that a
// rejected cookie-session did this, not a user signing out.
func (s *AuthService) RevokeIssuedSession(ctx context.Context, rawRefreshToken string) (int64, error) {
	return s.revokeSessionByRefreshToken(ctx, rawRefreshToken, RevokeReasonSessionRejected)
}

// revokeSessionByRefreshToken resolves the session a refresh token belongs to
// and revokes the whole family with the given reason.
//
// Shared by LogoutSession and RevokeIssuedSession so both get the same
// resolve-without-requiring-liveness behaviour; only the recorded reason
// differs.
func (s *AuthService) revokeSessionByRefreshToken(ctx context.Context, rawRefreshToken, reason string) (int64, error) {
	if rawRefreshToken == "" {
		return 0, nil
	}
	hash := HashToken(rawRefreshToken)

	// Resolve the session from the presented token WITHOUT requiring the token to
	// be live: logout must work for an already-rotated or already-expired token,
	// which is precisely the stale-client case above.
	//
	// COALESCE(session_id, session_family_id): a token inserted by the previous
	// binary during a rolling deploy has no session_id, and the ids coincide by
	// construction (migration 00069 reuses the family id as the session id), so the
	// fallback resolves to the same session rather than failing the logout.
	var userID, tenantID, sessionID int64
	err := s.pool.QueryRow(ctx, `
		SELECT user_id, tenant_id, COALESCE(session_id, session_family_id)
		FROM refresh_tokens WHERE token_hash = $1
	`, hash).Scan(&userID, &tenantID, &sessionID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// A token that never existed. Report success: for both callers
			// "your credential is not recognised" and "the session is gone" are
			// the same outcome — and for logout specifically, distinguishing
			// them would turn it into an oracle for whether a given token value
			// was ever issued.
			return 0, nil
		}
		return 0, fmt.Errorf("resolve session to revoke: %w", err)
	}

	return s.revokeSession(ctx, userID, tenantID, sessionID, reason)
}

// Logout revokes the session behind a refresh token.
//
// Retained as the pre-existing name/signature for callers that do not need the
// count; delegates to LogoutSession so both paths revoke the whole family.
func (s *AuthService) Logout(ctx context.Context, rawRefreshToken string) error {
	_, err := s.LogoutSession(ctx, rawRefreshToken)
	return err
}

// RevokeAllSessionsTx ends every session an account holds, inside the caller's
// transaction.
//
// The single entry point for the account-wide revocations scattered across this
// package and internal/admin — operator block, password reset, email change,
// invitation acceptance, administrative grant activation. Each of those previously
// wrote its own `UPDATE refresh_tokens SET revoked_at = NOW()`, which had two
// consequences worth removing:
//
//   - Each had to remember to also revoke the session rows once sessions became
//     first-class, and one that forgot would leave the account's session list
//     showing live sessions whose tokens were all dead. Enforcement would still be
//     correct — the refresh path requires both halves live — but an operator reading
//     "3 active sessions" after a password reset has been told something false.
//   - The reason was implicit, so nothing recorded WHY the sessions ended.
//
// Takes a tx rather than the pool because every caller is already mid-transaction
// with the credential change itself: the revocation must commit or roll back with
// it, never separately.
//
// Does NOT touch the Redis denylist — that cannot participate in a transaction.
// Callers must invoke DenyAccountSessions after their commit; see the comment on
// that function.
func RevokeAllSessionsTx(ctx context.Context, tx pgx.Tx, userID, tenantID int64, reason string) error {
	ct, err := tx.Exec(ctx, `
		UPDATE user_sessions
		SET revoked_at = NOW(), revoked_reason = $3, updated_at = NOW()
		WHERE user_id = $1 AND tenant_id = $2 AND revoked_at IS NULL
	`, userID, tenantID, reason)
	if err != nil {
		return fmt.Errorf("revoke account sessions: %w", err)
	}

	if _, err := tx.Exec(ctx, `
		UPDATE refresh_tokens
		SET revoked_at = NOW(), revoked_reason = $3, updated_at = NOW()
		WHERE user_id = $1 AND tenant_id = $2 AND revoked_at IS NULL
	`, userID, tenantID, reason); err != nil {
		return fmt.Errorf("revoke account tokens: %w", err)
	}

	if n := ct.RowsAffected(); n > 0 {
		metrics.SessionRevocations.WithLabelValues(reason).Add(float64(n))
	}
	return nil
}

// ---------------------------------------------------------------------------
// Device attribution
// ---------------------------------------------------------------------------

// DeviceHint renders a raw User-Agent as a short "Chrome on Windows" label,
// stored alongside the raw header on the session row.
//
// Server-side rather than left to each client: the session API has more than one
// consumer, and a caller that is not our own console should not have to ship a
// User-Agent parser to show a user which device they are looking at. The raw header
// is kept too — it is the evidence, and a parser that guesses wrong must not destroy
// the original.
//
// Deliberately approximate, and never used for a decision. The value exists so a
// person can recognise their own device in a list, and it comes from a header the
// client controls, so precision here would be false confidence.
func DeviceHint(ua string) string {
	if ua == "" {
		return ""
	}

	var browser string
	switch {
	// Edge and Opera before Chrome: both include "Chrome/" in their own strings, so
	// testing Chrome first would label every Edge session as Chrome.
	case strings.Contains(ua, "Edg/"):
		browser = "Edge"
	case strings.Contains(ua, "OPR/"):
		browser = "Opera"
	case strings.Contains(ua, "Chrome/"):
		browser = "Chrome"
	case strings.Contains(ua, "Firefox/"):
		browser = "Firefox"
	// Safari last of the browsers: Chrome and Edge both carry "Safari/" for
	// compatibility, so an earlier test would claim every Chrome session is Safari.
	case strings.Contains(ua, "Safari/"):
		browser = "Safari"
	// Non-browser clients, recognised before the fallback so a session list is not a
	// column of raw agent strings.
	//
	// These matter more than they look: an application's user base is reached through
	// its own backend or SDK far more often than through a browser, and those clients
	// send terse defaults — Node's fetch sends exactly "node", nothing more. Left to
	// the fallback that renders as a bare "node", which is what prompted this.
	//
	// Matched on the whole string, not a prefix: an SDK may append a version.
	case strings.Contains(ua, "curl/"):
		browser = "curl"
	case ua == "node" || strings.HasPrefix(ua, "node/") || strings.Contains(ua, "undici"):
		return "Node.js client"
	case strings.Contains(ua, "axios/"):
		return "Node.js client (axios)"
	case strings.Contains(ua, "python-requests/"), strings.Contains(ua, "httpx/"),
		strings.Contains(ua, "aiohttp/"):
		return "Python client"
	case strings.Contains(ua, "Go-http-client/"):
		return "Go client"
	case strings.Contains(ua, "okhttp/"):
		browser = "okhttp"
	case strings.Contains(ua, "PostmanRuntime/"):
		return "Postman"
	case strings.Contains(ua, "Insomnia/"):
		return "Insomnia"
	case strings.Contains(ua, "java/"), strings.Contains(ua, "Java/"):
		return "Java client"
	default:
		// Something unrecognised — an SDK, a script, a new browser. A truncated
		// slice of the real string is more use for telling two sessions apart than
		// the word "Unknown".
		if len(ua) > 32 {
			return ua[:32]
		}
		return ua
	}

	var os string
	switch {
	// iOS before macOS, and the order is load-bearing: every iPhone and iPad
	// User-Agent contains the literal "like Mac OS X", so a macOS test placed first
	// labels every phone session as a Mac.
	case strings.Contains(ua, "iPhone"), strings.Contains(ua, "iPad"), strings.Contains(ua, "iPod"):
		os = "iOS"
	case strings.Contains(ua, "Android"):
		os = "Android"
	case strings.Contains(ua, "Windows"):
		os = "Windows"
	case strings.Contains(ua, "Mac OS X"), strings.Contains(ua, "Macintosh"):
		os = "macOS"
	case strings.Contains(ua, "Linux"):
		os = "Linux"
	}

	if os == "" {
		return browser
	}
	return browser + " on " + os
}

// ---------------------------------------------------------------------------
// Concurrent-session cap
// ---------------------------------------------------------------------------

// enforceSessionCap evicts the least recently active sessions until inserting one
// more would leave the user at or below the policy ceiling.
//
// Runs inside the caller's transaction, which is what makes it correct: the
// obvious implementation — count, decide, then insert — is a read-then-write race
// that lets N concurrent logins each observe count < max and each insert,
// overshooting the cap by up to N. The caller additionally takes a per-user
// advisory lock (see issueTokenPair), so concurrent logins for the same user
// serialise here rather than interleaving.
//
// Eviction is by least-recently-active, so the session a user is actually working
// in is the last thing to be taken from them.
//
// Returns the evicted session ids so the caller can deny their access tokens after
// committing. Without that step an evicted device kept working for up to fifteen
// minutes while the metric and revoked_reason both reported it gone — the same
// inconsistency that made "revoke all" ineffective.
func enforceSessionCap(ctx context.Context, tx pgx.Tx, userID, tenantID int64, maxSessions int) ([]int64, error) {
	if maxSessions <= 0 {
		return nil, nil
	}

	// Sessions ranked most-recently-active first; those at position >= maxSessions
	// are evicted, leaving room for the one about to be inserted. One row per
	// session now, so no GROUP BY over a rotation log.
	rows, err := tx.Query(ctx, `
		WITH ranked AS (
			SELECT id, ROW_NUMBER() OVER (ORDER BY last_seen_at DESC) AS rn
			FROM user_sessions
			WHERE user_id = $1 AND tenant_id = $2 AND `+LiveSessionWhere("")+`
		)
		UPDATE user_sessions s
		SET revoked_at = NOW(), revoked_reason = $4, updated_at = NOW()
		FROM ranked
		WHERE s.id = ranked.id AND ranked.rn >= $3
		RETURNING s.id
	`, userID, tenantID, maxSessions, RevokeReasonCapEvicted)
	if err != nil {
		return nil, fmt.Errorf("enforce session cap: %w", err)
	}

	var evicted []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan evicted session: %w", err)
		}
		evicted = append(evicted, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("enforce session cap: %w", err)
	}

	if len(evicted) > 0 {
		if _, err := tx.Exec(ctx, `
			UPDATE refresh_tokens
			SET revoked_at = NOW(), revoked_reason = $2, updated_at = NOW()
			WHERE session_id = ANY($1) AND revoked_at IS NULL
		`, evicted, RevokeReasonCapEvicted); err != nil {
			return nil, fmt.Errorf("revoke evicted session tokens: %w", err)
		}
		metrics.SessionRevocations.WithLabelValues(RevokeReasonCapEvicted).Add(float64(len(evicted)))
	}
	return evicted, nil
}

// sessionCapLockKey derives the advisory-lock key that serialises concurrent
// logins for one user.
//
// pg_advisory_xact_lock takes two int32s; user and tenant ids are int64. The high
// bits are folded in rather than truncated so two users whose ids differ only
// above bit 32 do not collide — a collision is not a correctness bug (it only
// serialises two unrelated logins) but it is silent and would be miserable to
// diagnose, and avoiding it costs one XOR.
func sessionCapLockKey(userID, tenantID int64) (int32, int32) {
	fold := func(v int64) int32 {
		// #nosec G115 -- narrowing to 32 bits is the point, not an accident: the
		// lock key must be an int32 and any bit pattern is a valid one. The XOR
		// mixes the discarded high bits back in rather than dropping them.
		return int32(uint32(v) ^ uint32(v>>32))
	}
	return fold(userID), fold(tenantID)
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

// parseAppID converts the string app_id claim form back to the nullable row id
// used for policy resolution. Returns nil for tenant-level users (empty claim)
// and for anything unparseable — a malformed value must not silently resolve to
// application 0, which would be a real application's policy.
func parseAppID(appID string) *int64 {
	if appID == "" {
		return nil
	}
	id, err := strconv.ParseInt(appID, 10, 64)
	if err != nil {
		return nil
	}
	return &id
}

// parseAppIDValue is parseAppID for callers that want a plain int64, with 0
// meaning "no application".
//
// Zero is a safe sentinel here and not a real row: oauth_clients.id is
// GENERATED ALWAYS AS IDENTITY, which starts at 1. AudienceService treats 0 as
// "no client identity on this request", which is the first case of the
// resolution table and the one that must not be confused with a lookup miss.
func parseAppIDValue(appID string) int64 {
	if id := parseAppID(appID); id != nil {
		return *id
	}
	return 0
}
