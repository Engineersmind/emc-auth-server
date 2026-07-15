package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/engineersmind/emc-auth-server/internal/mailer"
)

// ---------------------------------------------------------------------------
// Passwordless magic-link sign-in (issue #63 follow-on)
//
// Per-application opt-in. The link replaces only the PASSWORD step: after
// verification the same mfaGate as password login applies, so an application
// that requires MFA still challenges (or force-enrolls) the user. A link
// click proves inbox control — the same factor as an email OTP — which is why
// it can never substitute for a TOTP requirement.
//
// Tokens are 256-bit random, stored only as SHA-256 hashes in Redis, TTL
// 15 minutes, strictly single-use (atomic GETDEL), and bound to the issuing
// application: a token minted for app A is worthless presented via app B.
// ---------------------------------------------------------------------------

// MagicLinkTTL is how long a sign-in link stays valid.
const MagicLinkTTL = 15 * time.Minute

// ErrMagicLinkDisabled is returned when the application has not enabled
// passwordless magic-link sign-in.
var ErrMagicLinkDisabled = errors.New("magic-link sign-in is not enabled for this application")

// ErrMagicLinkNotConfigured is returned when magic link is enabled without a
// redirect URL (or an admin tries to enable it without one).
var ErrMagicLinkNotConfigured = errors.New("magic-link sign-in requires a redirect URL")

// ErrInvalidMagicLink is returned when a presented token is unknown, expired,
// already used, or bound to a different application.
var ErrInvalidMagicLink = errors.New("invalid or expired sign-in link")

// magicLinkSession is the Redis payload behind one outstanding link.
type magicLinkSession struct {
	UserID   int64
	TenantID int64
	AppRowID int64
}

func magicLinkKey(token string) string {
	return "magic:link:" + HashToken(token)
}

// magicLinkConfig loads the application's magic-link settings (no row =
// disabled — pure opt-in).
func (s *AuthService) magicLinkConfig(ctx context.Context, appRowID int64) (enabled bool, redirectURL string, err error) {
	err = s.pool.QueryRow(ctx, `
		SELECT magic_link_enabled, magic_link_redirect_url
		FROM application_mfa_settings WHERE application_id = $1
	`, appRowID).Scan(&enabled, &redirectURL)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, "", nil
		}
		return false, "", fmt.Errorf("load magic link config: %w", err)
	}
	return enabled, redirectURL, nil
}

// RequestMagicLink authenticates the application, and — when the submitted
// email matches one of ITS OWN users — emails a single-use sign-in link.
// An unknown email is NOT an error: the caller receives the same success
// either way, so this endpoint cannot be used to enumerate accounts.
func (s *AuthService) RequestMagicLink(ctx context.Context, clientID, clientSecret, email string) error {
	if s.emailSvc == nil || s.redisCli == nil {
		return fmt.Errorf("magic link not configured on this server")
	}

	tenantID, appRowID, err := s.authenticateApp(ctx, clientID, clientSecret)
	if err != nil {
		return err
	}

	enabled, redirectURL, err := s.magicLinkConfig(ctx, appRowID)
	if err != nil {
		return err
	}
	if !enabled {
		return ErrMagicLinkDisabled
	}
	if redirectURL == "" {
		return ErrMagicLinkNotConfigured
	}

	// Anti-enumeration: from here on every outcome is reported as success.
	var userID int64
	err = s.pool.QueryRow(ctx, `
		SELECT u.id FROM users u
		JOIN tenants t ON t.id = u.tenant_id
		WHERE u.email = $1 AND u.tenant_id = $2 AND u.application_id = $3
		  AND u.is_active = true AND u.deleted_at IS NULL AND t.is_active = true
	`, email, tenantID, appRowID).Scan(&userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			s.logger.Debug().Str("email", email).Int64("app", appRowID).Msg("magic link requested for unknown account — pretending success")
			return nil
		}
		return fmt.Errorf("lookup magic link user: %w", err)
	}

	raw, err := GenerateRefreshToken()
	if err != nil {
		return err
	}
	payload, err := json.Marshal(magicLinkSession{UserID: userID, TenantID: tenantID, AppRowID: appRowID})
	if err != nil {
		return err
	}
	if err := s.redisCli.Set(ctx, magicLinkKey(raw), payload, MagicLinkTTL).Err(); err != nil {
		return fmt.Errorf("store magic link: %w", err)
	}

	link, err := buildMagicLink(redirectURL, raw)
	if err != nil {
		return err
	}

	msg := mailer.MagicLinkEmail{
		To:         email,
		Link:       link,
		AppName:    s.appNameByID(ctx, strconv.FormatInt(appRowID, 10)),
		TTLMinutes: int(MagicLinkTTL.Minutes()),
	}
	sender := s.resolveEmailSender(ctx, tenantID, &appRowID)
	if err := s.emailSvc.mailer.SendMagicLink(ctx, sender, msg); err != nil {
		if sender != nil {
			s.logger.Warn().Err(err).Str("from", sender.From).Msg("white-label sender failed for magic link — retrying via global sender")
			err = s.emailSvc.mailer.SendMagicLink(ctx, nil, msg)
		}
		if err != nil {
			s.redisCli.Del(ctx, magicLinkKey(raw)) //nolint:errcheck
			return fmt.Errorf("send magic link: %w", err)
		}
	}
	return nil
}

// VerifyMagicLink authenticates the application, consumes the token
// (single-use), and completes the login through the exact same MFA gate as a
// password login — the result may therefore be tokens, an OTP challenge, or
// a forced-enrollment challenge.
func (s *AuthService) VerifyMagicLink(ctx context.Context, clientID, clientSecret, token string) (*LoginResult, error) {
	if s.redisCli == nil {
		return nil, fmt.Errorf("magic link not configured on this server")
	}

	tenantID, appRowID, err := s.authenticateApp(ctx, clientID, clientSecret)
	if err != nil {
		return nil, err
	}

	// Atomic consume — a link can never be redeemed twice, even concurrently.
	data, err := s.redisCli.GetDel(ctx, magicLinkKey(token)).Bytes()
	if err != nil {
		return nil, ErrInvalidMagicLink
	}
	var sess magicLinkSession
	if err := json.Unmarshal(data, &sess); err != nil {
		return nil, ErrInvalidMagicLink
	}

	// Application binding: the verifying app must be the one the link was
	// minted for (defends against a confused-deputy sibling application).
	if sess.AppRowID != appRowID || sess.TenantID != tenantID {
		return nil, ErrInvalidMagicLink
	}

	// Load fresh identity state — the account may have been deactivated or
	// re-roled between request and click.
	var email, roleName string
	err = s.pool.QueryRow(ctx, `
		SELECT u.email, COALESCE(r.name, '')
		FROM users u
		LEFT JOIN roles r ON r.id = u.role_id
		JOIN tenants t ON t.id = u.tenant_id
		WHERE u.id = $1 AND u.tenant_id = $2 AND u.application_id = $3
		  AND u.is_active = true AND u.deleted_at IS NULL AND t.is_active = true
	`, sess.UserID, tenantID, appRowID).Scan(&email, &roleName)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrInvalidMagicLink
		}
		return nil, fmt.Errorf("load magic link user: %w", err)
	}

	perms, err := s.loadPermissions(ctx, sess.UserID, tenantID)
	if err != nil {
		s.logger.Warn().Err(err).Msg("magic link: failed to load permissions, continuing with empty set")
		perms = []string{}
	}

	appID := strconv.FormatInt(appRowID, 10)
	if gate, err := s.mfaGate(ctx, sess.UserID, tenantID, appRowID, appID, email, roleName, perms); err != nil {
		return nil, err
	} else if gate != nil {
		return gate, nil
	}

	tokens, err := s.issueTokenPair(ctx, sess.UserID, tenantID, email, roleName, perms, nil, appID)
	if err != nil {
		return nil, err
	}
	return &LoginResult{Token: tokens}, nil
}

// resolveEmailSender resolves the white-label sender chain, degrading to the
// global sender on any resolution error.
func (s *AuthService) resolveEmailSender(ctx context.Context, tenantID int64, appRowID *int64) *mailer.SMTPConfig {
	if s.emailSvc == nil || s.emailSvc.senderSvc == nil {
		return nil
	}
	sender, err := s.emailSvc.senderSvc.Resolve(ctx, tenantID, appRowID)
	if err != nil {
		s.logger.Warn().Err(err).Msg("magic link: sender resolution failed — using global sender")
		return nil
	}
	return sender
}

// validMagicRedirectURL reports whether s is an absolute http(s) URL.
func validMagicRedirectURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

// buildMagicLink appends the token as a query parameter to the application's
// redirect URL, validating the URL shape.
func buildMagicLink(redirectURL, token string) (string, error) {
	if !validMagicRedirectURL(redirectURL) {
		return "", ErrMagicLinkNotConfigured
	}
	u, _ := url.Parse(redirectURL)
	q := u.Query()
	q.Set("token", token)
	u.RawQuery = q.Encode()
	return u.String(), nil
}
