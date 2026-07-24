package auth

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"

	"github.com/engineersmind/emc-auth-server/internal/mailer"
)

// ---------------------------------------------------------------------------
// Email OTP as a second MFA method (issue #63)
//
// The factor is "control of the account's email inbox". No long-lived secret
// exists: every challenge mints a fresh numeric code, emails it, and stores
// only its SHA-256 hash in Redis with a short TTL and the shared per-session
// attempt budget. Enrollment is itself code-verified so an unverified inbox
// can never become a second factor.
// ---------------------------------------------------------------------------

const (
	// EmailOTPLength is the number of digits in an emailed one-time code.
	EmailOTPLength = 6
	// EmailOTPTTL is how long an emailed verification code stays valid.
	EmailOTPTTL = 10 * time.Minute
	// EmailOTPMaxResends bounds how many times one login challenge may re-send
	// its email code (mail-bombing / cost control).
	EmailOTPMaxResends = 3
)

// ErrEmailMFANotActive is returned when an email-code action requires an
// active email MFA enrollment that does not exist.
var ErrEmailMFANotActive = errors.New("email MFA is not active for this account")

// ErrEmailCodeInvalid is returned when a submitted email code does not match
// the pending code (or none is pending).
var ErrEmailCodeInvalid = errors.New("invalid or expired email code")

// ErrTooManyResends is returned when a login challenge exceeds its email
// re-send budget.
var ErrTooManyResends = errors.New("too many code emails requested — restart login")

// EmailMFAService manages email-OTP enrollment and code verification.
type EmailMFAService struct {
	pool      *pgxpool.Pool
	redis     *redis.Client
	mailer    mailer.Mailer
	senderSvc *EmailSenderService   // nil = always use the global sender
	tmplSvc   *EmailTemplateService // nil = always use the built-in template
	logger    zerolog.Logger
}

// NewEmailMFAService creates an EmailMFAService.
func NewEmailMFAService(pool *pgxpool.Pool, redisCli *redis.Client, m mailer.Mailer, logger zerolog.Logger) *EmailMFAService {
	return &EmailMFAService{pool: pool, redis: redisCli, mailer: m, logger: logger}
}

// WithSenders attaches the white-label sender resolver so codes go out via
// the application's or tenant's own sender when one is configured.
func (s *EmailMFAService) WithSenders(senderSvc *EmailSenderService) *EmailMFAService {
	s.senderSvc = senderSvc
	return s
}

// WithTemplates attaches the per-scope template resolver so MFA-code emails use
// the application's/tenant's customized template when one is configured.
func (s *EmailMFAService) WithTemplates(tmplSvc *EmailTemplateService) *EmailMFAService {
	s.tmplSvc = tmplSvc
	return s
}

// generateEmailOTP returns a crypto-random numeric code of EmailOTPLength digits.
func generateEmailOTP() (string, error) {
	max := big.NewInt(1)
	for i := 0; i < EmailOTPLength; i++ {
		max.Mul(max, big.NewInt(10))
	}
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", fmt.Errorf("generate email OTP: %w", err)
	}
	return fmt.Sprintf("%0*d", EmailOTPLength, n), nil
}

// emailVerifyKey is the Redis key holding the hash of a user's pending
// self-service verification code (enrollment / disable proof).
func emailVerifyKey(userID int64) string {
	return fmt.Sprintf("mfa:email:verify:%d", userID)
}

// IsActive returns true if the user has active email MFA.
func (s *EmailMFAService) IsActive(ctx context.Context, userID int64) (bool, error) {
	return emailMFAActive(ctx, s.pool, userID)
}

// mintAndSend generates a code, stores its hash under key with ttl, resets the
// key's attempt counter, and emails the plaintext to the user. The plaintext
// never touches the database or logs (except the DevMailer in development).
//
// The sender resolves on a priority basis — application sender → tenant
// sender → global — and a white-label relay failure falls back to the global
// sender: a tenant's broken SMTP must never lock their users out of login.
func (s *EmailMFAService) mintAndSend(ctx context.Context, key, email, appName string, tenantID int64, appRowID *int64, ttl time.Duration) error {
	code, err := generateEmailOTP()
	if err != nil {
		return err
	}
	if err := s.redis.Set(ctx, key, HashToken(code), ttl).Err(); err != nil {
		return fmt.Errorf("store email OTP: %w", err)
	}
	s.redis.Del(ctx, key+":attempts") //nolint:errcheck

	// Suppression: if the MFA-code template is disabled at this scope, don't send
	// (and drop the pending code so no unusable code is left behind).
	if !s.tmplSvc.IsTypeEnabled(ctx, tenantID, appRowID, mailer.TemplateMFACode) {
		s.logger.Info().Int64("tenant_id", tenantID).Msg("MFA-code template disabled at this scope — not sending")
		s.redis.Del(ctx, key) //nolint:errcheck
		return nil
	}

	msg := mailer.MFACodeEmail{
		To:         email,
		Code:       code,
		AppName:    appName,
		TTLMinutes: int(ttl.Minutes()),
	}

	var sender *mailer.SMTPConfig
	if s.senderSvc != nil {
		sender, err = s.senderSvc.Resolve(ctx, tenantID, appRowID)
		if err != nil {
			s.logger.Warn().Err(err).Int64("tenant_id", tenantID).Msg("email sender resolution failed — using global sender")
			sender = nil
		}
	}

	tmpl := s.tmplSvc.ResolveTemplate(ctx, tenantID, appRowID, mailer.TemplateMFACode)

	err = s.mailer.SendMFACode(ctx, sender, tmpl, msg)
	if err != nil && sender != nil {
		s.logger.Warn().Err(err).Str("from", sender.From).Msg("white-label sender failed — retrying via global sender")
		err = s.mailer.SendMFACode(ctx, nil, tmpl, msg)
	}
	if err != nil {
		// The code is unusable if the user never received it — remove it so a
		// failed send cannot leave a stale pending code around.
		s.redis.Del(ctx, key) //nolint:errcheck
		return fmt.Errorf("send email OTP: %w", err)
	}
	return nil
}

// verifyStoredCode checks a submitted code against the hash stored under key,
// enforcing the shared MaxOTPAttempts budget. On success the key and its
// attempt counter are consumed.
func (s *EmailMFAService) verifyStoredCode(ctx context.Context, key, code string) error {
	storedHash, err := s.redis.Get(ctx, key).Result()
	if err != nil {
		return ErrEmailCodeInvalid
	}

	attemptsKey := key + ":attempts"
	attempts, err := s.redis.Incr(ctx, attemptsKey).Result()
	if err != nil {
		return ErrServiceUnavailable
	}
	if attempts == 1 {
		s.redis.Expire(ctx, attemptsKey, EmailOTPTTL+time.Minute) //nolint:errcheck
	}
	if attempts > MaxOTPAttempts {
		s.redis.Del(ctx, key, attemptsKey) //nolint:errcheck
		return ErrTooManyOTPAttempts
	}

	if HashToken(code) != storedHash {
		return ErrEmailCodeInvalid
	}
	s.redis.Del(ctx, key, attemptsKey) //nolint:errcheck
	return nil
}

// BeginEnrollment starts email-MFA enrollment for a JWT-authenticated user:
// policy-checks the application (mode + allowed methods), records the pending
// enrollment, and emails a verification code. Completing enrollment requires
// ActivateEnrollment with that code — an inbox the user cannot read can never
// become their second factor.
func (s *EmailMFAService) BeginEnrollment(ctx context.Context, userID, tenantID int64, email string) error {
	uc, err := loadUserMFAContext(ctx, s.pool, userID, tenantID)
	if err != nil {
		return err
	}
	if uc.appRowID != nil && uc.mode == MFAModeDisabled {
		return ErrMFAEnrollmentDisabled
	}
	if !uc.methodPermitted(MFAMethodEmail) {
		return ErrMFAMethodNotAllowed
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO email_mfa_settings (user_id, tenant_id, is_active, updated_at)
		VALUES ($1, $2, false, NOW())
		ON CONFLICT (user_id) DO NOTHING
	`, userID, tenantID)
	if err != nil {
		return fmt.Errorf("record email MFA enrollment: %w", err)
	}

	return s.mintAndSend(ctx, emailVerifyKey(userID), email, uc.appName, tenantID, uc.appRowID, EmailOTPTTL)
}

// ActivateEnrollment verifies the emailed code and marks email MFA active.
func (s *EmailMFAService) ActivateEnrollment(ctx context.Context, userID int64, code string) error {
	if err := s.verifyStoredCode(ctx, emailVerifyKey(userID), code); err != nil {
		return err
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE email_mfa_settings SET is_active = true, updated_at = NOW()
		WHERE user_id = $1
	`, userID)
	if err != nil {
		return fmt.Errorf("activate email MFA: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrEmailCodeInvalid
	}
	return nil
}

// SendVerificationCode emails a fresh code to an already-enrolled user — used
// as proof for self-service actions such as disabling email MFA.
func (s *EmailMFAService) SendVerificationCode(ctx context.Context, userID, tenantID int64, email string) error {
	active, err := s.IsActive(ctx, userID)
	if err != nil {
		return err
	}
	if !active {
		return ErrEmailMFANotActive
	}
	uc, err := loadUserMFAContext(ctx, s.pool, userID, tenantID)
	if err != nil {
		return err
	}
	return s.mintAndSend(ctx, emailVerifyKey(userID), email, uc.appName, tenantID, uc.appRowID, EmailOTPTTL)
}

// Disable removes email MFA after verifying an emailed code (requested via
// SendVerificationCode). Users of a 'required' application may only remove
// email MFA while another active second factor (TOTP) remains.
func (s *EmailMFAService) Disable(ctx context.Context, userID, tenantID int64, code string) error {
	uc, err := loadUserMFAContext(ctx, s.pool, userID, tenantID)
	if err != nil {
		return err
	}
	if uc.appRowID != nil && uc.mode == MFAModeRequired {
		var totpActive bool
		err := s.pool.QueryRow(ctx,
			`SELECT COALESCE((SELECT is_active FROM totp_secrets WHERE user_id = $1), false)`,
			userID,
		).Scan(&totpActive)
		if err != nil {
			return fmt.Errorf("check TOTP active: %w", err)
		}
		if !totpActive {
			return ErrMFARequiredByPolicy
		}
	}

	if err := s.verifyStoredCode(ctx, emailVerifyKey(userID), code); err != nil {
		return err
	}
	if _, err := s.pool.Exec(ctx, `DELETE FROM email_mfa_settings WHERE user_id = $1`, userID); err != nil {
		return fmt.Errorf("disable email MFA: %w", err)
	}
	return nil
}

// ActivatePendingEnrollment marks email MFA active for a forced-enrollment
// login (the code was verified against the pre-auth session's email key, not
// the self-service key). Upserts so the row exists even when the user never
// touched the self-service path.
func (s *EmailMFAService) ActivatePendingEnrollment(ctx context.Context, userID, tenantID int64) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO email_mfa_settings (user_id, tenant_id, is_active, updated_at)
		VALUES ($1, $2, true, NOW())
		ON CONFLICT (user_id) DO UPDATE SET is_active = true, updated_at = NOW()
	`, userID, tenantID)
	if err != nil {
		return fmt.Errorf("activate pending email MFA: %w", err)
	}
	return nil
}
