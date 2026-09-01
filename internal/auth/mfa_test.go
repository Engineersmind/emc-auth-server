package auth_test

import (
	"context"
	"errors"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp/totp"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/mailer"
	"github.com/engineersmind/emc-auth-server/internal/store"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// captureMailer records MFA code emails instead of sending them, so tests can
// read the plaintext codes and assert which sender was resolved.
type captureMailer struct {
	mu            sync.Mutex
	sent          []mailer.MFACodeEmail
	links         []mailer.MagicLinkEmail
	resets        []mailer.ResetEmail
	verifications []mailer.VerificationEmail
	welcomes      []mailer.WelcomeEmail
	changed       []mailer.PasswordChangedEmail
	invitations   []mailer.InvitationEmail
	emailChanges  []mailer.ChangeEmailEmail
	blocks        []mailer.BlockedAccountEmail
	breaches      []mailer.PasswordBreachEmail
	adminActivity []mailer.AdminActivityEmail
	accessChanges []mailer.AccessChangedEmail
	lockoutAlerts []mailer.TenantLockoutAlertEmail
	senders       []*mailer.SMTPConfig // parallel to sends; nil = global sender
}

func (m *captureMailer) SendReset(ctx context.Context, sender *mailer.SMTPConfig, _ *mailer.Template, e mailer.ResetEmail) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.resets = append(m.resets, e)
	m.senders = append(m.senders, sender)
	return nil
}

func (m *captureMailer) SendMFACode(ctx context.Context, sender *mailer.SMTPConfig, _ *mailer.Template, e mailer.MFACodeEmail) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, e)
	m.senders = append(m.senders, sender)
	return nil
}

func (m *captureMailer) SendMagicLink(ctx context.Context, sender *mailer.SMTPConfig, _ *mailer.Template, e mailer.MagicLinkEmail) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.links = append(m.links, e)
	m.senders = append(m.senders, sender)
	return nil
}

func (m *captureMailer) SendVerification(ctx context.Context, sender *mailer.SMTPConfig, _ *mailer.Template, e mailer.VerificationEmail) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.verifications = append(m.verifications, e)
	m.senders = append(m.senders, sender)
	return nil
}

func (m *captureMailer) SendWelcome(ctx context.Context, sender *mailer.SMTPConfig, _ *mailer.Template, e mailer.WelcomeEmail) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.welcomes = append(m.welcomes, e)
	m.senders = append(m.senders, sender)
	return nil
}

func (m *captureMailer) SendPasswordChanged(ctx context.Context, sender *mailer.SMTPConfig, _ *mailer.Template, e mailer.PasswordChangedEmail) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.changed = append(m.changed, e)
	m.senders = append(m.senders, sender)
	return nil
}

func (m *captureMailer) SendInvitation(ctx context.Context, sender *mailer.SMTPConfig, _ *mailer.Template, e mailer.InvitationEmail) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.invitations = append(m.invitations, e)
	m.senders = append(m.senders, sender)
	return nil
}

func (m *captureMailer) SendChangeEmail(ctx context.Context, sender *mailer.SMTPConfig, _ *mailer.Template, e mailer.ChangeEmailEmail) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.emailChanges = append(m.emailChanges, e)
	m.senders = append(m.senders, sender)
	return nil
}

func (m *captureMailer) SendBlockedAccount(ctx context.Context, sender *mailer.SMTPConfig, _ *mailer.Template, e mailer.BlockedAccountEmail) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.blocks = append(m.blocks, e)
	m.senders = append(m.senders, sender)
	return nil
}

// Blocks returns a copy of the blocked-account mail captured so far, read under
// the mutex.
//
// Reading m.blocks directly is a data race: blocked_account sends are DETACHED
// (see AccountBlockService.sendBlockedAccountAsync — an inline SMTP handshake on
// the login path is both slow and a timing oracle), so a goroutine may be
// appending while the test reads. Use awaitBlocks when the test needs to assert on
// a send that has just been triggered.
func (m *captureMailer) Blocks() []mailer.BlockedAccountEmail {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]mailer.BlockedAccountEmail(nil), m.blocks...)
}

// awaitBlocks waits for the detached send goroutines to deliver want messages and
// returns them, failing the test if they do not arrive.
//
// Waits for an exact count rather than "at least one": several of these tests
// assert that a tier fired ONCE, and a first-match check would not catch a
// duplicate.
func (m *captureMailer) awaitBlocks(t *testing.T, want int) []mailer.BlockedAccountEmail {
	t.Helper()
	var got []mailer.BlockedAccountEmail
	for i := 0; i < 100; i++ { // ≤5s; a local fake mailer needs microseconds
		if got = m.Blocks(); len(got) >= want {
			return got
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("blocked-account emails = %d after waiting, want %d: %+v", len(got), want, got)
	return nil
}

func (m *captureMailer) SendPasswordBreach(ctx context.Context, sender *mailer.SMTPConfig, _ *mailer.Template, e mailer.PasswordBreachEmail) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.breaches = append(m.breaches, e)
	m.senders = append(m.senders, sender)
	return nil
}

func (m *captureMailer) SendTenantLockoutAlert(ctx context.Context, sender *mailer.SMTPConfig, _ *mailer.Template, e mailer.TenantLockoutAlertEmail) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lockoutAlerts = append(m.lockoutAlerts, e)
	m.senders = append(m.senders, sender)
	return nil
}

func (m *captureMailer) SendAdminActivity(ctx context.Context, sender *mailer.SMTPConfig, _ *mailer.Template, e mailer.AdminActivityEmail) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.adminActivity = append(m.adminActivity, e)
	m.senders = append(m.senders, sender)
	return nil
}

func (m *captureMailer) SendAccessChanged(ctx context.Context, sender *mailer.SMTPConfig, _ *mailer.Template, e mailer.AccessChangedEmail) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.accessChanges = append(m.accessChanges, e)
	m.senders = append(m.senders, sender)
	return nil
}

func (m *captureMailer) SendTest(ctx context.Context, sender *mailer.SMTPConfig, _ *mailer.Template, _ mailer.TemplateType, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.senders = append(m.senders, sender)
	return nil
}

// GlobalProvider satisfies mailer.Mailer. The fake never transmits, so it
// reports the same label the real mailer uses for its log-only transport.
func (m *captureMailer) GlobalProvider() string { return "dev" }

// lastLink returns the most recently "sent" magic link email.
func (m *captureMailer) lastLink(t *testing.T) mailer.MagicLinkEmail {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.links) == 0 {
		t.Fatal("no magic link email was sent")
	}
	return m.links[len(m.links)-1]
}

// linkCount returns how many magic link emails were sent.
func (m *captureMailer) linkCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.links)
}

// codeCount returns how many MFA code emails were sent.
func (m *captureMailer) codeCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sent)
}

// lastCode returns the most recently "sent" code.
func (m *captureMailer) lastCode(t *testing.T) mailer.MFACodeEmail {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.sent) == 0 {
		t.Fatal("no MFA code email was sent")
	}
	return m.sent[len(m.sent)-1]
}

// lastSender returns the sender override used for the most recent send
// (nil = global sender).
func (m *captureMailer) lastSender(t *testing.T) *mailer.SMTPConfig {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.senders) == 0 {
		t.Fatal("no MFA code email was sent")
	}
	return m.senders[len(m.senders)-1]
}

// mfaFixture bundles everything the application-scoped MFA tests need:
// real DB + Redis, the seeded "emc" tenant, and fully wired services.
type mfaFixture struct {
	ctx       context.Context
	pool      *pgxpool.Pool
	tenantID  int64
	authSvc   *auth.AuthService
	totpSvc   *auth.TOTPService
	emailSvc  *auth.EmailMFAService
	senderSvc *auth.EmailSenderService
	appSvc    *auth.ApplicationService
	jwtSvc    *auth.JWTService
	mail      *captureMailer
}

func newMFAFixture(t *testing.T) *mfaFixture {
	t.Helper()
	pool := testhelper.NewTestDB(t)
	rdb := testhelper.NewTestRedis(t)
	logger := testhelper.TestLogger()
	testhelper.CleanupTables(t, pool)

	ctx := context.Background()
	if err := store.RunSeed(ctx, pool, logger); err != nil {
		t.Fatalf("RunSeed: %v", err)
	}

	var tenantID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM tenants WHERE slug = 'emc' AND deleted_at IS NULL`).Scan(&tenantID); err != nil {
		t.Fatalf("fetch seed tenant id: %v", err)
	}

	totpSvc, err := auth.NewTOTPService(pool, totpEnvKey(), logger)
	if err != nil {
		t.Fatalf("NewTOTPService: %v", err)
	}
	appSvc := auth.NewApplicationService(pool, logger)
	jwtSvc := newTestJWTService(t, pool, "https://auth.emc.local")
	mail := &captureMailer{}
	senderSvc := auth.NewEmailSenderService(pool, totpSvc.EncryptionKey(), logger)
	emailSvc := auth.NewEmailMFAService(pool, rdb, mail, logger).WithSenders(senderSvc)
	authSvc := auth.NewAuthService(pool, jwtSvc, logger).
		WithTOTP(totpSvc, rdb).
		WithEmailMFA(emailSvc).
		WithApplications(appSvc)

	return &mfaFixture{
		ctx: ctx, pool: pool, tenantID: tenantID,
		authSvc: authSvc, totpSvc: totpSvc, emailSvc: emailSvc, senderSvc: senderSvc,
		appSvc: appSvc, jwtSvc: jwtSvc, mail: mail,
	}
}

// createApp registers an application and returns it plus its int64 row id.
func (f *mfaFixture) createApp(t *testing.T, name string) (*auth.AppResult, int64) {
	t.Helper()
	app, err := f.appSvc.CreateApplication(f.ctx, f.tenantID, name, "web", nil)
	if err != nil {
		t.Fatalf("CreateApplication(%q): %v", name, err)
	}
	id, err := strconv.ParseInt(app.ID, 10, 64)
	if err != nil {
		t.Fatalf("parse app id %q: %v", app.ID, err)
	}
	return app, id
}

// registerAppUser registers an end user in the application's isolated user
// base and returns the users.id.
func (f *mfaFixture) registerAppUser(t *testing.T, app *auth.AppResult, email, password string) int64 {
	t.Helper()
	if _, err := f.authSvc.Register(f.ctx, auth.RegisterInput{
		ClientID:     app.ClientID,
		ClientSecret: app.ClientSecret,
		Email:        email,
		Password:     password,
	}); err != nil {
		t.Fatalf("Register(app user %q): %v", email, err)
	}
	var userID int64
	if err := f.pool.QueryRow(f.ctx,
		`SELECT u.id FROM users u JOIN oauth_clients oc ON oc.id = u.application_id
		 WHERE u.email = $1 AND oc.client_id = $2 AND u.deleted_at IS NULL`,
		email, app.ClientID,
	).Scan(&userID); err != nil {
		t.Fatalf("fetch app user id for %q: %v", email, err)
	}
	return userID
}

// appLogin runs the application-authenticated login.
func (f *mfaFixture) appLogin(t *testing.T, app *auth.AppResult, email, password string) (*auth.LoginResult, error) {
	t.Helper()
	return f.authSvc.Login(f.ctx, auth.LoginInput{
		ClientID:     app.ClientID,
		ClientSecret: app.ClientSecret,
		Email:        email,
		Password:     password,
	})
}

// codeFor generates the current TOTP code for an otpauth:// secret.
func codeFor(t *testing.T, secret string) string {
	t.Helper()
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	return code
}

// enrollAndActivate voluntarily enrolls and activates TOTP for a user,
// returning the shared secret.
func (f *mfaFixture) enrollAndActivate(t *testing.T, userID int64, email string) string {
	t.Helper()
	result, err := f.totpSvc.EnrollUser(f.ctx, userID, f.tenantID, email, "")
	if err != nil {
		t.Fatalf("EnrollUser(%q): %v", email, err)
	}
	secret := secretFromOTPURI(t, result.OTPURI)
	if err := f.totpSvc.VerifyAndActivate(f.ctx, userID, codeFor(t, secret)); err != nil {
		t.Fatalf("VerifyAndActivate(%q): %v", email, err)
	}
	return secret
}

// ---------------------------------------------------------------------------
// Policy CRUD
// ---------------------------------------------------------------------------

func TestAppMFAPolicy_DefaultsAndUpsert(t *testing.T) {
	f := newMFAFixture(t)
	_, appID := f.createApp(t, "policy-app")

	// No explicit row → optional (pre-feature behaviour).
	mode, err := f.totpSvc.GetAppMFAMode(f.ctx, appID)
	if err != nil {
		t.Fatalf("GetAppMFAMode: %v", err)
	}
	if mode != auth.MFAModeOptional {
		t.Errorf("default mode = %q, want %q", mode, auth.MFAModeOptional)
	}

	// Invalid mode is rejected.
	if err := f.totpSvc.SetAppMFAPolicy(f.ctx, f.tenantID, appID, "sometimes", nil, nil); !errors.Is(err, auth.ErrInvalidMFAMode) {
		t.Errorf("SetAppMFAPolicy(invalid) error = %v, want ErrInvalidMFAMode", err)
	}

	// Upsert to required, then back to disabled.
	if err := f.totpSvc.SetAppMFAPolicy(f.ctx, f.tenantID, appID, auth.MFAModeRequired, nil, nil); err != nil {
		t.Fatalf("SetAppMFAPolicy(required): %v", err)
	}
	if mode, _ = f.totpSvc.GetAppMFAMode(f.ctx, appID); mode != auth.MFAModeRequired {
		t.Errorf("mode after set = %q, want required", mode)
	}
	if err := f.totpSvc.SetAppMFAPolicy(f.ctx, f.tenantID, appID, auth.MFAModeDisabled, nil, nil); err != nil {
		t.Fatalf("SetAppMFAPolicy(disabled): %v", err)
	}
	policy, err := f.totpSvc.GetAppMFAPolicy(f.ctx, f.tenantID, appID)
	if err != nil {
		t.Fatalf("GetAppMFAPolicy: %v", err)
	}
	if policy.Mode != auth.MFAModeDisabled {
		t.Errorf("policy.Mode = %q, want disabled", policy.Mode)
	}
	if policy.UpdatedAt == nil {
		t.Error("policy.UpdatedAt = nil, want set after explicit upsert")
	}
}

func TestAppMFAPolicy_StatsCountAppUserBase(t *testing.T) {
	f := newMFAFixture(t)
	app, appID := f.createApp(t, "stats-app")

	activeUser := f.registerAppUser(t, app, uniqueEmail("mfa-stats-active"), "Password123!")
	f.registerAppUser(t, app, uniqueEmail("mfa-stats-none"), "Password123!")
	pendingUser := f.registerAppUser(t, app, uniqueEmail("mfa-stats-pending"), "Password123!")

	f.enrollAndActivate(t, activeUser, "mfa-stats-active")
	if _, err := f.totpSvc.EnrollUser(f.ctx, pendingUser, f.tenantID, "mfa-stats-pending", ""); err != nil {
		t.Fatalf("EnrollUser(pending): %v", err)
	}

	policy, err := f.totpSvc.GetAppMFAPolicy(f.ctx, f.tenantID, appID)
	if err != nil {
		t.Fatalf("GetAppMFAPolicy: %v", err)
	}
	if policy.TotalUsers != 3 || policy.EnrolledUsers != 1 || policy.PendingEnrollments != 1 {
		t.Errorf("stats = total %d / enrolled %d / pending %d, want 3 / 1 / 1",
			policy.TotalUsers, policy.EnrolledUsers, policy.PendingEnrollments)
	}
}

// ---------------------------------------------------------------------------
// Login enforcement
// ---------------------------------------------------------------------------

// TestLogin_RequiredMode_ForcedEnrollmentCompletesLogin walks the entire
// forced-enrollment journey: password → enrollment challenge → enroll →
// activate → tokens, and verifies the issued JWT keeps the app_id claim.
func TestLogin_RequiredMode_ForcedEnrollmentCompletesLogin(t *testing.T) {
	f := newMFAFixture(t)
	app, appID := f.createApp(t, "required-app")
	email := uniqueEmail("mfa-required")
	f.registerAppUser(t, app, email, "Password123!")

	if err := f.totpSvc.SetAppMFAPolicy(f.ctx, f.tenantID, appID, auth.MFAModeRequired, nil, nil); err != nil {
		t.Fatalf("SetAppMFAPolicy: %v", err)
	}

	// Step 1: password login → enrollment challenge, never tokens.
	result, err := f.appLogin(t, app, email, "Password123!")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if result.Token != nil || result.OTPChallenge != nil || result.MFAEnrollment == nil {
		t.Fatalf("Login = %+v, want MFAEnrollment challenge only", result)
	}
	if !result.MFAEnrollment.MFAEnrollmentRequired || result.MFAEnrollment.EnrollmentToken == "" {
		t.Fatalf("bad enrollment challenge: %+v", result.MFAEnrollment)
	}

	// Step 2: enroll with the pre-auth token — issuer must be the app's name.
	enroll, session, err := f.authSvc.EnrollPending(f.ctx, result.MFAEnrollment.EnrollmentToken)
	if err != nil {
		t.Fatalf("EnrollPending: %v", err)
	}
	if session.Email != email {
		t.Errorf("session email = %q, want %q", session.Email, email)
	}
	u, err := url.Parse(enroll.OTPURI)
	if err != nil {
		t.Fatalf("parse OTP URI: %v", err)
	}
	if got := u.Query().Get("issuer"); got != "required-app" {
		t.Errorf("otpauth issuer = %q, want application name %q", got, "required-app")
	}

	// Step 3: activate with the first code → login completes with tokens.
	secret := secretFromOTPURI(t, enroll.OTPURI)
	tokens, _, err := f.authSvc.ActivatePending(f.ctx, result.MFAEnrollment.EnrollmentToken, codeFor(t, secret))
	if err != nil {
		t.Fatalf("ActivatePending: %v", err)
	}
	claims, err := f.jwtSvc.Verify(f.ctx, tokens.AccessToken)
	if err != nil {
		t.Fatalf("Verify(access token): %v", err)
	}
	if claims.AppID != app.ID {
		t.Errorf("claims.AppID = %q, want %q", claims.AppID, app.ID)
	}

	// The enrollment token is single-use: re-activation must fail.
	if _, _, err := f.authSvc.ActivatePending(f.ctx, result.MFAEnrollment.EnrollmentToken, codeFor(t, secret)); err == nil {
		t.Error("ActivatePending(reused token) succeeded, want error")
	}

	// Step 4: subsequent login → regular OTP challenge; completing it keeps
	// the app_id claim (regression: it was previously dropped here).
	result2, err := f.appLogin(t, app, email, "Password123!")
	if err != nil {
		t.Fatalf("second Login: %v", err)
	}
	if result2.OTPChallenge == nil {
		t.Fatalf("second Login = %+v, want OTPChallenge", result2)
	}
	tokens2, err := f.authSvc.LoginOTP(f.ctx, auth.LoginOTPInput{
		OTPSessionToken: result2.OTPChallenge.OTPSessionToken,
		Code:            codeFor(t, secret),
	})
	if err != nil {
		t.Fatalf("LoginOTP: %v", err)
	}
	claims2, err := f.jwtSvc.Verify(f.ctx, tokens2.AccessToken)
	if err != nil {
		t.Fatalf("Verify(post-OTP token): %v", err)
	}
	if claims2.AppID != app.ID {
		t.Errorf("post-OTP claims.AppID = %q, want %q (app context lost through OTP challenge)", claims2.AppID, app.ID)
	}
}

func TestLogin_OptionalMode_UnenrolledGetsTokens(t *testing.T) {
	f := newMFAFixture(t)
	app, _ := f.createApp(t, "optional-app")
	email := uniqueEmail("mfa-optional")
	f.registerAppUser(t, app, email, "Password123!")

	result, err := f.appLogin(t, app, email, "Password123!")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if result.Token == nil || result.OTPChallenge != nil || result.MFAEnrollment != nil {
		t.Fatalf("Login = %+v, want direct token pair under implicit optional mode", result)
	}
}

// TestLogin_SameEmailTwoApps_IndependentMFA verifies isolation: one email
// enrolled in app A is challenged there, while the same email in app B (not
// enrolled, optional) logs straight in.
func TestLogin_SameEmailTwoApps_IndependentMFA(t *testing.T) {
	f := newMFAFixture(t)
	appA, _ := f.createApp(t, "iso-app-a")
	appB, _ := f.createApp(t, "iso-app-b")
	email := uniqueEmail("mfa-iso")

	userA := f.registerAppUser(t, appA, email, "Password123!")
	f.registerAppUser(t, appB, email, "Password123!")
	f.enrollAndActivate(t, userA, email)

	resA, err := f.appLogin(t, appA, email, "Password123!")
	if err != nil {
		t.Fatalf("Login(app A): %v", err)
	}
	if resA.OTPChallenge == nil {
		t.Errorf("Login(app A) = %+v, want OTP challenge (enrolled)", resA)
	}

	resB, err := f.appLogin(t, appB, email, "Password123!")
	if err != nil {
		t.Fatalf("Login(app B): %v", err)
	}
	if resB.Token == nil {
		t.Errorf("Login(app B) = %+v, want direct tokens (independent user base)", resB)
	}
}

// ---------------------------------------------------------------------------
// Brute-force hardening
// ---------------------------------------------------------------------------

func TestLoginOTP_AttemptBudgetInvalidatesSession(t *testing.T) {
	f := newMFAFixture(t)
	app, _ := f.createApp(t, "budget-app")
	email := uniqueEmail("mfa-budget")
	userID := f.registerAppUser(t, app, email, "Password123!")
	secret := f.enrollAndActivate(t, userID, email)

	result, err := f.appLogin(t, app, email, "Password123!")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if result.OTPChallenge == nil {
		t.Fatalf("Login = %+v, want OTP challenge", result)
	}
	token := result.OTPChallenge.OTPSessionToken

	// Burn the attempt budget with wrong codes.
	for i := 0; i < auth.MaxOTPAttempts; i++ {
		_, err := f.authSvc.LoginOTP(f.ctx, auth.LoginOTPInput{OTPSessionToken: token, Code: "000000"})
		if err == nil {
			t.Fatalf("attempt %d with wrong code succeeded", i+1)
		}
		if errors.Is(err, auth.ErrTooManyOTPAttempts) {
			t.Fatalf("attempt %d hit the budget early: %v", i+1, err)
		}
	}

	// Budget exhausted: next attempt is rejected and the session destroyed.
	_, err = f.authSvc.LoginOTP(f.ctx, auth.LoginOTPInput{OTPSessionToken: token, Code: "000000"})
	if !errors.Is(err, auth.ErrTooManyOTPAttempts) {
		t.Fatalf("over-budget attempt error = %v, want ErrTooManyOTPAttempts", err)
	}

	// Even the CORRECT code is now useless — the session is gone.
	_, err = f.authSvc.LoginOTP(f.ctx, auth.LoginOTPInput{OTPSessionToken: token, Code: codeFor(t, secret)})
	if err == nil {
		t.Fatal("LoginOTP with valid code after budget exhaustion succeeded, want invalid session")
	}
}

// ---------------------------------------------------------------------------
// Enrollment policy guards
// ---------------------------------------------------------------------------

func TestEnrollUser_DisabledModeRejectsNewEnrollments(t *testing.T) {
	f := newMFAFixture(t)
	app, appID := f.createApp(t, "disabled-app")
	email := uniqueEmail("mfa-disabled")
	userID := f.registerAppUser(t, app, email, "Password123!")

	if err := f.totpSvc.SetAppMFAPolicy(f.ctx, f.tenantID, appID, auth.MFAModeDisabled, nil, nil); err != nil {
		t.Fatalf("SetAppMFAPolicy: %v", err)
	}

	if _, err := f.totpSvc.EnrollUser(f.ctx, userID, f.tenantID, email, ""); !errors.Is(err, auth.ErrMFAEnrollmentDisabled) {
		t.Errorf("EnrollUser(disabled app) error = %v, want ErrMFAEnrollmentDisabled", err)
	}
}

func TestEnrollUser_ReenrollRequiresCurrentCode(t *testing.T) {
	f := newMFAFixture(t)
	app, _ := f.createApp(t, "reenroll-app")
	email := uniqueEmail("mfa-reenroll")
	userID := f.registerAppUser(t, app, email, "Password123!")
	secret := f.enrollAndActivate(t, userID, email)

	// Without proof → rejected.
	if _, err := f.totpSvc.EnrollUser(f.ctx, userID, f.tenantID, email, ""); !errors.Is(err, auth.ErrTOTPReenrollProof) {
		t.Errorf("EnrollUser(active, no code) error = %v, want ErrTOTPReenrollProof", err)
	}
	// With a wrong code → rejected.
	if _, err := f.totpSvc.EnrollUser(f.ctx, userID, f.tenantID, email, "000000"); !errors.Is(err, auth.ErrTOTPReenrollProof) {
		t.Errorf("EnrollUser(active, bad code) error = %v, want ErrTOTPReenrollProof", err)
	}
	// With the current valid code → new secret issued, enrollment back to pending.
	result, err := f.totpSvc.EnrollUser(f.ctx, userID, f.tenantID, email, codeFor(t, secret))
	if err != nil {
		t.Fatalf("EnrollUser(active, valid code): %v", err)
	}
	if secretFromOTPURI(t, result.OTPURI) == secret {
		t.Error("re-enrollment did not rotate the secret")
	}
	active, err := f.totpSvc.IsActive(f.ctx, userID)
	if err != nil {
		t.Fatalf("IsActive: %v", err)
	}
	if active {
		t.Error("IsActive = true after re-enrollment, want false until re-activation")
	}
}

func TestDisableUser_RequiredModeRejected(t *testing.T) {
	f := newMFAFixture(t)
	app, appID := f.createApp(t, "no-optout-app")
	email := uniqueEmail("mfa-no-optout")
	userID := f.registerAppUser(t, app, email, "Password123!")
	secret := f.enrollAndActivate(t, userID, email)

	if err := f.totpSvc.SetAppMFAPolicy(f.ctx, f.tenantID, appID, auth.MFAModeRequired, nil, nil); err != nil {
		t.Fatalf("SetAppMFAPolicy: %v", err)
	}

	if err := f.totpSvc.DisableUser(f.ctx, userID, f.tenantID, codeFor(t, secret)); !errors.Is(err, auth.ErrMFARequiredByPolicy) {
		t.Errorf("DisableUser(required app) error = %v, want ErrMFARequiredByPolicy", err)
	}

	// Back to optional → the same request succeeds.
	if err := f.totpSvc.SetAppMFAPolicy(f.ctx, f.tenantID, appID, auth.MFAModeOptional, nil, nil); err != nil {
		t.Fatalf("SetAppMFAPolicy(optional): %v", err)
	}
	if err := f.totpSvc.DisableUser(f.ctx, userID, f.tenantID, codeFor(t, secret)); err != nil {
		t.Errorf("DisableUser(optional app) error = %v, want success", err)
	}
}

// ---------------------------------------------------------------------------
// Backup-code lifecycle
// ---------------------------------------------------------------------------

func TestTOTPStatus_And_RegenerateBackupCodes(t *testing.T) {
	f := newMFAFixture(t)
	app, _ := f.createApp(t, "codes-app")
	email := uniqueEmail("mfa-codes")
	userID := f.registerAppUser(t, app, email, "Password123!")

	// Not enrolled → empty status.
	st, err := f.totpSvc.Status(f.ctx, userID)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.Enrolled || st.Active || st.BackupCodesRemaining != 0 {
		t.Errorf("unenrolled status = %+v, want all-zero", st)
	}

	// Regeneration requires an active enrollment.
	if _, err := f.totpSvc.RegenerateBackupCodes(f.ctx, userID, "000000"); err == nil {
		t.Error("RegenerateBackupCodes(unenrolled) succeeded, want error")
	}

	secret := f.enrollAndActivate(t, userID, email)
	st, _ = f.totpSvc.Status(f.ctx, userID)
	if !st.Enrolled || !st.Active || st.BackupCodesRemaining != auth.BackupCodeCount {
		t.Errorf("active status = %+v, want enrolled/active with %d codes", st, auth.BackupCodeCount)
	}

	// Consuming a backup code shows up in the count.
	firstEnroll, err := f.totpSvc.EnrollUser(f.ctx, userID, f.tenantID, email, codeFor(t, secret))
	if err != nil {
		t.Fatalf("re-enroll to capture codes: %v", err)
	}
	secret = secretFromOTPURI(t, firstEnroll.OTPURI)
	if err := f.totpSvc.VerifyAndActivate(f.ctx, userID, codeFor(t, secret)); err != nil {
		t.Fatalf("re-activate: %v", err)
	}
	if err := f.totpSvc.VerifyBackupCode(f.ctx, userID, firstEnroll.BackupCodes[0]); err != nil {
		t.Fatalf("VerifyBackupCode: %v", err)
	}
	st, _ = f.totpSvc.Status(f.ctx, userID)
	if st.BackupCodesRemaining != auth.BackupCodeCount-1 {
		t.Errorf("codes remaining after one use = %d, want %d", st.BackupCodesRemaining, auth.BackupCodeCount-1)
	}

	// Regenerate without proof → rejected; with a wrong code → rejected.
	if _, err := f.totpSvc.RegenerateBackupCodes(f.ctx, userID, ""); !errors.Is(err, auth.ErrTOTPProofRequired) {
		t.Errorf("RegenerateBackupCodes(no code) error = %v, want ErrTOTPProofRequired", err)
	}
	if _, err := f.totpSvc.RegenerateBackupCodes(f.ctx, userID, "000000"); !errors.Is(err, auth.ErrTOTPProofRequired) {
		t.Errorf("RegenerateBackupCodes(bad code) error = %v, want ErrTOTPProofRequired", err)
	}

	// With a valid TOTP code → fresh full set; the secret still works and every
	// old backup code is dead.
	newCodes, err := f.totpSvc.RegenerateBackupCodes(f.ctx, userID, codeFor(t, secret))
	if err != nil {
		t.Fatalf("RegenerateBackupCodes: %v", err)
	}
	if len(newCodes) != auth.BackupCodeCount {
		t.Errorf("regenerated %d codes, want %d", len(newCodes), auth.BackupCodeCount)
	}
	st, _ = f.totpSvc.Status(f.ctx, userID)
	if st.BackupCodesRemaining != auth.BackupCodeCount {
		t.Errorf("codes remaining after regeneration = %d, want %d", st.BackupCodesRemaining, auth.BackupCodeCount)
	}
	if err := f.totpSvc.Verify(f.ctx, userID, codeFor(t, secret)); err != nil {
		t.Errorf("TOTP secret stopped working after backup-code regeneration: %v", err)
	}
	if err := f.totpSvc.VerifyBackupCode(f.ctx, userID, firstEnroll.BackupCodes[1]); err == nil {
		t.Error("old backup code still valid after regeneration, want invalidated")
	}
	if err := f.totpSvc.VerifyBackupCode(f.ctx, userID, newCodes[0]); err != nil {
		t.Errorf("new backup code rejected: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Admin reset
// ---------------------------------------------------------------------------

func TestResetUserMFA_ScopedAndIdempotent(t *testing.T) {
	f := newMFAFixture(t)
	appA, appAID := f.createApp(t, "reset-app-a")
	appB, appBID := f.createApp(t, "reset-app-b")
	email := uniqueEmail("mfa-reset")

	userA := f.registerAppUser(t, appA, email, "Password123!")
	f.enrollAndActivate(t, userA, email)

	// Resetting user A through app B's scope must not find (or touch) them.
	if err := f.totpSvc.ResetUserMFA(f.ctx, f.tenantID, &appBID, userA); !errors.Is(err, auth.ErrUserNotFound) {
		t.Errorf("ResetUserMFA(foreign app scope) error = %v, want ErrUserNotFound", err)
	}
	if active, _ := f.totpSvc.IsActive(f.ctx, userA); !active {
		t.Fatal("enrollment was touched by a foreign-scope reset")
	}
	_ = appB

	// Correct scope → enrollment removed.
	if err := f.totpSvc.ResetUserMFA(f.ctx, f.tenantID, &appAID, userA); err != nil {
		t.Fatalf("ResetUserMFA: %v", err)
	}
	if active, _ := f.totpSvc.IsActive(f.ctx, userA); active {
		t.Error("IsActive = true after reset, want false")
	}

	// Idempotent: resetting an unenrolled user succeeds.
	if err := f.totpSvc.ResetUserMFA(f.ctx, f.tenantID, &appAID, userA); err != nil {
		t.Errorf("second ResetUserMFA error = %v, want nil (idempotent)", err)
	}
}
