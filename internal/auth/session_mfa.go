package auth

import (
	"context"
	"fmt"
)

// ---------------------------------------------------------------------------
// Cookie-session completion of an MFA-gated console sign-in
//
// The admin console signs in through POST /auth/session, and its second step
// completes here. These wrap the shared completion paths with one extra rule:
// an application-scoped challenge is refused before anything is checked, so an
// app login can never be completed into first-party cookies.
// ---------------------------------------------------------------------------

// LoginOTPForCookieSession is LoginOTP for the console's cookie endpoint.
func (s *AuthService) LoginOTPForCookieSession(ctx context.Context, in LoginOTPInput) (*AuthResult, error) {
	if s.redisCli == nil {
		return nil, fmt.Errorf("TOTP not configured on this server")
	}
	session, err := s.loadOTPSession(ctx, otpSessionKey(in.OTPSessionToken))
	if err != nil {
		return nil, fmt.Errorf("invalid or expired OTP session")
	}
	if session.AppID != "" {
		return nil, ErrCookieSessionNotAvailable
	}
	return s.LoginOTP(ctx, in)
}

// ActivatePendingForCookieSession is ActivatePending for the console's cookie
// endpoint, with the same application-scope refusal.
func (s *AuthService) ActivatePendingForCookieSession(ctx context.Context, enrollmentToken, code string) (*AuthResult, *OTPSession, error) {
	if s.redisCli == nil {
		return nil, nil, fmt.Errorf("TOTP not configured on this server")
	}
	session, err := s.loadOTPSession(ctx, mfaEnrollKey(enrollmentToken))
	if err != nil {
		return nil, nil, fmt.Errorf("invalid or expired enrollment session")
	}
	if session.AppID != "" {
		return nil, session, ErrCookieSessionNotAvailable
	}
	return s.ActivatePending(ctx, enrollmentToken, code)
}
