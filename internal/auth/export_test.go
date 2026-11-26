package auth

import "context"

// SetAppMFAEnabled turns the application's MFA master switch on or off and
// returns the value it replaced. TEST-ONLY: it does no caller authorisation, so
// it lives in a _test.go file where no handler can reach it. Production code
// goes through UpdateAppMFASettings after AuthorizeMFASwitchOff.
func (s *TOTPService) SetAppMFAEnabled(ctx context.Context, tenantID, appRowID int64, enabled bool, updatedBy *int64) (prev bool, err error) {
	res, err := s.UpdateAppMFASettings(ctx, tenantID, appRowID, AppMFAUpdate{Enabled: &enabled}, updatedBy)
	return res.PrevEnabled, err
}
