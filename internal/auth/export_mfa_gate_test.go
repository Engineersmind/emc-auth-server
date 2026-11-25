package auth

import "context"

// Test seam for mfaGate and its options variant (passwordless plan, Phase 0).
//
// In an _test.go file, so nothing here is compiled into the binary.

// ExportedMFAGate calls the production mfaGate, the entry point password login
// and the magic link use today.
func ExportedMFAGate(ctx context.Context, s *AuthService, userID, tenantID, appRowID int64, appID, email string) (*LoginResult, error) {
	res, _, err := s.mfaGate(ctx, userID, tenantID, appRowID, appID, email, "", nil, false, nil, orgSessionRequest{})
	return res, err
}

// ExportedMFAGateInboxFirst calls mfaGateWith with inboxFirstFactor set, as the
// passwordless email-code flow will.
func ExportedMFAGateInboxFirst(ctx context.Context, s *AuthService, userID, tenantID, appRowID int64, appID, email string) (*LoginResult, error) {
	res, _, err := s.mfaGateWith(ctx, mfaGateOptions{inboxFirstFactor: true}, userID, tenantID, appRowID, appID, email, "", nil, false, nil, orgSessionRequest{})
	return res, err
}

// ExportedMFAGateZeroOptions calls mfaGateWith with the zero options value.
func ExportedMFAGateZeroOptions(ctx context.Context, s *AuthService, userID, tenantID, appRowID int64, appID, email string) (*LoginResult, error) {
	res, _, err := s.mfaGateWith(ctx, mfaGateOptions{}, userID, tenantID, appRowID, appID, email, "", nil, false, nil, orgSessionRequest{})
	return res, err
}
