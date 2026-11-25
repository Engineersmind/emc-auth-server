package auth

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"
)

// ---------------------------------------------------------------------------
// Step-up at refresh (#197, #189 backlog)
//
// An application MFA policy change applies at each user's next login; refresh
// rotation does not re-run the login gate. An application that opts in with
// refresh_step_up = true (default false) has every refresh re-checked: when the
// application now requires MFA of the user and the session was not established
// with MFA, the refresh is refused with ErrStepUpRequired and the user must
// sign in again, meeting the current policy.
//
// Cost: the flag is read in the refresh-token lookup the rotation already runs
// (a LEFT JOIN on application_mfa_settings by PK), so an application with the
// flag off pays no extra round trip. Only a flagged application whose session
// lacks "mfa" in its amr pays one more read (loadUserMFAContext).
// ---------------------------------------------------------------------------

// ErrStepUpRequired refuses a refresh because the session's application now
// requires MFA of its user and the session was established without it (#197).
// Nothing is revoked or rotated: the presented refresh token stays as it was,
// and the client sends the user through sign-in again.
var ErrStepUpRequired = errors.New("the application now requires two-factor authentication — sign in again")

// refreshStepUpSQL is the select-list fragment the two rotation paths add to
// their refresh-token lookup: the refresh_step_up flag of the token owner's
// application, false for a tenant-level user or an application with no settings
// row. It needs the joins in refreshStepUpJoin, with rt the refresh_tokens
// alias.
const refreshStepUpSQL = `COALESCE(stepup_ams.refresh_step_up, false)`

// refreshStepUpJoin joins the token owner's application MFA settings. LEFT
// JOINs only, so a lookup that must see every token row (RefreshWithLock's
// unfiltered read, which feeds replay detection) still does.
const refreshStepUpJoin = `
		LEFT JOIN users stepup_u ON stepup_u.id = rt.user_id
		LEFT JOIN application_mfa_settings stepup_ams ON stepup_ams.application_id = stepup_u.application_id`

// checkRefreshStepUp decides a refresh of a session with the given amr whose
// owner's application has refresh_step_up set (the caller has already read the
// flag; when it is false this is never called). It returns ErrStepUpRequired
// when the application requires MFA of this user right now and the session
// does not satisfy it, nil otherwise:
//
//   - amr already contains "mfa" → nil (no read at all);
//   - the user has no application, the switch is off, or nothing requires MFA
//     of them (mode 'optional' with no role rule, or 'disabled') → nil;
//   - a social (fed) or passkey (hwk) session on an application whose
//     federated_mfa is 'trust' → nil, consistent with login, where such
//     sign-ins skip the gate. Under 'enforce' they are stepped up;
//   - otherwise → ErrStepUpRequired.
//
// A user not found in the session's tenant (a tenant-switched administrator,
// who is never application-scoped, or a user deleted since) returns nil here:
// the rotation's own user load decides those. Any other read error fails
// closed — the refresh is refused rather than waved through.
func (s *AuthService) checkRefreshStepUp(ctx context.Context, userID, tenantID int64, amr []string) error {
	if slices.Contains(amr, AMRMFA) {
		return nil
	}
	uc, err := loadUserMFAContext(ctx, s.pool, userID, tenantID)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return nil
		}
		return err
	}
	if uc.appRowID == nil || !uc.requiredByPolicy() {
		return nil
	}
	federated := slices.Contains(amr, AMRFederated) || slices.Contains(amr, AMRWebAuthn)
	if federated && uc.federatedMFA != FederatedMFAEnforce {
		return nil
	}
	// Required-mode grace period (#198): a user with no permitted factor yet
	// would get tokens at login right now, so refusing their refresh would only
	// send them round to the same result. A user who HAS a factor is stepped up
	// as always — the grace covers enrolment, not challenges.
	if uc.inEnrollmentGrace(time.Now()) {
		has, err := s.hasPermittedFactor(ctx, userID, uc.allowedMethods)
		if err != nil {
			return err
		}
		if !has {
			return nil
		}
	}
	return ErrStepUpRequired
}

// hasPermittedFactor reports whether the user has any of methods active. A
// read error is returned, never read as "none".
func (s *AuthService) hasPermittedFactor(ctx context.Context, userID int64, methods []string) (bool, error) {
	for _, m := range methods {
		on, err := s.appFactorActive(ctx, userID, m)
		if err != nil {
			return false, fmt.Errorf("check %s MFA status: %w", m, err)
		}
		if on {
			return true, nil
		}
	}
	return false, nil
}
