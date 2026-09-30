package auth_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// GHSA-92p3-fj5f-8gx7: NewTOTPService must follow the NewSecretBox contract —
// fail closed on a missing key in production/staging instead of encrypting
// every seed under the all-zero key, and refuse that key when it is set
// explicitly. Development keeps its zero-key fallback. No database is needed:
// the constructor does not touch the pool.
func TestNewTOTPService_KeyPolicy(t *testing.T) {
	const realKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	zeroKey := strings.Repeat("0", 64)

	tests := []struct {
		name    string
		key     string
		env     string
		wantErr error // nil means success
	}{
		{name: "production with a real key", key: realKey, env: "production"},
		{name: "staging with a real key", key: realKey, env: "staging"},
		{name: "production without a key", key: "", env: "production", wantErr: auth.ErrEncryptionKeyRequired},
		{name: "staging without a key", key: "", env: "staging", wantErr: auth.ErrEncryptionKeyRequired},
		{name: "production with the zero key", key: zeroKey, env: "production", wantErr: auth.ErrTOTPZeroKey},
		{name: "staging with the zero key", key: zeroKey, env: "staging", wantErr: auth.ErrTOTPZeroKey},
		{name: "development without a key falls back", key: "", env: "development"},
		{name: "development with the zero key", key: zeroKey, env: "development"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc, err := auth.NewTOTPService(nil, tc.key, tc.env, testhelper.TestLogger())
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				if svc != nil {
					t.Fatal("service returned alongside an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestNewTOTPService_RejectsMalformedKey(t *testing.T) {
	for _, env := range []string{"development", "production"} {
		if _, err := auth.NewTOTPService(nil, "not-hex", env, testhelper.TestLogger()); err == nil {
			t.Errorf("env=%s: malformed key accepted", env)
		}
	}
}
