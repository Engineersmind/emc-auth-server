package auth_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// NewSecretBox shares the NewTOTPService contract: a missing key fails closed,
// and so does the all-zero key set explicitly — an explicitly-typed zero key
// used to sail through the empty-string check and encrypt the JWT signing key
// and OAuth client secrets under a key anyone can read in this repository.
// Only development and test keep the fallback. No database is needed: the
// constructor does not touch one.
func TestNewSecretBox_KeyPolicy(t *testing.T) {
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
		{name: "production with the zero key", key: zeroKey, env: "production", wantErr: auth.ErrZeroEncryptionKey},
		{name: "staging with the zero key", key: zeroKey, env: "staging", wantErr: auth.ErrZeroEncryptionKey},
		{name: "development without a key falls back", key: "", env: "development"},
		{name: "development with the zero key", key: zeroKey, env: "development"},
		{name: "test without a key falls back", key: "", env: "test"},
		{name: "test with the zero key", key: zeroKey, env: "test"},
		// Only the named non-deployed environments may fall back or hold the
		// zero key: a misspelt or unknown ENV must fail closed, not behave
		// like development.
		{name: "misspelled env without a key", key: "", env: "prodution", wantErr: auth.ErrEncryptionKeyRequired},
		{name: "misspelled env with the zero key", key: zeroKey, env: "prodution", wantErr: auth.ErrZeroEncryptionKey},
		{name: "empty env without a key", key: "", env: "", wantErr: auth.ErrEncryptionKeyRequired},
		{name: "empty env with the zero key", key: zeroKey, env: "", wantErr: auth.ErrZeroEncryptionKey},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			box, err := auth.NewSecretBox(tc.key, tc.env, "TEST_ENCRYPTION_KEY", testhelper.TestLogger())
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				if box != nil {
					t.Fatal("box returned alongside an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestNewSecretBox_RejectsMalformedKey(t *testing.T) {
	for _, env := range []string{"development", "production"} {
		if _, err := auth.NewSecretBox("not-hex", env, "TEST_ENCRYPTION_KEY", testhelper.TestLogger()); err == nil {
			t.Errorf("env=%s: malformed key accepted", env)
		}
	}
}
