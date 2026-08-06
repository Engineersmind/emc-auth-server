package emailaddr

import "testing"

func TestNormalize(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"already canonical", "subham.d@engineersmind.com", "subham.d@engineersmind.com"},
		{"mixed case local part", "Subham.D@engineersmind.com", "subham.d@engineersmind.com"},
		{"mixed case domain", "subham.d@EngineersMind.COM", "subham.d@engineersmind.com"},
		{"surrounding whitespace", "  Subham.D@engineersmind.com\t", "subham.d@engineersmind.com"},
		{"empty", "", ""},
		// +tags and dots are provider-specific aliasing rules, not ours to apply.
		{"plus tag preserved", "Subham.D+audit@Example.com", "subham.d+audit@example.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Normalize(tc.in); got != tc.want {
				t.Errorf("Normalize(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// The bug this package exists to prevent: an invitation addressed in one casing
// and a login typed in another must resolve to a single account.
func TestEqual_InviteCasingMatchesLoginCasing(t *testing.T) {
	if !Equal("Subham.D@engineersmind.com", "subham.d@engineersmind.com") {
		t.Fatal("invited address and lowercase login should be the same account")
	}
	if Equal("subham.d@engineersmind.com", "subham.e@engineersmind.com") {
		t.Fatal("different addresses must not compare equal")
	}
}
