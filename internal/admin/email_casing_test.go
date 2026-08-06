package admin_test

import (
	"context"
	"errors"
	"testing"

	"github.com/engineersmind/emc-auth-server/internal/admin"
	"github.com/engineersmind/emc-auth-server/internal/auth"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

// The reported bug: an owner invited as Subham.D@engineersmind.com could not
// sign in as subham.d@engineersmind.com. The invitation stored the address
// exactly as typed, while login matched users.email with a case-sensitive `=`,
// so the two were different accounts as far as the system was concerned.
//
// These tests pin both halves of the fix: writes canonicalize, and a second
// spelling of an address already taken is a collision rather than a new user.
func TestInviteUser_MixedCaseIsStoredCanonically(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	const invited = "Subham.D@Engineersmind.com"
	const canonical = "subham.d@engineersmind.com"

	res, err := f.svc.InviteUser(ctx, f.tenantID, nil, invited, "Subham", "D", nil, nil, "Operator")
	if err != nil {
		t.Fatalf("InviteUser(%q) error = %v", invited, err)
	}
	if res.Email != canonical {
		t.Errorf("stored email = %q, want %q", res.Email, canonical)
	}

	// The row itself, not just the DTO — login reads the column.
	var stored string
	if err := f.pool.QueryRow(ctx,
		`SELECT email FROM users WHERE id = $1`, res.ID,
	).Scan(&stored); err != nil {
		t.Fatalf("read back user: %v", err)
	}
	if stored != canonical {
		t.Errorf("users.email = %q, want %q — login would miss this row", stored, canonical)
	}

	// The invitation must reach the same address that was stored, otherwise the
	// recipient sets a password for an account they can never address again.
	invites := f.mail.Invitations()
	if len(invites) != 1 {
		t.Fatalf("got %d invitations, want 1", len(invites))
	}
	if invites[0].To != canonical {
		t.Errorf("invitation sent to %q, want %q", invites[0].To, canonical)
	}
}

// A case variant of an existing address is the SAME person. Before the fix both
// spellings satisfied every unique index and produced two parallel accounts.
func TestCreateUser_CaseVariantCollidesInsteadOfDuplicating(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	if _, err := f.svc.CreateUser(ctx, f.tenantID, nil, "casey@example.com", "Str0ngPass!", "Casey", "One", nil); err != nil {
		t.Fatalf("CreateUser(lowercase) error = %v", err)
	}
	_, err := f.svc.CreateUser(ctx, f.tenantID, nil, "Casey@Example.com", "Str0ngPass!", "Casey", "Two", nil)
	if !errors.Is(err, admin.ErrAlreadyExists) {
		t.Fatalf("CreateUser(mixed case) error = %v, want ErrAlreadyExists — a case variant must not become a second account", err)
	}
}

// End-to-end on the actual complaint: invited in one casing, signs in in
// another. This is the assertion that would have failed before the fix.
func TestLogin_SucceedsRegardlessOfCasing(t *testing.T) {
	f := newAdminFixture(t)
	ctx := context.Background()

	const password = "Str0ngPass!"
	if _, err := f.svc.CreateUser(ctx, f.tenantID, nil, "Subham.D@Engineersmind.com", password, "Subham", "D", nil); err != nil {
		t.Fatalf("CreateUser error = %v", err)
	}

	jwtSvc, err := auth.NewJWTService(f.pool, "emc-auth")
	if err != nil {
		t.Fatalf("NewJWTService: %v", err)
	}
	authSvc := auth.NewAuthService(f.pool, jwtSvc, testhelper.TestLogger())

	for _, typed := range []string{
		"subham.d@engineersmind.com", // what the user actually typed — used to fail
		"Subham.D@Engineersmind.com", // exactly as invited
		"SUBHAM.D@ENGINEERSMIND.COM",
		"  subham.d@engineersmind.com  ", // stray whitespace from a copy-paste
	} {
		// Tenant-level login (no app credentials): the account was created with
		// application_id NULL, which is the scope a plain login searches.
		if _, err := authSvc.Login(ctx, auth.LoginInput{
			Email:    typed,
			Password: password,
		}); err != nil {
			t.Errorf("Login(%q) error = %v, want success", typed, err)
		}
	}
}
