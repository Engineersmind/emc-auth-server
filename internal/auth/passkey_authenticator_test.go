package auth_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// ---------------------------------------------------------------------------
// A virtual authenticator.
//
// The ticket's acceptance criteria include "no mocks for the WebAuthn
// verification path", and that is the right call: the verification path is the
// entire security value of this feature, and a fake that returns "verified"
// tests our plumbing while proving nothing about the thing an attacker attacks.
//
// So this produces REAL ceremony responses — a real P-256 key, a real COSE
// public key, real CBOR attestation objects, and real ECDSA signatures over
// authenticatorData ‖ SHA256(clientDataJSON). The library verifies them exactly
// as it verifies Windows Hello, and a test that passes here proves the
// signature, the challenge binding, the origin check, and the RP ID hash all
// hold.
//
// What it does NOT do is attestation beyond 'none'. That is deliberate and
// matches production: we request PreferNoAttestation because we operate no
// metadata service to check a real attestation against (see aaguid.go).
// ---------------------------------------------------------------------------

// virtualAuthenticator is one simulated device holding one credential.
type virtualAuthenticator struct {
	key    *ecdsa.PrivateKey
	credID []byte
	aaguid []byte

	// signCount is what the authenticator reports and increments. Settable so a
	// test can force the regression that clone detection looks for — the whole
	// point of modelling it rather than always sending zero.
	signCount uint32

	// userVerified, backupEligible and backupState are the flag bits. Exposed
	// because every one of them changes a server decision: UV decides whether the
	// token may claim two factors, and a change in backupEligible is the clone
	// signal that actually fires on real hardware.
	userVerified   bool
	backupEligible bool
	backupState    bool

	// discoverable drives the credProps extension result. false is what an
	// authenticator that ignored residentKey:required would send, and the server
	// must refuse it.
	discoverable bool
}

// authenticator flag bits, per WebAuthn §6.1.
const (
	flagUserPresent    = 0x01
	flagUserVerified   = 0x04
	flagBackupEligible = 0x08
	flagBackupState    = 0x10
	flagAttestedCred   = 0x40
)

// newVirtualAuthenticator builds a device with the defaults a modern platform
// authenticator reports: user verification performed, synced (backup eligible
// and backed up), discoverable, and a signature counter of zero.
//
// Zero is not laziness — Apple and Google authenticators genuinely always report
// 0, which is why sign-counter clone detection is inert for most real passkeys.
// Starting here keeps the tests honest about that.
func newVirtualAuthenticator(t *testing.T) *virtualAuthenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate authenticator key: %v", err)
	}
	credID := make([]byte, 32)
	if _, err := rand.Read(credID); err != nil {
		t.Fatalf("generate credential id: %v", err)
	}
	// The Windows Hello AAGUID, so the AAGUID→name lookup is exercised with a
	// value the embedded registry actually knows.
	aaguid := mustDecodeAAGUID(t, "08987058-cadc-4b81-b6e1-30de50dcbe96")

	return &virtualAuthenticator{
		key: key, credID: credID, aaguid: aaguid,
		userVerified: true, backupEligible: true, backupState: true,
		discoverable: true,
	}
}

func mustDecodeAAGUID(t *testing.T, s string) []byte {
	t.Helper()
	hexOnly := strings.ReplaceAll(s, "-", "")
	out := make([]byte, 16)
	for i := 0; i < 16; i++ {
		var b byte
		if _, err := fmt.Sscanf(hexOnly[i*2:i*2+2], "%02x", &b); err != nil {
			t.Fatalf("decode aaguid: %v", err)
		}
		out[i] = b
	}
	return out
}

// flags assembles the flag byte for an assertion (no attested credential data).
func (a *virtualAuthenticator) flags(attested bool) byte {
	var f byte = flagUserPresent
	if a.userVerified {
		f |= flagUserVerified
	}
	if a.backupEligible {
		f |= flagBackupEligible
	}
	if a.backupState {
		f |= flagBackupState
	}
	if attested {
		f |= flagAttestedCred
	}
	return f
}

// cosePublicKey encodes the credential's public key as a COSE_Key, which is the
// format the server stores verbatim and the library parses on every assertion.
func (a *virtualAuthenticator) cosePublicKey(t *testing.T) []byte {
	t.Helper()
	// Integer keys per RFC 8152: 1=kty, 3=alg, -1=crv, -2=x, -3=y.
	// kty 2 = EC2, alg -7 = ES256, crv 1 = P-256.
	key := map[int]any{
		1:  2,
		3:  -7,
		-1: 1,
		-2: a.key.X.FillBytes(make([]byte, 32)),
		-3: a.key.Y.FillBytes(make([]byte, 32)),
	}
	enc, err := cbor.Marshal(key)
	if err != nil {
		t.Fatalf("encode COSE key: %v", err)
	}
	return enc
}

// authData builds authenticatorData. rpID is hashed rather than passed in
// hashed, so a test that wants an RP-ID mismatch simply passes a different
// string — which is the check being exercised.
func (a *virtualAuthenticator) authData(t *testing.T, rpID string, attested bool) []byte {
	t.Helper()
	rpIDHash := sha256.Sum256([]byte(rpID))

	out := make([]byte, 0, 128)
	out = append(out, rpIDHash[:]...)
	out = append(out, a.flags(attested))

	counter := make([]byte, 4)
	binary.BigEndian.PutUint32(counter, a.signCount)
	out = append(out, counter...)

	if attested {
		out = append(out, a.aaguid...)
		credIDLen := make([]byte, 2)
		// Credential IDs here are a fixed 32 bytes, so the conversion cannot
		// overflow; the spec's own field is a uint16 either way.
		binary.BigEndian.PutUint16(credIDLen, uint16(len(a.credID))) //nolint:gosec
		out = append(out, credIDLen...)
		out = append(out, a.credID...)
		out = append(out, a.cosePublicKey(t)...)
	}
	return out
}

// clientDataJSON builds the client data the browser would send. Its exact bytes
// are what the signature covers, which is why the server never re-serialises the
// request body.
func clientDataJSON(t *testing.T, ceremonyType, challenge, origin string) []byte {
	t.Helper()
	cd := map[string]any{
		"type":        ceremonyType,
		"challenge":   challenge,
		"origin":      origin,
		"crossOrigin": false,
	}
	raw, err := json.Marshal(cd)
	if err != nil {
		t.Fatalf("marshal clientDataJSON: %v", err)
	}
	return raw
}

// AttestationRequest builds the POST body for register/complete.
//
// The challenge arrives already base64url-encoded, exactly as the server put it
// in the creation options, because that is the string the browser echoes back —
// re-encoding it here would test our encoder rather than the server's binding.
func (a *virtualAuthenticator) AttestationRequest(t *testing.T, rpID, origin, challengeB64 string) *http.Request {
	t.Helper()
	authData := a.authData(t, rpID, true)

	attObj, err := cbor.Marshal(map[string]any{
		"fmt":      "none",
		"attStmt":  map[string]any{},
		"authData": authData,
	})
	if err != nil {
		t.Fatalf("encode attestation object: %v", err)
	}

	clientData := clientDataJSON(t, "webauthn.create", challengeB64, origin)

	body := map[string]any{
		"id":    b64(a.credID),
		"rawId": b64(a.credID),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64(clientData),
			"attestationObject": b64(attObj),
		},
		"clientExtensionResults": map[string]any{
			"credProps": map[string]any{"rk": a.discoverable},
		},
	}
	return jsonPost(t, body)
}

// AssertionRequest builds the POST body for login/complete, signing over
// authenticatorData ‖ SHA256(clientDataJSON) as the spec requires.
func (a *virtualAuthenticator) AssertionRequest(t *testing.T, rpID, origin, challengeB64 string, userHandle []byte) *http.Request {
	t.Helper()
	authData := a.authData(t, rpID, false)
	clientData := clientDataJSON(t, "webauthn.get", challengeB64, origin)

	clientDataHash := sha256.Sum256(clientData)
	signed := append(append([]byte{}, authData...), clientDataHash[:]...)
	digest := sha256.Sum256(signed)

	// ASN.1 DER, which is what the WebAuthn spec requires for ES256 and what the
	// library's verifier expects. A raw r‖s signature verifies nowhere.
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		t.Fatalf("sign assertion: %v", err)
	}

	body := map[string]any{
		"id":    b64(a.credID),
		"rawId": b64(a.credID),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64(clientData),
			"authenticatorData": b64(authData),
			"signature":         b64(sig),
			"userHandle":        b64(userHandle),
		},
		"clientExtensionResults": map[string]any{},
	}
	return jsonPost(t, body)
}

func b64(in []byte) string { return base64.RawURLEncoding.EncodeToString(in) }

func jsonPost(t *testing.T, body map[string]any) *http.Request {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal ceremony response: %v", err)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "/", strings.NewReader(string(raw)))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	return req
}
