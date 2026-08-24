package auth

import (
	"embed"
	"encoding/json"
	"sync"

	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// AAGUID → authenticator model name.
//
// An AAGUID identifies the make and model of the authenticator that created a
// credential. It is the only thing that lets a settings page say "iPhone
// (iCloud Keychain)" instead of "Passkey 3", and a user with four passkeys
// cannot safely revoke one without being told which device it is.
//
// WHAT THIS IS NOT
//
// This is a DISPLAY LABEL and nothing else. It is read from an unattested
// authenticator response, so a hostile client can claim any AAGUID it likes.
// Never branch on it for a trust or policy decision — that is what attestation
// verification is for, and we do not do attestation (see AttestationPreference
// in NewWebAuthnService: we ask for 'none', because a metadata service we do not
// operate cannot be checked against). Treat the name exactly as you would treat
// a User-Agent string.
//
// PROVENANCE AND REFRESH
//
// aaguids.json is derived from the community AAGUID registry, which is itself
// built from the FIDO Alliance Metadata Service:
//
//	https://github.com/passkeydeveloper/passkey-authenticator-aaguids
//	https://fidoalliance.org/metadata/
//
// The upstream file carries base64 icons and is ~7 MB; we keep only the
// id → name mapping, which is 28 KB and embeddable. To refresh it:
//
//	curl -sSL -o aaguid.json \
//	  https://raw.githubusercontent.com/passkeydeveloper/passkey-authenticator-aaguids/main/combined_aaguid.json
//	python - <<'PY'
//	import json, collections
//	src = json.load(open('aaguid.json', encoding='utf-8'))
//	out = {k.lower(): v['name'] for k, v in src.items() if (v or {}).get('name')}
//	with open('internal/auth/aaguids.json', 'w', encoding='utf-8', newline='\n') as f:
//	    json.dump(collections.OrderedDict(sorted(out.items())), f, indent=1, ensure_ascii=False)
//	    f.write('\n')
//	PY
//
// A stale file costs nothing but an unnamed row: an AAGUID we do not know
// returns empty and the UI falls back to the user's own label.
// ---------------------------------------------------------------------------

//go:embed aaguids.json
var aaguidFS embed.FS

var (
	aaguidOnce  sync.Once
	aaguidNames map[string]string
)

// loadAAGUIDs parses the embedded registry once, on first use.
//
// A parse failure leaves the map empty rather than panicking. The consequence is
// that passkeys show without a model name, which is a cosmetic regression; the
// alternative — refusing to start, or failing a sign-in — would trade a label
// for an outage.
func loadAAGUIDs() map[string]string {
	aaguidOnce.Do(func() {
		aaguidNames = make(map[string]string)
		raw, err := aaguidFS.ReadFile("aaguids.json")
		if err != nil {
			return
		}
		var parsed map[string]string
		if err := json.Unmarshal(raw, &parsed); err != nil {
			return
		}
		aaguidNames = parsed
	})
	return aaguidNames
}

// AuthenticatorName maps a raw 16-byte AAGUID to its model name, or "" when the
// authenticator is unknown or did not identify itself.
//
// The all-zero AAGUID is the common case rather than an edge case: it is what an
// authenticator returns under 'none' attestation, which is what we ask for. So
// "" is a normal answer and every caller has to render it — it is not an error
// and must not be logged as one.
func AuthenticatorName(aaguid []byte) string {
	if len(aaguid) != 16 {
		return ""
	}
	id, err := uuid.FromBytes(aaguid)
	if err != nil || id == uuid.Nil {
		return ""
	}
	return loadAAGUIDs()[id.String()]
}

// AAGUIDString renders a raw AAGUID as its canonical UUID text, or "" when it is
// absent or all-zero.
//
// Returned to clients alongside the name so a frontend can pick its own icon for
// a model we have a name for but it has artwork for, and so an unknown
// authenticator is still reportable — an AAGUID nobody recognises is exactly
// what a support ticket needs to carry.
func AAGUIDString(aaguid []byte) string {
	if len(aaguid) != 16 {
		return ""
	}
	id, err := uuid.FromBytes(aaguid)
	if err != nil || id == uuid.Nil {
		return ""
	}
	return id.String()
}
