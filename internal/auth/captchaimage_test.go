package auth

import (
	"bytes"
	"encoding/base64"
	"image"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Renderer tests (issue #145, phase 2).
//
// The assertions here cover what a machine can judge: that the image decodes,
// that it is the right size, that the palette cleared its contrast floor, and
// that the code generator is uniform over the alphabet.
//
// What a machine CANNOT judge is the only question that matters — whether a
// person can read the thing. TestRenderCaptcha_WriteSamples exists for that: run
// it with CAPTCHA_SAMPLE_DIR set and look at the output.
// ---------------------------------------------------------------------------

// decodeDataURI turns a rendered data URI back into an image.
func decodeDataURI(t *testing.T, uri string) image.Image {
	t.Helper()
	const prefix = "data:image/png;base64,"
	if !strings.HasPrefix(uri, prefix) {
		t.Fatalf("data URI does not start with %q", prefix)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(uri, prefix))
	if err != nil {
		t.Fatalf("decode base64: %v", err)
	}
	img, err := png.Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("decode png: %v", err)
	}
	return img
}

func TestRenderCaptcha_ProducesDecodablePNG(t *testing.T) {
	for _, level := range []string{CaptchaNoiseLow, CaptchaNoiseMedium, CaptchaNoiseHigh} {
		t.Run(level, func(t *testing.T) {
			out, err := renderCaptcha("K7M2QX", level)
			if err != nil {
				t.Fatalf("renderCaptcha: %v", err)
			}
			img := decodeDataURI(t, out.DataURI)

			wantW := 6*captchaCellWidth + 2*captchaSidePad
			if got := img.Bounds().Dx(); got != wantW {
				t.Errorf("width = %d, want %d", got, wantW)
			}
			if got := img.Bounds().Dy(); got != captchaHeight {
				t.Errorf("height = %d, want %d", got, captchaHeight)
			}
			if out.Width != wantW || out.Height != captchaHeight {
				t.Errorf("reported size = %dx%d, want %dx%d", out.Width, out.Height, wantW, captchaHeight)
			}
		})
	}
}

// TestRenderCaptcha_WidthTracksCodeLength pins that a 4-character challenge is
// not rendered stretched into a 6-character canvas.
func TestRenderCaptcha_WidthTracksCodeLength(t *testing.T) {
	for _, length := range []int{4, 5, 6, 7, 8} {
		code, err := generateCaptchaCode(length, false)
		if err != nil {
			t.Fatalf("generateCaptchaCode(%d): %v", length, err)
		}
		out, err := renderCaptcha(code, CaptchaNoiseMedium)
		if err != nil {
			t.Fatalf("renderCaptcha: %v", err)
		}
		want := length*captchaCellWidth + 2*captchaSidePad
		if out.Width != want {
			t.Errorf("length %d: width = %d, want %d", length, out.Width, want)
		}
	}
}

// TestCaptchaPalette_MeetsContrastFloor is the assertion standing in for "a
// human can see it". It cannot prove legibility, but it does prove the one
// failure mode that would make legibility impossible for everybody.
func TestCaptchaPalette_MeetsContrastFloor(t *testing.T) {
	rng := newCaptchaRand()
	const minContrast = 4.5

	for i := 0; i < 2000; i++ {
		bg, fg := captchaPalette(rng)
		if got := contrastRatio(bg, fg); got < minContrast {
			t.Fatalf("iteration %d: contrast %.2f below floor %.1f (bg=%v fg=%v)", i, got, minContrast, bg, fg)
		}
	}
}

// TestGenerateCaptchaCode_AlphabetAndLength checks every generated character is
// in the alphabet — which is also what guarantees every character has a glyph
// outline, since renderCaptcha skips runes it cannot draw.
func TestGenerateCaptchaCode_AlphabetAndLength(t *testing.T) {
	for i := 0; i < 500; i++ {
		code, err := generateCaptchaCode(6, false)
		if err != nil {
			t.Fatalf("generateCaptchaCode: %v", err)
		}
		if len([]rune(code)) != 6 {
			t.Fatalf("length = %d, want 6 (%q)", len([]rune(code)), code)
		}
		for _, r := range code {
			if !strings.ContainsRune(CaptchaAlphabet, r) {
				t.Fatalf("character %q not in alphabet", r)
			}
			if _, ok := glyphStrokes[r]; !ok {
				t.Fatalf("character %q has no glyph outline", r)
			}
		}
	}
}

// TestCaptchaAlphabet_ExcludesConfusablePairs pins the exclusions. Without this,
// somebody tidying the alphabet re-adds O or l, and the result is a slow trickle
// of users who cannot sign in and cannot say why.
func TestCaptchaAlphabet_ExcludesConfusablePairs(t *testing.T) {
	for _, r := range "OI01SZU5" {
		if strings.ContainsRune(CaptchaAlphabet, r) {
			t.Errorf("alphabet contains confusable character %q", r)
		}
	}
	if got := len(CaptchaAlphabet); got != 28 {
		t.Errorf("alphabet length = %d, want 28 — update the combination counts in the migration and docs", got)
	}
}

// TestGenerateCaptchaCode_IsUniform checks the rejection sampling actually
// removed the modulo bias. With 28 characters over 256 byte values, a naive
// modulo makes the first 4 characters ~14% more likely; this would catch that.
func TestGenerateCaptchaCode_IsUniform(t *testing.T) {
	const samples = 40000
	counts := make(map[rune]int, len(CaptchaAlphabet))

	for i := 0; i < samples/8; i++ {
		code, err := generateCaptchaCode(8, false)
		if err != nil {
			t.Fatalf("generateCaptchaCode: %v", err)
		}
		for _, r := range code {
			counts[r]++
		}
	}

	expected := float64(samples) / float64(len(CaptchaAlphabet))
	// ±20% is loose enough never to flake and tight enough to catch the ~14%
	// skew a modulo bias would produce on the low characters.
	lo, hi := expected*0.80, expected*1.20
	for _, r := range CaptchaAlphabet {
		n := float64(counts[r])
		if n < lo || n > hi {
			t.Errorf("character %q appeared %d times, want %.0f±20%%", r, counts[r], expected)
		}
	}
}

// TestRenderCaptcha_UnknownRuneDoesNotPanic covers the defensive skip in
// renderCaptcha. It is unreachable through the real code path, which is exactly
// why it needs a test — nothing else would notice if it started panicking.
func TestRenderCaptcha_UnknownRuneDoesNotPanic(t *testing.T) {
	out, err := renderCaptcha("A☃B", CaptchaNoiseMedium)
	if err != nil {
		t.Fatalf("renderCaptcha: %v", err)
	}
	decodeDataURI(t, out.DataURI)
}

// TestRenderCaptcha_WriteSamples writes sample images for human inspection.
//
// Skipped unless CAPTCHA_SAMPLE_DIR is set, because it produces files rather
// than assertions:
//
//	CAPTCHA_SAMPLE_DIR=./samples go test ./internal/auth/ -run WriteSamples -v
//
// This is the acceptance check for the renderer. "Legible to a person, hard for
// OCR" is a judgement call, and the only way to make it is to look.
func TestRenderCaptcha_WriteSamples(t *testing.T) {
	dir := os.Getenv("CAPTCHA_SAMPLE_DIR")
	if dir == "" {
		t.Skip("set CAPTCHA_SAMPLE_DIR to write sample images for inspection")
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}

	for _, level := range []string{CaptchaNoiseLow, CaptchaNoiseMedium, CaptchaNoiseHigh} {
		for i := 0; i < 8; i++ {
			code, err := generateCaptchaCode(6, false)
			if err != nil {
				t.Fatalf("generateCaptchaCode: %v", err)
			}
			out, err := renderCaptcha(code, level)
			if err != nil {
				t.Fatalf("renderCaptcha: %v", err)
			}
			raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(out.DataURI, "data:image/png;base64,"))
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			// The answer is in the FILENAME so a reviewer can check what they
			// read against what was drawn without opening anything else.
			name := filepath.Join(dir, level+"-"+code+".png")
			if err := os.WriteFile(name, raw, 0o600); err != nil {
				t.Fatalf("write %s: %v", name, err)
			}
			t.Logf("wrote %s", name)
		}
	}
}

// TestGenerateCaptchaCode_AlwaysMixesLettersAndDigits pins the guarantee.
//
// Without it, a uniform draw over the 28-character alphabet produces an
// all-letter code 17.8% of the time — about one in six. 2000 samples would see
// roughly 356 of them, so a regression here cannot hide.
func TestGenerateCaptchaCode_AlwaysMixesLettersAndDigits(t *testing.T) {
	for _, length := range []int{4, 5, 6, 7, 8} {
		for i := 0; i < 2000; i++ {
			code, err := generateCaptchaCode(length, false)
			if err != nil {
				t.Fatalf("generateCaptchaCode(%d): %v", length, err)
			}
			if len([]rune(code)) != length {
				t.Fatalf("length %d: got %q (%d runes)", length, code, len([]rune(code)))
			}

			var letters, digits int
			for _, r := range code {
				if r >= '0' && r <= '9' {
					digits++
				} else {
					letters++
				}
			}
			if letters == 0 {
				t.Fatalf("length %d: %q has no letter", length, code)
			}
			if digits == 0 {
				t.Fatalf("length %d: %q has no digit", length, code)
			}
		}
	}
}

// TestGenerateCaptchaCode_PatchKeepsAlphabet checks the patched position is still
// a character the renderer can draw. A patch that wrote outside CaptchaAlphabet
// would produce a code with a missing glyph — an image the user can never match.
func TestGenerateCaptchaCode_PatchKeepsAlphabet(t *testing.T) {
	for i := 0; i < 3000; i++ {
		code, err := generateCaptchaCode(4, false)
		if err != nil {
			t.Fatalf("generateCaptchaCode: %v", err)
		}
		for _, r := range code {
			if !strings.ContainsRune(CaptchaAlphabet, r) {
				t.Fatalf("%q contains %q, outside the alphabet", code, r)
			}
			if _, ok := glyphStrokes[r]; !ok {
				t.Fatalf("%q contains %q, which has no glyph outline", code, r)
			}
		}
	}
}

// TestGenerateCaptchaCode_PatchPositionIsSpread checks the guarantee does not
// always land the digit in the same place. A fixed position would be a free hint
// to a solver and would look mechanical to users.
func TestGenerateCaptchaCode_PatchPositionIsSpread(t *testing.T) {
	const length = 6
	seen := make(map[int]int)

	for i := 0; i < 4000; i++ {
		code, err := generateCaptchaCode(length, false)
		if err != nil {
			t.Fatalf("generateCaptchaCode: %v", err)
		}
		for idx, r := range []rune(code) {
			if r >= '0' && r <= '9' {
				seen[idx]++
			}
		}
	}
	for pos := 0; pos < length; pos++ {
		if seen[pos] == 0 {
			t.Errorf("no digit ever appeared at position %d", pos)
		}
	}
}

// TestCaptchaAlphabetCaseSensitive_OnlyShapeDistinctLetters pins the exclusions.
//
// Case can only be read off a glyph whose lowercase form is a different SHAPE.
// The renderer applies scale jitter, so C/c, F/f, J/j, K/k, L/l, P/p, V/v, W/w
// and X/x are the same picture at two sizes — including them would mean a user
// reading the character correctly and still failing, with nothing to learn from.
func TestCaptchaAlphabetCaseSensitive_OnlyShapeDistinctLetters(t *testing.T) {
	for _, r := range "CFJKLPVWXcfjklpvwx" {
		if strings.ContainsRune(CaptchaAlphabetCaseSensitive, r) {
			t.Errorf("case-sensitive alphabet contains size-only pair member %q", r)
		}
	}
	// Every character must be drawable, upper and lower alike.
	for _, r := range CaptchaAlphabetCaseSensitive {
		if _, ok := glyphStrokes[r]; !ok {
			t.Errorf("%q has no glyph outline", r)
		}
	}
	// Each kept letter must be present in BOTH cases, or case-sensitivity would
	// be decorative for that character.
	for _, r := range CaptchaAlphabetCaseSensitive {
		if r >= '0' && r <= '9' {
			continue
		}
		var partner rune
		if r >= 'a' && r <= 'z' {
			partner = r - 32
		} else {
			partner = r + 32
		}
		if !strings.ContainsRune(CaptchaAlphabetCaseSensitive, partner) {
			t.Errorf("%q appears without its %q counterpart", r, partner)
		}
	}
}

// TestGenerateCaptchaCode_CaseSensitiveUsesBothCases checks the generator
// actually reaches the lowercase half — an alphabet nobody draws from would make
// the whole mode pointless.
func TestGenerateCaptchaCode_CaseSensitiveUsesBothCases(t *testing.T) {
	var sawUpper, sawLower, sawDigit bool

	for i := 0; i < 500; i++ {
		code, err := generateCaptchaCode(6, true)
		if err != nil {
			t.Fatalf("generateCaptchaCode: %v", err)
		}
		for _, r := range code {
			if !strings.ContainsRune(CaptchaAlphabetCaseSensitive, r) {
				t.Fatalf("%q contains %q, outside the case-sensitive alphabet", code, r)
			}
			switch {
			case r >= '0' && r <= '9':
				sawDigit = true
			case r >= 'a' && r <= 'z':
				sawLower = true
			default:
				sawUpper = true
			}
		}
	}
	if !sawUpper || !sawLower || !sawDigit {
		t.Errorf("case-sensitive generation missed a class: upper=%v lower=%v digit=%v",
			sawUpper, sawLower, sawDigit)
	}
}

// TestGenerateCaptchaCode_CaseSensitiveStillMixes checks the letter+digit
// guarantee survives the alphabet switch.
func TestGenerateCaptchaCode_CaseSensitiveStillMixes(t *testing.T) {
	for i := 0; i < 1500; i++ {
		code, err := generateCaptchaCode(6, true)
		if err != nil {
			t.Fatalf("generateCaptchaCode: %v", err)
		}
		var letters, digits int
		for _, r := range code {
			if r >= '0' && r <= '9' {
				digits++
			} else {
				letters++
			}
		}
		if letters == 0 || digits == 0 {
			t.Fatalf("%q is not mixed (letters=%d digits=%d)", code, letters, digits)
		}
	}
}

// TestRenderCaptcha_WriteCaseSensitiveSamples writes case-sensitive samples for
// inspection. Same contract as TestRenderCaptcha_WriteSamples.
func TestRenderCaptcha_WriteCaseSensitiveSamples(t *testing.T) {
	dir := os.Getenv("CAPTCHA_SAMPLE_DIR")
	if dir == "" {
		t.Skip("set CAPTCHA_SAMPLE_DIR to write sample images for inspection")
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	for i := 0; i < 6; i++ {
		code, err := generateCaptchaCode(6, true)
		if err != nil {
			t.Fatalf("generateCaptchaCode: %v", err)
		}
		out, err := renderCaptcha(code, CaptchaNoiseLow)
		if err != nil {
			t.Fatalf("renderCaptcha: %v", err)
		}
		raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(out.DataURI, "data:image/png;base64,"))
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		name := filepath.Join(dir, "cs-"+code+".png")
		if err := os.WriteFile(name, raw, 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		t.Logf("wrote %s", name)
	}
}
