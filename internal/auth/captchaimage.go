package auth

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math"
)

// ---------------------------------------------------------------------------
// CAPTCHA image rendering (issue #145).
//
// Draws a code as distorted stroke outlines (see captchaglyphs.go) and encodes
// it as a PNG data URI.
//
// The pipeline, in order, and why each step is there:
//
//	1. colours      — random, but with a FORCED contrast floor. A captcha that
//	                  renders grey-on-grey is unreadable by everyone, which is a
//	                  worse outcome than no captcha at all.
//	2. per-glyph    — independent rotation, scale, and baseline offset for each
//	   transform      character. Per glyph, not per image: a single uniform
//	                  rotation is trivially undone by any solver that can find
//	                  the baseline, and undoing it costs one matrix.
//	3. wave warp    — a sine displacement applied to the outline points before
//	                  rasterising. Cheap, and it breaks template matching.
//	4. strike lines — two curves crossing the glyphs in the FOREGROUND colour.
//	                  These matter more than noise does: most OCR segments
//	                  characters by finding connected components, and a stroke
//	                  that joins every glyph to its neighbours defeats that step
//	                  before recognition is even attempted.
//	5. dot noise    — least valuable of the five, and the easiest to filter. It
//	                  is here because it costs nothing and raises the floor
//	                  against the laziest attacks.
//
// Everything random here comes from crypto/rand. Not because the visual jitter
// is security-critical — it is not — but because reaching for math/rand in a
// file that also generates the answer invites somebody to later use the
// convenient source for the code itself.
// ---------------------------------------------------------------------------

// Canvas geometry. Width scales with the code length so a 4-character challenge
// is not stretched and an 8-character one is not cramped.
const (
	captchaCellWidth  = 42
	captchaSidePad    = 14
	captchaHeight     = 84
	captchaGlyphTop   = 14
	captchaGlyphBot   = 70
	captchaStrokeHalf = 1.9 // half-width of a glyph stroke, in pixels
)

// CaptchaImage is a rendered challenge.
type CaptchaImage struct {
	// DataURI is the complete "data:image/png;base64,..." value, ready to be
	// dropped into an <img src>. Returned inline rather than from a second
	// endpoint: a separate image GET would put the challenge id in access logs
	// and fight caching, for no benefit to anybody.
	DataURI string
	// Width and Height are the rendered pixel dimensions, so a caller can size
	// the element without loading the image first.
	Width, Height int
}

// renderCaptcha draws code at the given noise level.
//
// Returns an error only if PNG encoding fails, which in practice means the
// process is out of memory — there is no input that can make this fail.
func renderCaptcha(code string, noiseLevel string) (CaptchaImage, error) {
	runes := []rune(code)
	width := len(runes)*captchaCellWidth + 2*captchaSidePad
	img := image.NewNRGBA(image.Rect(0, 0, width, captchaHeight))

	rng := newCaptchaRand()
	bg, fg := captchaPalette(rng)

	// Fill the background first so every later step composites over a known
	// colour rather than over transparent pixels, which would render as black in
	// clients that flatten PNG alpha against white.
	for y := 0; y < captchaHeight; y++ {
		for x := 0; x < width; x++ {
			img.SetNRGBA(x, y, bg)
		}
	}

	noise := noiseParams(noiseLevel)

	// A single wave shared by every glyph and both strike lines. Shared on
	// purpose: independent waves would look like each element had been jittered
	// separately, which reads as noise; one wave through everything reads as a
	// warped surface, which is harder to undo because it is globally consistent
	// but locally non-linear.
	wave := waveWarp{
		amplitude: noise.waveAmplitude * (0.6 + 0.8*rng.float()),
		period:    float64(width) / (1.0 + 1.5*rng.float()),
		phase:     rng.float() * 2 * math.Pi,
	}

	for i, r := range runes {
		strokes, ok := glyphStrokes[r]
		if !ok {
			// Unreachable: the code is generated from CaptchaAlphabet, and every
			// character in it has an outline. Skipping rather than failing means
			// a future alphabet change degrades to a shorter-looking challenge
			// instead of a 500 on the login path.
			continue
		}
		t := newGlyphTransform(rng, i, noise)
		for _, stroke := range strokes {
			pts := t.apply(stroke, wave)
			drawPolyline(img, pts, fg, captchaStrokeHalf*t.scale, bg)
		}
	}

	for i := 0; i < noise.strikeLines; i++ {
		drawPolyline(img, strikeLine(rng, width, wave), fg, captchaStrokeHalf*0.75, bg)
	}

	addDotNoise(img, rng, fg, noise.dots)

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return CaptchaImage{}, fmt.Errorf("encode captcha png: %w", err)
	}
	return CaptchaImage{
		DataURI: "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes()),
		Width:   width,
		Height:  captchaHeight,
	}, nil
}

// ---------------------------------------------------------------------------
// Noise levels
// ---------------------------------------------------------------------------

type captchaNoise struct {
	rotation      float64 // max per-glyph rotation, radians
	scaleJitter   float64 // max per-glyph scale deviation, fraction
	baselineJit   float64 // max per-glyph vertical offset, pixels
	waveAmplitude float64 // pixels
	strikeLines   int
	dots          int
}

// noiseParams maps a policy noise level to rendering parameters.
//
// 'high' is genuinely hard for people, not only for machines — which is why the
// admin console renders a live sample beside the field. An operator who cannot
// read their own preview has learnt something useful before their users do.
func noiseParams(level string) captchaNoise {
	switch level {
	case CaptchaNoiseLow:
		return captchaNoise{
			rotation: 0.16, scaleJitter: 0.07, baselineJit: 3,
			waveAmplitude: 2.0, strikeLines: 1, dots: 60,
		}
	case CaptchaNoiseHigh:
		return captchaNoise{
			rotation: 0.52, scaleJitter: 0.18, baselineJit: 8,
			waveAmplitude: 6.0, strikeLines: 3, dots: 340,
		}
	default: // CaptchaNoiseMedium
		return captchaNoise{
			rotation: 0.34, scaleJitter: 0.13, baselineJit: 5,
			waveAmplitude: 4.0, strikeLines: 2, dots: 170,
		}
	}
}

// ---------------------------------------------------------------------------
// Geometry
// ---------------------------------------------------------------------------

// waveWarp is a horizontal sine displacement applied to y.
type waveWarp struct {
	amplitude float64
	period    float64
	phase     float64
}

func (w waveWarp) at(x float64) float64 {
	if w.period == 0 {
		return 0
	}
	return w.amplitude * math.Sin(2*math.Pi*x/w.period+w.phase)
}

// glyphTransform maps a glyph's unit-grid outline onto the canvas.
type glyphTransform struct {
	cx, cy float64 // centre of the glyph's cell
	halfW  float64
	halfH  float64
	sin    float64
	cos    float64
	scale  float64
}

func newGlyphTransform(rng *captchaRand, index int, noise captchaNoise) glyphTransform {
	angle := (rng.float()*2 - 1) * noise.rotation
	scale := 1 + (rng.float()*2-1)*noise.scaleJitter

	cellLeft := float64(captchaSidePad + index*captchaCellWidth)
	// A small horizontal wobble inside the cell, so glyph centres are not on a
	// perfectly regular pitch. A fixed pitch is a free gift to a segmenter.
	cx := cellLeft + float64(captchaCellWidth)/2 + (rng.float()*2-1)*3
	cy := float64(captchaGlyphTop+captchaGlyphBot)/2 + (rng.float()*2-1)*noise.baselineJit

	return glyphTransform{
		cx: cx, cy: cy,
		halfW: float64(captchaCellWidth) * 0.40,
		halfH: float64(captchaGlyphBot-captchaGlyphTop) / 2,
		sin:   math.Sin(angle),
		cos:   math.Cos(angle),
		scale: scale,
	}
}

// apply maps unit-grid points to canvas pixels: centre, scale, rotate, translate,
// then warp. The warp is last so it displaces the final position rather than
// being rotated along with the glyph — a wave that rotated with each character
// would cancel out visually and cost the distortion its point.
func (t glyphTransform) apply(stroke []glyphPoint, wave waveWarp) []glyphPoint {
	out := make([]glyphPoint, len(stroke))
	for i, p := range stroke {
		x := (p.X - 0.5) * 2 * t.halfW * t.scale
		y := (p.Y - 0.5) * 2 * t.halfH * t.scale
		rx := x*t.cos - y*t.sin
		ry := x*t.sin + y*t.cos
		cx := t.cx + rx
		cy := t.cy + ry + wave.at(t.cx+rx)
		out[i] = glyphPoint{X: cx, Y: cy}
	}
	return out
}

// strikeLine builds a curve crossing the whole canvas.
//
// It enters and leaves at random heights and bows through two control heights in
// between, so it is not a straight line that could be found and subtracted with
// a Hough transform.
func strikeLine(rng *captchaRand, width int, wave waveWarp) []glyphPoint {
	const steps = 24
	y0 := 0.15 + rng.float()*0.7
	y1 := 0.15 + rng.float()*0.7
	bow := (rng.float()*2 - 1) * 0.35

	pts := make([]glyphPoint, 0, steps+1)
	for i := 0; i <= steps; i++ {
		u := float64(i) / steps
		// Quadratic in u: endpoints interpolate y0→y1, the bow term peaks in the
		// middle and vanishes at both ends.
		frac := y0 + (y1-y0)*u + bow*math.Sin(math.Pi*u)
		x := u * float64(width)
		pts = append(pts, glyphPoint{
			X: x,
			Y: frac*captchaHeight + wave.at(x),
		})
	}
	return pts
}

// ---------------------------------------------------------------------------
// Rasterising
// ---------------------------------------------------------------------------

// drawPolyline renders a thick anti-aliased polyline.
//
// Distance-based rather than scanline-based: for each pixel near a segment the
// coverage is derived from its distance to that segment, which gives free
// round joins and caps and antialiasing that does not depend on stroke
// direction. It costs more arithmetic than Bresenham, but only over the
// segment's bounding box, which is a few hundred pixels.
func drawPolyline(img *image.NRGBA, pts []glyphPoint, fg color.NRGBA, halfWidth float64, bg color.NRGBA) {
	if len(pts) < 2 || halfWidth <= 0 {
		return
	}
	bounds := img.Bounds()
	// One pixel of falloff outside the nominal edge is what produces the
	// antialiasing; without it the stroke is hard-edged and every glyph looks
	// like it was drawn with a different tool than the strike lines.
	const feather = 1.0

	for i := 0; i+1 < len(pts); i++ {
		a, b := pts[i], pts[i+1]

		minX := int(math.Floor(math.Min(a.X, b.X) - halfWidth - feather))
		maxX := int(math.Ceil(math.Max(a.X, b.X) + halfWidth + feather))
		minY := int(math.Floor(math.Min(a.Y, b.Y) - halfWidth - feather))
		maxY := int(math.Ceil(math.Max(a.Y, b.Y) + halfWidth + feather))

		if minX < bounds.Min.X {
			minX = bounds.Min.X
		}
		if minY < bounds.Min.Y {
			minY = bounds.Min.Y
		}
		if maxX > bounds.Max.X-1 {
			maxX = bounds.Max.X - 1
		}
		if maxY > bounds.Max.Y-1 {
			maxY = bounds.Max.Y - 1
		}

		for y := minY; y <= maxY; y++ {
			for x := minX; x <= maxX; x++ {
				d := distanceToSegment(float64(x)+0.5, float64(y)+0.5, a, b)
				if d > halfWidth+feather {
					continue
				}
				alpha := 1.0
				if d > halfWidth {
					alpha = 1 - (d-halfWidth)/feather
				}
				if alpha <= 0 {
					continue
				}
				blendPixel(img, x, y, fg, alpha)
			}
		}
	}
	_ = bg
}

// distanceToSegment is the perpendicular distance from (px,py) to segment a→b,
// clamped to the segment's endpoints.
func distanceToSegment(px, py float64, a, b glyphPoint) float64 {
	dx, dy := b.X-a.X, b.Y-a.Y
	lenSq := dx*dx + dy*dy
	if lenSq == 0 {
		return math.Hypot(px-a.X, py-a.Y)
	}
	t := ((px-a.X)*dx + (py-a.Y)*dy) / lenSq
	switch {
	case t < 0:
		t = 0
	case t > 1:
		t = 1
	}
	return math.Hypot(px-(a.X+t*dx), py-(a.Y+t*dy))
}

// blendPixel composites fg over the existing pixel at the given coverage.
func blendPixel(img *image.NRGBA, x, y int, fg color.NRGBA, alpha float64) {
	if alpha > 1 {
		alpha = 1
	}
	cur := img.NRGBAAt(x, y)
	img.SetNRGBA(x, y, color.NRGBA{
		R: blendChannel(cur.R, fg.R, alpha),
		G: blendChannel(cur.G, fg.G, alpha),
		B: blendChannel(cur.B, fg.B, alpha),
		A: 255,
	})
}

func blendChannel(dst, src uint8, alpha float64) uint8 {
	v := float64(dst)*(1-alpha) + float64(src)*alpha
	switch {
	case v < 0:
		return 0
	case v > 255:
		return 255
	}
	return uint8(v)
}

// addDotNoise speckles the canvas with foreground-coloured dots at varying
// opacity. Varying, because a field of identical full-opacity dots is removable
// with a single threshold pass.
func addDotNoise(img *image.NRGBA, rng *captchaRand, fg color.NRGBA, count int) {
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	for i := 0; i < count; i++ {
		x := int(rng.float() * float64(w))
		y := int(rng.float() * float64(h))
		if x >= w {
			x = w - 1
		}
		if y >= h {
			y = h - 1
		}
		blendPixel(img, x, y, fg, 0.25+rng.float()*0.6)
	}
}

// ---------------------------------------------------------------------------
// Colour
// ---------------------------------------------------------------------------

// captchaPalette picks a background and foreground with a guaranteed contrast
// ratio.
//
// The loop is not decorative. Random hues at random lightness produce an
// unreadable pair often enough that shipping without the check would mean a
// steady trickle of users who simply cannot see the code — and who have no way
// to describe the problem beyond "the captcha is broken". WCAG AA for large text
// is 3:1; 4.5:1 is used here because the glyphs are thin, warped, and crossed by
// strike lines, none of which the ratio accounts for.
func captchaPalette(rng *captchaRand) (bg, fg color.NRGBA) {
	const minContrast = 4.5

	for attempt := 0; attempt < 24; attempt++ {
		hue := rng.float() * 360
		bg = hslToNRGBA(hue, 0.20+rng.float()*0.25, 0.86+rng.float()*0.09)
		// Rotating the hue keeps the pair visually related rather than arbitrary,
		// which looks deliberate instead of broken.
		fgHue := math.Mod(hue+120+rng.float()*120, 360)
		fg = hslToNRGBA(fgHue, 0.45+rng.float()*0.4, 0.12+rng.float()*0.18)

		if contrastRatio(bg, fg) >= minContrast {
			return bg, fg
		}
	}
	// Deterministic fallback after 24 failures. Reaching this is essentially
	// impossible given the lightness ranges above, but "essentially impossible"
	// on an authentication path deserves a defined outcome rather than whatever
	// the last iteration happened to produce.
	return color.NRGBA{R: 0xF2, G: 0xF4, B: 0xF8, A: 255},
		color.NRGBA{R: 0x1A, G: 0x1E, B: 0x2C, A: 255}
}

// contrastRatio is the WCAG 2.1 contrast ratio between two opaque colours.
func contrastRatio(a, b color.NRGBA) float64 {
	la, lb := relativeLuminance(a), relativeLuminance(b)
	if la < lb {
		la, lb = lb, la
	}
	return (la + 0.05) / (lb + 0.05)
}

// relativeLuminance is the WCAG 2.1 relative luminance of an opaque colour.
func relativeLuminance(c color.NRGBA) float64 {
	lin := func(v uint8) float64 {
		f := float64(v) / 255
		if f <= 0.03928 {
			return f / 12.92
		}
		return math.Pow((f+0.055)/1.055, 2.4)
	}
	return 0.2126*lin(c.R) + 0.7152*lin(c.G) + 0.0722*lin(c.B)
}

// hslToNRGBA converts HSL (hue in degrees, saturation and lightness in 0..1).
// HSL rather than RGB because lightness is the axis contrast depends on, so
// bounding it directly is what makes the palette loop converge quickly.
func hslToNRGBA(h, s, l float64) color.NRGBA {
	c := (1 - math.Abs(2*l-1)) * s
	hp := math.Mod(h, 360) / 60
	x := c * (1 - math.Abs(math.Mod(hp, 2)-1))

	var r, g, b float64
	switch {
	case hp < 1:
		r, g, b = c, x, 0
	case hp < 2:
		r, g, b = x, c, 0
	case hp < 3:
		r, g, b = 0, c, x
	case hp < 4:
		r, g, b = 0, x, c
	case hp < 5:
		r, g, b = x, 0, c
	default:
		r, g, b = c, 0, x
	}
	m := l - c/2
	to8 := func(v float64) uint8 {
		f := (v + m) * 255
		switch {
		case f < 0:
			return 0
		case f > 255:
			return 255
		}
		return uint8(f)
	}
	return color.NRGBA{R: to8(r), G: to8(g), B: to8(b), A: 255}
}

// ---------------------------------------------------------------------------
// Randomness
// ---------------------------------------------------------------------------

// captchaRand hands out random floats from a crypto/rand-filled buffer.
//
// Buffered because rendering asks for a few hundred values and one syscall per
// value would make image generation a measurable cost on an unauthenticated
// endpoint. crypto/rand rather than math/rand even for the visual jitter: this
// package also generates the answer, and a convenient weak source sitting in the
// same file is how the wrong one eventually gets used.
type captchaRand struct {
	buf []byte
	pos int
}

func newCaptchaRand() *captchaRand {
	return &captchaRand{}
}

// float returns a value in [0,1).
func (r *captchaRand) float() float64 {
	if r.pos+8 > len(r.buf) {
		r.refill()
	}
	v := binary.BigEndian.Uint64(r.buf[r.pos : r.pos+8])
	r.pos += 8
	// 53 bits is the mantissa of a float64; taking more would add bits that
	// cannot be represented and bias the low end.
	return float64(v>>11) / float64(uint64(1)<<53)
}

func (r *captchaRand) refill() {
	r.buf = make([]byte, 4096)
	// crypto/rand.Read is documented never to return an error on any supported
	// platform since Go 1.24; it panics internally if the OS source fails. The
	// error is ignored deliberately rather than silently.
	_, _ = rand.Read(r.buf)
	r.pos = 0
}

// generateCaptchaCode returns a code of the given length, guaranteed to contain
// at least one letter and at least one digit.
//
// # WHY THE GUARANTEE
//
// Drawing uniformly from the 28-character alphabet leaves 21/28 of each position
// a letter, so a 6-character code comes out ALL letters 17.8% of the time —
// roughly one in six. Those codes read as a word-shaped blob rather than the
// mixed alphanumeric string users are told to expect, and a user who has been
// shown five mixed codes and then gets "TWFW" reasonably wonders whether the
// image is broken. The digit is doing UX work here, not security work.
//
// Rejection sampling rather than modulo: 256 is not a multiple of 28, so a plain
// modulo would make the first four characters of the alphabet measurably more
// likely. That bias is not exploitable at this scale — a challenge is single-use
// and TTL-bounded, so an attacker gets about one guess — but it is not worth
// carrying in a file somebody may later copy into a context where it matters.
func generateCaptchaCode(length int, caseSensitive bool) (string, error) {
	alphabet := CaptchaAlphabet
	if caseSensitive {
		alphabet = CaptchaAlphabetCaseSensitive
	}

	if length < 2 {
		// Below two characters the mix is unsatisfiable. The policy CHECK floors
		// code_length at 4, so this is defensive only.
		return randomCaptchaRun(length, alphabet)
	}

	out, err := randomCaptchaRun(length, alphabet)
	if err != nil {
		return "", err
	}

	// Patch rather than re-roll. Re-rolling until the mix appears would loop an
	// unbounded number of times for an unlucky seed, on an unauthenticated
	// endpoint; patching is one pass and the positions chosen are themselves
	// random, so the result stays uniform over codes that satisfy the rule.
	runes := []rune(out)
	hasLetter, hasDigit := false, false
	for _, r := range runes {
		if r >= '0' && r <= '9' {
			hasDigit = true
		} else {
			hasLetter = true
		}
	}

	letters, digits := splitCaptchaAlphabet(alphabet)
	if !hasDigit {
		if err := patchCaptchaRune(runes, digits); err != nil {
			return "", err
		}
	} else if !hasLetter {
		if err := patchCaptchaRune(runes, letters); err != nil {
			return "", err
		}
	}
	return string(runes), nil
}

// splitCaptchaAlphabet partitions an alphabet into its letters and its digits.
//
// Derived from the alphabet actually in use rather than written out, so it
// cannot drift from it — a hand-maintained copy would silently start producing
// characters with no glyph outline, and the user would be shown an image they
// could never match.
func splitCaptchaAlphabet(alphabet string) (letters, digits string) {
	var l, d []rune
	for _, r := range alphabet {
		if r >= '0' && r <= '9' {
			d = append(d, r)
		} else {
			l = append(l, r)
		}
	}
	return string(l), string(d)
}

// patchCaptchaRune replaces one randomly chosen position with a character from
// the given set.
func patchCaptchaRune(runes []rune, set string) error {
	idxBuf := make([]byte, 1)

	// Uniform over positions, by rejection for the same reason as above.
	//
	// posLimit is an int, NOT a byte. When len(runes) divides 256 — which it does
	// for the common lengths 4 and 8 — the remainder is zero and byte(256)
	// wraps to 0, so `b < posLimit` is never true and the loop never ends. That
	// is a hang on an unauthenticated endpoint, and it is exactly what happened
	// before this was widened.
	posLimit := 256 - (256 % len(runes))
	for {
		if _, err := rand.Read(idxBuf); err != nil {
			return fmt.Errorf("generate captcha code: %w", err)
		}
		if int(idxBuf[0]) < posLimit {
			break
		}
	}
	at := int(idxBuf[0]) % len(runes)

	replacement, err := randomCaptchaRun(1, set)
	if err != nil {
		return err
	}
	runes[at] = []rune(replacement)[0]
	return nil
}

// randomCaptchaRun draws length characters uniformly from alphabet.
func randomCaptchaRun(length int, alphabet string) (string, error) {
	if length <= 0 {
		return "", nil
	}
	chars := []rune(alphabet)
	// int, not byte — see patchCaptchaRune for why byte(256) is a trap. An
	// alphabet whose length divides 256 would otherwise reject every draw.
	limit := 256 - (256 % len(chars))

	out := make([]rune, 0, length)
	buf := make([]byte, length*2+8)
	for len(out) < length {
		if _, err := rand.Read(buf); err != nil {
			return "", fmt.Errorf("generate captcha code: %w", err)
		}
		for _, b := range buf {
			if int(b) >= limit {
				continue
			}
			out = append(out, chars[int(b)%len(chars)])
			if len(out) == length {
				break
			}
		}
	}
	return string(out), nil
}
