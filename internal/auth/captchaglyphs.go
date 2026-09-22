package auth

// ---------------------------------------------------------------------------
// CAPTCHA glyph outlines (issue #145).
//
// Each character is a set of polylines on a unit grid — (0,0) top-left, (1,1)
// bottom-right — rather than a rendered font.
//
// WHY NOT A FONT
//
// The obvious implementation embeds a TTF and rasterises with
// golang.org/x/image/font. That was the original plan and it was dropped for two
// reasons, in this order:
//
//  1. It adds a dependency and a licensed binary asset to a repository whose
//     whole shape is "one Go binary, no external anything". This feature is a
//     speed bump; it should not be the thing that changes the dependency graph.
//
//  2. Distorting a rendered bitmap means warping pixels that have already been
//     committed to a grid — you get soft, smeared glyphs, and the distortion is
//     uniform across the whole character. Distorting the OUTLINE instead means
//     every stroke moves independently before anything is rasterised, so the
//     result stays crisp at any rotation and the deformation is genuinely
//     per-stroke. That is both easier for a person to read and harder for
//     template matching, which is the trade this feature exists to make.
//
// The cost is that these 28 shapes are hand-written and look hand-drawn. For a
// captcha that is not a defect.
//
// THE ALPHABET
//
// 21 letters and 7 digits. Excluded on purpose: O and 0, I and 1 (and lowercase
// l, which is why the alphabet is uppercase-only), S and 5, Z and 2, and U,
// which is indistinguishable from V once rotated. A captcha a human cannot read
// is an outage with extra steps, and every one of those pairs is a support
// ticket waiting to happen.
//
// B and 8 are BOTH kept, which looks like an oversight and is not: in these
// outlines B has a straight left stem and 8 is two closed loops, so they stay
// distinguishable under rotation in a way the excluded pairs do not. If the
// outlines are ever redrawn, re-check that.
//
// 28 characters over the default length of 6 is ~4.8e8 combinations. That number
// is not what makes guessing hard — a challenge is single-use and TTL-bounded,
// so an attacker is limited by how many challenges they can obtain, not by the
// size of the answer space. It is here so the answer space is never the weakest
// link.
// ---------------------------------------------------------------------------

// CaptchaAlphabet is the set of characters a challenge is drawn from, in a fixed
// order. Stored uppercase; answers are upper-cased before comparison unless the
// policy sets case_sensitive.
const CaptchaAlphabet = "ABCDEFGHJKLMNPQRTVWXY2346789"

// glyphPoint is a coordinate on the unit grid.
type glyphPoint struct{ X, Y float64 }

// glyphStrokes maps a character to its polylines. Curves are approximated by
// enough points that a segment is never long enough to read as a straight edge
// at the sizes this renders at.
var glyphStrokes = map[rune][][]glyphPoint{
	'A': {
		{{0.05, 1.00}, {0.50, 0.00}, {0.95, 1.00}},
		{{0.22, 0.62}, {0.78, 0.62}},
	},
	'B': {
		{{0.15, 0.00}, {0.15, 1.00}},
		{{0.15, 0.00}, {0.62, 0.06}, {0.76, 0.24}, {0.66, 0.44}, {0.15, 0.50}},
		{{0.15, 0.50}, {0.70, 0.56}, {0.82, 0.76}, {0.68, 0.94}, {0.15, 1.00}},
	},
	'C': {
		{{0.88, 0.20}, {0.66, 0.03}, {0.36, 0.03}, {0.13, 0.26}, {0.10, 0.55},
			{0.20, 0.85}, {0.48, 0.99}, {0.78, 0.92}, {0.90, 0.78}},
	},
	'D': {
		{{0.15, 0.00}, {0.15, 1.00}},
		{{0.15, 0.00}, {0.58, 0.05}, {0.84, 0.28}, {0.86, 0.58}, {0.66, 0.92}, {0.15, 1.00}},
	},
	'E': {
		{{0.88, 0.02}, {0.16, 0.02}, {0.16, 0.98}, {0.88, 0.98}},
		{{0.16, 0.50}, {0.70, 0.50}},
	},
	'F': {
		{{0.88, 0.02}, {0.16, 0.02}, {0.16, 1.00}},
		{{0.16, 0.48}, {0.70, 0.48}},
	},
	'G': {
		{{0.88, 0.20}, {0.64, 0.03}, {0.34, 0.04}, {0.12, 0.28}, {0.11, 0.60},
			{0.28, 0.92}, {0.62, 0.98}, {0.86, 0.80}, {0.86, 0.56}, {0.56, 0.56}},
	},
	'H': {
		{{0.15, 0.00}, {0.15, 1.00}},
		{{0.85, 0.00}, {0.85, 1.00}},
		{{0.15, 0.50}, {0.85, 0.50}},
	},
	'J': {
		{{0.74, 0.00}, {0.74, 0.72}, {0.62, 0.94}, {0.36, 1.00}, {0.14, 0.84}},
	},
	'K': {
		{{0.16, 0.00}, {0.16, 1.00}},
		{{0.86, 0.00}, {0.16, 0.56}},
		{{0.36, 0.42}, {0.88, 1.00}},
	},
	'L': {
		{{0.20, 0.00}, {0.20, 0.98}, {0.86, 0.98}},
	},
	'M': {
		{{0.08, 1.00}, {0.08, 0.00}, {0.50, 0.62}, {0.92, 0.00}, {0.92, 1.00}},
	},
	'N': {
		{{0.15, 1.00}, {0.15, 0.00}, {0.85, 1.00}, {0.85, 0.00}},
	},
	'P': {
		{{0.16, 1.00}, {0.16, 0.00}},
		{{0.16, 0.00}, {0.68, 0.06}, {0.82, 0.28}, {0.68, 0.50}, {0.16, 0.56}},
	},
	'Q': {
		{{0.50, 0.02}, {0.22, 0.18}, {0.11, 0.50}, {0.22, 0.82}, {0.50, 0.98},
			{0.78, 0.82}, {0.89, 0.50}, {0.78, 0.18}, {0.50, 0.02}},
		{{0.58, 0.68}, {0.94, 1.00}},
	},
	'R': {
		{{0.16, 1.00}, {0.16, 0.00}},
		{{0.16, 0.00}, {0.68, 0.06}, {0.82, 0.26}, {0.68, 0.48}, {0.16, 0.54}},
		{{0.42, 0.54}, {0.88, 1.00}},
	},
	'T': {
		{{0.08, 0.03}, {0.92, 0.03}},
		{{0.50, 0.03}, {0.50, 1.00}},
	},
	'V': {
		{{0.08, 0.00}, {0.50, 1.00}, {0.92, 0.00}},
	},
	'W': {
		{{0.04, 0.00}, {0.26, 1.00}, {0.50, 0.34}, {0.74, 1.00}, {0.96, 0.00}},
	},
	'X': {
		{{0.12, 0.00}, {0.88, 1.00}},
		{{0.88, 0.00}, {0.12, 1.00}},
	},
	'Y': {
		{{0.10, 0.00}, {0.50, 0.50}, {0.90, 0.00}},
		{{0.50, 0.50}, {0.50, 1.00}},
	},
	'2': {
		{{0.14, 0.24}, {0.30, 0.04}, {0.60, 0.02}, {0.82, 0.18}, {0.78, 0.44},
			{0.16, 0.98}, {0.88, 0.98}},
	},
	'3': {
		{{0.16, 0.14}, {0.42, 0.02}, {0.72, 0.10}, {0.78, 0.30}, {0.52, 0.46}},
		{{0.46, 0.46}, {0.80, 0.58}, {0.80, 0.84}, {0.50, 0.98}, {0.16, 0.86}},
	},
	'4': {
		{{0.70, 1.00}, {0.70, 0.00}},
		{{0.70, 0.00}, {0.08, 0.70}, {0.94, 0.70}},
	},
	'6': {
		{{0.76, 0.06}, {0.46, 0.02}, {0.20, 0.24}, {0.13, 0.62}, {0.24, 0.90},
			{0.54, 0.99}, {0.80, 0.86}, {0.82, 0.62}, {0.60, 0.47}, {0.30, 0.50},
			{0.15, 0.64}},
	},
	'7': {
		{{0.10, 0.03}, {0.90, 0.03}, {0.42, 1.00}},
		{{0.28, 0.50}, {0.74, 0.50}},
	},
	'8': {
		{{0.50, 0.47}, {0.24, 0.35}, {0.26, 0.11}, {0.50, 0.02}, {0.74, 0.11},
			{0.76, 0.35}, {0.50, 0.47}, {0.20, 0.61}, {0.19, 0.87}, {0.50, 0.98},
			{0.81, 0.87}, {0.80, 0.61}, {0.50, 0.47}},
	},
	'9': {
		{{0.24, 0.94}, {0.54, 0.98}, {0.80, 0.76}, {0.87, 0.38}, {0.76, 0.10},
			{0.46, 0.01}, {0.20, 0.14}, {0.18, 0.38}, {0.40, 0.53}, {0.70, 0.50},
			{0.85, 0.36}},
	},
}

// ---------------------------------------------------------------------------
// Lowercase forms, for case-sensitive mode
//
// WHY ONLY TWELVE
//
// Case can only be read off a glyph whose lowercase form is a different SHAPE,
// not merely a smaller one. The renderer applies ±15% per-glyph scale jitter as
// an anti-OCR measure, so for C/c, F/f, J/j, K/k, L/l, P/p, V/v, W/w and X/x —
// which differ in size alone — a scaled-down capital and a lowercase letter are
// the same picture. Including them would mean a user seeing an unambiguous
// character and still getting it wrong half the time, with no way to tell why.
//
// So case-sensitive mode drops those nine letters and keeps the twelve whose
// forms genuinely differ, plus the digits. 12 letters x 2 cases + 7 digits = 31
// characters, against 28 for the case-insensitive alphabet — slightly MORE
// answer space, and no ambiguity introduced.
//
// Ascenders and descenders deliberately overrun the 0..1 box (b, d, g, q, y),
// which is what makes them unmistakable at a glance.
// ---------------------------------------------------------------------------

// CaptchaAlphabetCaseSensitive is drawn from when a policy sets case_sensitive.
const CaptchaAlphabetCaseSensitive = "ABDEGHMNQRTYabdeghmnqrty2346789"

func init() {
	lower := map[rune][][]glyphPoint{
		'a': {
			{{0.74, 0.40}, {0.54, 0.28}, {0.32, 0.36}, {0.26, 0.56}, {0.36, 0.76},
				{0.58, 0.80}, {0.74, 0.66}},
			{{0.74, 0.30}, {0.74, 0.80}},
		},
		'b': {
			{{0.24, 0.02}, {0.24, 0.80}},
			{{0.24, 0.46}, {0.46, 0.30}, {0.68, 0.42}, {0.70, 0.62}, {0.50, 0.80}, {0.24, 0.72}},
		},
		'd': {
			{{0.76, 0.02}, {0.76, 0.80}},
			{{0.76, 0.46}, {0.54, 0.30}, {0.30, 0.42}, {0.28, 0.62}, {0.48, 0.80}, {0.76, 0.72}},
		},
		'e': {
			{{0.26, 0.56}, {0.74, 0.56}, {0.72, 0.40}, {0.50, 0.28}, {0.30, 0.40},
				{0.26, 0.60}, {0.40, 0.78}, {0.70, 0.74}},
		},
		'g': {
			{{0.72, 0.40}, {0.50, 0.28}, {0.30, 0.40}, {0.28, 0.60}, {0.48, 0.76}, {0.72, 0.66}},
			{{0.72, 0.30}, {0.72, 0.88}, {0.54, 0.99}, {0.30, 0.92}},
		},
		'h': {
			{{0.26, 0.02}, {0.26, 0.80}},
			{{0.26, 0.48}, {0.46, 0.30}, {0.68, 0.42}, {0.70, 0.80}},
		},
		'm': {
			{{0.14, 0.80}, {0.14, 0.32}},
			{{0.14, 0.42}, {0.30, 0.29}, {0.46, 0.42}, {0.46, 0.80}},
			{{0.46, 0.42}, {0.62, 0.29}, {0.80, 0.42}, {0.80, 0.80}},
		},
		'n': {
			{{0.26, 0.80}, {0.26, 0.32}},
			{{0.26, 0.45}, {0.46, 0.29}, {0.68, 0.42}, {0.70, 0.80}},
		},
		'q': {
			{{0.72, 0.42}, {0.50, 0.28}, {0.30, 0.40}, {0.30, 0.62}, {0.50, 0.78}, {0.72, 0.66}},
			{{0.72, 0.30}, {0.72, 0.99}},
		},
		'r': {
			{{0.32, 0.80}, {0.32, 0.32}},
			{{0.32, 0.46}, {0.52, 0.30}, {0.72, 0.33}},
		},
		't': {
			{{0.44, 0.08}, {0.44, 0.70}, {0.62, 0.81}},
			{{0.22, 0.34}, {0.66, 0.34}},
		},
		'y': {
			{{0.26, 0.30}, {0.50, 0.76}},
			{{0.74, 0.30}, {0.36, 0.99}},
		},
	}
	for r, strokes := range lower {
		glyphStrokes[r] = strokes
	}
}
