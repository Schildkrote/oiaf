// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package main

// Regression pin for the byte/rune desynchronisation panic found while triaging
// the round-6 mutation battery.
//
// WHAT IT WAS. redactCredential built a parallel case-folded BYTE string
// (`lowerS = strings.ToLower(s)`) and bounds-checked against len(s) while slicing
// lowerS. strings.ToLower can CHANGE BYTE LENGTH: U+212A KELVIN SIGN is 3 bytes and
// folds to 'k' (1 byte). So lowerS ended up SHORTER than s, and slicing
// lowerS[i:i+n] for an i derived from s ran off the end:
//
//	runtime error: slice bounds out of range [:90] with length 75
//
// WHY IT IS SEVERE, in three steps:
//  1. The attacker controls the input. `s` is server-controlled text from a hostile
//     Okta endpoint (response body, Link header, transport error). Any of them can
//     carry a single Kelvin sign, so this is a trivially reachable DoS.
//  2. The panic happens INSIDE the redaction path — the one function whose entire
//     job is to stop secrets leaving the process.
//  3. The Go runtime prints a panic value and stack directly to stderr. That output
//     never passes through the slog chokepoint in logredact.go, so the panic is a
//     redaction bypass by construction: the stack trace quotes the surrounding
//     server-controlled text, and the credential sits in a local variable in the
//     same frame. This is exactly the "panic bypasses the sink" hole the review
//     prompt asks about, and it was reachable without any cleverness.
//
// THE FIX is to match in RUNE SPACE. unicode.ToLower maps one rune to one rune, so
// the folded view is always the same LENGTH as the original and index i means the
// same position in both. Output is rebuilt from the original runes, so surrounding
// text keeps its case. fragmentThreshold is rune-based for the same reason — a
// byte-length threshold applied to rune-length runs would mix units.
//
// Reproduced on five distinct non-ASCII inputs before the fix (all five panicked);
// after the fix all five are clean with no leak and no corruption.

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// TestPanic_NonASCIIInputDoesNotPanic is the primary pin: every input that used to
// panic must now be handled. If this test is deleted or weakened, the DoS returns.
func TestPanic_NonASCIIInputDoesNotPanic(t *testing.T) {
	kelvin := "\u212A"  // K: 3 bytes, folds to 'k' (1 byte) — SHORTENS
	dottedI := "\u0130" // İ: 2 bytes, folds to 'i'+U+0307 — LENGTHENS

	tok := canaryOktaToken
	cases := map[string]string{
		// The original reproductions. Padding around the token pushes the folded
		// view far enough below len(s) that the old bounds check disagreed with the
		// slice it guarded.
		"kelvin-prefix":         strings.Repeat(kelvin, 40) + tok + strings.Repeat("x", 10),
		"kelvin-interleaved":    strings.Repeat(kelvin+"a", 30) + tok,
		"kelvin-tail-fragment":  strings.Repeat(kelvin, 60) + tok[len(tok)-3:],
		"dottedI-prefix":        strings.Repeat(dottedI, 40) + tok,
		"mixed-length-changing": strings.Repeat(kelvin+dottedI, 30) + tok,
		// Token itself non-ASCII, so the needle side also folds.
		"non-ascii-token": strings.Repeat(kelvin, 20) + "SÉCRÉT-TÖKEN-" + strings.Repeat(kelvin, 5),
		// Degenerate and boundary shapes.
		"only-kelvin":                 strings.Repeat(kelvin, 100),
		"kelvin-between-token-halves": tok[:5] + kelvin + tok[5:],
		"single-kelvin":               kelvin,
		"emoji":                       "🔥" + tok + "🔥",
		"invalid-utf8":                "\xff\xfe" + tok + "\x80",
	}
	// The non-ASCII token needs its own token value for the fold to matter.
	tokens := map[string]string{"non-ascii-token": "SÉCRÉT-TÖKEN-" + strings.Repeat(kelvin, 5)}

	for name, in := range cases {
		name, in := name, in
		t.Run(name, func(t *testing.T) {
			token := tokens[name]
			if token == "" {
				token = tok
			}
			var got string
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("redactCredential PANICKED on non-ASCII server text: %v\n"+
							"This is a remotely triggerable DoS and, because the Go runtime "+
							"prints panic output straight to stderr, it bypasses the slog "+
							"redaction chokepoint. Matching must stay in rune space.", r)
					}
				}()
				got = redactCredential(in, token)
			}()

			// No credential may survive, exact or folded or fragmentary.
			if strings.Contains(got, token) {
				t.Errorf("credential survived in the output: %q", got)
			}
			th := fragmentThreshold(token)
			folded := strings.ToLower(token)
			for _, v := range []string{token, folded} {
				for n := len([]rune(v)) - 1; n >= th; n-- {
					frag := string([]rune(v)[:n])
					if strings.Contains(got, frag) {
						t.Errorf("a %d-rune credential fragment survived: %q", n, got)
						return
					}
				}
			}
			// Output must be well-formed UTF-8. Byte-space surgery on folded text is
			// how invalid sequences get emitted.
			if !utf8.ValidString(got) {
				t.Errorf("output is not valid UTF-8: %q", got)
			}
			// The marker must be emitted exactly where credential material was, so a
			// silent no-op is distinguishable from a real redaction.
			if strings.Contains(in, token) && !strings.Contains(got, redactedMarker) {
				t.Errorf("input contained the credential but no marker was emitted: %q", got)
			}
		})
	}
}

// TestPanic_SurroundingTextSurvivesFolding is the over-redaction half: folding is
// only allowed to affect MATCHING, never the emitted text. A case-folded scan that
// wrote its folded view back out would silently lowercase every log line the
// adapter emits.
func TestPanic_SurroundingTextSurvivesFolding(t *testing.T) {
	kelvin := "\u212A"
	in := "Tenant ACME.Okta.COM returned " + kelvin + " status 503 for RequestID AbC123"
	got := redactCredential(in, canaryOktaToken)
	if got != in {
		t.Errorf("non-credential text was altered by case folding:\n  in:  %q\n  out: %q", in, got)
	}
	// Mixed case must survive alongside a real redaction.
	in2 := "Tenant ACME.Okta.COM rejected " + canaryOktaToken
	got2 := redactCredential(in2, canaryOktaToken)
	if !strings.Contains(got2, "Tenant ACME.Okta.COM rejected ") {
		t.Errorf("surrounding mixed-case text was lowercased or damaged: %q", got2)
	}
	if !strings.Contains(got2, redactedMarker) {
		t.Errorf("the credential was not redacted: %q", got2)
	}
}

// TestPanic_ThresholdIsRuneBased pins the unit consistency between
// fragmentThreshold and the rune-space scan. A byte-length threshold applied to
// rune-length runs would over-sweep on multi-byte credentials.
func TestPanic_ThresholdIsRuneBased(t *testing.T) {
	// 20 runes but far more bytes, so byte-based arithmetic would give a different
	// (larger) threshold and over-redact.
	tok := strings.Repeat("É", 20)
	got := fragmentThreshold(tok)
	want := 20 - maxUnknownCharsAfterLeak + 1 // = 9
	if got != want {
		t.Errorf("fragmentThreshold used bytes, not runes: got %d for a %d-rune/%d-byte "+
			"token, want %d", got, len([]rune(tok)), len(tok), want)
	}
	if got >= len([]rune(tok)) {
		t.Errorf("threshold %d >= token rune length %d, so the fragment sweep is "+
			"disabled for a token that should have it", got, len([]rune(tok)))
	}
	// A token whose rune count is below the floor must clamp to the floor, not to a
	// byte-derived number.
	short := strings.Repeat("É", 5) // 5 runes, 10 bytes
	if got := fragmentThreshold(short); got != minTokenFragmentLen {
		t.Errorf("short non-ASCII token: threshold %d, want the floor %d", got, minTokenFragmentLen)
	}
}
