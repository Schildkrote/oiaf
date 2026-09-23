// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package main

// Round-6 regression pins: BL-2 .. BL-5.
//
// Round 6's verdict on the previous fix was REJECT, and the reason is the lesson
// these tests exist to enforce: BL-1a and BL-1b were "genuinely closed and
// mutation-guarded", but the closure was "another member-of-the-class patch". Each
// round had found one more surface through which the same credential could leave
// the process, and each fix had patched exactly the reported surface.
//
// So these tests pin the CLASS, not members:
//
//   BL-2  a json decode error quotes server-controlled input (client.go:665)
//   BL-3  url.Parse LOWERCASES the scheme, so a token reflected in scheme
//         position arrives case-folded and exact matching cannot see it
//   BL-4  a fragment of the token that is neither a suffix nor the whole token
//         survives exact matching
//   BL-5  the matcher must be hardened (case-insensitive, percent-decoded,
//         fragment-aware) rather than exact-match ReplaceAll
//
// Every leak direction is paired with an over-redaction guard, because the
// hardened matcher can fail in the mirror-image way: stripping ordinary
// diagnostic text is a real defect too, and TestBL1_RedactionIsNotOverBroad in
// bl1_round5_test.go only covers one such case.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// BL-5: the matcher itself, in isolation. These are unit tests on
// redactCredential so the transformations are provable without a live server.
// ---------------------------------------------------------------------------

func TestBL5_ExactMatchStillWorks(t *testing.T) {
	got := redactCredential("prefix "+canaryOktaToken+" suffix", canaryOktaToken)
	assertNoCanary(t, got, "exact match")
	if !strings.Contains(got, "prefix") || !strings.Contains(got, "suffix") {
		t.Errorf("surrounding text was damaged: %q", got)
	}
	if got != "prefix [redacted] suffix" {
		t.Errorf("exact match produced unexpected output: %q", got)
	}
}

// TestBL5_CaseFoldedTokenIsRedacted is the BL-3 mechanism pinned directly:
// url.Parse lowercases the scheme, so a credential reflected there is case-folded
// and exact ReplaceAll cannot match it. For a 25-char mixed-case token that is
// ~2^12 candidates — seconds to brute-force the rest.
func TestBL5_CaseFoldedTokenIsRedacted(t *testing.T) {
	// Each token is redacted against ITSELF. The earlier version of this test
	// folded one token and then asked a DIFFERENT token's matcher to catch it,
	// which can never work and told us nothing about either.
	tokens := map[string]string{
		// The shipped canary is already mixed-case, so all-lower is exactly what
		// url.Parse hands back when a token lands in scheme position.
		"canary": canaryOktaToken,
		// A realistic SSWS-shaped secret: ~40 chars of high entropy, which is what
		// fragmentThreshold's scaling is designed around.
		"ssws": "00aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV1wX2yZ",
	}
	for name, tok := range tokens {
		t.Run(name, func(t *testing.T) {
			for _, variant := range []struct {
				label string
				s     string
			}{
				{"all-lower", strings.ToLower(tok)},
				{"all-upper", strings.ToUpper(tok)},
			} {
				got := redactCredential("scheme "+variant.s+" rejected", tok)
				if strings.Contains(got, variant.s) {
					t.Errorf("%s: case-folded credential survived redaction: %q", variant.label, got)
				}
				// No fragment of the folded form may survive either.
				th := fragmentThreshold(tok)
				for n := len(tok) - 1; n >= th; n-- {
					if strings.Contains(got, variant.s[:n]) {
						t.Errorf("%s: a %d-char folded fragment survived: %q", variant.label, n, got)
						break
					}
				}
			}
			// Over-redaction guard: the surrounding words must survive.
			got := redactCredential("scheme "+strings.ToLower(tok)+" rejected", tok)
			if !strings.Contains(got, "scheme") || !strings.Contains(got, "rejected") {
				t.Errorf("surrounding text damaged: %q", got)
			}
		})
	}
}

// TestBL5_PercentEncodedTokenIsRedacted covers a token reflected through a URL
// query or path, where it arrives percent-encoded.
// TestBL5_PercentEncodedTokenIsRedacted covers a token reflected through a URL
// query or path, where it arrives percent-encoded.
//
// NOTE ON THE EARLIER VERSION OF THIS TEST: it began with a t.Skip when the
// canary turned out to have no escapable characters — and t.Skip RETURNS, so the
// meaningful assertions written after it never executed. The test reported PASS
// while covering nothing. Each token now gets its own subtest, and the token that
// actually needs escaping lives in a test that cannot be skipped.
func TestBL5_PercentEncodedTokenIsRedacted(t *testing.T) {
	t.Run("canary-may-be-inert", func(t *testing.T) {
		q := url.QueryEscape(canaryOktaToken)
		if q == canaryOktaToken {
			t.Logf("the canary's alphabet is percent-encoding-inert (%q == %q); "+
				"TestBL5_PercentEncodedSpecialChars covers the real path", q, canaryOktaToken)
			return
		}
		got := redactCredential("next="+q, canaryOktaToken)
		if strings.Contains(got, q) {
			t.Errorf("percent-encoded credential survived: %q", got)
		}
	})
}

// TestBL5_PercentEncodedSpecialChars is the case that actually matters: a
// credential containing '/' and ' ', which percent-encoding genuinely alters.
func TestBL5_PercentEncodedSpecialChars(t *testing.T) {
	slashy := "SSWS/aB cD9f3e2b1a0Zy"
	enc := url.QueryEscape(slashy)
	if enc == slashy {
		t.Fatalf("expected QueryEscape to alter %q, got it back unchanged", slashy)
	}
	if !strings.Contains(enc, "%2F") || !strings.Contains(enc, "+") && !strings.Contains(enc, "%20") {
		t.Fatalf("QueryEscape did not encode the special characters as expected: %q", enc)
	}
	for label, variant := range map[string]string{
		"query-escaped": url.QueryEscape(slashy),
		"path-escaped":  url.PathEscape(slashy),
	} {
		t.Run(label, func(t *testing.T) {
			got := redactCredential("target="+variant+" done", slashy)
			if strings.Contains(got, variant) {
				t.Errorf("%s credential survived: %q", label, got)
			}
			if strings.Contains(got, slashy) {
				t.Errorf("%s: raw credential also survived: %q", label, got)
			}
			if !strings.Contains(got, "target=") || !strings.Contains(got, "done") {
				t.Errorf("surrounding text damaged: %q", got)
			}
		})
	}
}

// TestBL5_LargeFragmentsAreStripped is BL-4: a fragment that is neither the whole
// token nor a suffix. 39 of 40 characters at a KNOWN position is full credential
// recovery, because the missing character sits at a known index in a small
// alphabet.
func TestBL5_LargeFragmentsAreStripped(t *testing.T) {
	th := fragmentThreshold(canaryOktaToken)
	t.Logf("canary len=%d fragmentThreshold=%d (leaves %d chars unknown)",
		len(canaryOktaToken), th, len(canaryOktaToken)-th)

	// Every run length at or above the threshold must be swept. These are the
	// lengths where what remains unknown is too little to resist brute-force.
	for n := len(canaryOktaToken) - 1; n >= th; n-- {
		frag := canaryOktaToken[:n]
		t.Run(fmt.Sprintf("prefix-len-%d", n), func(t *testing.T) {
			got := redactCredential("body: "+frag+" trailing text", canaryOktaToken)
			if strings.Contains(got, frag) {
				t.Errorf("a %d-char credential fragment survived mid-string "+
					"(threshold %d): %q", n, th, got)
			}
		})
	}
	// Interior fragment, not anchored at either end.
	frag := canaryOktaToken[3 : 3+th]
	if len(frag) == th {
		got := redactCredential("x "+frag+" y", canaryOktaToken)
		if strings.Contains(got, frag) {
			t.Errorf("an interior %d-char fragment survived: %q", th, got)
		}
	}
	// Suffix fragment (not at the start of the token either).
	frag = canaryOktaToken[len(canaryOktaToken)-th:]
	got := redactCredential("tail "+frag, canaryOktaToken)
	if strings.Contains(got, frag) {
		t.Errorf("a trailing %d-char credential fragment survived: %q", th, got)
	}
}

// TestBL5_FragmentThresholdArithmetic pins the derivation, and pins the ONE case
// where it deliberately does not hold.
//
// The threshold is N-maxUnknownCharsAfterLeak+1. Using one less would sweep a run
// that still leaves the full bound unknown (over-redaction); one more would leave a
// brute-forceable remainder (a leak). Neither direction shows up in a happy-path
// test, so both are pinned.
//
// BUT the rule is clamped by minTokenFragmentLen, and for a short credential the
// floor wins. That is a real, deliberate limitation rather than an accident, so it
// is asserted here rather than hidden: for N <= maxUnknownCharsAfterLeak+
// minTokenFragmentLen-1 the fragment sweep leaves more characters unknown than
// maxUnknownCharsAfterLeak allows. The floor exists because a 2- or 3-character run
// of ANY token appears in ordinary text constantly, so honouring the derived rule
// for short tokens would shred every diagnostic the adapter emits. Real Okta
// credentials are ~40 characters, where the derived threshold (29) sits far above
// the floor and the exact/case-folded/percent-encoded passes carry the load anyway.
func TestBL5_FragmentThresholdArithmetic(t *testing.T) {
	for _, tok := range []string{
		canaryOktaToken, // 25 chars: derived rule binds
		"00aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV1wX2yZ", // 40 chars, SSWS-shaped
		strings.Repeat("a", 13),                    // too short: the floor clamps
		strings.Repeat("a", 19),                    // exactly the crossover
		strings.Repeat("a", 20),                    // just past it
	} {
		n := len(tok)
		th := fragmentThreshold(tok)
		derived := n - maxUnknownCharsAfterLeak + 1
		floored := derived < minTokenFragmentLen
		t.Run(fmt.Sprintf("len-%d-th-%d", n, th), func(t *testing.T) {
			if th < minTokenFragmentLen {
				t.Errorf("threshold %d is below the absolute floor %d", th, minTokenFragmentLen)
			}
			if floored {
				// Documented limitation: assert the floor won, and that the residual
				// is what we claim it is, so the tradeoff cannot silently change.
				if th != minTokenFragmentLen {
					t.Errorf("a short token should clamp to the floor %d, got %d", minTokenFragmentLen, th)
				}
				if unknown := n - th; unknown >= maxUnknownCharsAfterLeak {
					t.Logf("KNOWN LIMITATION for N=%d: a %d-char run leaves %d unknown "+
						"(bound is %d). The floor trades this away to keep ordinary "+
						"diagnostics readable.", n, th-1, unknown, maxUnknownCharsAfterLeak)
				}
				return
			}
			// Derived rule is operative: it must be exactly N-bound+1.
			if th != derived {
				t.Errorf("threshold %d != derived %d (N=%d, bound=%d)", th, derived, n, maxUnknownCharsAfterLeak)
			}
			// At the threshold the unknown remainder is strictly below the bound.
			if got := n - th; got >= maxUnknownCharsAfterLeak {
				t.Errorf("threshold %d leaves %d unknown, want < %d (LEAK)", th, got, maxUnknownCharsAfterLeak)
			}
			// One character below must NOT be swept — that is the boundary.
			if got := n - (th - 1); got < maxUnknownCharsAfterLeak {
				t.Errorf("threshold %d is one too high: a run of %d leaves %d unknown "+
					"(< %d) yet is not swept (OVER-REDACTION)", th, th-1, got, maxUnknownCharsAfterLeak)
			}
		})
	}

	// End-to-end boundary behaviour on a token where the derived rule binds: a run
	// one character below the threshold survives, a run at it does not.
	tok := canaryOktaToken
	th := fragmentThreshold(tok)
	below := tok[:th-1]
	if !strings.Contains(redactCredential("z "+below+" z", tok), below) {
		t.Errorf("a %d-char run (one below threshold %d) was swept: over-redaction", th-1, th)
	}
	at := tok[:th]
	if strings.Contains(redactCredential("z "+at+" z", tok), at) {
		t.Errorf("a %d-char run (at threshold %d) survived: leak", th, th)
	}

	// And the crossover must be exactly where the doc comment says: below it the
	// floor clamps, at/above it the derived rule takes over.
	crossover := maxUnknownCharsAfterLeak + minTokenFragmentLen // first N where derived >= floor
	if got := fragmentThreshold(strings.Repeat("a", crossover-1)); got != minTokenFragmentLen {
		t.Errorf("N=%d should be floor-clamped to %d, got %d", crossover-1, minTokenFragmentLen, got)
	}
	if got, want := fragmentThreshold(strings.Repeat("a", crossover)), crossover-maxUnknownCharsAfterLeak+1; got != want {
		t.Errorf("N=%d should use the derived rule (%d), got %d", crossover, want, got)
	}
}

// TestBL5_FragmentSweepDoesNotEatDiagnostics is the mirror-direction guard, and it
// is the test that earned the derived threshold.
//
// The first version of the matcher used a flat 8-character floor. This test caught
// it: the shipped canary is "CANARY-SSWS-OKTA-9f3e2b1a" and it ends in "9f3e2b1a",
// so a perfectly ordinary diagnostic — "request_id 9f3e2b1a-dead-beef" — was
// rewritten to "request_id [redacted]-dead-beef". Legitimate hex runs, base64
// fragments and request ids are 8 characters all the time.
//
// A test like this is the only thing standing between a hardened matcher and one
// that destroys the diagnostics an operator needs, so it is kept deliberately
// adversarial: it includes runs that coincide with the credential at lengths both
// below and above the threshold.
func TestBL5_FragmentSweepDoesNotEatDiagnostics(t *testing.T) {
	th := fragmentThreshold(canaryOktaToken)

	legit := []string{
		`{"errorCode":"E0000011","errorSummary":"Invalid token provided","errorLink":"E0000011"}`,
		`status 401: unauthorized`,
		`true`, `false`, `null`, `0`, `-1`,
		// The collision that broke the flat-8 version: the canary's own 8-char tail.
		`request_id 9f3e2b1a-dead-beef`,
		// Overlaps the canary's tail but stays BELOW the derived threshold, so it
		// must survive. NOTE: `trace=SSWS-OKTA-9f3e2b` was here originally and was
		// wrong — that is a 16-char substring of the canary, above the 14-char
		// threshold, i.e. genuine credential material that SHOULD be swept. A guard
		// test that lists real credential material as "legitimate" would have
		// forced the matcher to leak in order to pass.
		`trace=9f3e2b`,
		// Ordinary operational vocabulary that shares substrings with the canary.
		`okta tenant acme.okta.com responded`,
		`CANARY not present`,
	}
	for _, body := range legit {
		t.Run(body[:min(28, len(body))], func(t *testing.T) {
			got := redactCredential(body, canaryOktaToken)
			if got != body {
				t.Errorf("legitimate diagnostic was altered (threshold %d):\n  in:  %q\n  out: %q",
					th, body, got)
			}
		})
	}

	// The longest legitimate run that shares the credential's tail must still pass
	// through, and one character past the threshold must be swept. This pins the
	// boundary from the diagnostics side rather than only the leak side.
	tail := canaryOktaToken[len(canaryOktaToken)-th+1:] // th-1 chars, must survive
	if len(tail) == th-1 {
		body := "trace=" + tail
		if got := redactCredential(body, canaryOktaToken); got != body {
			t.Errorf("a %d-char legitimate run (one below threshold %d) was swept: %q",
				th-1, th, got)
		}
	}

	// A logged error body must remain valid JSON after redaction — mangling the
	// structure would make the line unparseable by every downstream tool.
	jsonBody := `{"errorCode":"E0000011","errorSummary":"Invalid token provided","errorLink":"E0000011"}`
	got := redactCredential(jsonBody, canaryOktaToken)
	var m map[string]any
	if err := json.Unmarshal([]byte(got), &m); err != nil {
		t.Errorf("redaction broke the JSON structure of a legitimate error body: %v\n%s", err, got)
	}
}

// TestBL5_EmptyTokenIsNotMatchEverything guards the degenerate case: an adapter
// started without a credential must not redact all of its output. An empty token
// matching everything is the most damaging possible failure of a matcher, because
// it is silent and total.
func TestBL5_EmptyTokenIsNotMatchEverything(t *testing.T) {
	in := "ordinary diagnostic text"
	if got := redactCredential(in, ""); got != in {
		t.Errorf("empty token altered the string (would redact everything): %q", got)
	}
	if got := redactCredential("", canaryOktaToken); got != "" {
		t.Errorf("empty input altered: %q", got)
	}
	// A pathological 1-character credential. Exact matching it is CORRECT — the
	// credential really is "a", so every "a" really is the credential. What must
	// not happen is the marker recursion: the fragment sweep has to be disabled
	// (threshold 8 >= len 1), otherwise the case-folded pass would match the 'a'
	// inside the "[redacted]" markers it just emitted and produce
	// "[red[redacted]cted]" garbage. That was a real bug in the first version.
	got := redactCredential("aaaaaaaaaa", "a")
	if strings.Contains(got, "[red[redacted]cted]") || strings.Contains(got, "red[") {
		t.Errorf("marker recursion: the redaction output was rewritten by a later "+
			"pass, which means the scan is not single-pass: %q", got)
	}
	if got != strings.Repeat("[redacted]", 10) {
		t.Errorf("a 1-char credential should exact-match every occurrence once, "+
			"got %q", got)
	}
	// Same check against the marker's own letters, which is the general hazard:
	// any single-character credential drawn from "redact" can recurse.
	for _, ch := range "redact" {
		s := "x" + string(ch) + "y"
		g := redactCredential(s, string(ch))
		if strings.Contains(g, "red[") || strings.Contains(g, "[red[") {
			t.Errorf("marker recursion with 1-char credential %q: %q", ch, g)
		}
	}
}

// TestBL5_RedactionIsIdempotent: safeErrSnippet redacts twice by design (once over
// the wide window before truncation, once over the exact returned string), and the
// slog chokepoint may see text the Client already scrubbed. A second pass must be
// a no-op rather than progressively eating the string.
func TestBL5_RedactionIsIdempotent(t *testing.T) {
	once := redactCredential("x "+canaryOktaToken+" y", canaryOktaToken)
	twice := redactCredential(once, canaryOktaToken)
	if once != twice {
		t.Errorf("redaction is not idempotent:\n  once:  %q\n  twice: %q", once, twice)
	}
	// Same for the marker itself plus folded/fragment forms.
	once = redactCredential("scheme "+strings.ToLower(canaryOktaToken)+" tail", canaryOktaToken)
	if twice := redactCredential(once, canaryOktaToken); once != twice {
		t.Errorf("case-folded redaction is not idempotent:\n  once:  %q\n  twice: %q", once, twice)
	}
}

// TestBL5_EveryTokenLengthPreservesTheUnknownBound pins the property the derived
// threshold exists to enforce: whatever the credential's length, the largest run
// that can SURVIVE the sweep leaves at least maxUnknownCharsAfterLeak characters
// unknown — except in the documented floor-clamped range for short tokens.
//
// This is the test that makes the entropy comment a claim someone can check rather
// than prose. Round 7 review corrected a wrong alphabet in that comment (~62
// symbols instead of the real 64 for SSWS), and the only durable defence against
// the same class of drift is an executable check of the arithmetic.
//
// It also uses a REAL SSWS-shaped credential — 42 characters, `00` prefix plus 40
// from [a-zA-Z0-9-_] — rather than only the 25-char canary, because the canary's
// length is not what production sees and the threshold scales with length.
func TestBL5_EveryTokenLengthPreservesTheUnknownBound(t *testing.T) {
	// The real production shape, per Okta: ^00[a-zA-Z0-9\-_]{40}$ => 42 runes.
	ssws := "00aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV1wX2yZ3a"
	if n := len([]rune(ssws)); n != 42 {
		t.Fatalf("the SSWS-shaped fixture should be 42 runes, got %d", n)
	}

	crossover := maxUnknownCharsAfterLeak + minTokenFragmentLen // 20
	for _, tok := range []string{
		ssws,                    // 42 runes: production shape
		canaryOktaToken,         // 25 runes: test canary
		strings.Repeat("z", 20), // crossover: derived rule starts to bind
		strings.Repeat("z", 24),
		strings.Repeat("z", 60), // longer than any real SSWS token
	} {
		n := len([]rune(tok))
		th := fragmentThreshold(tok)
		clamped := n < crossover
		t.Run(fmt.Sprintf("len-%d", n), func(t *testing.T) {
			// The largest run the sweep can LEAVE ALONE is th-1, so that is the
			// worst case an attacker can extract.
			largestSurviving := th - 1
			unknown := n - largestSurviving

			if clamped {
				// Documented limitation: the absolute floor wins and the bound is
				// NOT met. Assert that is the only reason, so a regression that
				// clamps long tokens is caught.
				if th != minTokenFragmentLen {
					t.Errorf("a %d-rune token is below the crossover %d, so the floor "+
						"should clamp the threshold to %d, got %d", n, crossover,
						minTokenFragmentLen, th)
				}
				if unknown >= maxUnknownCharsAfterLeak {
					t.Errorf("unexpected: a floor-clamped short token met the bound "+
						"(%d unknown >= %d), so the crossover arithmetic in "+
						"credential.go is wrong", unknown, maxUnknownCharsAfterLeak)
				}
				return
			}

			// Where the derived rule binds, the guarantee must hold EXACTLY: the
			// worst-case surviving run leaves precisely `bound` characters unknown.
			if unknown != maxUnknownCharsAfterLeak {
				t.Errorf("N=%d threshold=%d: the largest surviving run (%d) leaves %d "+
					"unknown, want exactly %d. Off-by-one here is either a leak (too "+
					"few unknown) or over-redaction (too many).",
					n, th, largestSurviving, unknown, maxUnknownCharsAfterLeak)
			}
		})
	}

	// And the production numbers stated in credential.go's comment, checked rather
	// than asserted: threshold 31 for a 42-rune SSWS token, 12 unknown, 64 symbols.
	if got, want := fragmentThreshold(ssws), 31; got != want {
		t.Errorf("SSWS threshold = %d, want %d (comment in credential.go says 31)", got, want)
	}
	const ssweAlphabet = 64 // [a-zA-Z0-9-_]
	unknown := len([]rune(ssws)) - (fragmentThreshold(ssws) - 1)
	bits := float64(unknown) * math.Log2(ssweAlphabet)
	if unknown != 12 {
		t.Errorf("SSWS worst-case unknown chars = %d, want 12", unknown)
	}
	// 64^12 = 4.72e21 = 72.0 bits. Guard the comment's figure with a tolerance so a
	// changed alphabet or bound fails the test instead of silently drifting.
	if bits < 71.5 || bits > 72.5 {
		t.Errorf("SSWS entropy = %.1f bits, want ~72.0 (credential.go documents 72.0; "+
			"64^12 = 4.7e21). If the alphabet or bound changed, update the comment "+
			"AND this check together.", bits)
	}
	t.Logf("SSWS: threshold=%d largest-surviving=%d unknown=%d entropy=%.1f bits",
		fragmentThreshold(ssws), fragmentThreshold(ssws)-1, unknown, bits)

	// Finally, the guarantee must be BEHAVIOURAL, not just arithmetic: a run of
	// exactly threshold-1 survives, and one of threshold does not.
	th := fragmentThreshold(ssws)
	if surv := ssws[:th-1]; !strings.Contains(redactCredential("z "+surv+" z", ssws), surv) {
		t.Errorf("a %d-rune run (one below threshold %d) was swept: over-redaction", th-1, th)
	}
	if at := ssws[:th]; strings.Contains(redactCredential("z "+at+" z", ssws), at) {
		t.Errorf("a %d-rune run (at threshold) survived: leak", th)
	}
}

// ---------------------------------------------------------------------------
// BL-3: the scheme site, through the real code path.
// ---------------------------------------------------------------------------

// TestBL3_TokenAsURLSchemeIsRedacted drives validateNextURL with a Link target
// whose scheme IS the credential. url.Parse lowercases the scheme, which is what
// made this a case-folding leak rather than an exact-match one.
func TestBL3_TokenAsURLSchemeIsRedacted(t *testing.T) {
	c := NewClient("https://tenant.example.okta.com", canaryOktaToken, 5*time.Second)

	raw := canaryOktaToken + "://tenant.example.okta.com/path"
	_, err := c.validateNextURL(raw)
	if err == nil {
		t.Fatalf("expected a non-https scheme to be rejected, got nil error")
	}
	msg := err.Error()
	t.Logf("validateNextURL error = %q", msg)

	assertNoCanary(t, msg, "validateNextURL scheme rejection")
	// The case-folded form is what url.Parse actually produced, so that is the
	// string that must not appear.
	folded := strings.ToLower(canaryOktaToken)
	if strings.Contains(msg, folded) {
		t.Errorf("BL-3: the case-folded credential from the scheme position reached the error string: %s", msg)
	}
	// Fragments must not survive either.
	for n := len(canaryOktaToken) - 1; n >= fragmentThreshold(canaryOktaToken); n-- {
		if strings.Contains(msg, folded[:n]) {
			t.Errorf("BL-3: a %d-char folded fragment survived: %s", n, msg)
			break
		}
	}
}

// ---------------------------------------------------------------------------
// BL-2: the decode-error site, through the real code path.
// ---------------------------------------------------------------------------

// TestBL2_DecodeErrorQuotingTheTokenIsRedacted makes the upstream return a body
// that is invalid JSON for []LogEvent *and* contains the reflected credential, so
// the json decoder's own message quotes server-controlled text.
func TestBL2_DecodeErrorQuotingTheTokenIsRedacted(t *testing.T) {
	// THE MECHANISM IS A TIME-PARSE ERROR, NOT A STRUCTURAL ONE — and getting this
	// wrong produced a vacuous test.
	//
	// A body like `"<TOKEN>"` (a string where an array is expected) yields
	// `json: cannot unmarshal string into Go value of type []main.LogEvent`, which
	// quotes at most ONE character of input — never the token. The first version of
	// this test used exactly that body, so it asserted "no canary" against a message
	// that could never have contained one. It passed with the redaction removed,
	// which is why mutation M11 (decode wrap unredacted) SURVIVED.
	//
	// The real leak is LogEvent.Published being a time.Time. Sending the token as
	// that field's value makes encoding/json delegate to time.Parse, whose error
	// quotes the VALUE VERBATIM, twice:
	//
	//   parsing time "<TOKEN>" as "2006-01-02T15:04:05Z07:00": cannot parse
	//   "<TOKEN>" as "2006"
	//
	// That is the reviewer's reproduction, and it is transient + retried, so it is
	// logged ~5x per poll cycle. This test pins it. A positive control below proves
	// the body actually produces a token-bearing error, so the test can never go
	// silently vacuous again.
	body := `[{"published":"` + canaryOktaToken + `"}]`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, canaryOktaToken, 5*time.Second)
	_, err := c.FetchLogs(context.Background(), FetchLogsParams{Limit: 10, MaxPages: 1})
	if err == nil {
		t.Fatalf("expected a decode error, got nil")
	}
	msg := err.Error()
	t.Logf("FetchLogs error = %q", msg)

	if !strings.Contains(msg, "decode page") {
		t.Errorf("expected the decode-page context in the error, got: %q", msg)
	}

	// POSITIVE CONTROL — the assertion that keeps this test honest. Decode the same
	// body the way the client does and confirm the RAW error text really does carry
	// the token. Without this, the test would pass vacuously against any body whose
	// error message merely never mentioned the credential (which is exactly what the
	// first version did). If Okta/Go ever stops quoting the value here, this fails
	// loudly and the test gets rewritten against a live mechanism instead of rotting
	// into a no-op.
	var ctl []LogEvent
	rawErr := json.NewDecoder(strings.NewReader(body)).Decode(&ctl)
	if rawErr == nil {
		t.Fatalf("expected the control decode to fail for %q", body)
	}
	if !strings.Contains(rawErr.Error(), canaryOktaToken) {
		t.Fatalf("the decode error no longer quotes the token verbatim, so this test "+
			"cannot pin BL-2 as written. Raw error was: %q — find a body whose error "+
			"text carries server-controlled content and rewrite the fixture.", rawErr.Error())
	}
	t.Logf("positive control: raw decode error DOES carry the token: %.160s", rawErr.Error())
	assertNoCanary(t, msg, "BL-2 decode error")
	for n := len(canaryOktaToken) - 1; n >= fragmentThreshold(canaryOktaToken); n-- {
		if strings.Contains(msg, canaryOktaToken[:n]) {
			t.Errorf("BL-2: a %d-char fragment survived in the decode error: %s", n, msg)
			break
		}
	}
	// The error must still be classified as retryable, i.e. the transientError
	// wrapper survived flattening the cause to a string.
	if !isRetryable(err) {
		t.Errorf("BL-2: flattening the wrap chain broke isRetryable, so a transient " +
			"decode failure will no longer be retried")
	}
}

// TestBL2_DecodeErrorPreservesDiagnostics is the over-redaction guard for BL-2: a
// decode failure with no credential in it must still explain itself.
func TestBL2_DecodeErrorPreservesDiagnostics(t *testing.T) {
	body := `{"not":"an array"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, canaryOktaToken, 5*time.Second)
	_, err := c.FetchLogs(context.Background(), FetchLogsParams{Limit: 10, MaxPages: 1})
	if err == nil {
		t.Fatalf("expected a decode error, got nil")
	}
	msg := err.Error()
	t.Logf("clean decode error = %q", msg)
	// The json package's own wording must survive: that is what makes the log line
	// actionable for an operator.
	if !strings.Contains(strings.ToLower(msg), "unmarshal") &&
		!strings.Contains(strings.ToLower(msg), "decode") {
		t.Errorf("the decode error lost its diagnostic content: %q", msg)
	}
}

// ---------------------------------------------------------------------------
// BL-1 class via the LOG chokepoint (logredact.go).
// ---------------------------------------------------------------------------

// TestBL1_SlogHandlerScrubsEveryChannel proves the chokepoint, not a member: a
// credential arriving as the message, as a string attribute, as an error
// attribute, and inside a bound attribute group must all come out redacted.
func TestBL1_SlogHandlerScrubsEveryChannel(t *testing.T) {
	var buf strings.Builder
	inner := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})
	logger := slog.New(newRedactingHandler(inner, func(s string) string {
		return redactCredential(s, canaryOktaToken)
	}))

	// Bound at logger construction: WithAttrs must scrub at bind time, because a
	// bound attribute is re-emitted on every subsequent record.
	bound := logger.With("bound_token", canaryOktaToken)
	bound.Info("cycle start")
	bound.Info("cycle end")

	// Message text.
	logger.Info("upstream said " + canaryOktaToken)
	// String attribute.
	logger.Error("poll failed", "detail", "token="+canaryOktaToken)
	// Error attribute — the KindAny path, which is where the decode/transport
	// leaks actually surfaced.
	logger.Error("poll failed", "error", fmt.Errorf("okta: decode page: %s", canaryOktaToken))
	// Nested group.
	logger.Error("nested", "ctx", slog.Group("inner", "tok", canaryOktaToken))

	out := buf.String()
	t.Logf("log output:\n%s", out)

	// No channel may carry the credential, exact or folded or fragmentary.
	assertNoCanary(t, out, "slog output across all channels")
	folded := strings.ToLower(canaryOktaToken)
	for _, variant := range []string{canaryOktaToken, folded} {
		for n := len(variant); n >= fragmentThreshold(canaryOktaToken); n-- {
			if strings.Contains(out, variant[:n]) {
				t.Errorf("a %d-char credential fragment reached the log: %s", n, out)
				return
			}
		}
	}

	// Over-redaction guard: the record structure must survive, so operators can
	// still filter. Check the keys and an unrelated value are intact.
	for _, want := range []string{`"level":"INFO"`, `"level":"ERROR"`, `"bound_token"`, `"detail"`, `"ctx"`} {
		if !strings.Contains(out, want) {
			t.Errorf("the chokepoint destroyed record structure — %s missing:\n%s", want, out)
		}
	}
	// Every emitted line must still be valid JSON.
	for i, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Errorf("log line %d is no longer valid JSON: %v\n%s", i, err, line)
		}
	}
}

// TestBL1_SlogHandlerKeepsOrdinaryDiagnostics is the mirror guard at the handler
// level: ordinary operational text must pass through untouched, or the adapter's
// logs become useless.
func TestBL1_SlogHandlerKeepsOrdinaryDiagnostics(t *testing.T) {
	var buf strings.Builder
	inner := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})
	logger := slog.New(newRedactingHandler(inner, func(s string) string {
		return redactCredential(s, canaryOktaToken)
	}))

	logger.Info("fetched 42 events", "count", 42, "tenant", "acme.okta.com")
	logger.Error("upstream unavailable", "status", 503, "retry_in", "4s")

	out := buf.String()
	t.Logf("output:\n%s", out)
	for _, want := range []string{"fetched 42 events", "acme.okta.com", "upstream unavailable", `"status":503`} {
		if !strings.Contains(out, want) {
			t.Errorf("ordinary diagnostic %q was eaten by the chokepoint:\n%s", want, out)
		}
	}
}

// TestBL1_NilRedactFunctionIsNotSilentlyInstalled pins newRedactingHandler's
// guard: a nil scrubber would disable the only net covering the log paths, and
// silently. Returning the inner handler unwrapped is a no-op, which is visible in
// review; wrapping with a nil func would panic at the first log line.
func TestBL1_NilRedactFunctionIsNotSilentlyInstalled(t *testing.T) {
	inner := slog.NewJSONHandler(&strings.Builder{}, nil)
	if h := newRedactingHandler(inner, nil); h != inner {
		t.Errorf("newRedactingHandler wrapped the handler despite a nil scrubber; " +
			"a nil redact func must return the inner handler unchanged")
	}
	if h := newRedactingHandler(nil, func(s string) string { return s }); h != nil {
		t.Errorf("newRedactingHandler should return nil for a nil inner handler, got %v", h)
	}
}
