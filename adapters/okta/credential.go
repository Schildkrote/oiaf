// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package main

// Hardened credential matcher — the BL-5 fix, and the piece that turns
// redactToken from an exact-match ReplaceAll into something that survives the
// ways a hostile endpoint can actually transform a reflected credential.
//
// Round 6 of review found that exact matching is defeated by three ordinary
// transformations, none of which require any cleverness from an attacker:
//
//   - CASE FOLDING. url.Parse lowercases the scheme, so a token echoed as the
//     scheme of a Link target arrives case-folded and exact matching cannot see
//     it. A mixed-case token comes back with every letter altered: for a 25-char
//     canary that is ~2^12 candidates, i.e. seconds to brute-force.
//   - PERCENT ENCODING. A token reflected through a URL query or path may arrive
//     percent-encoded.
//   - PARTIAL REFLECTION. A body truncated at a byte cap, or a fragment quoted
//     inside another error, carries most of the token but not all of it. 39 of 40
//     characters at a KNOWN position is full credential recovery, because the one
//     missing character sits at a known index in a small alphabet.
//
// So the matcher handles exact, case-folded, percent-encoded and fragmentary
// appearances. It is deliberately a single function used by both the Client
// (error strings) and the slog handler (log records), because having two
// implementations is how one of them drifts.

import (
	"net/url"
	"strings"
	"unicode"
)

// minTokenFragmentLen is an absolute floor on the shortest run of credential
// characters that will be stripped from server-controlled text. It is NOT the
// operative threshold — see fragmentThreshold for that. It exists only so a very
// short credential cannot end up with a threshold of 0 and match everything.
//
// WHY NOT A FLAT 8 (what round 6 suggested). A flat floor over-redacts, and the
// mutation battery found it rather than a reviewer having to: the shipped canary
// ends in "9f3e2b1a", and a perfectly ordinary diagnostic
// "request_id 9f3e2b1a-dead-beef" was turned into "request_id [redacted]-dead-beef".
// Legitimate hex runs, base64 fragments and request ids are 8 characters all the
// time, so a flat floor eats real diagnostics — and a logged error body that stops
// being valid JSON is a defect in its own right.
//
// The security argument does not need a flat floor anyway: what makes a leaked
// fragment dangerous is how many characters of the secret remain UNKNOWN, because
// those are the ones an attacker must brute-force. That is a property of the
// token's length, not of an absolute count, so the threshold is derived from it.
const minTokenFragmentLen = 8

// maxUnknownCharsAfterLeak bounds how few characters of the credential may remain
// unknown if a fragment does get through. Any run long enough that fewer than this
// many characters stay secret is stripped.
//
// 12 characters from a ~62-symbol token alphabet is ~71 bits — offline
// brute-force is infeasible. That is the property being enforced, so it is stated
// as a property rather than as a fragment length.
const maxUnknownCharsAfterLeak = 12

// fragmentThreshold returns the shortest run of `token` that must be swept from
// arbitrary text: the point at which the characters that would remain UNKNOWN
// drop below maxUnknownCharsAfterLeak.
//
// The arithmetic matters, so it is written out. For a token of length N and a
// leaked run of length L, exactly N-L characters stay secret. Sweeping is required
// when that is not enough to resist brute-force:
//
//	N - L < maxUnknownCharsAfterLeak
//	L   > N - maxUnknownCharsAfterLeak
//	L  >= N - maxUnknownCharsAfterLeak + 1
//
// so the threshold is N-maxUnknownCharsAfterLeak+1. Using N-maxUnknownCharsAfterLeak
// (one less) would sweep a run that still leaves exactly the full bound unknown,
// which is over-redaction — the same class of error a flat floor makes.
//
// It scales with the credential: a 40-character SSWS token is protected at a
// 29-character run, a 25-character test canary at a 14-character run. Short
// legitimate runs stay untouched in both cases, which is what the derived rule
// buys over a flat constant.
//
// KNOWN LIMITATION, deliberate. For a token shorter than
// maxUnknownCharsAfterLeak+minTokenFragmentLen (20 characters here) the derived
// rule falls below the absolute floor, so the floor clamps it and the sweep can
// leave MORE unknown characters than maxUnknownCharsAfterLeak allows. Honouring the
// derivation for short tokens would mean sweeping 2- and 3-character runs, which
// appear in ordinary text constantly and would shred every diagnostic this adapter
// emits. Real Okta credentials are ~40 characters, where the derived threshold sits
// far above the floor, so the clamped case is not reachable in production; the exact
// and case-folded passes cover a short token's appearances anyway. The crossover is
// pinned by TestBL5_FragmentThresholdArithmetic so the tradeoff cannot change
// silently.
func fragmentThreshold(token string) int {
	// Measured in RUNES, because the scan that consumes this threshold compares
	// rune slices. Using len(token) here would mix units for a non-ASCII
	// credential — the same class of byte/rune desync that caused the panic this
	// file's scan comment describes.
	t := len([]rune(token)) - maxUnknownCharsAfterLeak + 1
	if t < minTokenFragmentLen {
		return minTokenFragmentLen
	}
	return t
}

// redactedMarker replaces any recognised credential material.
const redactedMarker = "[redacted]"

// redactCredential strips `token` from `s` in every form a hostile endpoint can
// produce: exact, case-folded, percent-encoded, and as a fragment of at least
// minTokenFragmentLen characters.
//
// It never panics and never grows the string unboundedly. An empty token is a
// no-op rather than "match everything", which would otherwise redact all output.
// It does this in a SINGLE left-to-right pass, and that is a safety property
// rather than an optimisation. The obvious implementation is a sequence of
// ReplaceAll passes — exact, then case-folded, then percent-encoded, then
// fragments — and it is broken, because every pass re-examines the output of the
// previous one, including the markers it just inserted. The marker "[redacted]"
// itself contains 'a', 'c', 'd', 'e', 'r' and 't': for a credential that is any of
// those letters, pass 2 matches inside pass 1's markers and rewrites them, giving
// "[red[redacted]cted]" and recursing into garbage. A 1-character credential is
// the clean demonstration, but the hazard is general — any credential sharing a
// long enough run with the marker text can trigger it.
//
// So: one pass over the ORIGINAL input, advancing monotonically, appending markers
// to the output and never rescanning them. There is no composition hazard between
// forms because there is only one scan. This is the same lesson as the gateway's
// chokepoint — a single place the decision is made, rather than a chain of passes
// each of which can see the previous one's edits.
func redactCredential(s, token string) string {
	if token == "" || s == "" {
		return s
	}
	if s == token {
		return redactedMarker
	}

	// MATCHING IS DONE IN RUNE SPACE, NOT BYTE SPACE, AND THAT IS A PANIC FIX.
	//
	// The first version built a parallel folded byte string (`lowerS =
	// strings.ToLower(s)`) and bounds-checked against len(s) while slicing lowerS.
	// That is unsound because ToLower can CHANGE BYTE LENGTH: U+212A KELVIN SIGN is
	// 3 bytes and folds to 'k' (1 byte), so lowerS ends up SHORTER than s and the
	// slice runs off the end. A hostile endpoint controls the response body, so
	// feeding it a Kelvin sign panicked the adapter — a DoS, and worse, the Go
	// runtime prints a panic value directly to stderr, which bypasses the slog
	// chokepoint completely. Reproduced on five distinct non-ASCII inputs before the
	// fix.
	//
	// Folding in rune space cannot desynchronise: unicode.ToLower maps one rune to
	// one rune, so the folded view is always the same LENGTH as the original and
	// index i means the same position in both. Output is rebuilt from the ORIGINAL
	// runes, so surrounding text keeps its case.
	rs := []rune(s)
	fs := make([]rune, len(rs))
	for i, r := range rs {
		fs[i] = unicode.ToLower(r)
	}

	needles := credentialNeedles(token)
	threshold := fragmentThreshold(token)
	sweepFragments := threshold < len([]rune(token))

	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(rs); {
		// Full spellings first: a complete match is unambiguous and should win over
		// a shorter fragment match at the same position.
		if n := matchNeedleAt(fs, i, needles); n > 0 {
			b.WriteString(redactedMarker)
			i += n
			continue
		}
		if sweepFragments {
			if n := longestTokenFragmentAt(fs, i, needles[0].match, threshold); n > 0 {
				b.WriteString(redactedMarker)
				i += n
				continue
			}
		}
		// Not credential material: copy the ORIGINAL rune, preserving the case of
		// all surrounding text.
		b.WriteRune(rs[i])
		i++
	}
	return b.String()
}

// needle is one spelling of the credential that server-controlled text might
// carry, in folded rune form so it can be compared against the folded view of the
// input.
type needle struct {
	match []rune
}

// matchNeedleAt returns the length in RUNES of the longest needle matching fs at
// position i, or 0. `fs` is the case-folded rune view of the input; because it has
// the same length as the original rune slice, every index here is valid and no
// bounds check can disagree with the slice it indexes.
func matchNeedleAt(fs []rune, i int, needles []needle) int {
	for _, nd := range needles {
		n := len(nd.match)
		if n == 0 || i+n > len(fs) {
			continue
		}
		if string(fs[i:i+n]) == string(nd.match) {
			return n
		}
	}
	return 0
}

// longestTokenFragmentAt returns the length in runes of the longest substring of
// fs starting at i that also occurs inside the folded token and is at least
// `threshold` runes long, or 0 if there is none.
//
// Longest-first is what makes the replacement maximal rather than fragmented. The
// full token is excluded because an exact occurrence was already handled by
// matchNeedleAt, so re-matching it here would be redundant.
func longestTokenFragmentAt(fs []rune, i int, tokenFolded []rune, threshold int) int {
	avail := len(fs) - i
	maxLen := len(tokenFolded) - 1
	if maxLen > avail {
		maxLen = avail
	}
	for l := maxLen; l >= threshold; l-- {
		if strings.Contains(string(tokenFolded), string(fs[i:i+l])) {
			return l
		}
	}
	return 0
}

// credentialNeedles returns every spelling of `token` worth matching, longest
// first so that a maximal match wins at any given position. All needles are
// case-folded to runes, matching the folded view of the input, so one comparison
// path covers both the exact and the case-folded forms.
//
// QueryEscape and PathEscape disagree about which characters they encode (notably
// '/' and ' '), and a credential can be reflected through either context — a query
// value or a path segment — so both spellings are covered. Percent escapes are
// matched case-insensitively because encoders disagree on hex digit case ("%2f" vs
// "%2F") and an attacker choosing the spelling costs them nothing.
//
// needles[0] is always the folded token itself, which is what the fragment scan
// uses as its haystack.
func credentialNeedles(token string) []needle {
	foldRunes := func(s string) []rune {
		out := make([]rune, 0, len(s))
		for _, r := range s {
			out = append(out, unicode.ToLower(r))
		}
		return out
	}
	seen := map[string]bool{token: true}
	out := []needle{{match: foldRunes(token)}}
	for _, enc := range []string{url.QueryEscape(token), url.PathEscape(token)} {
		if enc == token || seen[enc] {
			continue
		}
		seen[enc] = true
		out = append(out, needle{match: foldRunes(enc)})
	}
	// Longest first. Equal lengths keep insertion order, which puts the plain
	// spelling ahead of the escaped ones, so an exact match wins over a
	// percent-encoded one of the same length.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && len(out[j].match) > len(out[j-1].match); j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
