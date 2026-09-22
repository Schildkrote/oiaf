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
	t := len(token) - maxUnknownCharsAfterLeak + 1
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

	// Case-insensitive matching is only safe for ASCII credentials: strings.ToLower
	// can change byte length for non-ASCII (e.g. 'İ'), which would desynchronise
	// the index arithmetic that advances through the input. SSWS tokens are ASCII by
	// construction; a non-ASCII token still gets exact, percent-encoded and
	// case-sensitive fragment coverage.
	fold := isASCII(token)
	tokenFolded := token
	lowerS := s
	if fold {
		tokenFolded = strings.ToLower(token)
		lowerS = strings.ToLower(s)
	}

	needles := credentialNeedles(token, fold)
	threshold := fragmentThreshold(token)
	sweepFragments := threshold < len(token)

	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		// Full spellings first: a complete match is unambiguous and should win over
		// a shorter fragment match at the same position.
		if n := matchNeedleAt(s, lowerS, i, needles); n > 0 {
			b.WriteString(redactedMarker)
			i += n
			continue
		}
		if sweepFragments {
			if n := longestTokenFragmentAt(lowerS, i, tokenFolded, threshold); n > 0 {
				b.WriteString(redactedMarker)
				i += n
				continue
			}
		}
		// Not credential material: copy the ORIGINAL byte, preserving the case of
		// all surrounding text.
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// needle is one spelling of the credential that server-controlled text might
// carry. `match` is compared against the case-folded input when `folded` is set,
// so a single code path handles both the exact and the case-folded forms.
type needle struct {
	match  string
	folded bool
}

// credentialNeedles returns every spelling of `token` worth matching, longest
// first so that a maximal match wins at any given position.
//
// QueryEscape and PathEscape disagree about which characters they encode (notably
// '/' and ' '), and a credential can be reflected through either context — a query
// value or a path segment — so both spellings are covered. Percent escapes are
// matched case-insensitively as well, because encoders disagree on hex digit case
// ("%2f" vs "%2F") and an attacker choosing the spelling costs them nothing.
func credentialNeedles(token string, fold bool) []needle {
	// The comparison string must match the folded-ness of the input view it is
	// checked against. A needle flagged folded is compared to lowerS, so it must
	// itself be lowercased — passing the mixed-case original would make the
	// case-insensitive pass silently match nothing, which is exactly the kind of
	// fix that looks present and does nothing.
	compare := func(n string) string {
		if fold {
			return strings.ToLower(n)
		}
		return n
	}
	seen := map[string]bool{}
	base := compare(token)
	out := []needle{{match: base, folded: fold}}
	seen[base] = true
	for _, enc := range []string{url.QueryEscape(token), url.PathEscape(token)} {
		if enc == token {
			continue
		}
		c := compare(enc)
		if seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, needle{match: c, folded: fold})
	}
	// Longest first. Equal lengths keep insertion order, which puts the plain
	// spelling ahead of the escaped ones.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && len(out[j].match) > len(out[j-1].match); j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// matchNeedleAt returns the length of the longest needle matching s at position i,
// or 0. `lowerS` is the case-folded view of s (identical to s when folding is off)
// and is used for needles whose `folded` flag is set.
func matchNeedleAt(s, lowerS string, i int, needles []needle) int {
	for _, nd := range needles {
		n := len(nd.match)
		if i+n > len(s) {
			continue
		}
		if nd.folded {
			if lowerS[i:i+n] == nd.match {
				return n
			}
			continue
		}
		if s[i:i+n] == nd.match {
			return n
		}
	}
	return 0
}

// isASCII reports whether every byte is 7-bit.
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// longestTokenFragmentAt returns the length of the longest substring of s
// starting at i that also occurs inside token and is at least `threshold` long,
// or 0 if there is none.
//
// Longest-first is what makes the replacement maximal rather than fragmented.
// The full token is excluded from consideration because an exact occurrence was
// already replaced by an earlier pass, and re-matching it here would be redundant.
func longestTokenFragmentAt(s string, i int, token string, threshold int) int {
	avail := len(s) - i
	maxLen := len(token) - 1
	if maxLen > avail {
		maxLen = avail
	}
	for l := maxLen; l >= threshold; l-- {
		if strings.Contains(token, s[i:i+l]) {
			return l
		}
	}
	return 0
}
