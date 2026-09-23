// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"testing"
)

// ---------------------------------------------------------------------------
// Exhaustive pin for truncateToRuneBoundary.
//
// This helper was first written as a HAND TRANSCRIPTION of the SDK's
// truncateToRuneBoundary (tools/adapter-sdk/client.go, PR #23). The SDK version is
// CORRECT and passes its own split-rune tests. The transcription was not: it
// dropped the "+1" from the SDK's len(b)-i+1 < size completeness check and
// returned b[:i] instead of b[:i-1], keeping the orphan lead byte, so it emitted
// invalid UTF-8 whenever the cap split a multi-byte rune.
//
// A hand-written table of 8 cases caught 4 failures. This test replaces the table
// with an exhaustive sweep so no alignment can hide: for every rune-width pattern
// up to runeSeqs sequences, truncate at EVERY cap from 0 to len(input) and require
// the output to be within the cap, valid UTF-8, and a prefix of the input.
//
// Exhaustive-over-alignments is the right shape here because the bug is purely
// positional: it only manifests when the cut lands inside a multi-byte sequence,
// and only for certain widths. Sampling caps would plausibly miss it - which is
// how the transcription shipped at all before this test existed.
// ---------------------------------------------------------------------------

// runeWidths covers every UTF-8 sequence length encoding/json and Okta can
// emit: 1 (ASCII), 2 (Latin-1 supplement), 3 (CJK / most non-Latin), 4 (emoji,
// supplementary planes).
var runeWidths = []string{"a", "\u00e9", "\u4e2d", "\U0001f512"}

// validUTF8Strict reports whether b decodes as UTF-8 with no invalid sequence.
// It deliberately does NOT use utf8.Valid from the standard library in the same
// breath as the code under test; an independent decode keeps the assertion from
// inheriting any shared misconception about what "valid" means here.
func validUTF8Strict(b []byte) bool {
	for i := 0; i < len(b); {
		switch {
		case b[i] < 0x80:
			i++
		case b[i]&0xE0 == 0xC0:
			if i+1 >= len(b) || b[i+1]&0xC0 != 0x80 {
				return false
			}
			i += 2
		case b[i]&0xF0 == 0xE0:
			if i+2 >= len(b) || b[i+1]&0xC0 != 0x80 || b[i+2]&0xC0 != 0x80 {
				return false
			}
			i += 3
		case b[i]&0xF8 == 0xF0:
			if i+3 >= len(b) || b[i+1]&0xC0 != 0x80 || b[i+2]&0xC0 != 0x80 || b[i+3]&0xC0 != 0x80 {
				return false
			}
			i += 4
		default:
			return false
		}
	}
	return true
}

func TestTruncateToRuneBoundaryNeverEmitsInvalidUTF8(t *testing.T) {
	const runeSeqs = 24 // 24 runes -> up to 96 bytes, every width alignment

	total := 0
	splitCuts := 0 // caps landing strictly inside a multi-byte sequence
	for n := 0; n <= runeSeqs; n++ {
		// Rotate the starting width so each n exercises a different alignment of
		// widths against the cut position.
		var in []byte
		for k := 0; k < n; k++ {
			in = append(in, runeWidths[(k+n)%len(runeWidths)]...)
		}
		for cap := 0; cap <= len(in); cap++ {
			got := truncateToRuneBoundary(in, cap)
			total++
			if cap < len(in) && !validUTF8Strict(in[:cap]) {
				splitCuts++ // the alignment the transcription off-by-one got wrong
			}
			if len(got) > cap {
				t.Fatalf("cap violated: input=%q cap=%d returned %d bytes", in, cap, len(got))
			}
			if !validUTF8Strict(got) {
				t.Fatalf("INVALID UTF-8: input=%q cap=%d returned %q (bytes %v)",
					in, cap, got, got)
			}
			// Prefix property: the result must be a prefix of the input. A
			// truncator that returned valid UTF-8 built from somewhere else
			// would be silently corrupting the diagnostic.
			for i := range got {
				if got[i] != in[i] {
					t.Fatalf("not a prefix: input=%q cap=%d returned %q", in, cap, got)
				}
			}
			// Maximality: VALID input that fits under the cap must be returned
			// untouched - guards against "fixing" validity by simply discarding
			// everything. Every input this sweep generates is valid UTF-8 by
			// construction (it is built from whole runes), so the condition
			// applies to all of them.
			if len(in) <= cap && len(got) != len(in) {
				t.Fatalf("valid input under cap was not returned verbatim: cap=%d in=%q got=%q", cap, in, got)
			}
		}
	}
	t.Logf("exhaustive sweep: %d (input, cap) pairs; %d of them cut inside a multi-byte rune",
		total, splitCuts)
	// Non-vacuity: the bug this pins is purely positional, so a sweep that never
	// lands a cap inside a multi-byte sequence would pass against the buggy
	// transcribed version too. Requiring splitCuts > 0 is what makes this test
	// able to fail; it is asserted, not assumed (456 of 781 pairs qualify).
	if splitCuts == 0 {
		t.Fatal("the sweep never cut inside a multi-byte rune - it cannot detect " +
			"the off-by-one it exists to pin")
	}
	if total == 0 {
		t.Fatal("sweep generated no cases")
	}
}

// The specific cases the hand transcription got wrong, kept as named
// reproductions: a multi-byte rune split by the cap must be dropped ENTIRELY,
// including its lead byte. Under the transcription's off-by-one (len(b)-i instead
// of len(b)-i+1, returning b[:i] instead of b[:i-1]) this kept the orphan lead
// byte 0xf0 and produced invalid UTF-8. The SDK original handles these
// correctly; only the copy did not.
func TestTruncateToRuneBoundaryDropsSplitRuneIncludingLeadByte(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		cap  int
		want int
	}{
		{"4byte_split_keeps_2_continuation", append(padASCII(510), 0xf0, 0x9f, 0x98, 0x80), 512, 510},
		{"4byte_split_keeps_1_continuation", append(padASCII(511), 0xf0, 0x9f, 0x98, 0x80), 512, 511},
		{"3byte_split_keeps_2", append(padASCII(510), 0xe4, 0xb8, 0xad), 512, 510},
		{"2byte_split_keeps_1", append(padASCII(511), 0xc3, 0xa9), 512, 511},
		{"4byte_complete_at_boundary", append(padASCII(508), 0xf0, 0x9f, 0x98, 0x80), 512, 512},
		{"3byte_complete_at_boundary", append(padASCII(509), 0xe4, 0xb8, 0xad), 512, 512},
		{"2byte_complete_at_boundary", append(padASCII(510), 0xc3, 0xa9), 512, 512},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := truncateToRuneBoundary(tc.in, tc.cap)
			if len(got) > tc.cap {
				t.Errorf("cap violated: %d > %d", len(got), tc.cap)
			}
			if !validUTF8Strict(got) {
				t.Errorf("invalid UTF-8: %q (tail bytes %v)", got, tail(got, 4))
			}
			if len(got) != tc.want {
				t.Errorf("length: got %d, want %d (tail %v)", len(got), tc.want, tail(got, 4))
			}
		})
	}
}

// Degenerate inputs must not panic or emit garbage: all-continuation bytes,
// invalid lead bytes (0xF8-0xFF), an empty slice, and a cap of zero.
func TestTruncateToRuneBoundaryDegenerateInputs(t *testing.T) {
	cases := map[string][]byte{
		"empty":               {},
		"all_continuation":    {0x80, 0x81, 0x82, 0x83, 0x84, 0x85},
		"invalid_leads":       {0xf8, 0xff, 0xfe, 0xc0, 0xc1},
		"lone_lead_at_cap":    append(padASCII(511), 0xf0),
		"continuations_only2": {0x80, 0x80},
	}
	for name, in := range cases {
		for _, cap := range []int{0, 1, 2, 4, len(in), 512} {
			t.Run(name, func(t *testing.T) {
				got := truncateToRuneBoundary(in, cap)
				if len(got) > cap {
					t.Errorf("cap violated: %d > %d", len(got), cap)
				}
				// Validity is now required at EVERY cap, not just when cutting.
				// The function always scans and stops at the first undecodable
				// byte, so invalid input yields a valid (possibly empty) prefix.
				// This replaced an earlier "validity only when cap < len(in)"
				// guard, which encoded a now-removed early return; that early
				// return made the helper a no-op for LimitReader-capped bodies
				// and was itself the bug being fixed.
				if !validUTF8Strict(got) {
					t.Errorf("invalid UTF-8 for %s at cap %d: %v", name, cap, got)
				}
				// The end-to-end property a caller depends on: whatever comes
				// back, sanitizeServerBody renders it valid UTF-8, because Go's
				// string range maps invalid bytes to U+FFFD.
				if s := sanitizeServerBody(got); !isValidUTF8String(s) {
					t.Errorf("sanitizeServerBody did not repair invalid bytes for %s at cap %d: %q",
						name, cap, s)
				}
				// No panics, and the result is always a prefix of the input.
				for i := range got {
					if got[i] != in[i] {
						t.Errorf("not a prefix for %s at cap %d", name, cap)
						break
					}
				}
			})
		}
	}
}

func padASCII(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'a'
	}
	return b
}

func tail(b []byte, n int) []byte {
	if len(b) <= n {
		return b
	}
	return b[len(b)-n:]
}
