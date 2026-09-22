// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// BL-1 regression tests (round-4 independent review of Okta PR #20).
//
// The reviewer REPRODUCED a token-to-logs channel: an endpoint returns 401 with
// a body that echoes the Authorization header back. The old code embedded the
// raw body in the error string, Poller.Run logged it through slog, and the SSWS
// token landed verbatim in captured stdout JSON (CWE-532). The existing
// leak suite missed it because its 401 fixture returned a body WITHOUT the
// token - a reflection scenario no test had authored.
//
// safeErrSnippet now sanitizes, rune-truncates and redacts the token at both
// error sites: the 401/403 branch and the default branch (which also covers
// refused 3xx, whose body a hostile redirect target controls).
//
// These tests reuse the project's proven leak-capture harness (startCapture /
// everything / assertNoCanary, itself mutation-proven by
// TestLeakCaptureDetectsALeak) rather than hand-rolling log capture, so the
// canary constant and assertion semantics stay identical to the shipped suite.
// ---------------------------------------------------------------------------

// hostileReflector echoes the request's Authorization header back inside an
// error body - the reviewer's exact reproduction shape.
func hostileReflector(t *testing.T, status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("Authorization")
		body, _ := json.Marshal(map[string]string{
			"errorCode":              "E0000011",
			"errorSummary":           "request rejected",
			"received_authorization": got,
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
}

// BL-1 core: a reflected token must reach neither the returned error string nor
// any logged channel, at every status whose body is embedded in an error.
// The positive control asserts the redaction marker IS present - proving the
// snippet path ran and the body was actually read, so a vacuous pass (body
// never inspected) cannot hide behind a missing canary.
func TestBL1_ReflectedTokenRedactedFromErrorAndLogs(t *testing.T) {
	for _, status := range []int{
		http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusNotFound,
		http.StatusBadRequest,
	} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			cap, logger, stop := startCapture(t)
			defer stop()

			srv := hostileReflector(t, status)
			defer srv.Close()

			client := NewClient(srv.URL, canaryOktaToken, 2*time.Second)
			_, err := client.FetchLogs(context.Background(), FetchLogsParams{Limit: 10, MaxPages: 1})
			if err == nil {
				t.Fatalf("expected an error for status %d", status)
			}

			// Mirror what Poller.Run does with a fatal error: log it.
			logger.Error("fetch failed", "error", err)

			blob := cap.everything(t, "", err)
			assertNoCanary(t, blob, fmt.Sprintf("BL-1 reflected-body path (status %d)", status))

			errStr := err.Error()
			if !strings.Contains(errStr, "[redacted]") {
				t.Errorf("the reflected body was not redacted - was the snippet "+
					"path exercised at all? err=%s", errStr)
			}
			if !strings.Contains(errStr, fmt.Sprint(status)) {
				t.Errorf("diagnostics lost: the status code should still be named "+
					"in the error: %s", errStr)
			}
		})
	}
}

// The reviewer's reproduction ran through the FULL Poller.Run path (slog
// capture of the running poller), not just FetchLogs. Pin that exact path.
func TestBL1_PollerRunDoesNotLogReflectedToken(t *testing.T) {
	cap, logger, stop := startCapture(t)
	defer stop()

	srv := hostileReflector(t, http.StatusUnauthorized)
	defer srv.Close()

	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")
	st := NewState()
	save := func() error { return st.Save(statePath, time.Now()) }
	cfg := &Config{
		StateFile:    statePath,
		OktaBaseURL:  srv.URL,
		OktaToken:    canaryOktaToken,
		AdapterToken: canaryAdapterToken,
		Limit:        10,
		MaxPages:     1,
		Once:         true,
		PollInterval: time.Millisecond,
		Timeout:      2 * time.Second,
	}

	client := NewClient(srv.URL, canaryOktaToken, 2*time.Second)
	p := NewPoller(NewLiveSource(client), NewDetector(defaultParams()),
		&erroringSink{err: fmt.Errorf("core rejected signal (simulated failure)")},
		st, save, cfg, logger)

	runErr := p.Run(context.Background())

	blob := cap.everything(t, statePath, runErr)
	assertNoCanary(t, blob, "BL-1 Poller.Run reflected-body path")

	if !strings.Contains(blob, "[redacted]") {
		t.Errorf("expected the redaction marker in captured output, proving the "+
			"reflected body was read and sanitized; got: %s", truncateForLog(blob, 600))
	}
}

// Token redaction must happen AFTER control-char sanitization, so a token
// surrounded by (or interleaved with) control characters still matches and is
// redacted - and so sanitization cannot be used to smuggle the token past the
// replacement.
func TestBL1_TokenRedactedEvenWhenSurroundedByControls(t *testing.T) {
	body := "prefix\x00\x1b[31m " + canaryOktaToken + " suffix\n\u202ebidi"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	client := NewClient(srv.URL, canaryOktaToken, 2*time.Second)
	_, err := client.FetchLogs(context.Background(), FetchLogsParams{Limit: 10, MaxPages: 1})
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), canaryOktaToken) {
		t.Errorf("BL-1 LEAK: token survived sanitize+redact: %s", err.Error())
	}
	if !strings.Contains(err.Error(), "[redacted]") {
		t.Errorf("redaction marker missing: %s", err.Error())
	}
	// Control characters must not survive into the error string either
	// (log-forging channel).
	for _, bad := range []string{"\x00", "\x1b", "\u202e", "\n"} {
		if strings.Contains(err.Error(), bad) {
			t.Errorf("control character %q survived sanitization: %q", bad, err.Error())
		}
	}
}

// Sanitizer unit behaviour: controls dropped, text shape preserved, and
// rune-boundary truncation never leaves invalid UTF-8 or exceeds the cap.
func TestSanitizeServerBodyDropsControlsAndKeepsUTF8Valid(t *testing.T) {
	in := []byte("line1\nline2\ttab\x00nul\x1b[31mred\u202ebidi")
	got := sanitizeServerBody(in)
	for _, bad := range []string{"\n", "\t", "\x00", "\x1b", "\u202e"} {
		if strings.Contains(got, bad) {
			t.Errorf("control char %q survived: %q", bad, got)
		}
	}
	if !strings.Contains(got, "line1 line2") {
		t.Errorf("readable text shape not preserved: %q", got)
	}

	// CUTTING case (len > max): a 4-byte rune split by the cut must be dropped
	// entirely rather than left half-decoded, and the result must stay within
	// the cap and remain valid UTF-8.
	long := append(bytes.Repeat([]byte("a"), 600), 0xf0, 0x9f, 0x98) // 603 bytes > 512
	tr := truncateToRuneBoundary(long, 512)
	if len(tr) > 512 {
		t.Errorf("truncation exceeded cap: %d", len(tr))
	}
	assertValidUTF8(t, tr, "truncateToRuneBoundary output when it cuts")
	if len(tr) != 512 {
		t.Errorf("the cut lands on ASCII here, so all 512 bytes should be kept; got %d", len(tr))
	}
	// A cut that lands MID-rune must walk back to the rune start.
	midRune := append(bytes.Repeat([]byte("a"), 510), 0xf0, 0x9f, 0x98, 0x80) // 514 bytes
	tr2 := truncateToRuneBoundary(midRune, 512)
	assertValidUTF8(t, tr2, "truncateToRuneBoundary output when the cut splits a rune")
	if len(tr2) != 510 {
		t.Errorf("expected the split 4-byte rune to be dropped entirely (510 bytes), got %d", len(tr2))
	}

	// UNDER-CAP case, and the one that caught a real bug in this very helper.
	// io.LimitReader caps the body at exactly maxErrBodyBytes, so the function is
	// ALWAYS called with len(b) <= max. An earlier version of THIS file's copy
	// short-circuited with `if len(b) <= max { return b }` (copied from the SDK,
	// where that early return is harmless because the SDK truncates a 1 MiB-capped
	// read down to 512 rather than reading a 512-capped stream), which meant it
	// never ran its scan at all and a rune split by LimitReader at the boundary
	// came out of sanitizeServerBody as U+FFFD garbage. The helper now always
	// scans, so an under-cap body ending mid-rune is cut cleanly to the last
	// complete rune.
	short := append(bytes.Repeat([]byte("a"), 509), 0xf0, 0x9f, 0x98) // 512 bytes, == cap
	// Named trShort, not got: `got` is already a string in this scope (the
	// sanitizeServerBody result above), and reusing the name would change its
	// type and fail to compile.
	trShort := truncateToRuneBoundary(short, 512)
	if len(trShort) != 509 {
		t.Errorf("under-cap body ending mid-rune must be cut to the last complete "+
			"rune (509 bytes), got %d - the early-return no-op bug is back", len(trShort))
	}
	if !validUTF8Strict(trShort) {
		t.Errorf("under-cap result is not valid UTF-8: %q", trShort)
	}
	if strings.Contains(string(trShort), "\ufffd") {
		t.Errorf("under-cap result contains U+FFFD: the split rune was mangled, not cut")
	}
	// VALID under-cap input must still be returned verbatim - always-scanning must
	// not become "always discarding".
	clean := []byte("caf\u00e9 \u4e2d\u6587 plain ascii tail")
	if gotClean := truncateToRuneBoundary(clean, 512); len(gotClean) != len(clean) {
		t.Errorf("valid under-cap input was not returned verbatim: %d of %d bytes",
			len(gotClean), len(clean))
	}
}

// BL-1 pipeline property that actually matters to a caller: whatever an endpoint
// returns - including a body ending mid-rune, or binary garbage - the string
// that Poller.Run hands to slog is valid UTF-8 and carries no token. This is the
// end-to-end form of the assertion above, exercised through FetchLogs.
func TestBL1_ErrorStringIsValidUTF8ForHostileBodies(t *testing.T) {
	cases := map[string][]byte{
		"partial_rune_at_end":  append(bytes.Repeat([]byte("a"), 509), 0xf0, 0x9f, 0x98),
		"raw_binary":           {0x00, 0x01, 0xff, 0xfe, 0x80, 0x81, 0xc0, 0xc1},
		"token_then_binary":    append([]byte(canaryOktaToken+"\x00"), 0xff, 0xfe, 0x80),
		"oversized_then_rune":  append(bytes.Repeat([]byte("z"), 900), 0xe2, 0x82),
		"valid_utf8_multibyte": []byte("caf\u00e9 \u4e2d\u6587 \xf0\x9f\x94\x92 ok"),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write(body)
			}))
			defer srv.Close()

			client := NewClient(srv.URL, canaryOktaToken, 2*time.Second)
			_, err := client.FetchLogs(context.Background(), FetchLogsParams{Limit: 10, MaxPages: 1})
			if err == nil {
				t.Fatal("expected an error")
			}
			s := err.Error()
			if !isValidUTF8String(s) {
				t.Errorf("error string is not valid UTF-8 (would render as U+FFFD garbage in "+
					"logs, and defeats JSON log encoding): %q", s)
			}
			assertNoCanary(t, s, "BL-1 hostile-body error string")
			if len(s) > 2048 {
				t.Errorf("error string is not bounded (%d bytes); the body cap should keep it small", len(s))
			}
		})
	}
}

func isValidUTF8String(s string) bool {
	for i := 0; i < len(s); {
		r, size := decodeRuneStrict([]byte(s[i:]))
		if r == -1 {
			return false
		}
		i += size
	}
	return true
}

func assertValidUTF8(t *testing.T, b []byte, what string) {
	t.Helper()
	for i := 0; i < len(b); {
		r, size := decodeRuneStrict(b[i:])
		if r == -1 {
			t.Fatalf("%s is not valid UTF-8 at offset %d: %q", what, i, b)
		}
		i += size
	}
}

// decodeRuneStrict is a minimal UTF-8 validator for the truncation test; it
// returns (-1, 0) on any invalid sequence rather than substituting U+FFFD, so
// the test cannot confuse "replaced" with "valid".
func decodeRuneStrict(b []byte) (rune, int) {
	if len(b) == 0 {
		return 0, 0
	}
	switch {
	case b[0] < 0x80:
		return rune(b[0]), 1
	case b[0]&0xE0 == 0xC0:
		if len(b) < 2 || b[1]&0xC0 != 0x80 {
			return -1, 0
		}
		return 0, 2
	case b[0]&0xF0 == 0xE0:
		if len(b) < 3 || b[1]&0xC0 != 0x80 || b[2]&0xC0 != 0x80 {
			return -1, 0
		}
		return 0, 3
	case b[0]&0xF8 == 0xF0:
		if len(b) < 4 || b[1]&0xC0 != 0x80 || b[2]&0xC0 != 0x80 || b[3]&0xC0 != 0x80 {
			return -1, 0
		}
		return 0, 4
	}
	return -1, 0
}

// N1 (round-4, non-blocking, pinned as requested): the success gate must be
// exactly 200. The reviewer noted mutation G8 ('< 400' treated as success)
// passed the ENTIRE shipped suite because every redirect test used an
// EMPTY-BODY 3xx, which fails at decode anyway - the gate itself was never
// load-bearing. This test makes it load-bearing: a 302 must be refused as a
// redirect (CheckRedirect: ErrUseLastResponse), the error must name the status,
// and no events may be returned - even though the Location target would serve a
// perfectly valid body if it were ever followed.
func TestN1_SuccessGateIsExactly200(t *testing.T) {
	validBody := `[{"uuid":"e1","published":"2026-01-01T00:00:00Z","eventType":"user.session.start","outcome":{"result":"SUCCESS"}}]`
	var followed int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/elsewhere" {
			followed++
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(validBody))
			return
		}
		w.Header().Set("Location", "/elsewhere")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	client := NewClient(srv.URL, canaryOktaToken, 2*time.Second)
	events, err := client.FetchLogs(context.Background(), FetchLogsParams{Limit: 10, MaxPages: 1})

	if err == nil {
		t.Fatalf("a 302 must never be treated as success even when its Location "+
			"target serves a valid body; got %d events", len(events))
	}
	if events != nil {
		t.Errorf("events returned from a redirect response: %v", events)
	}
	if !strings.Contains(err.Error(), "302") {
		t.Errorf("the error should name the redirect status: %s", err.Error())
	}
	if followed != 0 {
		t.Errorf("the redirect was followed %d time(s); CheckRedirect must stop at "+
			"the 3xx (no cross-host/same-host-diff-path credential forwarding)", followed)
	}
}

// M3 closed a real gap: mutation "delete the truncateToRuneBoundary call
// entirely" SURVIVED the suite, because every fixture body was already under
// maxErrBodyBytes - so no test observed truncation at all. An oversized body is
// the case that makes the cap load-bearing: it must bound the error string AND
// keep the token redaction working across the boundary.
func TestBL1_OversizedBodyIsTruncatedAndStillRedacted(t *testing.T) {
	// Token placed AFTER the cap, so a naive implementation that truncates first
	// and redacts second would drop the token and "pass" while never proving the
	// redaction ran on retained bytes. A second copy sits BEFORE the cap so the
	// retained portion must also be redacted.
	pad := strings.Repeat("P", maxErrBodyBytes)
	body := canaryOktaToken + "|" + pad + "|" + canaryOktaToken

	// 400, NOT 5xx: the >= 500 branch builds "okta: server error %d" without
	// reading the body at all, and it is a transientError so the client retries
	// with exponential backoff (seconds of sleeping to prove nothing). The
	// default branch is the one that embeds the body, and it is fatal, so this
	// stays fast.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	client := NewClient(srv.URL, canaryOktaToken, 2*time.Second)
	_, err := client.FetchLogs(context.Background(), FetchLogsParams{Limit: 10, MaxPages: 1})
	if err == nil {
		t.Fatal("expected an error")
	}
	s := err.Error()

	// The canary must not appear anywhere, including in the retained prefix.
	assertNoCanary(t, s, "BL-1 oversized-body path")
	if !strings.Contains(s, "[redacted]") {
		t.Errorf("redaction marker missing; the retained prefix should have been redacted: %.200s", s)
	}
	// The error string must be bounded: 512-byte body cap plus a fixed envelope.
	if len(s) > maxErrBodyBytes+256 {
		t.Errorf("error string is unbounded (%d bytes) - the body cap is not being applied", len(s))
	}
	// Positive control: the body really was read and really was oversized, so the
	// assertions above are about a truncated body rather than a short one.
	if len(body) <= maxErrBodyBytes {
		t.Fatalf("fixture is wrong: body (%d) is not over the cap (%d)", len(body), maxErrBodyBytes)
	}
	if !strings.Contains(s, "400") {
		t.Errorf("the status code diagnostic was lost: %s", s)
	}
	if !isValidUTF8String(s) {
		t.Errorf("error string is not valid UTF-8: %q", s)
	}
}

// The cap constant itself is pinned, so "fixing" a truncation failure by raising
// maxErrBodyBytes to something unbounded cannot pass silently.
func TestErrBodyCapIsBounded(t *testing.T) {
	if maxErrBodyBytes <= 0 || maxErrBodyBytes > 4096 {
		t.Errorf("maxErrBodyBytes = %d; an error-body cap must stay small and positive "+
			"(it bounds attacker-controlled text entering logs)", maxErrBodyBytes)
	}
}

// The reason M3 initially survived is worth pinning, because it documents what
// truncateToRuneBoundary is actually FOR in this pipeline. io.LimitReader
// already caps the read at maxErrBodyBytes, so for single-byte bodies the
// truncate call hits its early return and is a no-op - deleting it changed
// nothing observable. Its real job is repairing a multi-byte rune that
// LimitReader SPLITS at exactly the byte boundary. This test uses a body of
// 3-byte runes so the 512-byte cut lands mid-rune (512 is not a multiple of 3),
// making the truncation load-bearing: without it the error string carries
// invalid UTF-8.
func TestBL1_LimitReaderSplitRuneIsRepairedByTruncation(t *testing.T) {
	// U+4E2D encodes as 3 bytes (e4 b8 ad). 200 of them = 600 bytes > 512 cap,
	// and 512 % 3 == 2, so LimitReader cuts inside the 171st rune.
	body := strings.Repeat("\u4e2d", 200)
	if len(body)%3 != 0 {
		t.Fatalf("fixture assumption broken: %d bytes is not a multiple of 3", len(body))
	}
	if len(body) <= maxErrBodyBytes {
		t.Fatalf("fixture must exceed the cap: %d <= %d", len(body), maxErrBodyBytes)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	client := NewClient(srv.URL, canaryOktaToken, 2*time.Second)
	_, err := client.FetchLogs(context.Background(), FetchLogsParams{Limit: 10, MaxPages: 1})
	if err == nil {
		t.Fatal("expected an error")
	}
	s := err.Error()
	if !isValidUTF8String(s) {
		t.Errorf("error string carries invalid UTF-8: the rune split by LimitReader "+
			"was not repaired by truncateToRuneBoundary: tail bytes %v", tail([]byte(s), 6))
	}
	// This is the assertion that makes truncateToRuneBoundary OBSERVABLY
	// load-bearing, and it is worth stating why the weaker one above is not.
	// Deleting the truncate call does NOT produce invalid UTF-8 here, because
	// sanitizeServerBody runs afterwards and Go's string range maps the split
	// rune's bytes to U+FFFD - a valid, if wrong, character. Validity alone
	// therefore cannot distinguish "cut cleanly on a rune boundary" from
	// "mangled into replacement characters". The distinguishing signal is the
	// presence of U+FFFD: truncation drops the partial rune so no replacement
	// character is ever produced, which is exactly the contract the helper's doc
	// comment claims and this file's first transcription of it violated.
	if strings.Contains(s, "\ufffd") {
		t.Errorf("U+FFFD replacement character present: the rune split by "+
			"LimitReader was mangled by sanitizeServerBody instead of being cut "+
			"cleanly by truncateToRuneBoundary; tail %q", tail([]byte(s), 8))
	}
	if len(s) > maxErrBodyBytes+256 {
		t.Errorf("error string unbounded (%d bytes)", len(s))
	}
	assertNoCanary(t, s, "BL-1 split-rune path")
	if !strings.Contains(s, "400") {
		t.Errorf("status diagnostic lost: %s", s)
	}
}
