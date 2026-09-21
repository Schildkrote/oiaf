// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package sdk

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"
)

// --- Redirect token-leak regression ----------------------------------------
//
// doRequest sets "Authorization: Bearer <adapter token>" on every request and
// net/http follows 3xx transparently. Go strips Authorization only when the
// redirect changes the HOSTNAME — and it compares hostnames with the port
// stripped — so a 302 to the same hostname on a different port carried the
// bearer token to whatever was listening. That credential is shared by every
// sdk consumer (adapters/pam, adapters/okta, adapters/dc-agent).
//
// Reproduced before the fix with a throwaway probe:
//   target hits=1   target saw Authorization="Bearer PROBE-BEARER-SECRET"
// These tests pin that closed. Removing CheckRedirect from New must fail them.

const probeBearer = "PROBE-BEARER-SECRET-do-not-leak"

// redirectTarget stands up the "attacker" listener and a core that redirects
// to it, then reports whether the token ever arrived.
func redirectTarget(t *testing.T, code int) (coreURL string, gotAuth *atomic.Value, hits *int32) {
	t.Helper()
	gotAuth = &atomic.Value{}
	gotAuth.Store("")
	hits = new(int32)

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(hits, 1)
		gotAuth.Store(r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"decision":"allow"}`))
	}))
	t.Cleanup(target.Close)

	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Same hostname as the core (httptest binds 127.0.0.1), different port:
		// exactly the case net/http does NOT strip Authorization for.
		w.Header().Set("Location", target.URL+r.URL.Path)
		w.WriteHeader(code)
	}))
	t.Cleanup(core.Close)
	return core.URL, gotAuth, hits
}

func TestNoBearerLeakOnRedirect_AllCodes(t *testing.T) {
	for _, code := range []int{
		http.StatusMovedPermanently,  // 301
		http.StatusFound,             // 302
		http.StatusSeeOther,          // 303
		http.StatusTemporaryRedirect, // 307
		http.StatusPermanentRedirect, // 308
	} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			coreURL, gotAuth, hits := redirectTarget(t, code)
			c := New(coreURL, probeBearer)

			_, err := c.EvaluateAccess(context.Background(), json.RawMessage(`{"x":1}`))
			if err == nil {
				t.Errorf("status %d must be treated as an error, got nil", code)
			}
			if got := atomic.LoadInt32(hits); got != 0 {
				t.Errorf("SECURITY: redirect target was hit %d time(s) for status %d — the client must not follow redirects", got, code)
			}
			if v := gotAuth.Load().(string); v != "" {
				t.Errorf("SECURITY: bearer token reached the redirect target: %q", v)
			}
		})
	}
}

func TestNoBearerLeakOnRedirect_ReportEventAndHealthCheck(t *testing.T) {
	// The other two entry points set the same header, so both need coverage.
	t.Run("ReportEvent", func(t *testing.T) {
		coreURL, gotAuth, hits := redirectTarget(t, http.StatusFound)
		c := New(coreURL, probeBearer)
		if err := c.ReportEvent(context.Background(), json.RawMessage(`{}`)); err == nil {
			t.Error("expected an error for a redirected ReportEvent")
		}
		if atomic.LoadInt32(hits) != 0 || gotAuth.Load().(string) != "" {
			t.Errorf("SECURITY: ReportEvent followed the redirect (hits=%d auth=%q)",
				atomic.LoadInt32(hits), gotAuth.Load().(string))
		}
	})

	t.Run("HealthCheck", func(t *testing.T) {
		coreURL, gotAuth, hits := redirectTarget(t, http.StatusFound)
		c := New(coreURL, probeBearer)
		if err := c.HealthCheck(context.Background()); err == nil {
			t.Error("expected an error for a redirected HealthCheck")
		}
		if atomic.LoadInt32(hits) != 0 || gotAuth.Load().(string) != "" {
			t.Errorf("SECURITY: HealthCheck followed the redirect (hits=%d auth=%q)",
				atomic.LoadInt32(hits), gotAuth.Load().(string))
		}
	})
}

// --- 3xx must not be mistaken for success -----------------------------------
//
// Previously every caller treated "status < 400" as success. With redirects now
// refused, a 302 arrives with an empty body — decoding that as a valid decision
// is a silent fail-open, which is worse than a crash in an access-control path.

func TestThreeXXIsNotSuccess(t *testing.T) {
	cases := []struct {
		name string
		code int
		body string
	}{
		{"302 empty body", http.StatusFound, ""},
		{"302 with a JSON-looking body", http.StatusFound, `{"decision":"allow"}`},
		{"301 empty body", http.StatusMovedPermanently, ""},
		{"307 empty body", http.StatusTemporaryRedirect, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// A core that answers directly (no Location) so the client cannot
			// redirect anywhere; we only care how the status is classified.
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.code)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			c := New(srv.URL, "tok")
			out, err := c.EvaluateAccess(context.Background(), json.RawMessage(`{}`))
			if err == nil {
				t.Fatalf("status %d must be an error, got raw=%s", tc.code, out)
			}
			if out != nil {
				t.Errorf("no payload should be returned for status %d, got %s", tc.code, out)
			}
			if !strings.Contains(err.Error(), "server error") {
				t.Errorf("error should identify the status, got %v", err)
			}
		})
	}
}

func TestTwoXXStillSuccess(t *testing.T) {
	// Guard against over-correction: 2xx must keep working, including a 204-style
	// empty success on ReportEvent.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/healthz" || r.URL.Path == "/v1/audit/events" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"decision":"challenge","risk_score":42}`))
	}))
	defer srv.Close()

	c := New(srv.URL, "tok")
	raw, err := c.EvaluateAccess(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("200 must succeed, got %v", err)
	}
	var d struct {
		Decision string `json:"decision"`
	}
	if err := json.Unmarshal(raw, &d); err != nil || d.Decision != "challenge" {
		t.Fatalf("payload not decoded: raw=%s err=%v", raw, err)
	}
	if err := c.ReportEvent(context.Background(), json.RawMessage(`{}`)); err != nil {
		t.Errorf("204 on ReportEvent must be success, got %v", err)
	}
	if err := c.HealthCheck(context.Background()); err != nil {
		t.Errorf("204 on HealthCheck must be success, got %v", err)
	}
}

// --- Attacker-controlled body sanitisation ----------------------------------
//
// A hostile or compromised core can return any body, including text shaped like
// a credential. That body was embedded verbatim into the error string callers
// log, enabling token-mimicry in log aggregation (and defeating canary-based
// leak tests by making a secret-shaped string appear in otherwise clean
// output). Control characters are now stripped and the body is length-capped.

func TestSanitizeServerBody_StripsControlChars(t *testing.T) {
	in := "ok\nFAKE LOG LINE\tinjected\x1b[31mRED\x00null\u202ebidi"
	got := sanitizeServerBody([]byte(in))
	if strings.ContainsAny(got, "\n\t\x00") {
		t.Errorf("newline/tab/NUL survived sanitisation: %q", got)
	}
	if strings.Contains(got, "\x1b") {
		t.Errorf("ANSI escape survived sanitisation: %q", got)
	}
	if strings.Contains(got, "\u202e") {
		t.Errorf("bidi override survived sanitisation: %q", got)
	}
	// Legitimate text must survive, or the error is useless for diagnosis.
	if !strings.Contains(got, "FAKE LOG LINE") || !strings.Contains(got, "injected") {
		t.Errorf("printable text was mangled: %q", got)
	}
}

func TestErrorBodyIsSanitizedAndCapped(t *testing.T) {
	// The body contains a credential-shaped string, control chars, and — so the
	// rune-safe truncation is actually exercised through readResponse rather
	// only via a direct unit call — a long run of 4-byte runes placed so the
	// 512-byte cut lands mid-sequence. A naive data[:maxErrBodyBytes] slice
	// produces U+FFFD here; truncateToRuneBoundary does not.
	prefix := "reflected: Bearer LOOKS-LIKE-A-REAL-TOKEN\n"
	hostile := prefix + strings.Repeat("🙂", 600)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(hostile))
	}))
	defer srv.Close()

	c := New(srv.URL, "tok")
	_, err := c.EvaluateAccess(context.Background(), json.RawMessage(`{}`))
	if err == nil {
		t.Fatal("expected an error for a 502")
	}
	msg := err.Error()
	if strings.Contains(msg, "\n") {
		t.Errorf("error message contains a raw newline (log-injection vector): %q", msg)
	}
	// Cap: "server error (502): " prefix + at most maxErrBodyBytes of body.
	if len(msg) > len("server error (502): ")+maxErrBodyBytes+64 {
		t.Errorf("error message not length-capped: %d bytes", len(msg))
	}
	// The cut must be rune-aligned: this is the assertion that fails if
	// readResponse slices bytes naively instead of calling
	// truncateToRuneBoundary.
	if strings.ContainsRune(msg, utf8.RuneError) {
		t.Errorf("error body was sliced mid-rune (U+FFFD present); readResponse must truncate on a rune boundary: tail %q",
			msg[max(0, len(msg)-16):])
	}
	if !strings.Contains(msg, "LOOKS-LIKE-A-REAL-TOKEN") {
		t.Error("sanitisation destroyed legitimate diagnostic text")
	}
}

func TestIsNotSuccess(t *testing.T) {
	for code, want := range map[int]bool{
		100: true, 199: true, // informational: not a usable success
		200: false, 201: false, 204: false, 299: false,
		301: true, 302: true, 307: true, 308: true, 399: true,
		400: true, 401: true, 403: true, 404: true, 429: true,
		500: true, 502: true, 503: true,
	} {
		if got := isNotSuccess(code); got != want {
			t.Errorf("isNotSuccess(%d) = %v, want %v", code, got, want)
		}
	}
}

func TestNewRefusesRedirects(t *testing.T) {
	// Direct assertion on the client's policy, so a refactor that drops
	// CheckRedirect fails here even if the behavioural tests above are changed.
	c := New("http://127.0.0.1:1", "tok")
	if c.httpClient.CheckRedirect == nil {
		t.Fatal("SECURITY: NewClient must set CheckRedirect to refuse redirects")
	}
	req, _ := http.NewRequest(http.MethodGet, "http://example.invalid/x", nil)
	if err := c.httpClient.CheckRedirect(req, nil); err != http.ErrUseLastResponse {
		t.Errorf("CheckRedirect should return http.ErrUseLastResponse, got %v", err)
	}
	if c.httpClient.Timeout != 30*time.Second {
		t.Errorf("default timeout changed: %v", c.httpClient.Timeout)
	}
}

func TestWithTimeoutStillApplies(t *testing.T) {
	// Regression guard: CheckRedirect must not have displaced option handling.
	c := New("http://127.0.0.1:1", "tok", WithTimeout(7*time.Second))
	if c.httpClient.Timeout != 7*time.Second {
		t.Errorf("WithTimeout not applied: %v", c.httpClient.Timeout)
	}
	if c.httpClient.CheckRedirect == nil {
		t.Error("CheckRedirect lost when options are supplied")
	}
}

// --- rune-safe truncation ---------------------------------------------------
// The 512-byte error-body cap slices attacker-controlled bytes, so it can land
// mid-UTF-8-sequence and emit U+FFFD, making an otherwise readable diagnostic
// look corrupted. truncateToRuneBoundary walks back to a rune edge.

func TestTruncateToRuneBoundary_NeverSplitsARune(t *testing.T) {
	// Multi-byte runes of every width: 2-byte (é), 3-byte (€), 4-byte (🙂).
	long := strings.Repeat("aé€🙂", 400) // far past maxErrBodyBytes
	data := []byte(long)

	out := truncateToRuneBoundary(data, maxErrBodyBytes)
	if len(out) > maxErrBodyBytes {
		t.Errorf("exceeded the cap: %d > %d", len(out), maxErrBodyBytes)
	}
	s := string(out)
	if strings.ContainsRune(s, utf8.RuneError) {
		t.Errorf("truncation split a rune and produced U+FFFD: tail %q", s[len(s)-min(12, len(s)):])
	}
	if !utf8.Valid(out) {
		t.Error("truncated output is not valid UTF-8")
	}
	// Must have kept most of the budget rather than bailing out early.
	if len(out) < maxErrBodyBytes-4 {
		t.Errorf("dropped too much: %d bytes kept of a %d budget", len(out), maxErrBodyBytes)
	}
}

func TestTruncateToRuneBoundary_EdgeCases(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		max  int
	}{
		{"empty", []byte(""), 10},
		{"shorter than cap", []byte("abc"), 10},
		{"exactly at cap", []byte("abcde"), 5},
		{"ascii cut mid-word", []byte("abcdefgh"), 5},
		{"2-byte rune split", []byte("abcdé"), 5},
		{"3-byte rune split", []byte("abcd€"), 5},
		{"4-byte rune split", []byte("abcd🙂"), 5},
		{"all continuation bytes", []byte{0x80, 0x80, 0x80, 0x80}, 2},
		{"lone lead byte at end", append([]byte("abc"), 0xC3), 4},
		{"invalid utf8 tail", []byte("abc\xff\xfe"), 4},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := truncateToRuneBoundary(tc.in, tc.max)
			if len(out) > tc.max {
				t.Errorf("exceeded cap: %d > %d", len(out), tc.max)
			}
			// Must never panic, and must never emit a replacement char for a
			// clean-UTF-8 input. Invalid-byte inputs are allowed to keep the
			// bytes (sanitisation handles them downstream).
			if utf8.Valid(tc.in) && strings.ContainsRune(string(out), utf8.RuneError) {
				t.Errorf("valid input produced U+FFFD: in=%q out=%q", tc.in, out)
			}
		})
	}
}

func TestNewTrimsTrailingSlash(t *testing.T) {
	// A configured base URL ending in "/" produced "https://core//v1/access/
	// evaluate"; a real reverse proxy answers that with a 307. With redirects
	// now refused, that 307 becomes a hard failure — so normalising the URL
	// avoids breaking legitimate deployments that configure a trailing slash.
	c := New("https://core.example.com/", "tok")
	if c.baseURL != "https://core.example.com" {
		t.Errorf("trailing slash not trimmed: %q", c.baseURL)
	}
	if got := New("https://core.example.com", "tok").baseURL; got != "https://core.example.com" {
		t.Errorf("no-slash form changed: %q", got)
	}
	if got := New("https://core.example.com///", "tok").baseURL; got != "https://core.example.com" {
		t.Errorf("multiple trailing slashes not trimmed: %q", got)
	}
}
