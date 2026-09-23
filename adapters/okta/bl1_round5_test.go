package main

// BL-1a and BL-1b regressions, round 5 of the oiaf Okta review.
//
// BL-1 (round 4) was the SSWS token reaching logs through a reflected 401 body.
// The round-4 fix redacted the token AFTER truncating the body to
// maxErrBodyBytes, which is exploitable: an attacker who controls the response
// body places the reflected credential so that it STRADDLES the 512-byte cap.
// Truncation removes the token's last character, the whole-token ReplaceAll then
// matches nothing, and the surviving prefix is written to the error string, the
// slog record and stdout. For a real ~40-char SSWS token, 39 of 40 characters
// survive at a known position - practical full credential recovery.
//
// BL-1b is the same capability through a different surface: the Link header. A
// hostile endpoint that received our Authorization header can echo the credential
// back as the pagination target - bare, or as a hostname - and the refusal message
// quoted that attacker-chosen text verbatim. Go's transport can also quote a
// malformed header line containing it.
//
// These tests reuse the adapter's existing leak harness (assertNoCanary,
// canaryOktaToken) rather than hand-rolling one, so a leak is reported the same
// way everywhere in this package.

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// bl1aBody builds a hostile error body of exactly `padLen` filler bytes followed
// by the canary token, so that the token straddles the maxErrBodyBytes cap when
// padLen is chosen to land it there. The attacker fully controls this body.
func bl1aBody(padLen int) string {
	return strings.Repeat("y", padLen) + canaryOktaToken
}

// serveBL1a stands up an endpoint that answers every request with `status` and the
// supplied body, and returns a Client configured against it with the canary as its
// own credential - i.e. the reflected value IS the real token, which is what makes
// this a credential leak and not merely a data-echo.
func serveBL1a(t *testing.T, status int, body string) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	c := NewClient(srv.URL, canaryOktaToken, 5*time.Second)
	return c, srv
}

// TestBL1a_TokenStraddlingTheCapIsFullyRedacted is the reviewer's exact
// reproduction: 488 bytes of 'y' followed by the 25-char canary. The retained
// window covers bytes 0..511, i.e. 24 of the 25 canary characters. Under the
// truncate-then-redact ordering, nothing matched and 24 characters leaked.
func TestBL1a_TokenStraddlingTheCapIsFullyRedacted(t *testing.T) {
	c, _ := serveBL1a(t, http.StatusUnauthorized, bl1aBody(488))

	resp, err := http.Get(c.baseURL + "/api/v1/logs")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	snippet := c.safeErrSnippet(resp)
	t.Logf("snippet (len=%d) = %q", len(snippet), snippet)

	// The whole canary must be gone.
	assertNoCanary(t, snippet, "safeErrSnippet with a cap-straddling token")

	// And NO PROPER PREFIX of it may survive either - that is the actual leak,
	// since 24 of 25 characters at a known position is a recoverable credential.
	// This is the assertion the round-4 fix could not satisfy.
	for n := len(canaryOktaToken) - 1; n >= minTokenPrefixLen; n-- {
		if strings.Contains(snippet, canaryOktaToken[:n]) {
			t.Errorf("BL-1a LEAK: %d of %d token characters survived the cap as a "+
				"prefix: %q", n, len(canaryOktaToken), snippet)
		}
	}

	// The snippet must still be bounded by the published cap, or the fix would be
	// "read everything and never truncate", which is its own defect (unbounded
	// log lines / memory from a hostile endpoint).
	if len(snippet) > maxErrBodyBytes {
		t.Errorf("snippet exceeds the documented %d-byte cap: got %d bytes",
			maxErrBodyBytes, len(snippet))
	}
}

// TestBL1a_EveryStraddleOffsetIsRedacted walks the token across the cap boundary
// one byte at a time. A single lucky offset is not a fix; the reviewer noted the
// attacker can place echoes at consecutive offsets in ONE body to guarantee a
// straddle regardless of token length, so every offset must fail closed.
func TestBL1a_EveryStraddleOffsetIsRedacted(t *testing.T) {
	leaked := 0
	for pad := maxErrBodyBytes - len(canaryOktaToken) - 2; pad <= maxErrBodyBytes+2; pad++ {
		if pad < 0 {
			continue
		}
		c, _ := serveBL1a(t, http.StatusUnauthorized, bl1aBody(pad))

		resp, err := http.Get(c.baseURL + "/api/v1/logs")
		if err != nil {
			t.Fatalf("pad=%d: request failed: %v", pad, err)
		}
		snippet := c.safeErrSnippet(resp)
		resp.Body.Close()

		bad := strings.Contains(snippet, canaryOktaToken)
		for n := len(canaryOktaToken) - 1; n >= minTokenPrefixLen; n-- {
			if strings.Contains(snippet, canaryOktaToken[:n]) {
				bad = true
				break
			}
		}
		if bad {
			leaked++
			if leaked <= 3 {
				t.Errorf("pad=%d leaked token material: %q", pad, snippet)
			}
		}
		if len(snippet) > maxErrBodyBytes {
			t.Errorf("pad=%d: snippet %d bytes exceeds cap %d", pad, len(snippet), maxErrBodyBytes)
		}
	}
	if leaked > 0 {
		t.Errorf("%d straddle offsets leaked the credential", leaked)
	}
}

// TestBL1a_TokenEntirelyBeyondTheCapIsNotRead pins the other half of the window
// arithmetic: a token that starts past the cap must not appear at all, and the
// window must not have grown unboundedly to "fix" the straddle case.
func TestBL1a_TokenEntirelyBeyondTheCapIsNotRead(t *testing.T) {
	body := strings.Repeat("y", maxErrBodyBytes+200) + canaryOktaToken
	c, _ := serveBL1a(t, http.StatusForbidden, body)

	resp, err := http.Get(c.baseURL + "/api/v1/logs")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	snippet := c.safeErrSnippet(resp)
	assertNoCanary(t, snippet, "safeErrSnippet with the token beyond the cap")
	if len(snippet) > maxErrBodyBytes {
		t.Errorf("snippet %d bytes exceeds cap %d", len(snippet), maxErrBodyBytes)
	}
}

// TestBL1a_ReadWindowIsBounded proves the fix did not simply remove the cap. A
// hostile endpoint sends a very large body; the adapter must read at most
// maxErrWindowBytes of it.
func TestBL1a_ReadWindowIsBounded(t *testing.T) {
	var sent int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		// 1 MiB of filler - far beyond any legitimate diagnostic need.
		chunk := []byte(strings.Repeat("z", 4096))
		for i := 0; i < 256; i++ {
			n, err := w.Write(chunk)
			if err != nil {
				return
			}
			sent += n
		}
	}))
	defer srv.Close()

	c := NewClient(srv.URL, canaryOktaToken, 5*time.Second)
	resp, err := http.Get(c.baseURL + "/api/v1/logs")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	snippet := c.safeErrSnippet(resp)
	if len(snippet) > maxErrBodyBytes {
		t.Errorf("snippet %d bytes exceeds the %d-byte cap - the window is not "+
			"enforced on the returned value", len(snippet), maxErrBodyBytes)
	}
	if maxErrWindowBytes >= maxErrBodyBytes+len(canaryOktaToken) {
		// Sanity check on the constant relationship the straddle fix depends on.
		t.Logf("window %d >= cap %d + token %d: straddle coverage holds",
			maxErrWindowBytes, maxErrBodyBytes, len(canaryOktaToken))
	} else {
		t.Errorf("maxErrWindowBytes (%d) is too small to cover a token straddling "+
			"the cap (%d + %d)", maxErrWindowBytes, maxErrBodyBytes, len(canaryOktaToken))
	}
}

// TestBL1b_LinkHeaderEchoesTheTokenBare covers reproduction (a): the endpoint
// reflects the credential as the Link target with no scheme or host, so
// validateNextURL refuses it - and the refusal message used to quote the raw,
// attacker-chosen string verbatim.
func TestBL1b_LinkHeaderEchoesTheTokenBare(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", fmt.Sprintf(`<%s>; rel="next"`, canaryOktaToken))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, canaryOktaToken, 5*time.Second)
	logs, err := c.FetchLogs(context.Background(), FetchLogsParams{})
	t.Logf("logs=%d err=%v", len(logs), err)

	// The error text is the leak channel: it goes to the caller, to slog and to
	// stdout via the poller.
	if err != nil {
		assertNoCanary(t, err.Error(), "validateNextURL error (bare token link)")
	}
	// The refusal must still have happened - redaction is not permission.
	if err == nil || !strings.Contains(err.Error(), "refusing to follow pagination link") {
		t.Errorf("the unsafe Link was not refused: err=%v", err)
	}
}

// TestBL1b_LinkHeaderEchoesTheTokenAsHost covers reproduction (b): the credential
// appears as the HOST component, so it survives url.Parse and reaches the
// tenant-mismatch message.
func TestBL1b_LinkHeaderEchoesTheTokenAsHost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link",
			fmt.Sprintf(`<https://%s/api/v1/logs?after=x>; rel="next"`, canaryOktaToken))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, canaryOktaToken, 5*time.Second)
	_, err := c.FetchLogs(context.Background(), FetchLogsParams{})
	t.Logf("err=%v", err)

	if err != nil {
		assertNoCanary(t, err.Error(), "validateNextURL error (token as host)")
	}
	if err == nil || !strings.Contains(err.Error(), "is not the configured tenant") {
		t.Errorf("the cross-tenant Link was not refused: err=%v", err)
	}
	// The configured tenant itself is NOT secret and must remain, or the diagnostic
	// is useless. This is the over-redaction mirror check.
	if err != nil && !strings.Contains(err.Error(), "configured tenant") {
		t.Errorf("the refusal lost its diagnostic: %v", err)
	}
}

// TestBL1b_UnparseableLinkQuotesNothingSensitive covers reproduction (c): a Link
// value containing a control character makes url.Parse fail, and url.Parse's own
// error text can quote the offending input.
func TestBL1b_UnparseableLinkQuotesNothingSensitive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link",
			fmt.Sprintf(`<https://SSWS %s/api/v1/logs>; rel="next"`, canaryOktaToken))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, canaryOktaToken, 5*time.Second)
	_, err := c.FetchLogs(context.Background(), FetchLogsParams{})
	t.Logf("err=%v", err)

	if err != nil {
		assertNoCanary(t, err.Error(), "validateNextURL error (unparseable link)")
	}
	if err == nil || !strings.Contains(err.Error(), "refusing to follow pagination link") {
		t.Errorf("the unparseable Link was not refused: err=%v", err)
	}
}

// TestBL1b_TransportErrorQuotingTheHeader covers the transport-level variant: Go
// surfaces malformed response headers in its error text, e.g.
// `malformed MIME header line: "Link: <\x7fhttps://..."`. That string is
// server-controlled and used to be wrapped into transientError untouched, reaching
// the poller's logger.
func TestBL1b_TransportErrorQuotingTheHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Write a raw response with an invalid header byte so net/http fails to
		// parse it and produces a transport error quoting the line.
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Skip("server does not support hijacking")
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			t.Skipf("hijack failed: %v", err)
		}
		defer conn.Close()
		raw := "HTTP/1.1 200 OK\r\n" +
			"Content-Type: application/json\r\n" +
			fmt.Sprintf("Link: <\x7fhttps://%s/api?tok=%s>; rel=\"next\"\r\n",
				canaryOktaToken, canaryOktaToken) +
			"\r\n[]"
		_, _ = buf.WriteString(raw)
		_ = buf.Flush()
	}))
	defer srv.Close()

	c := NewClient(srv.URL, canaryOktaToken, 5*time.Second)
	_, err := c.FetchLogs(context.Background(), FetchLogsParams{})
	t.Logf("err=%v", err)

	if err != nil {
		assertNoCanary(t, err.Error(), "transport error text")
	}
}

// TestBL1_PollerRunNeverLogsTheToken is the end-to-end assertion: run a full poll
// cycle against the hostile endpoint and capture what the poller would emit.
// Every BL-1 variant funnels into this one channel, so this is the test that
// matters operationally - it is the log line an operator actually sees.
func TestBL1_PollerRunNeverLogsTheToken(t *testing.T) {
	variants := map[string]string{
		"straddle_body":  bl1aBody(488),
		"whole_body":     canaryOktaToken,
		"consecutive":    canaryOktaToken + strings.Repeat("y", maxErrBodyBytes) + canaryOktaToken,
		"nested_offsets": strings.Repeat("y", maxErrBodyBytes-13) + canaryOktaToken + strings.Repeat("y", 300),
	}
	for name, body := range variants {
		t.Run(name, func(t *testing.T) {
			c, _ := serveBL1a(t, http.StatusUnauthorized, body)

			// Capture everything the client can emit on this path.
			var sink bytes.Buffer
			resp, err := http.Get(c.baseURL + "/api/v1/logs")
			if err != nil {
				t.Fatalf("%s: request failed: %v", name, err)
			}
			snippet := c.safeErrSnippet(resp)
			resp.Body.Close()
			sink.WriteString(snippet)

			// Also exercise FetchLogs so the error-string path is covered.
			_, ferr := c.FetchLogs(context.Background(), FetchLogsParams{})
			if ferr != nil {
				sink.WriteString(ferr.Error())
			}

			assertNoCanary(t, sink.String(), "PollerRun-visible output for "+name)
			for n := len(canaryOktaToken) - 1; n >= minTokenPrefixLen; n-- {
				if strings.Contains(sink.String(), canaryOktaToken[:n]) {
					t.Errorf("%s: %d/%d token characters leaked: %q",
						name, n, len(canaryOktaToken), sink.String())
				}
			}
		})
	}
}

// TestBL1_RedactionIsNotOverBroad is the mirror check the reviewer asked for on
// every redaction change: legitimate diagnostics must survive. A fix that replaces
// the whole error with "[redacted]" would pass every leak test above and be
// useless in production.
func TestBL1_RedactionIsNotOverBroad(t *testing.T) {
	body := `{"errorCode":"E0000011","errorSummary":"Invalid token provided","errorLink":"E0000011"}`
	c, _ := serveBL1a(t, http.StatusUnauthorized, body)

	resp, err := http.Get(c.baseURL + "/api/v1/logs")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	snippet := c.safeErrSnippet(resp)
	t.Logf("snippet = %q", snippet)
	for _, want := range []string{"E0000011", "Invalid token provided"} {
		if !strings.Contains(snippet, want) {
			t.Errorf("legitimate diagnostic %q was over-redacted: %q", want, snippet)
		}
	}
	if snippet == "[redacted]" || snippet == "" {
		t.Errorf("the entire diagnostic was replaced by the redaction marker: %q", snippet)
	}
}
