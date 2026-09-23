// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// LogEvent is the subset of an Okta System Log event
// (GET /api/v1/logs) that this adapter consumes. Okta's schema is large;
// we decode only the fields needed for risk-signal extraction.
type LogEvent struct {
	UUID        string      `json:"uuid"`
	Published   time.Time   `json:"published"`
	EventType   string      `json:"eventType"`
	DisplayMsg  string      `json:"displayMessage"`
	Outcome     Outcome     `json:"outcome"`
	Actor       Actor       `json:"actor"`
	Client      EventClient `json:"client"`
	AuthContext AuthCtx     `json:"authenticationContext"`
	SecurityCtx SecurityCtx `json:"securityContext"`
	Context     DebugCtx    `json:"debugContext"`
	Targets     []Target    `json:"target"`
}

type Outcome struct {
	Result string `json:"result"`
	Reason string `json:"reason"`
}

type Actor struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	DisplayName string `json:"displayName"`
	AlternateID string `json:"alternateId"`
}

type EventClient struct {
	IPAddress  string     `json:"ipAddress"`
	UserAgent  UserAgent  `json:"userAgent"`
	Zone       string     `json:"zone"`
	Device     string     `json:"device"`
	ID         string     `json:"id"`
	Geographic Geographic `json:"geographicalContext"`
}

type UserAgent struct {
	RawUserAgent string `json:"rawUserAgent"`
	Browser      string `json:"browser"`
	OS           string `json:"os"`
}

type Geographic struct {
	City        string `json:"city"`
	State       string `json:"state"`
	Country     string `json:"country"`
	Geolocation *Geo   `json:"geolocation"`
}

type Geo struct {
	Lat float64 `json:"lat"`
	Lon float64 `json:"lon"`
}

type AuthCtx struct {
	AuthenticationProvider string `json:"authenticationProvider"`
	CredentialProvider     string `json:"credentialProvider"`
	CredentialType         string `json:"credentialType"`
	Context                string `json:"context"`
	ExternalSessionID      string `json:"externalSessionId"`
}

type SecurityCtx struct {
	ASNumber   int    `json:"asNumber"`
	ASOrg      string `json:"asOrganization"`
	ISP        string `json:"isp"`
	Domain     string `json:"domain"`
	IsProxy    bool   `json:"isProxy"`
	Anonymizer string `json:"anonymizer"`
}

type DebugCtx struct {
	// DebugData is Okta's free-form debug blob. Its values are NOT reliably
	// strings: real tenants return numbers, booleans, nulls and nested objects
	// here. A plain map[string]string would fail to decode such an event, which
	// fails the ENTIRE PAGE decode, which is retried 5x, which wedges the poll
	// loop on one odd event — a silent, permanent stall. DebugDataMap accepts
	// any JSON value and stringifies it, so decoding can never fail here while
	// consumers keep seeing plain strings.
	DebugData DebugDataMap `json:"debugData"`
}

// DebugDataMap decodes Okta's debugData as map[string]string without ever
// failing on a non-string value. Strings keep their exact value; everything
// else is rendered with its compact JSON form (so a number 42 stays "42", a
// bool stays "true", an object stays {"a":1}).
type DebugDataMap map[string]string

func (m *DebugDataMap) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		return nil
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		// Not an object at all: ignore rather than fail the page. debugData is
		// advisory signal input, never load-bearing for correctness.
		*m = nil
		return nil
	}
	out := make(DebugDataMap, len(raw))
	for k, v := range raw {
		if v == nil || string(v) == "null" {
			out[k] = ""
			continue
		}
		var s string
		if err := json.Unmarshal(v, &s); err == nil {
			out[k] = s
			continue
		}
		// Numbers, booleans, arrays, objects: keep the compact JSON text so the
		// substring matching in isLegacyAuth still works on it.
		out[k] = string(v)
	}
	*m = out
	return nil
}

type Target struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	AlternateID string `json:"alternateId"`
	DisplayName string `json:"displayName"`
}

// ActorLogin returns the best username/login identifier for the actor.
// Okta puts the login in Actor.AlternateID for user actors.
func (e *LogEvent) ActorLogin() string {
	if e.Actor.AlternateID != "" {
		return e.Actor.AlternateID
	}
	return e.Actor.DisplayName
}

// DeviceFingerprint returns a stable-ish device identifier for new-device
// detection. Okta does not expose a device ID for unmanaged sign-ins, so we
// combine the client device string with the raw user agent.
func (e *LogEvent) DeviceFingerprint() string {
	if e.Client.Device == "" && e.Client.UserAgent.RawUserAgent == "" {
		return ""
	}
	return e.Client.Device + "|" + e.Client.UserAgent.RawUserAgent
}

// GeoLabel returns "City, Country" (or whichever parts exist) for
// new-geolocation detection and signal metadata.
func (e *LogEvent) GeoLabel() string {
	g := e.Client.Geographic
	switch {
	case g.City != "" && g.Country != "":
		return g.City + ", " + g.Country
	case g.City != "":
		return g.City
	case g.Country != "":
		return g.Country
	case g.State != "":
		return g.State
	}
	return ""
}

// Client is a read-only Okta System Log API client.
//
// It only ever issues GET requests against {baseURL}/api/v1/logs — this
// adapter is signal-in-only and never writes back to Okta (no enforcement,
// no user/policy mutation).
type Client struct {
	baseURL        string
	token          string
	httpClient     *http.Client
	maxBackoff     time.Duration
	lastRetryAfter time.Duration // server-provided wait, consumed by backoffFor
}

// NewClient builds a System Log client. The token is held in memory only and
// is sent as the SSWS Authorization header on every request. It is never
// logged and never rendered in errors.
//
// SECURITY — redirects are refused outright. net/http follows 3xx
// transparently, which would bypass the host:port pinning validateNextURL
// applies to Link-header hops: a redirect to the same hostname on a DIFFERENT
// port is enough to carry the SSWS token to a listener the operator never
// pinned. Okta's System Log API paginates with Link headers, not 3xx, so
// there is no legitimate redirect to support here. ErrUseLastResponse makes
// the client return the 3xx untouched, and doFetchPage's status switch turns
// it into a non-retryable "unexpected status" error.
// maxErrBodyBytes bounds how much of a server error body is kept for diagnosis.
// The body is tenant/proxy-controlled; capping it limits both log noise and how
// much attacker-chosen text can travel inside an error string.
const maxErrBodyBytes = 512

// maxErrWindowBytes caps how many bytes safeErrSnippet reads BEFORE truncation.
// The window must exceed maxErrBodyBytes by at least one token length so a
// credential straddling the cap is fully inside the redacted region (BL-1a); the
// ceiling stops a hostile endpoint from making the adapter buffer an unbounded
// prefix of its response.
const maxErrWindowBytes = 4096

// minTokenPrefixLen is the shortest proper prefix of the credential that
// safeErrSnippet will strip from a retained tail. Below this a "prefix" is one or
// two characters - not credential material, and stripping it would mangle
// legitimate diagnostics.
const minTokenPrefixLen = 4

// sanitizeServerBody renders a server-supplied error body safe to embed in an
// error string that callers log.
//
// Ported from tools/adapter-sdk/client.go (PR #23), which closed this exact class
// for the shared SDK. This adapter keeps its own copy because it is a standalone
// binary: it cannot import the SDK's unexported helper, and duplicating the
// fifteen-line function is cheaper than a new shared package for one caller. If a
// third component ever needs it, extract it then.
//
// Why: the body is attacker-controlled. A hostile or misconfigured endpoint (or a
// proxy in front of it) can return anything, including the real Authorization
// header echoed back in a verbose error, or text crafted to look like a
// credential. Either string would land verbatim in the error, get logged by
// Poller.Run, and leak the token into log aggregation (CWE-532) or defeat
// canary-based leak tests. The round-4 independent review REPRODUCED the first:
// a 401 whose JSON body echoed the SSWS token, which then appeared in captured
// slog output.
//
// Control characters are dropped entirely (no newlines, tabs, NULs, ANSI escapes,
// bidi overrides); the caller rune-truncates the result.
func sanitizeServerBody(data []byte) string {
	out := make([]rune, 0, len(data))
	for _, r := range string(data) {
		switch {
		case r == '\t', r == '\n', r == '\r':
			// Preserve the rough shape of the text but break any line structure.
			out = append(out, ' ')
		case r < 0x20 || r == 0x7f:
			// C0 controls, NUL, DEL: drop.
			continue
		case unicode.IsControl(r), unicode.Is(unicode.Cf, r):
			// Unicode control/format chars, incl. ESC and bidi overrides: drop.
			continue
		default:
			out = append(out, r)
		}
	}
	return string(out)
}

// truncateToRuneBoundary returns at most max bytes of b, cut so that the result
// is a valid-UTF-8 PREFIX of b. Valid under-cap input is returned unchanged;
// invalid bytes are cut away at the first undecodable position.
//
// History, kept because the bug it records is the reason for the shape of this
// function. This was first written as a hand transcription of the SDK's
// truncateToRuneBoundary (tools/adapter-sdk/client.go, PR #23). THE TRANSCRIPTION
// WAS WRONG, NOT THE ORIGINAL: it dropped the "+1" from the SDK's
// len(b)-i+1 < size completeness check and returned b[:i] instead of b[:i-1],
// keeping the orphan lead byte. An exhaustive sweep over every rune-width
// alignment showed the copy emitted invalid UTF-8 whenever the cap split a
// multi-byte rune - 4 of 8 hand-written cases, 456 of 781 generated ones. The
// SDK version is correct and passes its own split-rune tests; only this file's
// copy was broken. A first repair added explicit checks for stray continuation
// and 0xF8-0xFF lead bytes; that failed too, because a RUN of invalid bytes needs
// the same treatment recursively. Enumerating byte classes is the wrong shape for
// this problem, and hand-copying a subtle bit-twiddling helper is how the bug
// arrived in the first place.
//
// So this version does not classify bytes at all. It walks forward with
// utf8.DecodeRune - which already implements the UTF-8 grammar correctly - and
// keeps the end offset of the last COMPLETE valid rune that fits under the cap.
// Nothing to enumerate, therefore no alignment to miss. It also diverges from the
// SDK deliberately in one respect: the SDK keeps an invalid lead byte and lets
// sanitizeServerBody handle it, whereas this returns the valid prefix. Both are
// safe; the prefix form is simpler to reason about and is what the tests below
// pin.
//
// Invalid input: the scan stops at the first byte that does not begin a valid
// rune, so a body that is binary garbage yields an empty (still valid) prefix
// rather than propagating invalid bytes into a logged error string. That is a
// deliberate loss of diagnostics, and an acceptable one: the status code is the
// primary diagnostic and survives in the caller's error, while unreadable bytes
// carry none. Repairing invalid bytes rather than dropping them is
// sanitizeServerBody's job - it runs after this and maps them to U+FFFD - so
// this helper does not need to be a validator.
func truncateToRuneBoundary(b []byte, max int) []byte {
	if max <= 0 {
		return b[:0]
	}
	// NOTE: there is deliberately NO "len(b) <= max, return b unchanged" early
	// return here, and the SDK version HAS one. That difference is intentional and
	// comes from the differing call sites, not from a disagreement about the
	// helper. The SDK reads the whole body under a 1 MiB success cap and then
	// truncates to 512, so len(data) <= max only when the server sent a short,
	// COMPLETE body that cannot end mid-rune - the early return is harmless there.
	// THIS adapter reads through io.LimitReader(resp.Body, maxErrBodyBytes), so the
	// body arrives capped at exactly max bytes and CAN be split mid-rune. Under
	// that call site the same early return fires on every call and makes the
	// function a complete no-op: the one case it exists for is never repaired, and
	// the split bytes reach sanitizeServerBody and come back as U+FFFD replacement
	// characters in the logged error. Always scanning is O(max) over at most 512
	// bytes, which is nothing next to the network call that produced the body.
	end := 0
	limit := max
	if len(b) < limit {
		limit = len(b)
	}
	for i := 0; i < limit; {
		r, size := utf8.DecodeRune(b[i:])
		if r == utf8.RuneError && size <= 1 {
			break // invalid byte: keep the valid prefix gathered so far
		}
		if i+size > limit {
			break // complete rune, but it would cross the cap
		}
		i += size
		end = i
	}
	return b[:end]
}

// redactToken strips the client's own credential from ANY string the adapter is
// about to embed in an error message, audit record or log line. It is the single
// chokepoint for the BL-1 class (CWE-532: credentials written to logs).
//
// The threat model is a hostile or compromised Okta endpoint that reflects the
// Authorization header it just received back into material the adapter puts in an
// error: the body (round 4), a Link header target (round 5), or a transport-level
// message quoting that header (round 5). Those are the same capability and the
// same leak, arrived at through different surfaces, so they are redacted through
// one function rather than three ad-hoc ReplaceAll calls.
//
// Every call site MUST go through this helper. A site that formats
// server-controlled material into an error without calling redactToken is a
// BL-1-class leak regardless of how correct the rest of the adapter is.
func (c *Client) redactToken(s string) string {
	return redactCredential(s, c.token)
}

// safeErrSnippet builds the diagnostic fragment for an error response: the body
// is sanitized, the client's own token is redacted, THEN the result is
// rune-truncated to the cap and trimmed.
//
// ORDER MATTERS AND IS A SECURITY PROPERTY, NOT A STYLE CHOICE. Redaction runs
// BEFORE truncation, over a read window large enough to contain a token that
// straddles the cap. The previous implementation truncated first and redacted
// after, which is exploitable: an attacker who controls the body places the
// reflected credential so that it straddles the 512-byte boundary. The truncation
// then removes the token's final character, the whole-token ReplaceAll no longer
// matches anything, and the surviving 24 of 25 characters are written to the error
// string, the slog record and stdout. For a real ~40-char SSWS token 39 of 40
// characters survive at a known position - practical full credential recovery.
// Reading maxErrBodyBytes+len(token) bytes and redacting before the cut closes it
// for every offset the attacker can choose.
func (c *Client) safeErrSnippet(resp *http.Response) string {
	// Window = cap + token length, so a token straddling the cap is fully inside
	// the bytes we redact over. Bounded by a hard ceiling to keep a hostile
	// endpoint from making us buffer an unbounded prefix.
	window := maxErrBodyBytes
	if c.token != "" && c.token != "[redacted]" {
		window += len(c.token)
	}
	if window > maxErrWindowBytes {
		window = maxErrWindowBytes
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, int64(window)))

	// 1. Redact the whole token over the WIDER window, before any cut.
	s := c.redactToken(string(body))

	// 2. Sanitize (defeats log forging, control chars, invalid UTF-8).
	s = sanitizeServerBody([]byte(s))

	// 3. Only now truncate to the published cap, on a rune boundary.
	s = string(truncateToRuneBoundary([]byte(s), maxErrBodyBytes))

	// 4. Re-redact: sanitizing can rewrite bytes (e.g. invalid sequences become
	// U+FFFD) and truncation can cut a redaction marker's neighbour, so assert the
	// invariant once more on the exact string being returned. Cheap, and it makes
	// "no token leaves this function" true by construction rather than by ordering
	// argument.
	s = c.redactToken(s)

	// 5. A straddling token whose tail was cut can still leave a PROPER PREFIX of
	// the credential in the output. Trim any retained tail that is a prefix of the
	// token, longest first, so partial-credential recovery is impossible even if a
	// future change reorders the steps above.
	if c.token != "" {
		for n := len(c.token) - 1; n >= minTokenPrefixLen; n-- {
			if strings.HasSuffix(s, c.token[:n]) {
				s = s[:len(s)-n] + "[redacted]"
				break
			}
		}
	}
	return strings.TrimSpace(s)
}

func NewClient(baseURL, token string, timeout time.Duration) *Client {
	return &Client{
		baseURL: strings.TrimSuffix(baseURL, "/"),
		token:   token,
		httpClient: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		maxBackoff: 60 * time.Second,
	}
}

// ErrAuth is returned for 401/403 responses (bad/revoked token, missing
// permission). It is non-retryable: backing off on an auth failure just
// burns the Okta lockout budget.
var ErrAuth = errors.New("okta: authentication failed (check API token and permissions)")

// ErrTooManyPages signals that more events remain than MaxPages allows.
// The caller should persist the cursor it has and continue on the next poll
// (rather than treating it as an error).
var ErrTooManyPages = errors.New("okta: page limit reached with events pending")

// FetchLogsParams controls one poll of the System Log.
type FetchLogsParams struct {
	Since    time.Time // lower bound (Okta 'since'); zero = start of retention
	Until    time.Time // upper bound (Okta 'until'); zero = now
	Limit    int       // per-page limit (Okta clamps to 1000)
	MaxPages int       // safety cap; FetchLogs returns ErrTooManyPages when hit with data pending
}

// FetchLogs retrieves System Log events in the [Since, Until] window,
// following Okta's Link-header pagination. Okta returns events oldest-first
// (sortOrder=ASCENDING), which is what the cursor logic assumes.
//
// Rate limiting: 429 (and transient 5xx / network errors) are retried with
// exponential backoff plus jitter, honoring Retry-After / X-Rate-Limit-Reset
// when present. 401/403 fail immediately with ErrAuth.
func (c *Client) FetchLogs(ctx context.Context, p FetchLogsParams) ([]LogEvent, error) {
	if p.Limit <= 0 {
		p.Limit = 500
	}
	if p.Limit > 1000 {
		p.Limit = 1000
	}
	if p.MaxPages <= 0 {
		p.MaxPages = 50
	}

	q := url.Values{}
	q.Set("limit", strconv.Itoa(p.Limit))
	q.Set("sortOrder", "ASCENDING")
	if !p.Since.IsZero() {
		// Okta treats 'since' as exclusive. The caller advances the cursor to
		// the last processed event's timestamp; events sharing that exact
		// timestamp on a page boundary would be skipped by Okta itself, so we
		// step the query slightly *before* the cursor and let the poller dedupe
		// by event UUID against its processed set.
		q.Set("since", p.Since.UTC().Add(-time.Millisecond).Format(time.RFC3339Nano))
	}
	if !p.Until.IsZero() {
		q.Set("until", p.Until.UTC().Format(time.RFC3339Nano))
	}

	var (
		out     []LogEvent
		nextURL = c.baseURL + "/api/v1/logs?" + q.Encode()
		pages   int
	)

	for nextURL != "" {
		if pages >= p.MaxPages {
			return out, ErrTooManyPages
		}
		events, next, err := c.fetchPage(ctx, nextURL)
		if err != nil {
			return out, err
		}
		out = append(out, events...)
		pages++
		// The next-page URL comes from the response's Link header, i.e. from the
		// remote endpoint. Validating it before the next request is load-bearing:
		// doFetchPage attaches the SSWS Authorization header to whatever URL it is
		// handed, so following an unvalidated Link would let a compromised or
		// misconfigured endpoint exfiltrate the API token to an arbitrary host.
		if next != "" {
			validated, verr := c.validateNextURL(next)
			if verr != nil {
				return out, verr
			}
			nextURL = validated
		} else {
			nextURL = ""
		}
	}
	return out, nil
}

// ErrUnsafeNextURL is returned when a paginated Link header points somewhere we
// refuse to send credentials. Non-retryable: retrying cannot change the answer.
var ErrUnsafeNextURL = errors.New("okta: refusing to follow pagination link")

// validateNextURL ensures a Link-header pagination target is safe to send the
// API token to. Requirements:
//   - scheme must be https, EXCEPT http on a loopback host (so httptest-backed
//     tests work); plaintext to a non-loopback host is always refused
//   - host:port must exactly match the configured base URL's host:port
//
// Anything else is rejected rather than silently followed.
func (c *Client) validateNextURL(raw string) (string, error) {
	// BL-1b: `raw` is attacker-chosen Link-header content and `next.Host` is
	// derived from it. A hostile endpoint that received our Authorization header
	// can echo the credential back as the link target - bare, or as a hostname -
	// and the refusal message would then carry the live token into the returned
	// error, the slog record and stdout. Same capability and same leak as BL-1,
	// different surface, so every site that quotes server-controlled link material
	// goes through redactToken. url.Parse's own error text can also quote the
	// input, so it is redacted too.
	next, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("%w: unparseable %q: %v", ErrUnsafeNextURL,
			c.redactToken(raw), c.redactToken(err.Error()))
	}
	base, err := url.Parse(c.baseURL)
	if err != nil {
		return "", fmt.Errorf("%w: base URL is invalid: %v", ErrUnsafeNextURL, err)
	}
	if next.Host == "" {
		return "", fmt.Errorf("%w: missing host in %q", ErrUnsafeNextURL, c.redactToken(raw))
	}
	if next.Host != base.Host {
		return "", fmt.Errorf("%w: host %q is not the configured tenant %q", ErrUnsafeNextURL,
			c.redactToken(next.Host), base.Host)
	}
	if next.Scheme == "https" {
		return next.String(), nil
	}
	if next.Scheme == "http" && isLoopbackHost(next.Hostname()) {
		return next.String(), nil
	}
	return "", fmt.Errorf("%w: scheme %q is not permitted (https required; http only on loopback)", ErrUnsafeNextURL,
		// BL-3: the scheme comes from url.Parse, which LOWERCASES it. A hostile
		// endpoint that puts the token in the scheme position therefore hands back
		// a case-folded credential, and exact-match ReplaceAll cannot see it. This
		// is the site that made case-insensitive matching a requirement rather than
		// a nicety.
		c.redactToken(next.Scheme))
}

// isLoopbackHost reports whether a host refers to the local machine. Used to
// allow http:// in tests only; never permits plaintext to a remote tenant.
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// fetchPage retrieves one page (with retries) and returns the rel="next"
// pagination URL (empty when this is the last page).
func (c *Client) fetchPage(ctx context.Context, pageURL string) ([]LogEvent, string, error) {
	const maxAttempts = 5
	var lastErr error

	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			wait := c.backoffFor(attempt)
			timer := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, "", ctx.Err()
			case <-timer.C:
			}
		}

		events, next, wait, err := c.doFetchPage(ctx, pageURL)
		if err == nil {
			return events, next, nil
		}
		if errors.Is(err, ErrAuth) {
			return nil, "", err
		}
		if ctx.Err() != nil {
			return nil, "", ctx.Err()
		}
		lastErr = err
		c.lastRetryAfter = wait
		if !isRetryable(err) {
			return nil, "", err
		}
	}
	return nil, "", fmt.Errorf("okta: giving up after retries: %w", lastErr)
}

func (c *Client) doFetchPage(ctx context.Context, pageURL string) ([]LogEvent, string, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
	if err != nil {
		return nil, "", 0, fmt.Errorf("okta: build request: %w", err)
	}
	// Okta API-token auth: SSWS scheme. Never log this header.
	req.Header.Set("Authorization", "SSWS "+c.token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "oiaf-okta-adapter/0.1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		// BL-1b corollary: Go's transport surfaces malformed response headers in its
		// error text, e.g. `malformed MIME header line: "Link: <\x7fhttps://..."`.
		// A hostile endpoint can put the reflected credential in a header it then
		// makes unparseable, so the transport error is server-controlled material
		// too and must be redacted before it reaches the poller's logger.
		return nil, "", 0, &transientError{err: errors.New(c.redactToken(err.Error()))}
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusOK:
		// fallthrough to body decode below
	case resp.StatusCode == http.StatusUnauthorized, resp.StatusCode == http.StatusForbidden:
		// Include a snippet of the body (Okta error code) but never request
		// headers — they carry the token.
		// The BODY is tenant/proxy controlled and can echo the Authorization
		// header back; safeErrSnippet sanitizes, rune-truncates and redacts the
		// token before the snippet enters this error (round-4 review BL-1).
		return nil, "", 0, fmt.Errorf("%w: status %d: %s", ErrAuth, resp.StatusCode, c.safeErrSnippet(resp))
	case resp.StatusCode == http.StatusTooManyRequests:
		return nil, "", retryAfter(resp), &transientError{err: errors.New("okta: rate limited (429)")}
	case resp.StatusCode >= 500:
		return nil, "", 0, &transientError{err: fmt.Errorf("okta: server error %d", resp.StatusCode)}
	default:
		// Same channel as the 401/403 case; this default branch also covers
		// refused 3xx responses, whose body a hostile redirect target controls.
		return nil, "", 0, fmt.Errorf("okta: unexpected status %d: %s", resp.StatusCode, c.safeErrSnippet(resp))
	}

	var events []LogEvent
	dec := json.NewDecoder(io.LimitReader(resp.Body, 16<<20))
	if err := dec.Decode(&events); err != nil {
		// BL-2: a json decode error quotes the offending input — server-controlled
		// bytes that may contain the reflected credential, e.g.
		// `json: cannot unmarshal string into Go value of type ...` preceded by the
		// raw payload fragment. redactToken is the same fix as the body/Link/
		// transport sites.
		//
		// %s, NOT %w. Redacting a string and preserving the wrap chain are mutually
		// exclusive: the whole point is to stop quoting the original error's text,
		// so the returned error cannot also BE that error. The chain is already
		// flattened the same way at the transport-error site above, and nothing
		// unwraps this error — the sentinel checks in this package are ErrAuth,
		// ErrTooManyPages and os.ErrNotExist, none of which can appear inside a json
		// decode failure. isRetryable still works, since it matches the
		// *transientError wrapper rather than the cause.
		return nil, "", 0, &transientError{err: fmt.Errorf("okta: decode page: %s", c.redactToken(err.Error()))}
	}
	return events, nextLink(resp.Header.Get("Link")), 0, nil
}

// backoffFor returns the wait before the given retry attempt: a server-
// provided Retry-After when we saw one, otherwise exponential backoff
// (1s, 2s, 4s…) capped at maxBackoff plus up to 25% jitter.
func (c *Client) backoffFor(attempt int) time.Duration {
	if c.lastRetryAfter > 0 {
		ra := c.lastRetryAfter
		c.lastRetryAfter = 0
		return ra
	}
	base := float64(time.Second) * math.Pow(2, float64(attempt-1))
	if base > float64(c.maxBackoff) {
		base = float64(c.maxBackoff)
	}
	jitter := base * 0.25 * rand.Float64()
	return time.Duration(base + jitter)
}

// transientError marks errors that are worth retrying.
type transientError struct{ err error }

func (t *transientError) Error() string { return t.err.Error() }
func (t *transientError) Unwrap() error { return t.err }

func isRetryable(err error) bool {
	var t *transientError
	return errors.As(err, &t)
}

// retryAfter parses Retry-After (seconds or HTTP-date) and X-Rate-Limit-Reset
// (epoch seconds), preferring whichever yields the shorter wait.
func retryAfter(resp *http.Response) time.Duration {
	var best time.Duration
	if v := resp.Header.Get("Retry-After"); v != "" {
		if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
			best = time.Duration(secs) * time.Second
		} else if t, err := http.ParseTime(v); err == nil {
			if d := time.Until(t); d > 0 {
				best = d
			}
		}
	}
	if v := resp.Header.Get("X-Rate-Limit-Reset"); v != "" {
		if epoch, err := strconv.ParseInt(v, 10, 64); err == nil {
			if d := time.Until(time.Unix(epoch, 0)); d > 0 && (best == 0 || d < best) {
				best = d
			}
		}
	}
	return best
}

// nextLink extracts the rel="next" URL from an Okta Link header. Okta omits
// the Link header entirely on the final page.
func nextLink(header string) string {
	for _, part := range strings.Split(header, ",") {
		lt := strings.Index(part, "<")
		gt := strings.Index(part, ">")
		if lt < 0 || gt < 0 || gt < lt {
			continue
		}
		link := part[lt+1 : gt]
		rest := strings.ToLower(part[gt+1:])
		for _, attr := range strings.Split(rest, ";") {
			attr = strings.TrimSpace(attr)
			if strings.HasPrefix(attr, `rel="next"`) || attr == `rel=next` {
				return link
			}
		}
	}
	return ""
}
