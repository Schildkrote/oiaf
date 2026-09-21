// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package sdk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode"
)

type Client struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

type Option func(*Client)

func WithTimeout(d time.Duration) Option {
	return func(c *Client) {
		c.httpClient.Timeout = d
	}
}

// New builds an SDK client for the given OIAF core.
//
// SECURITY — redirects are refused. doRequest sets "Authorization: Bearer <token>"
// on every request, and net/http follows 3xx transparently. Go only strips the
// Authorization header when the redirect changes the HOSTNAME; it compares
// hostnames with the port stripped, so a 302 to the same hostname on a
// DIFFERENT PORT carries the bearer token to whatever is listening there. A
// compromised core, or a redirect-issuing proxy in front of it, could therefore
// collect every adapter credential. This affects every sdk consumer — currently
// adapters/pam/oiaf-pam-helper, which ships in tag v0.2.0-mfa.
//
// NOTE: adapters/dc-agent does NOT import this package; it carries its own
// http.Client and had the identical bug, fixed separately in
// adapters/dc-agent/sender.go. Don't assume fixing the SDK protects dc-agent.
//
// OIAF core never issues redirects on these endpoints, so refusing them outright
// is both safe and minimal: CheckRedirect returns http.ErrUseLastResponse, the
// 3xx is returned untouched, and readResponse/ReportEvent/HealthCheck treat any
// non-2xx as an error (they previously treated "status < 400" as success, which
// would have decoded an empty 302 body as a valid decision — a silent
// fail-open, worse than a crash).
func New(baseURL, token string, opts ...Option) *Client {
	c := &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// isNotSuccess reports whether a status code is anything other than 2xx.
// 3xx counts as a failure: with redirects refused, a 3xx means the request was
// NOT processed by the core, so treating it as success would silently swallow
// the decision (and, for a body-less 302, decode an empty payload as valid).
func isNotSuccess(status int) bool { return status < 200 || status >= 300 }

func (c *Client) EvaluateAccess(ctx context.Context, req json.RawMessage) (json.RawMessage, error) {
	resp, err := c.doRequest(ctx, http.MethodPost, "/v1/access/evaluate", bytes.NewReader(req))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return readResponse(resp)
}

func (c *Client) VerifyChallenge(ctx context.Context, challengeID string, payload json.RawMessage) (json.RawMessage, error) {
	resp, err := c.doRequest(ctx, http.MethodPost, "/v1/challenge/"+challengeID+"/verify", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return readResponse(resp)
}

func (c *Client) ReportEvent(ctx context.Context, event json.RawMessage) error {
	resp, err := c.doRequest(ctx, http.MethodPost, "/v1/audit/events", bytes.NewReader(event))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if isNotSuccess(resp.StatusCode) {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrBodyBytes))
		return fmt.Errorf("server error (%d): %s", resp.StatusCode, sanitizeServerBody(data))
	}
	return nil
}

func (c *Client) HealthCheck(ctx context.Context) error {
	resp, err := c.doRequest(ctx, http.MethodGet, "/healthz", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if isNotSuccess(resp.StatusCode) {
		return fmt.Errorf("health check failed (%d)", resp.StatusCode)
	}
	return nil
}

func (c *Client) doRequest(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("User-Agent", "oiaf-adapter-sdk/0.1.0")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.httpClient.Do(req)
}

func readResponse(resp *http.Response) (json.RawMessage, error) {
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxRespBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if isNotSuccess(resp.StatusCode) {
		// Truncate to the diagnosis budget before sanitising. The body was read
		// with the much larger success cap (a valid decision payload may be
		// large), but an error body is attacker-controlled and callers log this
		// string — so it must not carry up to maxRespBodyBytes into the logs.
		// Cut on a rune boundary: slicing mid-rune would emit U+FFFD and make
		// the message look corrupted for no diagnostic gain.
		data = truncateToRuneBoundary(data, maxErrBodyBytes)
		return nil, fmt.Errorf("server error (%d): %s", resp.StatusCode, sanitizeServerBody(data))
	}
	return data, nil
}

// truncateToRuneBoundary returns at most max bytes of b, walking back off any
// partial UTF-8 sequence at the cut so no replacement character is produced.
func truncateToRuneBoundary(b []byte, max int) []byte {
	if len(b) <= max {
		return b
	}
	b = b[:max]
	// Walk back over continuation bytes (10xxxxxx) to the start of the last
	// rune, then drop it if the sequence is incomplete.
	i := len(b)
	for i > 0 && b[i-1]&0xC0 == 0x80 {
		i--
	}
	if i == 0 {
		return b[:max]
	}
	lead := b[i-1]
	var size int
	switch {
	case lead < 0x80:
		size = 1
	case lead&0xE0 == 0xC0:
		size = 2
	case lead&0xF0 == 0xE0:
		size = 3
	case lead&0xF8 == 0xF0:
		size = 4
	default:
		size = 1 // invalid lead byte; keep it and let sanitisation handle it
	}
	if len(b)-i+1 < size {
		return b[:i-1] // incomplete trailing rune: drop it, lead byte included
	}
	return b
}

const (
	// maxRespBodyBytes bounds a successful decision payload. OIAF decisions are
	// small JSON objects; this is generous headroom, not a tight fit.
	maxRespBodyBytes = 1 << 20 // 1 MiB
	// maxErrBodyBytes bounds how much of an error body we keep for diagnosis.
	maxErrBodyBytes = 512
)

// sanitizeServerBody renders a server-supplied error body safe to embed in an
// error string that callers log.
//
// Why: the body is attacker-controlled. A hostile or compromised core (or a
// proxy in front of it) can return anything — including text crafted to look
// like a credential, e.g. "reflected: Bearer <looks-like-a-real-token>". That
// string lands verbatim in the error, gets logged, and then (a) pollutes log
// aggregation with what looks like a leaked secret and (b) can defeat
// canary-based leak tests by making a secret-shaped string appear in otherwise
// clean output. slog's JSON encoding prevents classic newline log-injection,
// so the realistic risk is token-mimicry and second-order exfiltration into
// logs rather than log forging — moderate, but free to close.
//
// Control characters are dropped entirely (no newlines, tabs, NULs, ANSI
// escapes), and the result is length-capped by the caller's LimitReader.
func sanitizeServerBody(data []byte) string {
	out := make([]rune, 0, len(data))
	for _, r := range string(data) {
		switch {
		case r == '	', r == '\n', r == '\r':
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
