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
	DebugData map[string]string `json:"debugData"`
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
func NewClient(baseURL, token string, timeout time.Duration) *Client {
	return &Client{
		baseURL:    strings.TrimSuffix(baseURL, "/"),
		token:      token,
		httpClient: &http.Client{Timeout: timeout},
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
	next, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("%w: unparseable %q: %v", ErrUnsafeNextURL, raw, err)
	}
	base, err := url.Parse(c.baseURL)
	if err != nil {
		return "", fmt.Errorf("%w: base URL is invalid: %v", ErrUnsafeNextURL, err)
	}
	if next.Host == "" {
		return "", fmt.Errorf("%w: missing host in %q", ErrUnsafeNextURL, raw)
	}
	if next.Host != base.Host {
		return "", fmt.Errorf("%w: host %q is not the configured tenant %q", ErrUnsafeNextURL, next.Host, base.Host)
	}
	if next.Scheme == "https" {
		return next.String(), nil
	}
	if next.Scheme == "http" && isLoopbackHost(next.Hostname()) {
		return next.String(), nil
	}
	return "", fmt.Errorf("%w: scheme %q is not permitted (https required; http only on loopback)", ErrUnsafeNextURL, next.Scheme)
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
		return nil, "", 0, &transientError{err: err}
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusOK:
		// fallthrough to body decode below
	case resp.StatusCode == http.StatusUnauthorized, resp.StatusCode == http.StatusForbidden:
		// Include a snippet of the body (Okta error code) but never request
		// headers — they carry the token.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, "", 0, fmt.Errorf("%w: status %d: %s", ErrAuth, resp.StatusCode, strings.TrimSpace(string(body)))
	case resp.StatusCode == http.StatusTooManyRequests:
		return nil, "", retryAfter(resp), &transientError{err: errors.New("okta: rate limited (429)")}
	case resp.StatusCode >= 500:
		return nil, "", 0, &transientError{err: fmt.Errorf("okta: server error %d", resp.StatusCode)}
	default:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, "", 0, fmt.Errorf("okta: unexpected status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var events []LogEvent
	dec := json.NewDecoder(io.LimitReader(resp.Body, 16<<20))
	if err := dec.Decode(&events); err != nil {
		return nil, "", 0, &transientError{err: fmt.Errorf("okta: decode page: %w", err)}
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
