// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: Apache-2.0

package sdk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
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

func New(baseURL, token string, opts ...Option) *Client {
	c := &Client{
		baseURL: baseURL,
		token:   token,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

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
	if resp.StatusCode >= http.StatusBadRequest {
		data, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server error (%d): %s", resp.StatusCode, string(data))
	}
	return nil
}

func (c *Client) HealthCheck(ctx context.Context) error {
	resp, err := c.doRequest(ctx, http.MethodGet, "/healthz", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= http.StatusBadRequest {
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
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return nil, fmt.Errorf("server error (%d): %s", resp.StatusCode, string(data))
	}
	return data, nil
}
