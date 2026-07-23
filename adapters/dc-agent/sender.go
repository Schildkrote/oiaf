// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

type Sender struct {
	baseURL    string
	token      string
	httpClient *http.Client
	logger     *slog.Logger
}

func NewSender(baseURL, token string, batchSize int, interval time.Duration, logger *slog.Logger) *Sender {
	return &Sender{
		baseURL: baseURL,
		token:   token,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: logger,
	}
}

func (s *Sender) Flush(ctx context.Context, events []EventRecord) {
	if len(events) == 0 {
		return
	}

	batch := struct {
		Events []EventRecord `json:"events"`
	}{Events: events}

	body, err := json.Marshal(batch)
	if err != nil {
		s.logger.Error("failed to marshal batch", "error", err)
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL+"/v1/ad/events", bytes.NewReader(body))
	if err != nil {
		s.logger.Error("failed to create request", "error", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.token)
	req.Header.Set("User-Agent", "oiaf-dc-agent/0.1.0")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		s.logger.Error("failed to send batch", "error", err, "count", len(events))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= http.StatusBadRequest {
		s.logger.Error("server rejected batch", "status", resp.StatusCode, "count", len(events))
		return
	}

	var result struct {
		Accepted  int `json:"accepted"`
		Decisions []struct {
			AccountSID  string `json:"account_sid"`
			AccountName string `json:"account_name"`
			Decision    string `json:"decision"`
			RiskScore   int    `json:"risk_score"`
		} `json:"decisions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err == nil {
		for _, d := range result.Decisions {
			s.logger.Warn("baseline deviation detected",
				"account", d.AccountName,
				"sid", d.AccountSID,
				"decision", d.Decision,
				"risk_score", d.RiskScore,
			)
		}
	}

	s.logger.Debug("batch sent", "count", len(events), "status", resp.StatusCode)
}

func (s *Sender) Close() {}

func (s *Sender) HealthCheck(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.baseURL+"/healthz", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.token)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("health check: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= http.StatusBadRequest {
		return fmt.Errorf("health check failed: %d", resp.StatusCode)
	}
	return nil
}
