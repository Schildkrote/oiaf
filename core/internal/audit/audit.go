// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/Schildkrote/oiaf/core/internal/storage"
	"github.com/Schildkrote/oiaf/core/internal/types"
)

type Service struct {
	store storage.Store
}

func New(store storage.Store) *Service {
	return &Service{store: store}
}

func (s *Service) Emit(ctx context.Context, eventType string, actor types.AuditActor, target types.AuditTarget, decision types.Decision, riskScore int, reasons []string, metadata map[string]interface{}) error {
	prevHash, err := s.store.AuditEvents(ctx).GetLastHash(ctx)
	if err != nil {
		return err
	}

	event := &types.AuditEvent{
		ID:           types.NewID(),
		Timestamp:    time.Now().UTC(),
		Type:         eventType,
		Actor:        actor,
		Target:       target,
		Decision:     decision,
		RiskScore:    riskScore,
		Reasons:      reasons,
		Metadata:     metadata,
		PreviousHash: prevHash,
	}

	event.Hash = computeHash(prevHash, event)
	return s.store.AuditEvents(ctx).Append(ctx, event)
}

func computeHash(prevHash string, event *types.AuditEvent) string {
	type hashableEvent struct {
		ID           string                 `json:"id"`
		Timestamp    time.Time              `json:"timestamp"`
		Type         string                 `json:"type"`
		Actor        types.AuditActor       `json:"actor"`
		Target       types.AuditTarget      `json:"target"`
		Decision     types.Decision         `json:"decision,omitempty"`
		RiskScore    int                    `json:"risk_score,omitempty"`
		Reasons      []string               `json:"reasons,omitempty"`
		Metadata     map[string]interface{} `json:"metadata,omitempty"`
		PreviousHash string                 `json:"previous_hash"`
	}
	he := hashableEvent{
		ID:           event.ID,
		Timestamp:    event.Timestamp,
		Type:         event.Type,
		Actor:        event.Actor,
		Target:       event.Target,
		Decision:     event.Decision,
		RiskScore:    event.RiskScore,
		Reasons:      event.Reasons,
		Metadata:     event.Metadata,
		PreviousHash: event.PreviousHash,
	}
	data, _ := json.Marshal(he)
	h := sha256.Sum256(append([]byte(prevHash), data...))
	return hex.EncodeToString(h[:])
}

func (s *Service) List(ctx context.Context, filter storage.AuditFilter) ([]*types.AuditEvent, error) {
	return s.store.AuditEvents(ctx).List(ctx, filter)
}

func (s *Service) Verify(ctx context.Context) (bool, int, error) {
	return s.store.AuditEvents(ctx).Verify(ctx)
}
