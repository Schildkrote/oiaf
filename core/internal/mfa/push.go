// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: Apache-2.0

package mfa

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	"github.com/Schildkrote/oiaf/core/internal/storage"
	"github.com/Schildkrote/oiaf/core/internal/types"
)

type PushService struct {
	store      storage.Store
	skewWindow time.Duration
}

func NewPushService(store storage.Store, skewSeconds int) *PushService {
	return &PushService{
		store:      store,
		skewWindow: time.Duration(skewSeconds) * time.Second,
	}
}

func (s *PushService) RegisterDevice(ctx context.Context, identityID string, name string) (*types.Device, string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, "", err
	}
	secret := hex.EncodeToString(raw)
	hash := hashSecret(secret)

	device := &types.Device{
		ID:         types.NewID(),
		IdentityID: identityID,
		Name:       name,
		Managed:    true,
		Compliant:  true,
		SecretHash: hash,
		CreatedAt:  time.Now().UTC(),
	}

	if err := s.store.Devices(ctx).Create(ctx, device); err != nil {
		return nil, "", err
	}

	return device, secret, nil
}

func (s *PushService) GenerateNumber() (int, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(100))
	if err != nil {
		return 0, err
	}
	return int(n.Int64()), nil
}

func (s *PushService) VerifyApproval(ctx context.Context, deviceID string, challengeID string, number int, signature string, timestamp time.Time) error {
	if time.Since(timestamp) > s.skewWindow || time.Until(timestamp) > s.skewWindow {
		return fmt.Errorf("timestamp outside acceptable window")
	}

	device, err := s.store.Devices(ctx).Get(ctx, deviceID)
	if err != nil {
		return fmt.Errorf("device not found")
	}

	payload := fmt.Sprintf("%s|%d|%s", challengeID, number, timestamp.Format(time.RFC3339))
	expectedSig := computeHMAC(payload, device.SecretHash)
	if !hmac.Equal([]byte(signature), []byte(expectedSig)) {
		return fmt.Errorf("invalid signature")
	}

	return nil
}

func computeHMAC(payload string, key string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

func hashSecret(secret string) string {
	h := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(h[:])
}

func ComputePushSignature(deviceSecret string, challengeID string, number int, timestamp time.Time) string {
	payload := fmt.Sprintf("%s|%d|%s", challengeID, number, timestamp.Format(time.RFC3339))
	return computeHMAC(payload, hashSecret(deviceSecret))
}
