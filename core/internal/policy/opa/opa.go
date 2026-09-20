// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package opa

import (
	"context"
	"fmt"

	"github.com/Schildkrote/oiaf/core/internal/types"
)

type Engine struct{}

func New() *Engine {
	return &Engine{}
}

func (e *Engine) Evaluate(ctx context.Context, req types.AccessRequest) (types.PolicyDecision, error) {
	return types.PolicyDecision{}, fmt.Errorf("not implemented: OPA policy engine")
}
