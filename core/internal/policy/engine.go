// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/Schildkrote/oiaf/core/internal/storage"
	"github.com/Schildkrote/oiaf/core/internal/types"
)

type Engine interface {
	Evaluate(ctx context.Context, req types.AccessRequest) (types.PolicyDecision, error)
}

type BuiltinEngine struct {
	store storage.Store
}

func NewBuiltinEngine(store storage.Store) *BuiltinEngine {
	return &BuiltinEngine{store: store}
}

func (e *BuiltinEngine) Evaluate(ctx context.Context, req types.AccessRequest) (types.PolicyDecision, error) {
	policies, err := e.store.Policies(ctx).List(ctx)
	if err != nil {
		return types.PolicyDecision{}, fmt.Errorf("listing policies: %w", err)
	}

	var enabled []*types.Policy
	for _, p := range policies {
		if p.Enabled {
			enabled = append(enabled, p)
		}
	}

	sort.Slice(enabled, func(i, j int) bool {
		return enabled[i].Priority > enabled[j].Priority
	})

	reqMap, err := requestToMap(req)
	if err != nil {
		return types.PolicyDecision{}, fmt.Errorf("converting request to map: %w", err)
	}

	var matched []types.PolicyDecision
	for _, p := range enabled {
		cond, err := evaluateConditions(p.Conditions, reqMap)
		if err != nil {
			continue
		}
		if cond {
			matched = append(matched, types.PolicyDecision{
				Effect:    p.Effect,
				PolicyID:  p.ID,
				Reasons:   []string{fmt.Sprintf("policy %s matched", p.ID)},
				Challenge: p.Challenge,
			})
		}
	}

	order := map[types.Decision]int{
		types.DecisionDeny:      0,
		types.DecisionChallenge: 1,
		types.DecisionAlert:     2,
		types.DecisionAllow:     3,
	}

	if len(matched) > 0 {
		sort.Slice(matched, func(i, j int) bool {
			return order[matched[i].Effect] < order[matched[j].Effect]
		})
		return matched[0], nil
	}

	sens := strings.ToLower(req.Resource.Sensitivity)
	if sens == "high" || sens == "critical" {
		return types.PolicyDecision{
			Effect:  types.DecisionDeny,
			Reasons: []string{"default deny for high/critical sensitivity resource"},
		}, nil
	}
	if sens == "low" {
		return types.PolicyDecision{
			Effect:  types.DecisionAllow,
			Reasons: []string{"default allow for low sensitivity resource"},
		}, nil
	}

	return types.PolicyDecision{
		Effect:  types.DecisionDeny,
		Reasons: []string{"no policy matched"},
	}, nil
}

func requestToMap(req types.AccessRequest) (map[string]interface{}, error) {
	data, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func resolvePath(m map[string]interface{}, path string) (interface{}, bool) {
	parts := strings.Split(path, ".")
	var current interface{} = m
	for _, part := range parts {
		switch v := current.(type) {
		case map[string]interface{}:
			val, ok := v[part]
			if !ok {
				return nil, false
			}
			current = val
		default:
			return nil, false
		}
	}
	return current, true
}

type conditionNode struct {
	All   []json.RawMessage `json:"all"`
	Any   []json.RawMessage `json:"any"`
	Not   *json.RawMessage  `json:"not"`
	Path  string            `json:"path"`
	Op    string            `json:"op"`
	Value interface{}       `json:"value"`
}

func evaluateConditions(raw json.RawMessage, reqMap map[string]interface{}) (bool, error) {
	var node conditionNode
	if err := json.Unmarshal(raw, &node); err != nil {
		return false, err
	}

	if node.All != nil {
		for _, sub := range node.All {
			result, err := evaluateConditions(sub, reqMap)
			if err != nil {
				return false, err
			}
			if !result {
				return false, nil
			}
		}
		return true, nil
	}

	if node.Any != nil {
		for _, sub := range node.Any {
			result, err := evaluateConditions(sub, reqMap)
			if err != nil {
				return false, err
			}
			if result {
				return true, nil
			}
		}
		return false, nil
	}

	if node.Not != nil {
		result, err := evaluateConditions(*node.Not, reqMap)
		if err != nil {
			return false, err
		}
		return !result, nil
	}

	if node.Path != "" && node.Op != "" {
		return evaluateLeaf(node.Path, node.Op, node.Value, reqMap)
	}

	return false, nil
}

func evaluateLeaf(path, op string, value interface{}, reqMap map[string]interface{}) (bool, error) {
	actual, exists := resolvePath(reqMap, path)

	switch op {
	case "exists":
		return exists, nil
	case "not_exists":
		return !exists, nil
	}

	if !exists {
		return false, nil
	}

	switch op {
	case "eq":
		return compareEq(actual, value), nil
	case "neq":
		return !compareEq(actual, value), nil
	case "in":
		return compareIn(actual, value), nil
	case "not_in":
		return !compareIn(actual, value), nil
	case "contains":
		return compareContains(actual, value), nil
	case "not_contains":
		return !compareContains(actual, value), nil
	case "gt":
		return compareNumeric(actual, value, func(a, b float64) bool { return a > b }), nil
	case "gte":
		return compareNumeric(actual, value, func(a, b float64) bool { return a >= b }), nil
	case "lt":
		return compareNumeric(actual, value, func(a, b float64) bool { return a < b }), nil
	case "lte":
		return compareNumeric(actual, value, func(a, b float64) bool { return a <= b }), nil
	case "regex":
		return compareRegex(actual, value), nil
	default:
		return false, fmt.Errorf("unknown operator: %s", op)
	}
}

func compareEq(actual, expected interface{}) bool {
	return fmt.Sprintf("%v", actual) == fmt.Sprintf("%v", expected)
}

func compareIn(actual, expected interface{}) bool {
	switch v := expected.(type) {
	case []interface{}:
		actualStr := fmt.Sprintf("%v", actual)
		for _, item := range v {
			if fmt.Sprintf("%v", item) == actualStr {
				return true
			}
		}
	}
	return false
}

func compareContains(actual, expected interface{}) bool {
	switch v := actual.(type) {
	case []interface{}:
		expectedStr := fmt.Sprintf("%v", expected)
		for _, item := range v {
			if fmt.Sprintf("%v", item) == expectedStr {
				return true
			}
		}
	case string:
		return strings.Contains(v, fmt.Sprintf("%v", expected))
	}
	return false
}

func compareNumeric(actual, expected interface{}, cmp func(float64, float64) bool) bool {
	a, ok1 := toFloat64(actual)
	b, ok2 := toFloat64(expected)
	if !ok1 || !ok2 {
		return false
	}
	return cmp(a, b)
}

func toFloat64(v interface{}) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	}
	return 0, false
}

func compareRegex(actual, expected interface{}) bool {
	pattern, ok := expected.(string)
	if !ok {
		return false
	}
	actualStr := fmt.Sprintf("%v", actual)
	re, err := regexp.Compile(pattern)
	if err != nil {
		return false
	}
	return re.MatchString(actualStr)
}
