// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: AGPL-3.0-only

// Package bus emits OIAF decisions as integration events onto the
// open-security-platform spine. Events conform to the platform's
// integration event schema (open-security-platform
// platform/schemas/integration_event.schema.json) and are hash-chained with
// the platform's tamper-evident algorithm: sha256 over the canonical JSON of
// the event (compact, sorted keys, raw UTF-8) with the hash field zeroed;
// prev_hash is seeded at "genesis".
//
// Emission is opt-in (no subscriber URLs => no-op, so offline behaviour and
// existing API responses are unchanged) and best-effort: a missing or failing
// subscriber never returns an error to the caller, so a down subscriber cannot
// break the decision path.
package bus

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"time"
)

const genesis = "genesis"

// Emitter publishes hash-chained integration events to subscriber webhooks.
type Emitter struct {
	mu     sync.Mutex
	source string
	urls   []string
	prev   string
	client *http.Client
}

// New returns an Emitter for the named source component. An empty urls slice
// disables emission.
func New(source string, urls []string) *Emitter {
	return &Emitter{
		source: source,
		urls:   urls,
		prev:   genesis,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// Enabled reports whether the emitter has any subscribers.
func (e *Emitter) Enabled() bool { return len(e.urls) > 0 }

// Emit builds, chains and POSTs an integration event to every subscriber, and
// returns the emitted event (nil when there are no subscribers). Errors
// delivering to subscribers are swallowed (best-effort).
func (e *Emitter) Emit(eventType, action, subject string, refs, data map[string]any) (map[string]any, error) {
	if !e.Enabled() {
		return nil, nil
	}
	if refs == nil {
		refs = map[string]any{}
	}
	if data == nil {
		data = map[string]any{}
	}
	e.mu.Lock()
	ev := map[string]any{
		"id":        newID(),
		"time":      time.Now().UTC().Format(time.RFC3339Nano),
		"type":      eventType,
		"source":    e.source,
		"action":    action,
		"subject":   subject,
		"refs":      refs,
		"data":      data,
		"prev_hash": e.prev,
		"hash":      "",
	}
	ev["hash"] = Digest(ev)
	e.prev, _ = ev["hash"].(string)
	e.mu.Unlock()

	payload, err := marshalCanonical(ev)
	if err != nil {
		return ev, err
	}
	for _, u := range e.urls {
		req, err := http.NewRequest(http.MethodPost, u, bytes.NewReader(payload))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		if resp, err := e.client.Do(req); err == nil {
			resp.Body.Close()
		}
	}
	return ev, nil
}

// Digest computes the chain hash: sha256 over the canonical JSON of the event
// with its hash field zeroed.
func Digest(ev map[string]any) string {
	copied := make(map[string]any, len(ev))
	for k, v := range ev {
		copied[k] = v
	}
	copied["hash"] = ""
	b, _ := marshalCanonical(copied)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// marshalCanonical renders v as compact JSON with keys sorted recursively, so
// the same event hashes identically in Go, Python and Node (the platform's
// cross-language canonical form).
func marshalCanonical(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeCanonical(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonical(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
	case string:
		return encodeString(buf, t)
	case float64:
		b, err := json.Marshal(t)
		if err != nil {
			return err
		}
		buf.Write(b)
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case []any:
		buf.WriteByte('[')
		for i, item := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := encodeString(buf, k); err != nil {
				return err
			}
			buf.WriteByte(':')
			if err := writeCanonical(buf, t[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return err
		}
		buf.Write(b)
	}
	return nil
}

func encodeString(buf *bytes.Buffer, s string) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	buf.Write(b)
	return nil
}

func newID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("id-%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
