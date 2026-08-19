// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: Apache-2.0

package bus

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestEmitChainsAndDelivers(t *testing.T) {
	var mu sync.Mutex
	var received []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var ev map[string]any
		_ = json.Unmarshal(b, &ev)
		mu.Lock()
		received = append(received, ev)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	e := New("oiaf", []string{srv.URL})
	first, err := e.Emit("access.decided", "evaluate", "req-1", map[string]any{"request_id": "r1"}, map[string]any{"decision": "allow"})
	if err != nil {
		t.Fatalf("emit 1: %v", err)
	}
	second, err := e.Emit("challenge.verified", "verify", "ch-1", map[string]any{"request_id": "r1"}, map[string]any{"method": "totp"})
	if err != nil {
		t.Fatalf("emit 2: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 2 {
		t.Fatalf("expected 2 delivered events, got %d", len(received))
	}
	if first["prev_hash"] != "genesis" {
		t.Errorf("first event prev_hash = %v, want genesis", first["prev_hash"])
	}
	if second["prev_hash"] != first["hash"] {
		t.Errorf("second event prev_hash = %v, want first hash %v", second["prev_hash"], first["hash"])
	}
	// Verify the chain: hash = sha256 over canonical JSON with hash zeroed.
	if got := Digest(second); got != second["hash"] {
		t.Errorf("Digest mismatch: %v vs %v", got, second["hash"])
	}
}

func TestDisabledNoOp(t *testing.T) {
	e := New("oiaf", nil)
	ev, err := e.Emit("access.decided", "evaluate", "req-1", nil, nil)
	if err != nil || ev != nil {
		t.Fatalf("disabled emitter must be a no-op, got (%v, %v)", ev, err)
	}
}

func TestDigestMatchesCrossLanguageCanonicalForm(t *testing.T) {
	// Golden value produced by the platform's Python reference
	// (json.dumps(sort_keys=True, separators=(",", ":")) over the same event):
	// pinned so Go/Python/Node cannot drift silently.
	ev := map[string]any{
		"id":        "e1",
		"time":      "2026-08-19T12:00:00Z",
		"type":      "access.decided",
		"source":    "oiaf",
		"action":    "evaluate",
		"subject":   "req-1",
		"refs":      map[string]any{"request_id": "r1"},
		"data":      map[string]any{"decision": "allow", "risk_score": 10},
		"prev_hash": "genesis",
		"hash":      "",
	}
	want := sha256.Sum256([]byte(`{"action":"evaluate","data":{"decision":"allow","risk_score":10},"hash":"","id":"e1","prev_hash":"genesis","refs":{"request_id":"r1"},"source":"oiaf","subject":"req-1","time":"2026-08-19T12:00:00Z","type":"access.decided"}`))
	if got := Digest(ev); got != hex.EncodeToString(want[:]) {
		t.Errorf("canonical digest drift:\n got  %s\n want %s", got, hex.EncodeToString(want[:]))
	}
}

func TestDownSubscriberNeverErrors(t *testing.T) {
	e := New("oiaf", []string{"http://127.0.0.1:1"})
	if _, err := e.Emit("access.decided", "evaluate", "req-1", nil, nil); err != nil {
		t.Fatalf("best-effort emit must not error, got %v", err)
	}
}
