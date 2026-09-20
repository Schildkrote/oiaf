// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// State is the adapter's persisted cursor and per-identity detection memory.
// It lives in a single JSON file (path from config, default
// .oiaf/okta-state.json) matching the repo's offline-first ethos — no
// database, safe to delete (the adapter just re-learns baselines).
//
// Cursor semantics: Cursor is the published timestamp of the last
// successfully processed event. The next poll queries Okta with
// since=Cursor-1ms (Okta 'since' is exclusive) and dedupes by event UUID
// against RecentUUIDs, so re-runs neither duplicate nor gap even when
// multiple events share a timestamp.
type State struct {
	Cursor      time.Time                 `json:"cursor"`
	LastUUID    string                    `json:"last_uuid,omitempty"`
	RecentUUIDs []string                  `json:"recent_uuids,omitempty"`
	Identities  map[string]*IdentityState `json:"identities,omitempty"`
	SavedAt     time.Time                 `json:"saved_at"`

	// processed is an in-memory index of RecentUUIDs for O(1) dedupe; it is
	// not serialized.
	processed map[string]struct{}
}

// IdentityState is the per-login detection memory feeding impossible-travel,
// new-device and MFA-fatigue detection. Bounded by maxTrackedIdentities /
// maxDevicesPerIdentity / maxRecentUUIDs to keep the state file small.
type IdentityState struct {
	LastSeen time.Time   `json:"last_seen"`
	LastGeo  string      `json:"last_geo,omitempty"`
	Geos     []string    `json:"geos,omitempty"` // recently seen geo labels (bounded)
	LastLat  float64     `json:"last_lat,omitempty"`
	LastLon  float64     `json:"last_lon,omitempty"`
	HasGeo   bool        `json:"has_geo,omitempty"` // whether last lat/lon are valid
	Devices  []string    `json:"devices,omitempty"` // most recent device fingerprints
	MFAFails []time.Time `json:"mfa_fails,omitempty"`
	Admin    bool        `json:"admin,omitempty"` // seen performing admin actions
}

const (
	maxRecentUUIDs         = 4096
	maxTrackedIdentities   = 4096
	maxDevicesPerIdentity  = 32
	maxGeosPerIdentity     = 16
	maxMFAFailsPerIdentity = 32
)

// LoadState reads the state file. A missing file yields a fresh state (first
// run); a corrupt file is an error (we refuse to silently reprocess the whole
// retention window or skip events).
func LoadState(path string) (*State, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return NewState(), nil
		}
		return nil, fmt.Errorf("read state file: %w", err)
	}
	var st State
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("parse state file %s: %w", path, err)
	}
	st.reindex()
	return &st, nil
}

// NewState returns an empty, initialized state.
func NewState() *State {
	return &State{
		Identities: map[string]*IdentityState{},
		processed:  map[string]struct{}{},
	}
}

func (s *State) reindex() {
	s.processed = make(map[string]struct{}, len(s.RecentUUIDs))
	for _, u := range s.RecentUUIDs {
		s.processed[u] = struct{}{}
	}
	if s.Identities == nil {
		s.Identities = map[string]*IdentityState{}
	}
}

// AlreadyProcessed reports whether the event UUID was handled by a previous
// run/poll.
func (s *State) AlreadyProcessed(uuid string) bool {
	if uuid == "" {
		return false
	}
	_, ok := s.processed[uuid]
	return ok
}

// MarkProcessed records the UUID in the bounded dedupe window.
func (s *State) MarkProcessed(uuid string) {
	if uuid == "" || s.AlreadyProcessed(uuid) {
		return
	}
	s.RecentUUIDs = append(s.RecentUUIDs, uuid)
	s.processed[uuid] = struct{}{}
	if len(s.RecentUUIDs) > maxRecentUUIDs {
		drop := s.RecentUUIDs[:len(s.RecentUUIDs)-maxRecentUUIDs]
		for _, u := range drop {
			delete(s.processed, u)
		}
		s.RecentUUIDs = s.RecentUUIDs[len(drop):]
	}
}

// Identity returns (creating if needed) the detection memory for a login.
func (s *State) Identity(login string) *IdentityState {
	if id, ok := s.Identities[login]; ok {
		return id
	}
	id := &IdentityState{}
	s.Identities[login] = id
	s.evictIdentities()
	return id
}

// evictIdentities bounds the tracked-identity map by dropping the
// least-recently-seen entries when over the cap.
func (s *State) evictIdentities() {
	if len(s.Identities) <= maxTrackedIdentities {
		return
	}
	type kv struct {
		login string
		seen  time.Time
	}
	all := make([]kv, 0, len(s.Identities))
	for login, st := range s.Identities {
		all = append(all, kv{login, st.LastSeen})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].seen.Before(all[j].seen) })
	for i := 0; i < len(all)-maxTrackedIdentities; i++ {
		delete(s.Identities, all[i].login)
	}
}

// Save writes the state atomically (temp file + rename) with 0600 perms —
// it contains login identifiers and IPs (PII-adjacent), and must never be
// left half-written.
func (s *State) Save(path string, now time.Time) error {
	s.SavedAt = now.UTC()
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create state dir: %w", err)
		}
	}
	tmp, err := os.CreateTemp(dir, ".okta-state-*.json")
	if err != nil {
		return fmt.Errorf("create temp state file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after successful rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp state file: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod temp state file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp state file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename state file: %w", err)
	}
	return nil
}
