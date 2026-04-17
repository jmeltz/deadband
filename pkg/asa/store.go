package asa

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sync"
)

const maxSnapshotsPerConfig = 10

// Store persists ASA collection snapshots to disk.
type Store struct {
	mu        sync.Mutex
	path      string
	Snapshots []ASASnapshot `json:"snapshots"`
}

// DefaultStorePath returns ~/.deadband/asa_snapshots.json.
func DefaultStorePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "asa_snapshots.json"
	}
	return filepath.Join(home, ".deadband", "asa_snapshots.json")
}

// LoadStore loads from disk or returns an empty store.
func LoadStore(path string) *Store {
	s := &Store{path: path}
	data, err := os.ReadFile(path)
	if err != nil {
		return s
	}
	if err := json.Unmarshal(data, s); err != nil {
		log.Printf("[deadband] asa store %s: parse failed, starting empty: %v", path, err)
		return &Store{path: path}
	}
	s.path = path
	return s
}

// Save writes the store to disk.
func (s *Store) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0o644)
}

// AddSnapshot prepends a snapshot and caps per-config history.
func (s *Store) AddSnapshot(snap ASASnapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Snapshots = append([]ASASnapshot{snap}, s.Snapshots...)

	counts := make(map[string]int)
	var kept []ASASnapshot
	for _, sn := range s.Snapshots {
		counts[sn.ConfigID]++
		if counts[sn.ConfigID] <= maxSnapshotsPerConfig {
			kept = append(kept, sn)
		}
	}
	s.Snapshots = kept
}

// GetLatest returns the most recent snapshot for a site.
func (s *Store) GetLatest(siteID string) *ASASnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.Snapshots {
		if s.Snapshots[i].SiteID == siteID {
			sn := s.Snapshots[i]
			return &sn
		}
	}
	return nil
}

// GetSnapshot returns a snapshot by ID.
func (s *Store) GetSnapshot(id string) *ASASnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.Snapshots {
		if s.Snapshots[i].ID == id {
			sn := s.Snapshots[i]
			return &sn
		}
	}
	return nil
}

// List returns all snapshots.
func (s *Store) List() []ASASnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ASASnapshot, len(s.Snapshots))
	copy(out, s.Snapshots)
	return out
}

// ListBySite returns snapshots for a given site.
func (s *Store) ListBySite(siteID string) []ASASnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []ASASnapshot
	for _, sn := range s.Snapshots {
		if sn.SiteID == siteID {
			out = append(out, sn)
		}
	}
	return out
}
