package sentinel

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sync"
)

const maxSnapshotsPerSite = 20

// Store persists Sentinel flow snapshots to disk.
type Store struct {
	mu        sync.Mutex
	path      string
	Snapshots []SentinelSnapshot `json:"snapshots"`
}

// DefaultStorePath returns ~/.deadband/sentinel_flows.json.
func DefaultStorePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "sentinel_flows.json"
	}
	return filepath.Join(home, ".deadband", "sentinel_flows.json")
}

// LoadStore loads from disk or returns an empty store.
func LoadStore(path string) *Store {
	s := &Store{path: path}
	data, err := os.ReadFile(path)
	if err != nil {
		return s
	}
	if err := json.Unmarshal(data, s); err != nil {
		log.Printf("[deadband] sentinel store %s: parse failed, starting empty: %v", path, err)
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

// AddSnapshot prepends a snapshot and caps per-site history.
func (s *Store) AddSnapshot(snap SentinelSnapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Snapshots = append([]SentinelSnapshot{snap}, s.Snapshots...)

	// Cap per site
	counts := make(map[string]int)
	var kept []SentinelSnapshot
	for _, sn := range s.Snapshots {
		counts[sn.SiteID]++
		if counts[sn.SiteID] <= maxSnapshotsPerSite {
			kept = append(kept, sn)
		}
	}
	s.Snapshots = kept
}

// GetLatest returns the most recent snapshot for a site.
func (s *Store) GetLatest(siteID string) *SentinelSnapshot {
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
func (s *Store) GetSnapshot(id string) *SentinelSnapshot {
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
func (s *Store) List() []SentinelSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]SentinelSnapshot, len(s.Snapshots))
	copy(out, s.Snapshots)
	return out
}

// ListBySite returns snapshots for a given site.
func (s *Store) ListBySite(siteID string) []SentinelSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []SentinelSnapshot
	for _, sn := range s.Snapshots {
		if sn.SiteID == siteID {
			out = append(out, sn)
		}
	}
	return out
}
