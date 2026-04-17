package integration

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sync"
)

// Store persists integration configurations to disk.
type Store struct {
	mu              sync.Mutex
	path            string
	SentinelConfigs []SentinelConfig `json:"sentinel_configs"`
	ASAConfigs      []ASAConfig      `json:"asa_configs"`
}

// DefaultStorePath returns ~/.deadband/integrations.json.
func DefaultStorePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "integrations.json"
	}
	return filepath.Join(home, ".deadband", "integrations.json")
}

// LoadStore loads from disk or returns an empty store.
func LoadStore(path string) *Store {
	s := &Store{path: path}
	data, err := os.ReadFile(path)
	if err != nil {
		return s
	}
	if err := json.Unmarshal(data, s); err != nil {
		log.Printf("[deadband] integration store %s: parse failed, starting empty: %v", path, err)
		return &Store{path: path}
	}
	s.path = path
	return s
}

// Save writes the store to disk with restrictive permissions (contains credentials).
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
	return os.WriteFile(s.path, data, 0o600)
}

// --- Sentinel config methods ---

// UpsertSentinel adds or replaces a Sentinel config by ID.
func (s *Store) UpsertSentinel(cfg SentinelConfig) SentinelConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.SentinelConfigs {
		if s.SentinelConfigs[i].ID == cfg.ID {
			s.SentinelConfigs[i] = cfg
			return cfg
		}
	}
	s.SentinelConfigs = append(s.SentinelConfigs, cfg)
	return cfg
}

// DeleteSentinel removes a Sentinel config by ID.
func (s *Store) DeleteSentinel(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.SentinelConfigs {
		if s.SentinelConfigs[i].ID == id {
			s.SentinelConfigs = append(s.SentinelConfigs[:i], s.SentinelConfigs[i+1:]...)
			return true
		}
	}
	return false
}

// GetSentinel returns a Sentinel config by ID.
func (s *Store) GetSentinel(id string) *SentinelConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.SentinelConfigs {
		if s.SentinelConfigs[i].ID == id {
			c := s.SentinelConfigs[i]
			return &c
		}
	}
	return nil
}

// ListSentinel returns all Sentinel configs.
func (s *Store) ListSentinel() []SentinelConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]SentinelConfig, len(s.SentinelConfigs))
	copy(out, s.SentinelConfigs)
	return out
}

// GetSentinelBySite returns Sentinel configs for a given site.
func (s *Store) GetSentinelBySite(siteID string) []SentinelConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []SentinelConfig
	for _, c := range s.SentinelConfigs {
		if c.SiteID == siteID {
			out = append(out, c)
		}
	}
	return out
}

// --- ASA config methods ---

// UpsertASA adds or replaces an ASA config by ID.
func (s *Store) UpsertASA(cfg ASAConfig) ASAConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cfg.Port == 0 {
		cfg.Port = 22
	}
	for i := range s.ASAConfigs {
		if s.ASAConfigs[i].ID == cfg.ID {
			s.ASAConfigs[i] = cfg
			return cfg
		}
	}
	s.ASAConfigs = append(s.ASAConfigs, cfg)
	return cfg
}

// DeleteASA removes an ASA config by ID.
func (s *Store) DeleteASA(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.ASAConfigs {
		if s.ASAConfigs[i].ID == id {
			s.ASAConfigs = append(s.ASAConfigs[:i], s.ASAConfigs[i+1:]...)
			return true
		}
	}
	return false
}

// GetASA returns an ASA config by ID.
func (s *Store) GetASA(id string) *ASAConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.ASAConfigs {
		if s.ASAConfigs[i].ID == id {
			c := s.ASAConfigs[i]
			return &c
		}
	}
	return nil
}

// ListASA returns all ASA configs.
func (s *Store) ListASA() []ASAConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ASAConfig, len(s.ASAConfigs))
	copy(out, s.ASAConfigs)
	return out
}

// GetASABySite returns ASA configs for a given site.
func (s *Store) GetASABySite(siteID string) []ASAConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []ASAConfig
	for _, c := range s.ASAConfigs {
		if c.SiteID == siteID {
			out = append(out, c)
		}
	}
	return out
}
