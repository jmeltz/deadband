package acl

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sync"
)

// Store persists ACL policies to disk.
type Store struct {
	mu       sync.Mutex
	path     string
	Policies []Policy `json:"policies"`
}

// DefaultStorePath returns ~/.deadband/acl_policies.json.
func DefaultStorePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "acl_policies.json"
	}
	return filepath.Join(home, ".deadband", "acl_policies.json")
}

// LoadStore loads from disk or returns an empty store.
func LoadStore(path string) *Store {
	s := &Store{path: path}
	data, err := os.ReadFile(path)
	if err != nil {
		return s
	}
	if err := json.Unmarshal(data, s); err != nil {
		log.Printf("[deadband] acl store %s: parse failed, starting empty: %v", path, err)
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

// Upsert adds or replaces a policy by ID.
func (s *Store) Upsert(p Policy) Policy {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.Policies {
		if s.Policies[i].ID == p.ID {
			s.Policies[i] = p
			return p
		}
	}
	s.Policies = append(s.Policies, p)
	return p
}

// Delete removes a policy by ID.
func (s *Store) Delete(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.Policies {
		if s.Policies[i].ID == id {
			s.Policies = append(s.Policies[:i], s.Policies[i+1:]...)
			return true
		}
	}
	return false
}

// Get returns a policy by ID.
func (s *Store) Get(id string) *Policy {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.Policies {
		if s.Policies[i].ID == id {
			p := s.Policies[i]
			return &p
		}
	}
	return nil
}

// GetBySite returns all policies for a site.
func (s *Store) GetBySite(siteID string) []Policy {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Policy
	for _, p := range s.Policies {
		if p.SiteID == siteID {
			out = append(out, p)
		}
	}
	return out
}

// List returns all policies.
func (s *Store) List() []Policy {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Policy, len(s.Policies))
	copy(out, s.Policies)
	return out
}
