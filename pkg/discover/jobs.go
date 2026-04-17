package discover

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const maxJobHistory = 100

// JobRecord is a persisted summary of a completed discovery job.
type JobRecord struct {
	ID           string     `json:"id"`
	CIDR         string     `json:"cidr"`
	Mode         string     `json:"mode"`
	Status       string     `json:"status"` // complete, error
	Error        string     `json:"error,omitempty"`
	StartedAt    time.Time  `json:"started_at"`
	CompletedAt  *time.Time `json:"completed_at,omitempty"`
	DeviceCount  int        `json:"device_count"`
	NewCount     int        `json:"new_count"`
	UpdatedCount int        `json:"updated_count"`
	Duration     string     `json:"duration,omitempty"`
}

// JobStore persists discovery job history to disk.
type JobStore struct {
	mu      sync.Mutex
	path    string
	Version int         `json:"version"`
	Jobs    []JobRecord `json:"jobs"`
}

// DefaultJobStorePath returns ~/.deadband/discovery_jobs.json.
func DefaultJobStorePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "discovery_jobs.json"
	}
	return filepath.Join(home, ".deadband", "discovery_jobs.json")
}

// LoadJobStore loads from disk or returns an empty store.
func LoadJobStore(path string) *JobStore {
	s := &JobStore{path: path, Version: 1}
	data, err := os.ReadFile(path)
	if err != nil {
		return s
	}
	if err := json.Unmarshal(data, s); err != nil {
		log.Printf("[deadband] job store %s: parse failed, starting empty: %v", path, err)
		return &JobStore{path: path, Version: 1}
	}
	s.path = path
	return s
}

// Save writes the store to disk.
func (s *JobStore) Save() error {
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

// Add appends a job record and trims to maxJobHistory.
func (s *JobStore) Add(rec JobRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Prepend (newest first)
	s.Jobs = append([]JobRecord{rec}, s.Jobs...)
	if len(s.Jobs) > maxJobHistory {
		s.Jobs = s.Jobs[:maxJobHistory]
	}
}

// Get returns a job by ID.
func (s *JobStore) Get(id string) *JobRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.Jobs {
		if s.Jobs[i].ID == id {
			return &s.Jobs[i]
		}
	}
	return nil
}

// List returns all job records (newest first).
func (s *JobStore) List() []JobRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]JobRecord, len(s.Jobs))
	copy(out, s.Jobs)
	return out
}
