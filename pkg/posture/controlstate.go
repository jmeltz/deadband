package posture

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ControlState records whether a compensating control has been applied, planned, or marked not applicable.
type ControlState struct {
	FindingType string `json:"finding_type"`
	ControlID   string `json:"control_id"`
	Status      string `json:"status"` // "applied", "planned", "not_applicable"
	Notes       string `json:"notes,omitempty"`
	UpdatedAt   string `json:"updated_at"`
}

// ControlStateStore persists control states to disk.
type ControlStateStore struct {
	mu     sync.Mutex
	path   string
	States []ControlState `json:"states"`
}

// DefaultControlStatePath returns ~/.deadband/control_states.json.
func DefaultControlStatePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "control_states.json"
	}
	return filepath.Join(home, ".deadband", "control_states.json")
}

// LoadControlStateStore loads from disk or returns an empty store.
func LoadControlStateStore(path string) *ControlStateStore {
	s := &ControlStateStore{path: path}
	data, err := os.ReadFile(path)
	if err != nil {
		return s
	}
	if err := json.Unmarshal(data, s); err != nil {
		log.Printf("[deadband] control state store %s: parse failed, starting empty: %v", path, err)
		return &ControlStateStore{path: path}
	}
	s.path = path
	return s
}

// Save writes the store to disk.
func (s *ControlStateStore) Save() error {
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

// SetState adds or updates a control state.
func (s *ControlStateStore) SetState(findingType, controlID, status, notes string) ControlState {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC().Format(time.RFC3339)

	for i := range s.States {
		if s.States[i].FindingType == findingType && s.States[i].ControlID == controlID {
			s.States[i].Status = status
			s.States[i].Notes = notes
			s.States[i].UpdatedAt = now
			return s.States[i]
		}
	}

	cs := ControlState{
		FindingType: findingType,
		ControlID:   controlID,
		Status:      status,
		Notes:       notes,
		UpdatedAt:   now,
	}
	s.States = append(s.States, cs)
	return cs
}

// GetStates returns all control states.
func (s *ControlStateStore) GetStates() []ControlState {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ControlState, len(s.States))
	copy(out, s.States)
	return out
}

// GetByFinding returns control states for a specific finding type.
func (s *ControlStateStore) GetByFinding(findingType string) []ControlState {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []ControlState
	for _, cs := range s.States {
		if cs.FindingType == findingType {
			out = append(out, cs)
		}
	}
	return out
}

// DeleteState removes a control state entry.
func (s *ControlStateStore) DeleteState(findingType, controlID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.States {
		if s.States[i].FindingType == findingType && s.States[i].ControlID == controlID {
			s.States = append(s.States[:i], s.States[i+1:]...)
			return true
		}
	}
	return false
}
