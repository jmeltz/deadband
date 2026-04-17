package posture

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// PostureSummary holds aggregate stats for a posture report.
type PostureSummary struct {
	TotalHosts    int     `json:"total_hosts"`
	OTHosts       int     `json:"ot_hosts"`
	ITHosts       int     `json:"it_hosts"`
	NetworkHosts  int     `json:"network_hosts"`
	UnknownHosts  int     `json:"unknown_hosts"`
	SubnetsScanned int    `json:"subnets_scanned"`
	MixedSubnets  int     `json:"mixed_subnets"`
	FindingCount  int     `json:"finding_count"`
	CriticalCount int     `json:"critical_count"`
	HighCount     int     `json:"high_count"`
	MediumCount   int     `json:"medium_count"`
	OverallScore  float64 `json:"overall_score"` // 0-10, lower is better
}

// PostureReport captures the full results of a posture scan.
type PostureReport struct {
	ID        string           `json:"id"`
	CIDR      string           `json:"cidr"`
	ScannedAt time.Time        `json:"scanned_at"`
	Duration  string           `json:"duration"`
	Subnets   []SubnetAnalysis `json:"subnets"`
	Findings  []Finding        `json:"findings"`
	Summary   PostureSummary   `json:"summary"`
}

// Store persists posture reports to disk.
type Store struct {
	mu      sync.Mutex
	path    string
	Reports []PostureReport `json:"reports"`
}

// DefaultStorePath returns ~/.deadband/posture.json.
func DefaultStorePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "posture.json"
	}
	return filepath.Join(home, ".deadband", "posture.json")
}

// LoadStore loads from disk or returns an empty store.
func LoadStore(path string) *Store {
	s := &Store{path: path}
	data, err := os.ReadFile(path)
	if err != nil {
		return s
	}
	if err := json.Unmarshal(data, s); err != nil {
		log.Printf("[deadband] posture store %s: parse failed, starting empty: %v", path, err)
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

// AddReport prepends a report and keeps the most recent 50.
func (s *Store) AddReport(r PostureReport) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Reports = append([]PostureReport{r}, s.Reports...)
	if len(s.Reports) > 50 {
		s.Reports = s.Reports[:50]
	}
}

// Latest returns the most recent report, or nil if none.
func (s *Store) Latest() *PostureReport {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.Reports) == 0 {
		return nil
	}
	r := s.Reports[0]
	return &r
}

// List returns all reports (newest first).
func (s *Store) List() []PostureReport {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]PostureReport, len(s.Reports))
	copy(out, s.Reports)
	return out
}

// Get returns a report by ID.
func (s *Store) Get(id string) *PostureReport {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.Reports {
		if s.Reports[i].ID == id {
			r := s.Reports[i]
			return &r
		}
	}
	return nil
}

// BuildSummary computes aggregate stats from subnets and findings.
func BuildSummary(subnets []SubnetAnalysis, findings []Finding) PostureSummary {
	sum := PostureSummary{
		SubnetsScanned: len(subnets),
		FindingCount:   len(findings),
	}
	for _, s := range subnets {
		sum.TotalHosts += s.TotalHosts
		sum.OTHosts += s.OTCount
		sum.ITHosts += s.ITCount
		sum.NetworkHosts += s.NetworkCount
		sum.UnknownHosts += s.UnknownCount
		if s.IsMixed {
			sum.MixedSubnets++
		}
	}
	maxRisk := 0.0
	for _, f := range findings {
		switch f.Severity {
		case "critical":
			sum.CriticalCount++
		case "high":
			sum.HighCount++
		case "medium":
			sum.MediumCount++
		}
	}
	for _, s := range subnets {
		if s.RiskScore > maxRisk {
			maxRisk = s.RiskScore
		}
	}
	sum.OverallScore = maxRisk
	return sum
}
