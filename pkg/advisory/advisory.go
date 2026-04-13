package advisory

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type Database struct {
	Updated         time.Time  `json:"updated"`
	PreviousUpdated *time.Time `json:"previous_updated,omitempty"`
	Source          string     `json:"source"`
	Advisories      []Advisory `json:"advisories"`
}

type Advisory struct {
	ID               string        `json:"id"`
	Title            string        `json:"title"`
	Vendor           string        `json:"vendor"`
	Products         []string      `json:"products"`
	AffectedVersions []string      `json:"affected_versions"`
	CVSSv3Max        float64       `json:"cvss_v3_max"`
	CVEs             []string      `json:"cves"`
	URL              string        `json:"url"`
	Published        string        `json:"published"`
	Summary          string        `json:"summary,omitempty"`
	Weaknesses       []Weakness    `json:"weaknesses,omitempty"`
	Sectors          []string      `json:"sectors,omitempty"`
	Remediations     []Remediation `json:"remediations,omitempty"`
	FirstSeen        *time.Time    `json:"first_seen,omitempty"`
	LastSeen         *time.Time    `json:"last_seen,omitempty"`
}

type Weakness struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Remediation struct {
	Category string `json:"category"`
	Details  string `json:"details"`
	URL      string `json:"url,omitempty"`
}

func DefaultDBPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", ".deadband", "advisories.json")
	}
	return filepath.Join(home, ".deadband", "advisories.json")
}

func LoadDatabase(path string) (*Database, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading advisory database: %w", err)
	}
	var db Database
	if err := json.Unmarshal(data, &db); err != nil {
		return nil, fmt.Errorf("parsing advisory database: %w", err)
	}
	return &db, nil
}

func SaveDatabase(path string, db *Database) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("creating directory: %w", err)
	}
	data, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling database: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return fmt.Errorf("writing temp file: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("replacing database: %w", err)
	}
	return nil
}

func (db *Database) Stats() string {
	return fmt.Sprintf("Advisory DB: %d advisories, last updated %s, source: %s",
		len(db.Advisories), db.Updated.Format("2006-01-02"), db.Source)
}

// StalenessStats returns the number of advisories added since the given time
// and the number of chronic advisories (first seen more than 6 months ago).
// If since is nil, addedSince is returned as -1 (unknown).
func (db *Database) StalenessStats(since *time.Time) (addedSince int, chronic int) {
	sixMonthsAgo := time.Now().Add(-6 * 30 * 24 * time.Hour)
	if since == nil {
		addedSince = -1
	}
	for _, a := range db.Advisories {
		if since != nil && a.FirstSeen != nil && a.FirstSeen.After(*since) {
			addedSince++
		}
		if a.FirstSeen != nil && a.FirstSeen.Before(sixMonthsAgo) {
			chronic++
		}
	}
	return
}
