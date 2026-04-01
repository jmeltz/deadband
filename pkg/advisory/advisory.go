package advisory

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type Database struct {
	Updated    time.Time  `json:"updated"`
	Source     string     `json:"source"`
	Advisories []Advisory `json:"advisories"`
}

type Advisory struct {
	ID               string   `json:"id"`
	Title            string   `json:"title"`
	Vendor           string   `json:"vendor"`
	Products         []string `json:"products"`
	AffectedVersions []string `json:"affected_versions"`
	CVSSv3Max        float64  `json:"cvss_v3_max"`
	CVEs             []string `json:"cves"`
	URL              string   `json:"url"`
	Published        string   `json:"published"`
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
