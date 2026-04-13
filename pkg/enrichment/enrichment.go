package enrichment

import (
	"fmt"
	"os"
	"path/filepath"
)

// DB holds all enrichment data (KEV + EPSS) for runtime lookups.
type DB struct {
	KEV  *KEVData
	EPSS *EPSSData
}

// CVEEnrichment holds the enrichment data for a single CVE.
type CVEEnrichment struct {
	KEV            bool    `json:"kev"`
	KEVRansomware  bool    `json:"kev_ransomware,omitempty"`
	KEVDateAdded   string  `json:"kev_date_added,omitempty"`
	KEVDueDate     string  `json:"kev_due_date,omitempty"`
	EPSSScore      float64 `json:"epss_score,omitempty"`
	EPSSPercentile float64 `json:"epss_percentile,omitempty"`
	RiskScore      float64 `json:"risk_score"`
}

// AdvisoryEnrichment holds the enrichment data for an advisory (aggregated from its CVEs).
type AdvisoryEnrichment struct {
	KEV            bool    `json:"kev"`
	KEVRansomware  bool    `json:"kev_ransomware,omitempty"`
	MaxEPSS        float64 `json:"epss_score,omitempty"`
	MaxEPSSPercent float64 `json:"epss_percentile,omitempty"`
	RiskScore      float64 `json:"risk_score"`
}

// Stats returns enrichment database statistics.
type Stats struct {
	KEVCount      int    `json:"kev_count"`
	KEVDate       string `json:"kev_date"`
	EPSSCount     int    `json:"epss_count"`
	EPSSDate      string `json:"epss_date"`
	EPSSVersion   string `json:"epss_version"`
}

// GetStats returns enrichment database statistics.
func (db *DB) GetStats() Stats {
	s := Stats{}
	if db.KEV != nil {
		s.KEVCount = len(db.KEV.Entries)
		s.KEVDate = db.KEV.DateReleased
	}
	if db.EPSS != nil {
		s.EPSSCount = len(db.EPSS.Entries)
		s.EPSSDate = db.EPSS.ScoreDate
		s.EPSSVersion = db.EPSS.ModelVersion
	}
	return s
}

// LookupCVE returns enrichment data for a single CVE.
func (db *DB) LookupCVE(cve string) CVEEnrichment {
	var e CVEEnrichment
	if db.KEV != nil {
		if entry, ok := db.KEV.Entries[cve]; ok {
			e.KEV = true
			e.KEVRansomware = entry.IsRansomware()
			e.KEVDateAdded = entry.DateAdded
			e.KEVDueDate = entry.DueDate
		}
	}
	if db.EPSS != nil {
		if entry, ok := db.EPSS.Entries[cve]; ok {
			e.EPSSScore = entry.Score
			e.EPSSPercentile = entry.Percentile
		}
	}
	e.RiskScore = ComputeRiskScore(e.KEV, e.KEVRansomware, e.EPSSScore, 0)
	return e
}

// EnrichAdvisory returns aggregated enrichment data for an advisory's CVEs.
func (db *DB) EnrichAdvisory(cves []string, cvss float64) AdvisoryEnrichment {
	var ae AdvisoryEnrichment
	for _, cve := range cves {
		ce := db.LookupCVE(cve)
		if ce.KEV {
			ae.KEV = true
		}
		if ce.KEVRansomware {
			ae.KEVRansomware = true
		}
		if ce.EPSSScore > ae.MaxEPSS {
			ae.MaxEPSS = ce.EPSSScore
			ae.MaxEPSSPercent = ce.EPSSPercentile
		}
	}
	ae.RiskScore = ComputeRiskScore(ae.KEV, ae.KEVRansomware, ae.MaxEPSS, cvss)
	return ae
}

// Loaded returns true if any enrichment data is available.
func (db *DB) Loaded() bool {
	return (db.KEV != nil && len(db.KEV.Entries) > 0) ||
		(db.EPSS != nil && len(db.EPSS.Entries) > 0)
}

// FetchAll downloads both KEV and EPSS data.
func FetchAll(progress func(string)) (*DB, error) {
	db := &DB{}

	kev, err := FetchKEV(progress)
	if err != nil {
		if progress != nil {
			progress(fmt.Sprintf("Warning: KEV fetch failed: %v", err))
		}
	} else {
		db.KEV = kev
		if progress != nil {
			progress(fmt.Sprintf("KEV catalog: %d entries (released %s)", len(kev.Entries), kev.DateReleased))
		}
	}

	epss, err := FetchEPSS(progress)
	if err != nil {
		if progress != nil {
			progress(fmt.Sprintf("Warning: EPSS fetch failed: %v", err))
		}
	} else {
		db.EPSS = epss
		if progress != nil {
			progress(fmt.Sprintf("EPSS scores: %d CVEs (model %s)", len(epss.Entries), epss.ModelVersion))
		}
	}

	return db, nil
}

// LoadFromDir loads cached KEV and EPSS data from a directory.
func LoadFromDir(dir string) *DB {
	db := &DB{}

	kevPath := filepath.Join(dir, "kev.json")
	if _, err := os.Stat(kevPath); err == nil {
		if kev, err := LoadKEVFromFile(kevPath); err == nil {
			db.KEV = kev
		}
	}

	epssPath := filepath.Join(dir, "epss_scores.csv")
	if _, err := os.Stat(epssPath); err == nil {
		if epss, err := LoadEPSSFromFile(epssPath); err == nil {
			db.EPSS = epss
		}
	}

	return db
}

// SaveToDir saves KEV and EPSS data to a directory.
func (db *DB) SaveToDir(dir string) error {
	if db.KEV != nil {
		if err := SaveKEV(dir, db.KEV); err != nil {
			return fmt.Errorf("saving KEV data: %w", err)
		}
	}
	if db.EPSS != nil {
		if err := SaveEPSS(dir, db.EPSS); err != nil {
			return fmt.Errorf("saving EPSS data: %w", err)
		}
	}
	return nil
}
