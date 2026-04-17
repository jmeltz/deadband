package asset

import (
	"strings"
	"time"
)

// VulnState captures the vulnerability assessment state of an asset.
type VulnState struct {
	CheckedAt  time.Time       `json:"checked_at"`
	Status     string          `json:"status"`     // VULNERABLE, POTENTIAL, OK
	Confidence string          `json:"confidence"`  // HIGH, MEDIUM, LOW
	RiskScore  float64         `json:"risk_score"`
	Advisories []VulnAdvisory  `json:"advisories,omitempty"`
	CVECount   int             `json:"cve_count"`
	KEVCount   int             `json:"kev_count"`
}

// VulnAdvisory is a matched advisory stored on an asset.
type VulnAdvisory struct {
	ID        string   `json:"id"`
	Title     string   `json:"title"`
	CVEs      []string `json:"cves"`
	CVSSv3    float64  `json:"cvss_v3"`
	KEV       bool     `json:"kev"`
	RiskScore float64  `json:"risk_score"`
}

// UpdateVulnState sets the vulnerability state for an asset by ID.
// Returns false if the asset was not found.
func (s *Store) UpdateVulnState(id string, state *VulnState) bool {
	a := s.Get(id)
	if a == nil {
		return false
	}
	a.VulnState = state
	return true
}

// assetHasCVE checks whether an asset's vuln state references the given CVE.
func assetHasCVE(a Asset, cve string) bool {
	if a.VulnState == nil {
		return false
	}
	cve = strings.ToUpper(cve)
	for _, adv := range a.VulnState.Advisories {
		for _, c := range adv.CVEs {
			if strings.ToUpper(c) == cve {
				return true
			}
		}
	}
	return false
}
