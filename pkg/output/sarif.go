package output

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/jmeltz/deadband/pkg/advisory"
	"github.com/jmeltz/deadband/pkg/cli"
	"github.com/jmeltz/deadband/pkg/matcher"
)

// SARIF 2.1.0 types (subset sufficient for vulnerability reporting)

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	ShortDescription sarifMessage   `json:"shortDescription"`
	HelpURI          string         `json:"helpUri,omitempty"`
	Properties       map[string]any `json:"properties,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID       string           `json:"ruleId"`
	Level        string           `json:"level"`
	Message      sarifMessage     `json:"message"`
	Locations    []sarifLocation  `json:"locations,omitempty"`
	Fingerprints map[string]string `json:"fingerprints,omitempty"`
	Properties   map[string]any   `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}

type sarifArtifact struct {
	URI         string `json:"uri"`
	Description *sarifMessage `json:"description,omitempty"`
}

// sarifWriter implements ResultWriter for SARIF 2.1.0 output.
type sarifWriter struct {
	w       io.Writer
	db      advisory.Database
	count   int
	results []matcher.Result
}

func newSARIFWriter(w io.Writer) *sarifWriter {
	return &sarifWriter{w: w}
}

func (sw *sarifWriter) WriteHeader(db advisory.Database, deviceCount int) error {
	sw.db = db
	sw.count = deviceCount
	return nil
}

func (sw *sarifWriter) WriteResult(r matcher.Result) error {
	sw.results = append(sw.results, r)
	return nil
}

func (sw *sarifWriter) WriteSummary(_ Summary, _ int) error {
	return nil
}

func (sw *sarifWriter) Flush() error {
	// Collect unique advisories as rules
	ruleIndex := make(map[string]int)
	var rules []sarifRule

	for _, r := range sw.results {
		for _, m := range r.Matches {
			if _, exists := ruleIndex[m.Advisory.ID]; !exists {
				ruleIndex[m.Advisory.ID] = len(rules)
				props := map[string]any{
					"cvss_v3": m.Advisory.CVSSv3Max,
				}
				if len(m.Advisory.CVEs) > 0 {
					props["cves"] = m.Advisory.CVEs
				}
				rules = append(rules, sarifRule{
					ID:               m.Advisory.ID,
					ShortDescription: sarifMessage{Text: strings.TrimSpace(m.Advisory.Title)},
					HelpURI:          m.Advisory.URL,
					Properties:       props,
				})
			}
		}
	}

	// Build results
	var results []sarifResult
	for _, r := range sw.results {
		for _, m := range r.Matches {
			level := "note"
			switch strings.ToUpper(r.Status) {
			case "VULNERABLE":
				level = "error"
			case "POTENTIAL":
				level = "warning"
			}

			msg := fmt.Sprintf("%s %s (fw %s) is %s to %s (CVSS %.1f)",
				r.Device.IP, r.Device.Model, r.Device.Firmware,
				strings.ToLower(r.Status), m.Advisory.ID, m.Advisory.CVSSv3Max)

			fingerprint := fmt.Sprintf("%x", sha256.Sum256(
				[]byte(r.Device.IP+":"+r.Device.Model+":"+m.Advisory.ID)))

			props := map[string]any{
				"confidence": string(m.Confidence),
				"vendor":     r.Device.Vendor,
				"firmware":   r.Device.Firmware,
				"checked_at": time.Now().UTC().Format(time.RFC3339),
			}
			if m.KEV {
				props["kev"] = true
			}
			if m.KEVRansomware {
				props["kev_ransomware"] = true
			}
			if m.EPSSScore > 0 {
				props["epss_score"] = m.EPSSScore
				props["epss_percentile"] = m.EPSSPercentile
			}
			if m.RiskScore > 0 {
				props["risk_score"] = m.RiskScore
			}

			results = append(results, sarifResult{
				RuleID:  m.Advisory.ID,
				Level:   level,
				Message: sarifMessage{Text: msg},
				Locations: []sarifLocation{{
					PhysicalLocation: sarifPhysical{
						ArtifactLocation: sarifArtifact{
							URI:         r.Device.IP,
							Description: &sarifMessage{Text: r.Device.Model + " fw " + r.Device.Firmware},
						},
					},
				}},
				Fingerprints: map[string]string{
					"deadband/v1": fingerprint[:16],
				},
				Properties: props,
			})
		}
	}

	log := sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:           "deadband",
					Version:        cli.Version,
					InformationURI: "https://github.com/jmeltz/deadband",
					Rules:          rules,
				},
			},
			Results: results,
		}},
	}

	enc := json.NewEncoder(sw.w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}
