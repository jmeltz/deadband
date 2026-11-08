package updater

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jmeltz/deadband/pkg/advisory"
)

func TestMergeAdvisories_NewAdvisoryGetsFirstSeen(t *testing.T) {
	now := time.Now().UTC()
	existing := make(map[string]advisory.Advisory)

	fetched := []advisory.Advisory{
		{ID: "ICSA-24-001-01", Title: "New Advisory"},
	}

	result := mergeAdvisories(existing, fetched, now)
	a := result["ICSA-24-001-01"]
	if a.FirstSeen == nil {
		t.Fatal("expected FirstSeen to be set for new advisory")
	}
	if !a.FirstSeen.Equal(now) {
		t.Errorf("FirstSeen = %v, want %v", a.FirstSeen, now)
	}
	if a.LastSeen == nil || !a.LastSeen.Equal(now) {
		t.Errorf("LastSeen = %v, want %v", a.LastSeen, now)
	}
}

func TestMergeAdvisories_ExistingPreservesFirstSeen(t *testing.T) {
	oldTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	now := time.Now().UTC()

	existing := map[string]advisory.Advisory{
		"ICSA-24-001-01": {
			ID:        "ICSA-24-001-01",
			Title:     "Old Title",
			FirstSeen: &oldTime,
			LastSeen:  &oldTime,
		},
	}

	fetched := []advisory.Advisory{
		{ID: "ICSA-24-001-01", Title: "Updated Title"},
	}

	result := mergeAdvisories(existing, fetched, now)
	a := result["ICSA-24-001-01"]

	if a.Title != "Updated Title" {
		t.Errorf("Title = %q, want %q", a.Title, "Updated Title")
	}
	if a.FirstSeen == nil || !a.FirstSeen.Equal(oldTime) {
		t.Errorf("FirstSeen = %v, want %v (should be preserved)", a.FirstSeen, oldTime)
	}
	if a.LastSeen == nil || !a.LastSeen.Equal(now) {
		t.Errorf("LastSeen = %v, want %v", a.LastSeen, now)
	}
}

func TestMergeAdvisories_MixedNewAndExisting(t *testing.T) {
	oldTime := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	now := time.Now().UTC()

	existing := map[string]advisory.Advisory{
		"EXISTING-01": {ID: "EXISTING-01", FirstSeen: &oldTime},
	}

	fetched := []advisory.Advisory{
		{ID: "EXISTING-01"},
		{ID: "NEW-01"},
	}

	result := mergeAdvisories(existing, fetched, now)

	if len(result) != 2 {
		t.Fatalf("expected 2 advisories, got %d", len(result))
	}
	if !result["EXISTING-01"].FirstSeen.Equal(oldTime) {
		t.Error("existing advisory FirstSeen should be preserved")
	}
	if !result["NEW-01"].FirstSeen.Equal(now) {
		t.Error("new advisory FirstSeen should be set to now")
	}
}

func TestParseCSAF_NonCISAPublishersAndFixedVersionExclusion(t *testing.T) {
	// 1. Beckhoff CSAF 2.0 advisory omitting category="vendor" in product_tree,
	// with both known_affected and fixed product_ids.
	beckhoffJSON := `{
		"document": {
			"title": "Beckhoff TwinCAT XAR Remote Code Execution",
			"publisher": {
				"category": "vendor",
				"name": "Beckhoff Automation",
				"namespace": "https://info.beckhoff.com/psirt"
			},
			"tracking": {
				"id": "BECKHOFF-2024-004",
				"initial_release_date": "2024-07-11T08:00:00Z",
				"current_release_date": "2024-07-15T08:00:00Z"
			},
			"references": [
				{"category": "self", "url": "https://beckhoff.csaf-tp.certvde.com/.well-known/csaf/white/2024/beckhoff-2024-004.json"},
				{"category": "external", "url": "https://cert.vde.com/en/advisories/BECKHOFF-2024-004/"}
			],
			"notes": [
				{"category": "description", "text": "Unauthenticated ADS packet handling vulnerability in TwinCAT 3."}
			]
		},
		"product_tree": {
			"branches": [
				{
					"category": "product_name",
					"name": "TwinCAT XAR",
					"branches": [
						{
							"category": "product_version_range",
							"name": "vers:all/<3.1.4024.53",
							"product": {"name": "TwinCAT XAR < 3.1.4024.53", "product_id": "CSAFPID-0001"}
						},
						{
							"category": "product_version",
							"name": "3.1.4024.53",
							"product": {"name": "TwinCAT XAR 3.1.4024.53", "product_id": "CSAFPID-0002"}
						}
					]
				}
			]
		},
		"vulnerabilities": [
			{
				"cve": "CVE-2024-7123",
				"cwe": {"id": "CWE-121", "name": "Stack-based Buffer Overflow"},
				"product_status": {
					"known_affected": ["CSAFPID-0001"],
					"fixed": ["CSAFPID-0002"]
				},
				"scores": [
					{"cvss_v3": {"baseScore": 9.8}}
				]
			}
		]
	}`

	var doc csafDoc
	if err := json.Unmarshal([]byte(beckhoffJSON), &doc); err != nil {
		t.Fatalf("unmarshal beckhoff CSAF: %v", err)
	}
	advs := parseCSAF(&doc)
	if len(advs) != 1 {
		t.Fatalf("parseCSAF count = %d, want 1", len(advs))
	}
	got := advs[0]
	if got.Vendor != "Beckhoff Automation" {
		t.Errorf("Vendor = %q, want Beckhoff Automation", got.Vendor)
	}
	if got.URL != "https://cert.vde.com/en/advisories/BECKHOFF-2024-004/" {
		t.Errorf("URL = %q, want CERT@VDE advisory URL (not cisa.gov)", got.URL)
	}
	if strings.Contains(got.URL, "cisa.gov") {
		t.Errorf("non-CISA advisory must not fabricate cisa.gov URL: %q", got.URL)
	}
	if len(got.AffectedVersions) != 1 || got.AffectedVersions[0] != "vers:all/<3.1.4024.53" {
		t.Errorf("AffectedVersions = %v, want [vers:all/<3.1.4024.53] (fixed 3.1.4024.53 excluded)", got.AffectedVersions)
	}
	if got.Summary == "" {
		t.Error("expected fallback description note to populate Summary")
	}

	// 2. SICK PSIRT CSAF 2.0 advisory with only JSON self reference
	sickJSON := `{
		"document": {
			"title": "SICK CLV65x CoLa Authentication Bypass",
			"publisher": {"category": "vendor", "name": "SICK AG", "namespace": "https://www.sick.com/psirt"},
			"tracking": {"id": "SICK-2024-0003", "initial_release_date": "2024-05-02T00:00:00Z"},
			"references": [
				{"category": "self", "url": "https://www.sick.com/.well-known/csaf/white/2024/sick-2024-0003.json"}
			]
		},
		"product_tree": {
			"branches": [
				{
					"category": "vendor",
					"name": "SICK",
					"branches": [
						{
							"category": "product_name",
							"name": "CLV650",
							"branches": [
								{"category": "product_version_range", "name": "vers:generic/<=2.10.0"}
							]
						}
					]
				}
			]
		},
		"vulnerabilities": [{"cve": "CVE-2024-39001", "scores": [{"cvss_v3": {"baseScore": 8.6}}]}]
	}`
	var sickDoc csafDoc
	if err := json.Unmarshal([]byte(sickJSON), &sickDoc); err != nil {
		t.Fatalf("unmarshal SICK CSAF: %v", err)
	}
	sickAdvs := parseCSAF(&sickDoc)
	if len(sickAdvs) != 1 {
		t.Fatalf("parseCSAF(SICK) count = %d, want 1", len(sickAdvs))
	}
	if sickAdvs[0].Vendor != "SICK" || sickAdvs[0].URL != "https://www.sick.com/.well-known/csaf/white/2024/sick-2024-0003.json" {
		t.Errorf("SICK advisory = %+v", sickAdvs[0])
	}
}
