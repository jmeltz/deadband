package updater

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jmeltz/deadband/pkg/advisory"
	"github.com/jmeltz/deadband/pkg/matcher"
)

func TestFetchNVDAdvisories_CPERangeConversionAndFiltering(t *testing.T) {
	var sawAPIKey atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("apiKey") == "test-key-123" {
			sawAPIKey.Store(true)
		}
		kw := r.URL.Query().Get("keywordSearch")
		w.Header().Set("Content-Type", "application/json")
		switch kw {
		case "Vaisala viewLinc":
			_, _ = w.Write([]byte(`{
				"vulnerabilities": [
					{
						"cve": {
							"id": "CVE-2024-21001",
							"published": "2024-08-14T10:00:00.000",
							"lastModified": "2024-08-20T12:00:00.000",
							"descriptions": [{"lang": "en", "value": "Authentication bypass in Vaisala viewLinc Enterprise Server."}],
							"metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.1}}]},
							"weaknesses": [{"description": [{"lang": "en", "value": "CWE-287"}]}],
							"configurations": [{
								"nodes": [{
									"cpeMatch": [
										{
											"vulnerable": true,
											"criteria": "cpe:2.3:a:vaisala:viewlinc_enterprise_server:*:*:*:*:*:*:*:*",
											"versionStartIncluding": "5.0.0",
											"versionEndExcluding": "5.1.4"
										},
										{
											"vulnerable": true,
											"criteria": "cpe:2.3:a:unrelated_vendor:other_app:1.0:*:*:*:*:*:*:*"
										}
									]
								}]
							}]
						}
					},
					{
						"cve": {
							"id": "CVE-2020-0001",
							"published": "2020-01-01T00:00:00.000",
							"lastModified": "2020-01-02T00:00:00.000",
							"descriptions": [{"lang": "en", "value": "Old Vaisala viewLinc issue filtered by since."}],
							"configurations": [{
								"nodes": [{"cpeMatch": [{"vulnerable": true, "criteria": "cpe:2.3:a:vaisala:viewlinc:4.3:*:*:*:*:*:*:*"}]}]
							}]
						}
					}
				]
			}`))
		case "KNAPP KiSoft":
			// Awaiting CPE analysis in NVD (empty configurations), matched via explicit keyword phrase in description
			_, _ = w.Write([]byte(`{
				"vulnerabilities": [
					{
						"cve": {
							"id": "CVE-2024-55010",
							"published": "2024-10-03T08:00:00.000",
							"descriptions": [{"lang": "en", "value": "Privilege escalation in KNAPP KiSoft WCS web portal before 4.12.2."}],
							"metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 8.0}}]},
							"configurations": []
						}
					}
				]
			}`))
		default:
			_, _ = w.Write([]byte(`{"vulnerabilities": []}`))
		}
	}))
	defer srv.Close()

	targets := []NVDTarget{
		{Vendor: "Vaisala", Keyword: "Vaisala viewLinc", VendorTokens: []string{"vaisala"}, FallbackModel: "viewLinc"},
		{Vendor: "KNAPP", Keyword: "KNAPP KiSoft", VendorTokens: []string{"knapp"}, FallbackModel: "KiSoft"},
	}

	since := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	advs := fetchNVDAdvisoriesWithConfig(srv.Client(), srv.URL, targets, "test-key-123", 0, since, nil)
	if !sawAPIKey.Load() {
		t.Error("expected apiKey header to be sent when configured")
	}
	if len(advs) != 2 {
		t.Fatalf("got %d NVD advisories (%+v), want 2", len(advs), advs)
	}

	vaisala := advs[0]
	if vaisala.ID != "CVE-2024-21001" || vaisala.Vendor != "Vaisala" {
		t.Fatalf("unexpected Vaisala advisory: %+v", vaisala)
	}
	if len(vaisala.AffectedVersions) != 1 || vaisala.AffectedVersions[0] != ">=5.0.0|<5.1.4" {
		t.Fatalf("AffectedVersions = %v, want [>=5.0.0|<5.1.4]", vaisala.AffectedVersions)
	}
	// Verify matcher evaluates the generated CPE range expression accurately
	if affected, _ := matcher.VersionAffected("5.1.2", vaisala.AffectedVersions); !affected {
		t.Error("expected viewLinc 5.1.2 to match >=5.0.0|<5.1.4")
	}
	if affected, _ := matcher.VersionAffected("5.1.4", vaisala.AffectedVersions); affected {
		t.Error("expected viewLinc 5.1.4 (fixed) NOT to match >=5.0.0|<5.1.4")
	}

	knapp := advs[1]
	if knapp.ID != "CVE-2024-55010" || knapp.Vendor != "KNAPP" || len(knapp.Products) != 1 || knapp.Products[0] != "KiSoft" {
		t.Errorf("unexpected KNAPP advisory: %+v", knapp)
	}
}

func TestUpdate_AirGapIsolationNeverCallsSupplementalFeeds(t *testing.T) {
	var externalCalls atomic.Int32
	origROLIE := rolieFetcher
	origNVD := nvdFetcher
	rolieFetcher = func(_ *http.Client, _ time.Time, _ func(string)) []advisory.Advisory {
		externalCalls.Add(1)
		return nil
	}
	nvdFetcher = func(_ *http.Client, _ time.Time, _ func(string)) []advisory.Advisory {
		externalCalls.Add(1)
		return nil
	}
	defer func() {
		rolieFetcher = origROLIE
		nvdFetcher = origNVD
	}()

	// 1. Local air-gapped CSAF mirror directory
	tmpDir := t.TempDir()
	mirrorDir := filepath.Join(tmpDir, "csaf-mirror")
	if err := os.MkdirAll(filepath.Join(mirrorDir, "2024"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mirrorDir, "index.txt"), []byte("2024/icsa-24-001-01.json\n"), 0644); err != nil {
		t.Fatal(err)
	}
	csafPayload := `{
		"document": {
			"title": "Air-Gap Mirror Test",
			"tracking": {"id": "ICSA-24-001-01", "initial_release_date": "2024-01-05T00:00:00Z"}
		},
		"product_tree": {
			"branches": [{"category": "vendor", "name": "Danfoss", "branches": [{"category": "product_name", "name": "AK-SM 800A", "branches": [{"category": "product_version_range", "name": "<4.3.0"}]}]}]
		},
		"vulnerabilities": [{"cve": "CVE-2024-1000", "scores": [{"cvss_v3": {"baseScore": 8.1}}]}]
	}`
	if err := os.WriteFile(filepath.Join(mirrorDir, "2024", "icsa-24-001-01.json"), []byte(csafPayload), 0644); err != nil {
		t.Fatal(err)
	}

	dbPath := filepath.Join(tmpDir, "advisories.json")
	db, err := Update(UpdateOpts{DBPath: dbPath, Source: mirrorDir})
	if err != nil {
		t.Fatalf("Update(local mirror) failed: %v", err)
	}
	if len(db.Advisories) != 1 {
		t.Errorf("got %d advisories, want 1", len(db.Advisories))
	}
	if externalCalls.Load() != 0 {
		t.Errorf("local air-gapped update made %d supplemental feed calls, want 0", externalCalls.Load())
	}

	// 2. Explicit internal snapshot URL (--source http://...)
	snapSrv := fixtureSnapshotServer(t, advisory.Database{
		Updated:    time.Now().UTC(),
		Source:     "internal-snapshot",
		Advisories: []advisory.Advisory{{ID: "ICSA-24-002-01", Title: "Internal Snapshot"}},
	}, nil)
	defer snapSrv.Close()

	db2Path := filepath.Join(tmpDir, "advisories2.json")
	db2, err := Update(UpdateOpts{DBPath: db2Path, Source: snapSrv.URL + "/x.json"})
	if err != nil {
		t.Fatalf("Update(explicit snapshot URL) failed: %v", err)
	}
	if len(db2.Advisories) != 1 {
		t.Errorf("got %d advisories, want 1", len(db2.Advisories))
	}
	if externalCalls.Load() != 0 {
		t.Errorf("explicit snapshot URL update made %d supplemental feed calls, want 0", externalCalls.Load())
	}
}

func TestMergeSupplementalOnlineFeeds_DeduplicatesCVEsCoveredByCSAF(t *testing.T) {
	origROLIE := rolieFetcher
	origNVD := nvdFetcher
	rolieFetcher = func(_ *http.Client, _ time.Time, _ func(string)) []advisory.Advisory {
		return []advisory.Advisory{
			{
				ID:     "BECKHOFF-2024-004",
				Vendor: "Beckhoff",
				CVEs:   []string{"CVE-2024-7123"},
			},
		}
	}
	nvdFetcher = func(_ *http.Client, _ time.Time, _ func(string)) []advisory.Advisory {
		return []advisory.Advisory{
			{ID: "CVE-2024-7123", Vendor: "Beckhoff", CVEs: []string{"CVE-2024-7123"}}, // duplicate of ROLIE CSAF
			{ID: "CVE-2024-55010", Vendor: "KNAPP", CVEs: []string{"CVE-2024-55010"}},  // unique OEM CVE
		}
	}
	defer func() {
		rolieFetcher = origROLIE
		nvdFetcher = origNVD
	}()

	existing := map[string]advisory.Advisory{
		"ICSA-24-001-01": {ID: "ICSA-24-001-01", Vendor: "Danfoss", CVEs: []string{"CVE-2024-1000"}},
	}
	now := time.Now().UTC()
	rCount, nCount := mergeSupplementalOnlineFeeds(existing, "2024-01-01", now, nil)
	if rCount != 1 || nCount != 1 {
		t.Fatalf("counts = (%d, %d), want (1, 1)", rCount, nCount)
	}
	if _, dupPresent := existing["CVE-2024-7123"]; dupPresent {
		t.Error("expected CVE-2024-7123 (already covered by BECKHOFF-2024-004) to be skipped")
	}
	if _, ok := existing["CVE-2024-55010"]; !ok {
		t.Error("expected unique KNAPP CVE-2024-55010 to be merged")
	}
}
