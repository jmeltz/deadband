package updater

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestFetchROLIEAdvisories_SinceFilterDedupAndNonFatalFallback(t *testing.T) {
	mux := http.NewServeMux()

	var srvURL string
	mux.HandleFunc("/.well-known/csaf/white/csaf-feed-tlp-white.json", func(w http.ResponseWriter, r *http.Request) {
		feed := fmt.Sprintf(`{
			"feed": {
				"id": "beckhoff-tlp-white",
				"title": "Beckhoff PSIRT TLP:WHITE",
				"updated": "2025-02-01T00:00:00Z",
				"entry": [
					{
						"id": "BECKHOFF-2022-001",
						"published": "2022-05-10T00:00:00Z",
						"updated": "2022-05-12T00:00:00Z",
						"content": {"type": "application/json", "src": "%s/.well-known/csaf/white/2022/beckhoff-2022-001.json"}
					},
					{
						"id": "BECKHOFF-2024-004",
						"published": "2024-07-11T08:00:00Z",
						"updated": "2024-07-15T08:00:00Z",
						"content": {"type": "application/json", "src": "2024/beckhoff-2024-004.json"}
					}
				]
			}
		}`, srvURL)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(feed))
	})

	// Coordinator feed linking the same BECKHOFF-2024-004 + a SICK advisory via link[rel=self]
	mux.HandleFunc("/vde/csaf-feed-tlp-white.json", func(w http.ResponseWriter, r *http.Request) {
		feed := fmt.Sprintf(`{
			"feed": {
				"id": "certvde-tlp-white",
				"updated": "2025-02-01T00:00:00Z",
				"entry": [
					{
						"id": "BECKHOFF-2024-004",
						"updated": "2024-07-15T08:00:00Z",
						"content": {"type": "application/json", "src": "%s/.well-known/csaf/white/2024/beckhoff-2024-004.json"}
					},
					{
						"id": "VDE-2024-055",
						"updated": "2024-11-03T10:00:00Z",
						"link": [{"rel": "self", "href": "%s/vde/2024/vde-2024-055.json"}]
					}
				]
			}
		}`, srvURL, srvURL)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(feed))
	})

	mux.HandleFunc("/broken/csaf-feed-tlp-white.json", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "upstream gateway timeout", http.StatusGatewayTimeout)
	})

	mux.HandleFunc("/.well-known/csaf/white/2022/beckhoff-2022-001.json", func(w http.ResponseWriter, r *http.Request) {
		t.Error("expected 2022 entry to be skipped by since filter")
		http.NotFound(w, r)
	})

	mux.HandleFunc("/.well-known/csaf/white/2024/beckhoff-2024-004.json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{
			"document": {
				"title": "Beckhoff TwinCAT ADS RCE",
				"publisher": {"category": "vendor", "name": "Beckhoff"},
				"tracking": {"id": "BECKHOFF-2024-004", "initial_release_date": "2024-07-11T08:00:00Z"},
				"references": [{"category": "external", "url": "https://cert.vde.com/en/advisories/BECKHOFF-2024-004/"}]
			},
			"product_tree": {
				"branches": [{"category": "product_name", "name": "TwinCAT 3", "branches": [{"category": "product_version_range", "name": "<3.1.4024.53"}]}]
			},
			"vulnerabilities": [{"cve": "CVE-2024-7123", "scores": [{"cvss_v3": {"baseScore": 9.8}}]}]
		}`))
	})

	mux.HandleFunc("/vde/2024/vde-2024-055.json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{
			"document": {
				"title": "Pilz PNOZmulti Configurator Improper Auth",
				"publisher": {"category": "coordinator", "name": "CERT@VDE"},
				"tracking": {"id": "VDE-2024-055", "initial_release_date": "2024-11-03T10:00:00Z"},
				"references": [{"category": "self", "url": "https://cert.vde.com/en/advisories/VDE-2024-055/"}]
			},
			"product_tree": {
				"branches": [{"category": "vendor", "name": "Pilz", "branches": [{"category": "product_name", "name": "PNOZmulti", "branches": [{"category": "product_version_range", "name": "<11.3.0"}]}]}]
			},
			"vulnerabilities": [{"cve": "CVE-2024-9901", "scores": [{"cvss_v3": {"baseScore": 7.5}}]}]
		}`))
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()
	srvURL = srv.URL

	providers := []ROLIEProvider{
		{Name: "Beckhoff", FeedURL: srv.URL + "/.well-known/csaf/white/csaf-feed-tlp-white.json"},
		{Name: "CERT@VDE", FeedURL: srv.URL + "/vde/csaf-feed-tlp-white.json"},
		{Name: "BrokenProvider", FeedURL: srv.URL + "/broken/csaf-feed-tlp-white.json"},
	}

	since := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	var (
		msgsMu sync.Mutex
		msgs   []string
	)
	advs := fetchROLIEAdvisoriesFromProviders(srv.Client(), providers, since, func(m string) {
		msgsMu.Lock()
		msgs = append(msgs, m)
		msgsMu.Unlock()
	})

	if len(advs) != 2 {
		t.Fatalf("got %d advisories (%+v), want 2 deduplicated advisories", len(advs), advs)
	}

	found := make(map[string]string)
	for _, a := range advs {
		found[a.ID] = a.Vendor
	}
	if found["BECKHOFF-2024-004"] != "Beckhoff" {
		t.Errorf("BECKHOFF-2024-004 vendor = %q, want Beckhoff", found["BECKHOFF-2024-004"])
	}
	if found["VDE-2024-055"] != "Pilz" {
		t.Errorf("VDE-2024-055 vendor = %q, want Pilz", found["VDE-2024-055"])
	}

	warnedBroken := false
	for _, m := range msgs {
		if strings.Contains(m, "BrokenProvider") {
			warnedBroken = true
		}
	}
	if !warnedBroken {
		t.Errorf("expected warning for BrokenProvider, got progress messages: %v", msgs)
	}
}
