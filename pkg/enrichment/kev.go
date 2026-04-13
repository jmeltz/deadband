package enrichment

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

const kevURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

// KEVEntry represents a single entry from the CISA Known Exploited Vulnerabilities catalog.
type KEVEntry struct {
	CVEID                       string `json:"cveID"`
	VendorProject               string `json:"vendorProject"`
	Product                     string `json:"product"`
	VulnerabilityName           string `json:"vulnerabilityName"`
	DateAdded                   string `json:"dateAdded"`
	ShortDescription            string `json:"shortDescription"`
	RequiredAction              string `json:"requiredAction"`
	DueDate                     string `json:"dueDate"`
	KnownRansomwareCampaignUse  string `json:"knownRansomwareCampaignUse"`
}

// IsRansomware returns true if this KEV entry is associated with known ransomware campaigns.
func (k KEVEntry) IsRansomware() bool {
	return k.KnownRansomwareCampaignUse == "Known"
}

// KEVCatalog holds the full KEV JSON structure.
type KEVCatalog struct {
	Title         string     `json:"title"`
	CatalogVersion string   `json:"catalogVersion"`
	DateReleased  string     `json:"dateReleased"`
	Count         int        `json:"count"`
	Vulnerabilities []KEVEntry `json:"vulnerabilities"`
}

// KEVData is the runtime lookup structure for KEV entries.
type KEVData struct {
	DateReleased string
	Count        int
	Entries      map[string]KEVEntry // keyed by CVE ID
}

// FetchKEV downloads the CISA KEV catalog and returns parsed data.
func FetchKEV(progress func(string)) (*KEVData, error) {
	if progress != nil {
		progress("Fetching CISA KEV catalog...")
	}

	resp, err := http.Get(kevURL)
	if err != nil {
		return nil, fmt.Errorf("fetching KEV catalog: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("KEV catalog HTTP %d", resp.StatusCode)
	}

	return parseKEV(resp.Body)
}

// LoadKEVFromFile loads KEV data from a local file (for air-gapped environments).
func LoadKEVFromFile(path string) (*KEVData, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseKEV(f)
}

func parseKEV(r io.Reader) (*KEVData, error) {
	var catalog KEVCatalog
	if err := json.NewDecoder(r).Decode(&catalog); err != nil {
		return nil, fmt.Errorf("parsing KEV catalog: %w", err)
	}

	data := &KEVData{
		DateReleased: catalog.DateReleased,
		Count:        catalog.Count,
		Entries:      make(map[string]KEVEntry, len(catalog.Vulnerabilities)),
	}
	for _, v := range catalog.Vulnerabilities {
		data.Entries[v.CVEID] = v
	}
	return data, nil
}

// SaveKEV writes the raw KEV JSON to disk for caching.
func SaveKEV(dir string, data *KEVData) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// Rebuild catalog for serialization
	catalog := KEVCatalog{
		DateReleased: data.DateReleased,
		Count:        data.Count,
	}
	for _, e := range data.Entries {
		catalog.Vulnerabilities = append(catalog.Vulnerabilities, e)
	}

	out, err := json.Marshal(catalog)
	if err != nil {
		return err
	}

	path := filepath.Join(dir, "kev.json")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, out, 0644); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
